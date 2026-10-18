"""Authentication, account recovery, and designation management for the dashboard."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import string
import time
import base64
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken
import streamlit as st


LOGGER = logging.getLogger(__name__)
PASSWORD_ITERATIONS = 600_000
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
TOKEN_LIFETIME_SECONDS = 60 * 60
RATE_WINDOW_SECONDS = 15 * 60
ROLE_VALUES = {"public", "worker", "manager", "hr", "admin"}
DEFAULT_DESIGNATIONS = (
    ("Administrator", "admin"),
    ("Manager", "manager"),
    ("HR / Human Resources", "hr"),
    ("Employee / Staff", "worker"),
    ("Customer / General User", "public"),
    ("Other", "public"),
)


class AuthError(Exception):
    """An expected authentication or account-management failure."""


class AuthConfigurationError(AuthError):
    """A required authentication service is not configured."""


@contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    database_path = Path(os.getenv("SMARTBIN_AUTH_DB_PATH", "data/smartbin_auth.sqlite3")).expanduser()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        yield connection
        if connection.in_transaction:
            connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        algorithm, iterations, salt_hex, expected_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def password_error(password: str) -> str | None:
    if len(password) < 12:
        return "Use at least 12 characters."
    if len(password) > 256:
        return "Use no more than 256 characters."
    if not any(char.islower() for char in password):
        return "Include at least one lowercase letter."
    if not any(char.isupper() for char in password):
        return "Include at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return "Include at least one number."
    if not any(char in string.punctuation for char in password):
        return "Include at least one symbol."
    return None


def _normalize_email(email: str) -> str:
    return email.strip().casefold()


def _valid_email(email: str) -> bool:
    return len(email) <= 254 and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def _valid_username(username: str) -> bool:
    return re.fullmatch(r"[a-z0-9_.-]{3,32}", username.casefold()) is not None


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _totp_cipher() -> Fernet:
    key = os.getenv("SMARTBIN_TOTP_ENCRYPTION_KEY", "").strip()
    if not key:
        raise AuthConfigurationError(
            "Two-factor authentication is not configured. Set SMARTBIN_TOTP_ENCRYPTION_KEY."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise AuthConfigurationError("SMARTBIN_TOTP_ENCRYPTION_KEY must be a valid Fernet key.") from exc


def _new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_code(secret: str, counter: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


def _verify_totp(secret: str, code: str, now: int | None = None) -> bool:
    return _matching_totp_counter(secret, code, now) is not None


def _matching_totp_counter(secret: str, code: str, now: int | None = None) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    counter = int(time.time() if now is None else now) // 30
    match = None
    for offset in (-1, 0, 1):
        candidate = counter + offset
        if hmac.compare_digest(_totp_code(secret, candidate), code):
            match = candidate
    return match


def _decrypt_totp_secret(encrypted: bytes) -> str:
    try:
        return _totp_cipher().decrypt(encrypted).decode("ascii")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise AuthConfigurationError(
            "The two-factor encryption key does not match the configured account data."
        ) from exc


def _subject_hash(value: str) -> str:
    return _secret_hash(value.strip().casefold())


def _create_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS designations (
            name TEXT PRIMARY KEY COLLATE NOCASE,
            role TEXT NOT NULL CHECK (role IN ('public', 'worker', 'manager', 'hr', 'admin')),
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            phone TEXT,
            password_hash TEXT NOT NULL,
            designation TEXT NOT NULL,
            requested_role TEXT NOT NULL CHECK (requested_role IN ('public', 'worker', 'manager', 'hr', 'admin')),
            role TEXT NOT NULL DEFAULT 'public' CHECK (role IN ('public', 'worker', 'manager', 'hr', 'admin')),
            designation_approved INTEGER NOT NULL DEFAULT 0,
            email_verified_at INTEGER,
            totp_secret_enc BLOB,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_last_counter INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            terms_accepted_at INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS one_time_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS recovery_codes (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            used_at INTEGER,
            PRIMARY KEY (user_id, code_hash)
        );
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rate_limits (
            bucket TEXT NOT NULL,
            subject_hash TEXT NOT NULL,
            window_started INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            PRIMARY KEY (bucket, subject_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_user ON one_time_tokens(user_id, purpose);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
        """
    )
    connection.executemany(
        "INSERT OR IGNORE INTO designations(name, role) VALUES (?, ?)",
        DEFAULT_DESIGNATIONS,
    )
    user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
    if "totp_secret_enc" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN totp_secret_enc BLOB")
    if "totp_enabled" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
    if "totp_last_counter" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN totp_last_counter INTEGER")
    if "terms_accepted_at" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN terms_accepted_at INTEGER")


def _bootstrap_admin(connection: sqlite3.Connection) -> None:
    email = _normalize_email(os.getenv("SMARTBIN_BOOTSTRAP_ADMIN_EMAIL", ""))
    password = os.getenv("SMARTBIN_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not email and not password:
        return
    if not email or not password or not _valid_email(email):
        raise AuthConfigurationError(
            "Set both SMARTBIN_BOOTSTRAP_ADMIN_EMAIL and SMARTBIN_BOOTSTRAP_ADMIN_PASSWORD to bootstrap an administrator."
        )
    if (error := password_error(password)) is not None:
        raise AuthConfigurationError(f"The bootstrap administrator password is not strong enough: {error}")
    if connection.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone():
        return
    username = re.sub(r"[^a-z0-9_.-]", "", email.split("@", 1)[0].casefold())[:32]
    if len(username) < 3:
        username = f"admin-{secrets.token_hex(4)}"
    existing = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        connection.execute(
            """UPDATE users SET full_name = 'Bootstrap Administrator', password_hash = ?,
               designation = 'Administrator', requested_role = 'admin', role = 'admin',
               designation_approved = 1, email_verified_at = ?, enabled = 1 WHERE id = ?""",
            (_hash_password(password), int(time.time()), existing["id"]),
        )
    else:
        if connection.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            username = f"admin-{secrets.token_hex(4)}"
        connection.execute(
            """INSERT INTO users(full_name, username, email, password_hash, designation,
               requested_role, role, designation_approved, email_verified_at, created_at)
               VALUES ('Bootstrap Administrator', ?, ?, ?, 'Administrator', 'admin', 'admin', 1, ?, ?)""",
            (username, email, _hash_password(password), int(time.time()), int(time.time())),
        )


def initialize_auth() -> None:
    with _database() as connection:
        _create_tables(connection)
        _bootstrap_admin(connection)


def _consume_rate_limit(bucket: str, subject: str, limit: int, window: int = RATE_WINDOW_SECONDS) -> bool:
    now = int(time.time())
    digest = _subject_hash(subject)
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM rate_limits WHERE window_started < ?", (now - 7 * 24 * 60 * 60,))
        row = connection.execute(
            "SELECT window_started, attempts FROM rate_limits WHERE bucket = ? AND subject_hash = ?",
            (bucket, digest),
        ).fetchone()
        if row is None or now - row["window_started"] >= window:
            connection.execute(
                """INSERT INTO rate_limits(bucket, subject_hash, window_started, attempts)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(bucket, subject_hash) DO UPDATE SET window_started = excluded.window_started, attempts = 1""",
                (bucket, digest, now),
            )
            return False
        if row["attempts"] >= limit:
            return True
        connection.execute(
            "UPDATE rate_limits SET attempts = attempts + 1 WHERE bucket = ? AND subject_hash = ?",
            (bucket, digest),
        )
        return False


def _mailer_config() -> tuple[str, int, str, str, str, str]:
    base_url = os.getenv("SMARTBIN_APP_BASE_URL", "").strip().rstrip("/")
    host = os.getenv("SMARTBIN_SMTP_HOST", "").strip()
    sender = os.getenv("SMARTBIN_SMTP_FROM", "").strip()
    if not base_url or not host or not sender:
        raise AuthConfigurationError(
            "Email verification is not configured. Set SMARTBIN_APP_BASE_URL, SMARTBIN_SMTP_HOST, and SMARTBIN_SMTP_FROM."
        )
    if not _valid_email(sender):
        raise AuthConfigurationError("SMARTBIN_SMTP_FROM must be a valid email address.")
    try:
        port = int(os.getenv("SMARTBIN_SMTP_PORT", "587"))
    except ValueError as exc:
        raise AuthConfigurationError("SMARTBIN_SMTP_PORT must be a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise AuthConfigurationError("SMARTBIN_SMTP_PORT must be between 1 and 65535.")
    return (
        base_url,
        port,
        host,
        sender,
        os.getenv("SMARTBIN_SMTP_USERNAME", ""),
        os.getenv("SMARTBIN_SMTP_PASSWORD", ""),
    )


def _token_url(base_url: str, parameter: str, token: str) -> str:
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[parameter] = token
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _send_email(recipient: str, subject: str, body: str) -> None:
    _, port, host, sender, username, password = _mailer_config()
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            if username:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)


def _issue_token(connection: sqlite3.Connection, user_id: int, purpose: str) -> str:
    now = int(time.time())
    connection.execute(
        "UPDATE one_time_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL",
        (now, user_id, purpose),
    )
    token = secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO one_time_tokens(token_hash, user_id, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (_secret_hash(token), user_id, purpose, now, now + TOKEN_LIFETIME_SECONDS),
    )
    return token


def register_user(
    full_name: str,
    username: str,
    email: str,
    phone: str,
    password: str,
    designation: str,
    terms_accepted: bool = False,
) -> None:
    full_name = full_name.strip()
    username = username.strip().casefold()
    email = _normalize_email(email)
    phone = phone.strip()
    if not full_name or len(full_name) > 120:
        raise AuthError("Enter a full name of 1–120 characters.")
    if not _valid_username(username):
        raise AuthError("Username must be 3–32 characters using letters, numbers, dots, underscores, or hyphens.")
    if not _valid_email(email):
        raise AuthError("Enter a valid email address.")
    if phone and not re.fullmatch(r"\+?[0-9 ()-]{7,20}", phone):
        raise AuthError("Enter a valid phone number or leave it blank.")
    if not terms_accepted:
        raise AuthError("Accept the terms and conditions to create an account.")
    if (error := password_error(password)) is not None:
        raise AuthError(error)
    if _consume_rate_limit("register", email, 3, 60 * 60):
        raise AuthError("Too many registration attempts. Try again later.")
    base_url, _, _, _, _, _ = _mailer_config()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM users WHERE email = ? OR username = ?", (email, username)
        ).fetchone():
            raise AuthError("An account could not be created with those details. Sign in or use account recovery if you already registered.")
        option = connection.execute(
            "SELECT name, role FROM designations WHERE name = ? COLLATE NOCASE AND enabled = 1",
            (designation,),
        ).fetchone()
        if not option:
            raise AuthError("Choose an available designation.")
        requested_role = option["role"]
        approved = int(requested_role == "public")
        now = int(time.time())
        cursor = connection.execute(
            """INSERT INTO users(full_name, username, email, phone, password_hash, designation,
               requested_role, role, designation_approved, terms_accepted_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'public', ?, ?, ?)""",
            (
                full_name, username, email, phone or None, _hash_password(password),
                option["name"], requested_role, approved, now, now,
            ),
        )
        token = _issue_token(connection, cursor.lastrowid, "verify_email")
        link = _token_url(base_url, "verify", token)
        _send_email(
            email,
            "Verify your Smart Waste Dashboard account",
            f"Hello {full_name},\n\nVerify your email address with this one-time link (valid for one hour):\n{link}\n\nIf you did not request this account, you can ignore this message.",
        )


def verify_email_token(token: str) -> bool:
    now = int(time.time())
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        token_row = connection.execute(
            """SELECT user_id FROM one_time_tokens WHERE token_hash = ?
               AND purpose = 'verify_email' AND used_at IS NULL AND expires_at > ?""",
            (_secret_hash(token), now),
        ).fetchone()
        if not token_row:
            return False
        connection.execute(
            "UPDATE one_time_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (now, _secret_hash(token)),
        )
        connection.execute(
            "UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL",
            (now, token_row["user_id"]),
        )
        return True


def resend_verification(email: str) -> None:
    email = _normalize_email(email)
    if _consume_rate_limit("resend_verification", email, 3):
        raise AuthError("Too many requests. Try again later.")
    if not _valid_email(email):
        return
    base_url, _, _, _, _, _ = _mailer_config()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            "SELECT id, full_name FROM users WHERE email = ? AND email_verified_at IS NULL AND enabled = 1",
            (email,),
        ).fetchone()
        if not user:
            return
        token = _issue_token(connection, user["id"], "verify_email")
        link = _token_url(base_url, "verify", token)
        _send_email(
            email,
            "Verify your Smart Waste Dashboard account",
            f"Hello {user['full_name']},\n\nVerify your email address with this one-time link (valid for one hour):\n{link}\n",
        )


def _verify_second_factor(
    connection: sqlite3.Connection, user: sqlite3.Row, code: str
) -> tuple[bool, bool]:
    if not user["totp_enabled"] or not user["totp_secret_enc"]:
        return False, False
    totp_counter = _matching_totp_counter(_decrypt_totp_secret(user["totp_secret_enc"]), code)
    if totp_counter is not None:
        updated = connection.execute(
            """UPDATE users SET totp_last_counter = ?
               WHERE id = ? AND (totp_last_counter IS NULL OR totp_last_counter < ?)""",
            (totp_counter, user["id"], totp_counter),
        )
        return updated.rowcount == 1, False
    normalized_code = re.sub(r"[^A-Fa-f0-9]", "", code).casefold()
    candidate_hash = _secret_hash(normalized_code)
    rows = connection.execute(
        "SELECT code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user["id"],),
    ).fetchall()
    matched_hash = None
    for row in rows:
        if hmac.compare_digest(candidate_hash, row["code_hash"]):
            matched_hash = row["code_hash"]
    if not matched_hash:
        return False, False
    updated = connection.execute(
        "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        (int(time.time()), user["id"], matched_hash),
    )
    return updated.rowcount == 1, updated.rowcount == 1


def login(identifier: str, password: str, second_factor_code: str = "") -> tuple[str, dict | None]:
    identifier = identifier.strip().casefold()
    if _consume_rate_limit("login", identifier or "empty", 5):
        return "limited", None
    recovered = False
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            "SELECT * FROM users WHERE (email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE) AND enabled = 1",
            (identifier, identifier),
        ).fetchone()
        candidate_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
        password_matches = _verify_password(password, candidate_hash)
        if not user or not password_matches:
            return "invalid", None
        if user["email_verified_at"] is None:
            return "invalid", None
        if user["totp_enabled"]:
            second_factor_valid, recovered = _verify_second_factor(connection, user, second_factor_code)
            if not second_factor_valid:
                return "invalid", None
        connection.execute(
            "DELETE FROM rate_limits WHERE bucket = 'login' AND subject_hash = ?",
            (_subject_hash(identifier),),
        )
        public_user = _public_user(user)
        email = user["email"]
    if recovered:
        _send_security_notice(email, "A recovery code was used to sign in to your Smart Waste Dashboard account.")
    return "ok", public_user


_DUMMY_PASSWORD_HASH = _hash_password("DummyInvalidPasswordForTimingOnly!42")


def _public_user(user: sqlite3.Row | dict) -> dict:
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "username": user["username"],
        "email": user["email"],
        "phone": user["phone"],
        "designation": user["designation"],
        "role": user["role"],
        "totp_enabled": bool(user["totp_enabled"]),
    }


def _create_session(user_id: int) -> str:
    now = int(time.time())
    raw_token = secrets.token_urlsafe(32)
    with _database() as connection:
        connection.execute(
            "INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?)",
            (_secret_hash(raw_token), user_id, now, now, now + SESSION_ABSOLUTE_SECONDS),
        )
    st.session_state["auth_session_token"] = raw_token
    st.session_state.pop("recovery_codes_pending", None)
    st.session_state.pop("totp_setup_pending", None)
    return raw_token


def _end_session() -> None:
    raw_token = st.session_state.pop("auth_session_token", None)
    if raw_token:
        with _database() as connection:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_secret_hash(raw_token),))
    st.session_state.pop("authenticated_user", None)
    st.session_state.pop("recovery_codes_pending", None)
    st.session_state.pop("totp_setup_pending", None)
    st.session_state.pop("recovery_codes_ack", None)


def current_user() -> dict | None:
    raw_token = st.session_state.get("auth_session_token")
    if not raw_token:
        return None
    now = int(time.time())
    token_hash = _secret_hash(raw_token)
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        session = connection.execute(
            "SELECT user_id, created_at, last_seen, expires_at FROM auth_sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if (
            not session
            or session["expires_at"] <= now
            or session["last_seen"] + SESSION_IDLE_SECONDS <= now
            or session["created_at"] + SESSION_ABSOLUTE_SECONDS <= now
        ):
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
            st.session_state.pop("auth_session_token", None)
            st.session_state.pop("recovery_codes_pending", None)
            st.session_state.pop("totp_setup_pending", None)
            return None
        user = connection.execute(
            "SELECT * FROM users WHERE id = ? AND enabled = 1 AND email_verified_at IS NOT NULL",
            (session["user_id"],),
        ).fetchone()
        if not user:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
            st.session_state.pop("auth_session_token", None)
            st.session_state.pop("recovery_codes_pending", None)
            st.session_state.pop("totp_setup_pending", None)
            return None
        connection.execute("UPDATE auth_sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash))
        public_user = _public_user(user)
        st.session_state["authenticated_user"] = public_user
        return public_user


ROLE_PERMISSIONS = {
    "admin": {
        "dashboard", "map", "fleet", "routes", "forecast", "classifier", "alerts",
        "analytics", "telemetry", "tasks", "reports", "user_admin", "manage_bins",
        "collect_bins", "control_hardware", "dispatch", "simulate_telemetry", "export",
    },
    "manager": {
        "dashboard", "map", "fleet", "routes", "forecast", "classifier", "alerts",
        "analytics", "telemetry", "tasks", "reports", "manage_bins", "collect_bins",
        "control_hardware", "dispatch", "simulate_telemetry", "export",
    },
    "hr": {"dashboard", "reports"},
    "worker": {
        "dashboard", "map", "routes", "telemetry", "tasks", "reports",
        "collect_bins", "dispatch", "simulate_telemetry",
    },
    "public": {"dashboard", "map", "classifier", "reports"},
}


def has_permission(user: dict, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.get("role"), set())


def _session_actor(actor: dict) -> sqlite3.Row | None:
    raw_token = st.session_state.get("auth_session_token")
    if not raw_token:
        return None
    now = int(time.time())
    with _database() as connection:
        return connection.execute(
            """SELECT users.id, users.role
               FROM auth_sessions
               JOIN users ON users.id = auth_sessions.user_id
               WHERE auth_sessions.token_hash = ? AND users.id = ? AND users.enabled = 1
               AND users.email_verified_at IS NOT NULL AND auth_sessions.expires_at > ?
               AND auth_sessions.last_seen + ? > ?
               AND auth_sessions.created_at + ? > ?""",
            (
                _secret_hash(raw_token), actor.get("id"), now, SESSION_IDLE_SECONDS, now,
                SESSION_ABSOLUTE_SECONDS, now,
            ),
        ).fetchone()


def require_permission(user: dict, permission: str) -> None:
    actor = _session_actor(user)
    if not actor or permission not in ROLE_PERMISSIONS.get(actor["role"], set()):
        raise PermissionError("Your account is not authorized to perform this action.")


def designation_options() -> list[dict]:
    with _database() as connection:
        rows = connection.execute(
            "SELECT name, role FROM designations WHERE enabled = 1 ORDER BY name COLLATE NOCASE"
        ).fetchall()
    return [dict(row) for row in rows]


def pending_approvals(actor: dict) -> list[dict]:
    require_permission(actor, "user_admin")
    with _database() as connection:
        rows = connection.execute(
            """SELECT id, full_name, username, email, designation, requested_role, created_at
               FROM users WHERE designation_approved = 0 AND email_verified_at IS NOT NULL
               ORDER BY created_at"""
        ).fetchall()
    return [dict(row) for row in rows]


def approve_designation(actor: dict, user_id: int) -> None:
    require_permission(actor, "user_admin")
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            """SELECT designations.role FROM users
               JOIN designations ON designations.name = users.designation COLLATE NOCASE
               WHERE users.id = ? AND users.designation_approved = 0 AND designations.enabled = 1""",
            (user_id,),
        ).fetchone()
        if not target:
            raise AuthError("This designation request is no longer pending or its designation is disabled.")
        connection.execute(
            "UPDATE users SET role = ?, designation_approved = 1 WHERE id = ?",
            (target["role"], user_id),
        )


def reject_designation(actor: dict, user_id: int) -> None:
    require_permission(actor, "user_admin")
    with _database() as connection:
        connection.execute(
            "UPDATE users SET designation = 'Customer / General User', requested_role = 'public', role = 'public', designation_approved = 1 WHERE id = ? AND designation_approved = 0",
            (user_id,),
        )


def all_users(actor: dict) -> list[dict]:
    require_permission(actor, "user_admin")
    with _database() as connection:
        rows = connection.execute(
            """SELECT id, full_name, username, email, designation, role, email_verified_at, enabled
               FROM users ORDER BY created_at DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def add_designation(actor: dict, name: str, role: str) -> None:
    require_permission(actor, "user_admin")
    name = name.strip()
    if not name or len(name) > 60 or role not in ROLE_VALUES:
        raise AuthError("Enter a designation of up to 60 characters and select a valid permission role.")
    try:
        with _database() as connection:
            connection.execute(
                "INSERT INTO designations(name, role, enabled) VALUES (?, ?, 1)",
                (name, role),
            )
    except sqlite3.IntegrityError as exc:
        raise AuthError("That designation already exists.") from exc


def disable_designation(actor: dict, name: str) -> None:
    require_permission(actor, "user_admin")
    if name in {item[0] for item in DEFAULT_DESIGNATIONS}:
        raise AuthError("Built-in designations cannot be removed.")
    with _database() as connection:
        connection.execute("UPDATE designations SET enabled = 0 WHERE name = ?", (name,))


def request_password_reset(email: str) -> bool:
    email = _normalize_email(email)
    if _consume_rate_limit("password_reset", email or "empty", 3, 60 * 60):
        return False
    if not _valid_email(email):
        return False
    try:
        base_url, _, _, _, _, _ = _mailer_config()
        with _database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            user = connection.execute(
                "SELECT id, full_name FROM users WHERE email = ? AND enabled = 1 AND email_verified_at IS NOT NULL",
                (email,),
            ).fetchone()
            if not user:
                return True
            token = _issue_token(connection, user["id"], "reset_password")
            link = _token_url(base_url, "reset", token)
            _send_email(
                email,
                "Reset your Smart Waste Dashboard password",
                f"Hello {user['full_name']},\n\nUse this one-time link within one hour to reset your password:\n{link}\n\nIf you did not request this change, ignore this message.",
            )
    except (AuthConfigurationError, OSError, smtplib.SMTPException) as exc:
        LOGGER.warning("Password-reset message could not be delivered (%s).", type(exc).__name__)
    return True


def _replace_password(connection: sqlite3.Connection, user_id: int, password: str) -> str:
    connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_hash_password(password), user_id))
    connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
    connection.execute(
        "UPDATE one_time_tokens SET used_at = ? WHERE user_id = ? AND purpose = 'reset_password' AND used_at IS NULL",
        (int(time.time()), user_id),
    )
    email_row = connection.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    return email_row["email"]


def reset_password_from_token(token: str, password: str) -> bool:
    rate_subject = st.session_state.get("password_reset_rate_subject")
    if not rate_subject:
        rate_subject = secrets.token_hex(16)
        st.session_state["password_reset_rate_subject"] = rate_subject
    if _consume_rate_limit("password_reset_submit", f"{rate_subject}:{_secret_hash(token)}", 5):
        return False
    if (error := password_error(password)) is not None:
        raise AuthError(error)
    now = int(time.time())
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        token_row = connection.execute(
            """SELECT user_id FROM one_time_tokens WHERE token_hash = ?
               AND purpose = 'reset_password' AND used_at IS NULL AND expires_at > ?""",
            (_secret_hash(token), now),
        ).fetchone()
        if not token_row:
            return False
        connection.execute(
            "UPDATE one_time_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (now, _secret_hash(token)),
        )
        recipient = _replace_password(connection, token_row["user_id"], password)
    _send_security_notice(recipient, "Your Smart Waste Dashboard password was changed.")
    return True


def reset_password_with_recovery(email: str, code: str, password: str) -> tuple[bool, bool]:
    email = _normalize_email(email)
    if _consume_rate_limit("recovery_reset", email or "empty", 5):
        return False, False
    if (error := password_error(password)) is not None:
        raise AuthError(error)
    normalized_code = re.sub(r"[^A-Fa-f0-9]", "", code).casefold()
    candidate_hash = _secret_hash(normalized_code)
    now = int(time.time())
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            "SELECT id FROM users WHERE email = ? AND enabled = 1 AND email_verified_at IS NOT NULL",
            (email,),
        ).fetchone()
        if not user:
            hmac.compare_digest(candidate_hash, _secret_hash(secrets.token_hex(16)))
            return False, False
        code_rows = connection.execute(
            "SELECT code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
            (user["id"],),
        ).fetchall()
        matching_hash = None
        for row in code_rows:
            if hmac.compare_digest(candidate_hash, row["code_hash"]):
                matching_hash = row["code_hash"]
        if not matching_hash:
            return False, False
        updated = connection.execute(
            "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
            (now, user["id"], matching_hash),
        )
        if updated.rowcount != 1:
            return False, False
        recipient = _replace_password(connection, user["id"], password)
    notified = _send_security_notice(recipient, "A recovery code was used and your Smart Waste Dashboard password was changed.")
    return True, notified


def _send_security_notice(recipient: str, body: str) -> bool:
    try:
        _send_email(recipient, "Smart Waste Dashboard security notice", body)
        return True
    except (AuthConfigurationError, OSError, smtplib.SMTPException) as exc:
        LOGGER.warning("Security notification could not be delivered (%s).", type(exc).__name__)
        return False


def regenerate_recovery_codes(
    actor: dict, password: str, second_factor_code: str = ""
) -> tuple[list[str] | None, bool]:
    with _database() as connection:
        user = connection.execute(
            "SELECT id, password_hash, email, totp_enabled, totp_secret_enc FROM users WHERE id = ? AND enabled = 1",
            (actor["id"],),
        ).fetchone()
        if not user or not _session_actor(actor) or not _verify_password(password, user["password_hash"]):
            return None, False
        connection.execute("BEGIN IMMEDIATE")
        if user["totp_enabled"]:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            factor_valid, _ = _verify_second_factor(connection, row, second_factor_code)
            if not factor_valid:
                return None, False
        codes = [secrets.token_hex(16).upper() for _ in range(10)]
        now = int(time.time())
        connection.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        connection.executemany(
            "INSERT INTO recovery_codes(user_id, code_hash, created_at) VALUES (?, ?, ?)",
            [(user["id"], _secret_hash(code.casefold()), now) for code in codes],
        )
    notified = _send_security_notice(user["email"], "Your account recovery codes were regenerated. Previous codes have been revoked.")
    return codes, notified


def begin_totp_setup(actor: dict, password: str) -> tuple[str, str] | None:
    with _database() as connection:
        user = connection.execute(
            "SELECT id, email, password_hash, totp_enabled FROM users WHERE id = ? AND enabled = 1",
            (actor["id"],),
        ).fetchone()
        if not user or not _session_actor(actor) or not _verify_password(password, user["password_hash"]):
            return None
        if user["totp_enabled"]:
            raise AuthError("Two-factor authentication is already enabled.")
    secret = _new_totp_secret()
    issuer = "EcoBin AI + SmartBin 360"
    label = quote(f"{issuer}:{user['email']}")
    uri = (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    st.session_state["totp_setup_pending"] = {
        "user_id": user["id"],
        "secret": secret,
        "uri": uri,
        "expires_at": int(time.time()) + 10 * 60,
    }
    return secret, uri


def confirm_totp_setup(actor: dict, code: str) -> bool:
    pending = st.session_state.get("totp_setup_pending")
    if (
        not pending
        or pending.get("user_id") != actor.get("id")
        or pending.get("expires_at", 0) <= int(time.time())
        or not _session_actor(actor)
    ):
        st.session_state.pop("totp_setup_pending", None)
        return False
    secret = pending["secret"]
    counter = _matching_totp_counter(secret, code)
    if counter is None:
        return False
    encrypted_secret = _totp_cipher().encrypt(secret.encode("ascii"))
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            """UPDATE users SET totp_secret_enc = ?, totp_enabled = 1, totp_last_counter = ?
               WHERE id = ? AND enabled = 1 AND totp_enabled = 0""",
            (encrypted_secret, counter, actor["id"]),
        )
        if updated.rowcount != 1:
            return False
    st.session_state.pop("totp_setup_pending", None)
    _send_security_notice(actor["email"], "Two-factor authentication was enabled for your Smart Waste Dashboard account.")
    return True


def disable_totp(actor: dict, password: str, code: str) -> bool:
    if not _session_actor(actor):
        return False
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            "SELECT password_hash, totp_secret_enc, totp_last_counter FROM users WHERE id = ? AND enabled = 1 AND totp_enabled = 1",
            (actor["id"],),
        ).fetchone()
        totp_counter = (
            _matching_totp_counter(_decrypt_totp_secret(user["totp_secret_enc"]), code)
            if user else None
        )
        if (
            not user
            or not _verify_password(password, user["password_hash"])
            or totp_counter is None
            or (user["totp_last_counter"] is not None and totp_counter <= user["totp_last_counter"])
        ):
            return False
        connection.execute(
            "UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_counter = NULL WHERE id = ?",
            (actor["id"],),
        )
        current_token = st.session_state.get("auth_session_token")
        connection.execute(
            "DELETE FROM auth_sessions WHERE user_id = ? AND token_hash != ?",
            (actor["id"], _secret_hash(current_token) if current_token else ""),
        )
    _send_security_notice(actor["email"], "Two-factor authentication was disabled. Other account sessions were revoked.")
    return True


def remaining_recovery_codes(user_id: int) -> int:
    with _database() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        ).fetchone()
    return row["count"]


def _handle_query_tokens() -> None:
    verification_token = st.query_params.get("verify")
    if verification_token:
        try:
            verified = verify_email_token(verification_token)
        except (sqlite3.Error, OSError) as exc:
            LOGGER.error("Email verification failed (%s).", type(exc).__name__)
            st.error("We could not verify the email right now. Please try again.")
        else:
            if verified:
                st.success("Email verified. You can now sign in.")
            else:
                st.error("This verification link is invalid, expired, or already used.")
        del st.query_params["verify"]
    reset_token = st.query_params.get("reset")
    if reset_token:
        st.title("Reset your password")
        st.caption("Choose a new strong password. This one-time link expires after one hour.")
        with st.form("token_password_reset"):
            password = st.text_input("New password", type="password")
            confirmation = st.text_input("Confirm new password", type="password")
            submitted = st.form_submit_button("Reset password")
        if submitted:
            if password != confirmation:
                st.error("The passwords do not match.")
            else:
                try:
                    changed = reset_password_from_token(reset_token, password)
                except AuthError as exc:
                    st.error(str(exc))
                except (sqlite3.Error, OSError, smtplib.SMTPException) as exc:
                    LOGGER.error("Password reset failed (%s).", type(exc).__name__)
                    st.error("We could not complete the password reset. Request a new link and try again.")
                else:
                    del st.query_params["reset"]
                    if changed:
                        st.success("Password changed. Existing sessions have been signed out. You can now sign in.")
                        st.session_state.pop("auth_session_token", None)
                        st.session_state.pop("authenticated_user", None)
                        st.session_state.pop("recovery_codes_pending", None)
                        st.session_state.pop("totp_setup_pending", None)
                    else:
                        st.error("This reset link is invalid, expired, or already used. Request a new one.")
                    st.rerun()
        st.stop()


def _render_recovery_settings(user: dict) -> None:
    with st.sidebar.expander("Account security & recovery"):
        st.caption(f'{user["email"]} · {user["designation"]} · {user["role"].title()}')
        if user["totp_enabled"]:
            st.success("Authenticator two-factor authentication is enabled.")
            with st.form("disable_totp"):
                disable_password = st.text_input("Password to disable 2FA", type="password")
                disable_code = st.text_input("Current authenticator code", max_chars=6)
                disable_submitted = st.form_submit_button("Disable two-factor authentication")
            if disable_submitted:
                try:
                    disabled = disable_totp(user, disable_password, disable_code)
                except (AuthConfigurationError, sqlite3.Error, OSError) as exc:
                    LOGGER.error("Two-factor disable failed (%s).", type(exc).__name__)
                    st.error("Two-factor authentication could not be disabled. Check configuration and try again.")
                else:
                    if disabled:
                        st.success("Two-factor authentication disabled.")
                        st.rerun()
                    else:
                        st.error("The password or authenticator code was not accepted.")
        else:
            with st.form("begin_totp_setup"):
                setup_password = st.text_input("Password to enable 2FA", type="password")
                setup_submitted = st.form_submit_button("Set up authenticator")
            if setup_submitted:
                try:
                    setup = begin_totp_setup(user, setup_password)
                except (AuthConfigurationError, sqlite3.Error, OSError) as exc:
                    LOGGER.error("Two-factor setup failed (%s).", type(exc).__name__)
                    st.error("Two-factor authentication is not available. Check the app configuration.")
                else:
                    if setup:
                        st.rerun()
                    else:
                        st.error("The password was not accepted.")
            pending_totp = st.session_state.get("totp_setup_pending")
            if pending_totp and pending_totp.get("expires_at", 0) <= int(time.time()):
                st.session_state.pop("totp_setup_pending", None)
                pending_totp = None
            if pending_totp and pending_totp.get("user_id") == user["id"]:
                st.info("Add this key to an authenticator app, then verify a current code to enable 2FA.")
                st.code(pending_totp["secret"])
                st.caption("Authenticator provisioning URI")
                st.code(pending_totp["uri"])
                with st.form("confirm_totp_setup"):
                    setup_code = st.text_input("Authenticator code", max_chars=6)
                    confirm_submitted = st.form_submit_button("Verify and enable 2FA")
                if confirm_submitted:
                    try:
                        enabled = confirm_totp_setup(user, setup_code)
                    except (AuthConfigurationError, sqlite3.Error, OSError) as exc:
                        LOGGER.error("Two-factor confirmation failed (%s).", type(exc).__name__)
                        st.error("Two-factor authentication could not be enabled. Try again.")
                    else:
                        if enabled:
                            st.success("Two-factor authentication enabled.")
                            st.rerun()
                        else:
                            st.error("That authenticator code was not accepted.")
        st.write(f"Unused recovery codes: **{remaining_recovery_codes(user['id'])}**")
        with st.form("regenerate_recovery_codes"):
            password = st.text_input("Confirm password to regenerate codes", type="password")
            second_factor_code = st.text_input(
                "Authenticator code or recovery code (if 2FA is enabled)", max_chars=64
            )
            generate = st.form_submit_button("Generate new recovery codes")
        if generate:
            try:
                codes, notified = regenerate_recovery_codes(user, password, second_factor_code)
            except PermissionError as exc:
                st.error(str(exc))
            except (sqlite3.Error, OSError) as exc:
                LOGGER.error("Recovery-code regeneration failed (%s).", type(exc).__name__)
                st.error("Recovery codes could not be regenerated. Try again.")
            else:
                if codes is None:
                    st.error("Password was not accepted. Existing recovery codes were not changed.")
                else:
                    st.session_state["recovery_codes_pending"] = {"user_id": user["id"], "codes": codes}
                    if not notified:
                        st.warning("Codes were regenerated, but the security notification email could not be delivered.")
                    st.rerun()
        pending = st.session_state.get("recovery_codes_pending")
        if pending and pending["user_id"] == user["id"]:
            st.warning("Save these codes now. Each works once, and they will not be shown again.")
            code_text = "\n".join(pending["codes"])
            st.code(code_text)
            st.download_button(
                "Download recovery codes",
                data=code_text.encode("utf-8"),
                file_name="smart-waste-recovery-codes.txt",
                mime="text/plain",
            )
            acknowledged = st.checkbox("I saved these recovery codes", key="recovery_codes_ack")
            if st.button("Finish saving codes", disabled=not acknowledged):
                st.session_state.pop("recovery_codes_pending", None)
                st.session_state.pop("recovery_codes_ack", None)
                st.rerun()


def render_authenticated_sidebar(user: dict) -> None:
    st.sidebar.markdown("---")
    st.sidebar.markdown(f'**Signed in:** {user["full_name"]}')
    st.sidebar.caption(f'{user["designation"]} · {user["role"].title()}')
    _render_recovery_settings(user)
    if st.sidebar.button("Sign out", use_container_width=True):
        _end_session()
        st.rerun()


def render_admin_management(actor: dict) -> None:
    require_permission(actor, "user_admin")
    st.subheader("User accounts")
    users = all_users(actor)
    if users:
        st.dataframe(
            [
                {
                    "Name": user["full_name"], "Username": user["username"], "Email": user["email"],
                    "Designation": user["designation"], "Role": user["role"],
                    "Email verified": bool(user["email_verified_at"]), "Enabled": bool(user["enabled"]),
                }
                for user in users
            ],
            hide_index=True,
            width="stretch",
        )
    st.markdown("#### Pending designation approvals")
    requests = pending_approvals(actor)
    if not requests:
        st.info("No verified designation requests are waiting for approval.")
    for request in requests:
        columns = st.columns([4, 1, 1])
        columns[0].markdown(
            f'**{request["full_name"]}** · {request["email"]}  \n'
            f'Requested: {request["designation"]} → `{request["requested_role"]}`'
        )
        if columns[1].button("Approve", key=f'approve_{request["id"]}'):
            try:
                approve_designation(actor, request["id"])
            except AuthError as exc:
                st.error(str(exc))
            else:
                st.rerun()
        if columns[2].button("Reject", key=f'reject_{request["id"]}'):
            try:
                reject_designation(actor, request["id"])
            except AuthError as exc:
                st.error(str(exc))
            else:
                st.rerun()

    st.markdown("#### Available registration designations")
    designation_frame = designation_options()
    st.dataframe(designation_frame, hide_index=True, width="stretch")
    with st.form("add_designation"):
        new_name = st.text_input("New designation name")
        role_labels = {
            "Public": "public", "Employee / Staff": "worker", "Manager": "manager",
            "HR": "hr", "Administrator": "admin",
        }
        new_role_label = st.selectbox("Role granted only after admin approval", list(role_labels))
        add_submitted = st.form_submit_button("Add designation")
    if add_submitted:
        try:
            add_designation(actor, new_name, role_labels[new_role_label])
        except AuthError as exc:
            st.error(str(exc))
        else:
            st.success("Designation added.")
            st.rerun()
    removable = [item["name"] for item in designation_frame if item["name"] not in {entry[0] for entry in DEFAULT_DESIGNATIONS}]
    if removable:
        with st.form("disable_designation"):
            disable_name = st.selectbox("Disable a custom designation", removable)
            disable_submitted = st.form_submit_button("Disable designation")
        if disable_submitted:
            try:
                disable_designation(actor, disable_name)
            except AuthError as exc:
                st.error(str(exc))
            else:
                st.success("Designation disabled for new registrations.")
                st.rerun()


def _render_login() -> None:
    identifier = st.text_input("Email address or username", autocomplete="username")
    show_password = st.checkbox("Show password", key="show_login_password")
    password = st.text_input(
        "Password", type="default" if show_password else "password", autocomplete="current-password"
    )
    second_factor_code = st.text_input(
        "Authenticator or recovery code (if enabled)", autocomplete="one-time-code"
    )
    submitted = st.button("Sign in", width="stretch")
    if submitted:
        try:
            result, user = login(identifier, password, second_factor_code)
        except AuthConfigurationError as exc:
            LOGGER.error("Sign-in configuration failed (%s).", type(exc).__name__)
            st.error("Sign-in is temporarily unavailable. Contact the administrator.")
            return
        except (sqlite3.Error, OSError) as exc:
            LOGGER.error("Sign-in failed (%s).", type(exc).__name__)
            st.error("Sign-in is temporarily unavailable. Try again.")
            return
        if result == "ok" and user:
            _create_session(user["id"])
            st.rerun()
        if result == "limited":
            st.error("Too many sign-in attempts. Try again later.")
        else:
            st.error("Email/username or password is incorrect.")
def _render_registration() -> None:
    options = designation_options()
    if not options:
        st.error("No registration designations are configured. Contact an administrator.")
        return
    with st.form("registration_form"):
        full_name = st.text_input("Full name", max_chars=120)
        username = st.text_input("Username", help="3–32 letters, numbers, dots, underscores, or hyphens.")
        email = st.text_input("Email address", autocomplete="email")
        phone = st.text_input("Phone number (optional)", help="Phone verification is optional; the account is verified by email.")
        password = st.text_input("Password", type="password", autocomplete="new-password")
        confirmation = st.text_input("Confirm password", type="password", autocomplete="new-password")
        designation_names = [option["name"] for option in options]
        designation = st.selectbox("Requested designation", designation_names)
        terms = st.checkbox("I accept the terms and conditions and privacy notice.")
        submitted = st.form_submit_button("Create account", width="stretch")
    if submitted:
        if password != confirmation:
            st.error("The passwords do not match.")
        elif not terms:
            st.error("Accept the terms and conditions to create an account.")
        else:
            try:
                register_user(full_name, username, email, phone, password, designation, terms_accepted=terms)
            except AuthError as exc:
                st.error(str(exc))
            except (sqlite3.Error, OSError, smtplib.SMTPException) as exc:
                LOGGER.error("Registration email could not be delivered (%s).", type(exc).__name__)
                st.error("The account could not be created because verification email delivery failed. Try again later.")
            else:
                st.success("Account created. Check your email and verify it within one hour before signing in.")
                option = next(option for option in options if option["name"] == designation)
                if option["role"] != "public":
                    st.info("Your privileged designation is a request. Access remains limited until an administrator approves it.")
    st.markdown("#### Resend email verification")
    with st.form("resend_verification_form"):
        resend_email = st.text_input("Email address for verification")
        resend_submitted = st.form_submit_button("Send verification link")
    if resend_submitted:
        try:
            resend_verification(resend_email)
        except (AuthError, AuthConfigurationError) as exc:
            LOGGER.error("Verification resend could not be completed (%s).", type(exc).__name__)
            st.info("If an unverified account matches that address, a new link has been sent.")
        except (OSError, smtplib.SMTPException, sqlite3.Error) as exc:
            LOGGER.error("Verification email could not be sent (%s).", type(exc).__name__)
            st.info("If an unverified account matches that address, a new link has been sent.")
        else:
            st.info("If an unverified account matches that address, a new link has been sent.")


def _render_recovery() -> None:
    st.markdown("#### Request a password reset")
    with st.form("forgot_password_form"):
        email = st.text_input("Registered email address")
        reset_submitted = st.form_submit_button("Send reset link")
    if reset_submitted:
        try:
            request_password_reset(email)
        except (sqlite3.Error, OSError) as exc:
            LOGGER.error("Password-reset request failed (%s).", type(exc).__name__)
            st.error("The request could not be completed. Please try again.")
        else:
            st.info("If a verified account matches that address and mail is configured, a reset link will be sent.")

    st.markdown("#### Reset using a recovery code")
    st.caption("Recovery codes are single-use. Enter one with the account email, then choose a new password.")
    with st.form("recovery_code_reset_form"):
        recovery_email = st.text_input("Account email", key="recovery_email")
        recovery_code = st.text_input("Unused recovery code", key="recovery_code", autocomplete="off")
        password = st.text_input("New password", type="password", key="recovery_new_password")
        confirmation = st.text_input("Confirm new password", type="password", key="recovery_confirm_password")
        recovery_submitted = st.form_submit_button("Reset with recovery code")
    if recovery_submitted:
        if password != confirmation:
            st.error("The passwords do not match.")
            return
        try:
            changed, notified = reset_password_with_recovery(recovery_email, recovery_code, password)
        except AuthError as exc:
            st.error(str(exc))
            return
        except (sqlite3.Error, OSError, smtplib.SMTPException) as exc:
            LOGGER.error("Recovery-code reset failed (%s).", type(exc).__name__)
            st.error("The recovery request could not be completed. Try again.")
            return
        if changed:
            st.success("Password changed and existing sessions were revoked.")
            if not notified:
                st.warning("The security email could not be delivered. Contact an administrator if this was unexpected.")
        else:
            st.error("The account or recovery code was not accepted, or the code was already used.")


def render_authentication() -> None:
    initialize_auth()
    handle_auth_tokens()
    st.title("EcoBin AI + SmartBin 360")
    st.caption("Sign in to access your role-authorized smart waste dashboard.")
    signin_tab, register_tab, recovery_tab = st.tabs(["Sign in", "Create account", "Recover account"])
    with signin_tab:
        _render_login()
    with register_tab:
        _render_registration()
    with recovery_tab:
        _render_recovery()


def handle_auth_tokens() -> None:
    _handle_query_tokens()


def authenticate_request() -> dict | None:
    initialize_auth()
    handle_auth_tokens()
    user = current_user()
    if user is None:
        render_authentication()
        return None
    render_authenticated_sidebar(user)
    return user
