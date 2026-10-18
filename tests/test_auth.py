import os
import re
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet

import auth


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {
                "SMARTBIN_AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "SMARTBIN_BOOTSTRAP_ADMIN_EMAIL": "admin@example.com",
                "SMARTBIN_BOOTSTRAP_ADMIN_PASSWORD": "Strong-Admin-Password-42!",
                "SMARTBIN_TOTP_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            },
        )
        self.environment.start()
        self.sent_messages = []
        self.mailer_config = patch.object(
            auth, "_mailer_config",
            return_value=("http://localhost:8501", 587, "smtp.example.com", "no-reply@example.com", "", ""),
        )
        self.mailer_config.start()
        self.email_sender = patch.object(
            auth, "_send_email", side_effect=lambda *args: self.sent_messages.append(args)
        )
        self.email_sender.start()
        self.streamlit = patch.object(auth, "st", SimpleNamespace(session_state={}))
        self.streamlit.start()
        auth.initialize_auth()

    def tearDown(self):
        patch.stopall()
        self.temp_dir.cleanup()

    def _last_token(self, purpose):
        body = self.sent_messages[-1][2]
        match = re.search(rf"{purpose}=([A-Za-z0-9_-]+)", body)
        self.assertIsNotNone(match)
        return match.group(1)

    def _register_verified(self, email="person@example.com", designation="Customer / General User"):
        auth.register_user(
            "Test Person", email.split("@")[0], email, "", "Strong-Person-Password-42!",
            designation, terms_accepted=True,
        )
        self.assertTrue(auth.verify_email_token(self._last_token("verify")))
        with auth._database() as connection:
            row = connection.execute(
                "SELECT id, terms_accepted_at FROM users WHERE email = ?", (email,)
            ).fetchone()
            self.assertIsNotNone(row["terms_accepted_at"])
            return row["id"]

    def _admin(self):
        with auth._database() as connection:
            row = connection.execute("SELECT * FROM users WHERE email = 'admin@example.com'").fetchone()
        return auth._public_user(row)

    def test_registration_verification_and_duplicate_prevention(self):
        user_id = self._register_verified()
        result, user = auth.login("person@example.com", "Strong-Person-Password-42!")
        self.assertEqual(result, "ok")
        self.assertEqual(user["id"], user_id)
        with self.assertRaises(auth.AuthError):
            auth.register_user(
                "Another Person", "person2", "person@example.com", "",
                "Strong-Person-Password-42!", "Customer / General User", terms_accepted=True,
            )

    def test_privileged_designation_requires_database_approval(self):
        user_id = self._register_verified("manager@example.com", "Manager")
        result, user = auth.login("manager@example.com", "Strong-Person-Password-42!")
        self.assertEqual(result, "ok")
        self.assertEqual(user["role"], "public")
        admin = self._admin()
        auth._create_session(admin["id"])
        auth.approve_designation(admin, user_id)
        result, user = auth.login("manager@example.com", "Strong-Person-Password-42!")
        self.assertEqual(result, "ok")
        self.assertEqual(user["role"], "manager")

    def test_permissions_use_database_role_not_caller_supplied_role(self):
        user_id = self._register_verified()
        auth._create_session(user_id)
        with self.assertRaises(PermissionError):
            auth.require_permission({"id": user_id, "role": "admin"}, "user_admin")

    def test_reset_token_is_single_use_and_revokes_sessions(self):
        user_id = self._register_verified()
        auth._create_session(user_id)
        self.assertTrue(auth.request_password_reset("person@example.com"))
        token = self._last_token("reset")
        self.assertTrue(auth.reset_password_from_token(token, "New-Strong-Password-84!"))
        self.assertFalse(auth.reset_password_from_token(token, "Other-Strong-Password-84!"))
        self.assertIsNone(auth.current_user())
        self.assertEqual(auth.login("person@example.com", "New-Strong-Password-84!")[0], "ok")

    def test_expired_reset_token_is_rejected(self):
        self._register_verified()
        self.assertTrue(auth.request_password_reset("person@example.com"))
        token = self._last_token("reset")
        with auth._database() as connection:
            connection.execute(
                "UPDATE one_time_tokens SET expires_at = 0 WHERE token_hash = ?",
                (auth._secret_hash(token),),
            )
        self.assertFalse(auth.reset_password_from_token(token, "New-Strong-Password-84!"))

    def test_totp_and_recovery_code_are_single_use(self):
        admin = self._admin()
        auth._create_session(admin["id"])
        secret, _ = auth.begin_totp_setup(admin, "Strong-Admin-Password-42!")
        current_counter = int(auth.time.time()) // 30
        setup_code = auth._totp_code(secret, current_counter)
        self.assertTrue(auth.confirm_totp_setup(admin, setup_code))
        next_code = auth._totp_code(secret, current_counter + 1)
        codes, _ = auth.regenerate_recovery_codes(
            admin, "Strong-Admin-Password-42!", next_code
        )
        self.assertEqual(len(codes), 10)
        self.assertEqual(
            auth.login("admin@example.com", "Strong-Admin-Password-42!", codes[0])[0], "ok"
        )
        self.assertEqual(
            auth.login("admin@example.com", "Strong-Admin-Password-42!", codes[0])[0], "invalid"
        )

    def test_totp_login_code_cannot_be_replayed(self):
        admin = self._admin()
        auth._create_session(admin["id"])
        secret, _ = auth.begin_totp_setup(admin, "Strong-Admin-Password-42!")
        counter = int(auth.time.time()) // 30
        self.assertTrue(auth.confirm_totp_setup(admin, auth._totp_code(secret, counter)))
        next_code = auth._totp_code(secret, counter + 1)
        self.assertEqual(
            auth.login("admin@example.com", "Strong-Admin-Password-42!", next_code)[0], "ok"
        )
        self.assertEqual(
            auth.login("admin@example.com", "Strong-Admin-Password-42!", next_code)[0], "invalid"
        )

    def test_recovery_reset_consumes_code_and_revokes_sessions(self):
        user_id = self._register_verified()
        auth._create_session(user_id)
        user = auth.current_user()
        codes, _ = auth.regenerate_recovery_codes(
            user, "Strong-Person-Password-42!"
        )
        changed, _ = auth.reset_password_with_recovery(
            "person@example.com", codes[0], "New-Strong-Password-84!"
        )
        self.assertTrue(changed)
        self.assertFalse(
            auth.reset_password_with_recovery(
                "person@example.com", codes[0], "Other-Strong-Password-84!"
            )[0]
        )
        self.assertIsNone(auth.current_user())


if __name__ == "__main__":
    unittest.main()
