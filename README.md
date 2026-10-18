# EcoBin AI + SmartBin 360 Dashboard

A unified smart-waste app combining the EcoBin AI and SmartBin 360 feature sets. One Python/Streamlit dashboard provides shared bin operations, fleet search and CSV export, GPS maps, route planning, demand insights, waste-classifier demos, telemetry-driven alerts, analytics, ESP32 simulation, role/settings, field tasks, and public reports.

## Run the unified Python app

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run server.py
```

Streamlit opens at `http://localhost:8501`. The **SmartBin 360** menu section summarizes fleet status, and its repository link opens the original GitHub project. Sample classifier results and demand forecasts are labeled as demonstrations, not predictions from a trained model.

## Authentication setup

Users can sign in immediately after registration. Password reset is available only with a single-use recovery code; no password reset email is sent. On first sign-in, open **Account security & recovery** and generate, copy or download, and safely store your recovery codes. They are only displayed once. Configure a bootstrap administrator to manage roles/designations. SMTP settings are optional and used only for security notifications. Set secrets in the deployment environment, not in source control:

```powershell
$env:SMARTBIN_BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
$env:SMARTBIN_BOOTSTRAP_ADMIN_PASSWORD = "Use-a-long-unique-password-42!"
$env:SMARTBIN_TOTP_ENCRYPTION_KEY = (python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Optional: enables account security notification emails.
$env:SMARTBIN_SMTP_HOST = "smtp.example.com"
$env:SMARTBIN_SMTP_PORT = "587"
$env:SMARTBIN_SMTP_FROM = "no-reply@example.com"
$env:SMARTBIN_SMTP_USERNAME = "smtp-user"
$env:SMARTBIN_SMTP_PASSWORD = "smtp-password"
```

The bootstrap administrator is created on first startup. Remove the bootstrap email/password variables after setup. Keep the TOTP encryption key stable and backed up: changing or losing it prevents users with enabled authenticator two-factor authentication from signing in. The SQLite database defaults to `data/smartbin_auth.sqlite3`; use a durable private volume in production and configure SMTP/TOTP keys through the hosting secret manager.

Authentication and authorization are enforced by this Streamlit Python dashboard. Retained React/Vite, HTML, and `legacy_streamlit.py` frontends are unauthenticated demos and should not be exposed as production alternatives.

## Legacy frontends

The standalone EcoBin React/Vite frontend remains available in its original repository. The original SmartBin 360 standalone `index.html` is preserved in the combined repository and can be served with `npm start`; the Streamlit dashboard is the unified app.
