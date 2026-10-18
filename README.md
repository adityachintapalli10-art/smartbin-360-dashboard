# EcoBin AI + SmartBin 360 Dashboard

A unified smart-waste app combining the EcoBin AI and SmartBin 360 feature sets. One Python/Streamlit dashboard provides shared bin operations, fleet search and CSV export, GPS maps, route planning, demand insights, waste-classifier demos, telemetry-driven alerts, analytics, ESP32 simulation, role/settings, field tasks, and public reports.

## Run the unified Python app

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run server.py
```

Streamlit opens at `http://localhost:8501`. Sample classifier results and demand forecasts are labeled as demonstrations, not predictions from a trained model.

## Authentication setup

Email verification is disabled: users can sign in immediately after registration. Configure a bootstrap administrator to manage roles/designations. SMTP settings are optional and only needed for password-reset links and security notifications. Set secrets in the deployment environment, not in source control:

```powershell
$env:SMARTBIN_BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
$env:SMARTBIN_BOOTSTRAP_ADMIN_PASSWORD = "Use-a-long-unique-password-42!"
$env:SMARTBIN_TOTP_ENCRYPTION_KEY = (python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Optional: enables password-reset email links and security notifications.
$env:SMARTBIN_APP_BASE_URL = "https://your-app.example.com"
$env:SMARTBIN_SMTP_HOST = "smtp.example.com"
$env:SMARTBIN_SMTP_PORT = "587"
$env:SMARTBIN_SMTP_FROM = "no-reply@example.com"
$env:SMARTBIN_SMTP_USERNAME = "smtp-user"
$env:SMARTBIN_SMTP_PASSWORD = "smtp-password"
```

The bootstrap administrator is created on first startup. Remove the bootstrap email/password variables after setup. Keep the TOTP encryption key stable and backed up: changing or losing it prevents users with enabled authenticator two-factor authentication from signing in. When SMTP is configured, set `SMARTBIN_APP_BASE_URL` to the publicly reachable HTTPS app URL so password-reset links work. The SQLite database defaults to `data/smartbin_auth.sqlite3`; use a durable private volume in production and configure SMTP/TOTP keys through the hosting secret manager.

Authentication and authorization are enforced by this Streamlit Python dashboard. Retained React/Vite, HTML, and `legacy_streamlit.py` frontends are unauthenticated demos and should not be exposed as production alternatives.

## Legacy frontends

The standalone EcoBin React/Vite frontend remains available in its original repository. The original SmartBin 360 standalone `index.html` is preserved in the combined repository and can be served with `npm start`; the Streamlit dashboard is the unified app.
