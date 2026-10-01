# Deployment

The application is one Python process (uvicorn) that serves the API and the built React app, plus one SQLite file. Put a reverse proxy
(or the platform's TLS termination) in front of it for HTTPS.

## 1. Prerequisites

* Python **3.13** on the server, Node 22 on the build machine (only to build the front end).
* A domain controller reachable on TCP 636 (LDAPS) with a certificate the server trusts.
* An Okta OIDC application ([OKTA-SETUP.md](OKTA-SETUP.md)).
* The delegation from [AD-DELEGATION.md](AD-DELEGATION.md) for the account the service runs as.

## 2. Install

```bash
git clone <repo> /opt/itdash && cd /opt/itdash
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cd frontend && npm ci && npm run build && cd ..     # writes app/static
```

The application binds to Active Directory without a stored password using **Kerberos**, so install the optional package for your platform:
`pip install gssapi` (Linux, with a keytab for the service account) or `pip install winkerberos` (Windows, service running as the gMSA).
**This integrated bind is the least-tested path in this edition (see DECISIONS.md): verify it against a test domain first.**

## 3. Configure

Create `config/settings.local.json` (non-secrets) and set secrets as environment variables of the service:

```json
{
  "App": {
    "ProductName": "IT Administration Dashboard", "Environment": "Production",
    "DataDirectory": "/var/lib/itdash/data", "AssetDirectory": "/var/lib/itdash/assets", "BackupDirectory": "/var/lib/itdash/backups",
    "BootstrapAdminOktaGroup": "ITDash-Admins", "DailyBackupEnabled": true
  },
  "Okta": { "Issuer": "https://<OKTA_DOMAIN>/oauth2/default", "ClientId": "<OKTA_CLIENT_ID>", "GroupsClaim": "groups" },
  "ActiveDirectory": { "Provider": "Ldap", "Domain": "corp.test", "Server": "dc01.corp.test", "BaseDn": "DC=corp,DC=test" },
  "Serilog": { "LogDirectory": "/var/log/itdash" }
}
```

Secret: `SD__Okta__ClientSecret=<secret>`. `SD_ENVIRONMENT=Production` (the default). The application **refuses to start** in Production with development
sign-in, the Fake directory, plain LDAP, disabled certificate checks, local bind credentials, or any unfilled `<PLACEHOLDER>`.

## 4. Run as a service

Linux (systemd):

```ini
[Unit]
Description=IT Administration Dashboard
After=network-online.target

[Service]
User=itdash
WorkingDirectory=/opt/itdash
EnvironmentFile=/etc/itdash.env            # SD__Okta__ClientSecret=..., SD_ENVIRONMENT=Production
ExecStart=/opt/itdash/.venv/bin/python -m uvicorn app.main:app_factory --factory --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Windows: install the service with NSSM (or a similar wrapper) running the same command, and set the service's log-on account to the gMSA
(`<AD_NETBIOS>\svc-itdash$`). **Run a single worker** (no `--workers`): the rate limiter and settings cache live in the process.

## 5. HTTPS

Terminate TLS at the reverse proxy and forward the scheme (`X-Forwarded-Proto`), with `--proxy-headers` as above so the application sees `https`.
Session cookies are `Secure` outside Development, so the site must be served over HTTPS; the application sends HSTS on HTTPS responses.
The redirect URIs registered in Okta must use the public `https://<APP_HOST>` address.

## 6. Data, logs and backups

* `DataDirectory` holds `service-dashboard.db` (SQLite, WAL). `AssetDirectory/logos` holds uploaded logos.
* Logs: `LogDirectory/app.log`, rotated daily, 30 files kept. Passwords, secrets and tokens are redacted.
* Set `App:DailyBackupEnabled` and `BackupDirectory` for a daily online backup (`VACUUM INTO` plus the logo folder, newest `BackupRetentionCount` kept).
  Copy backups off the server.
* Audit rows older than `App:AuditRetentionDays` (default 365, 0 = keep forever) are removed daily; the removal is itself audited.

## 7. Upgrades

Stop the service, `git pull`, `pip install -r requirements.txt`, rebuild the front end if it changed, start the service. Database changes are applied
automatically at startup by the built-in migration runner (recorded in `schema_migrations`); take a backup first.

## 8. Health

`GET /api/health` answers `{"status":"ok"}` (503 if the database cannot be read). It needs no sign-in.
