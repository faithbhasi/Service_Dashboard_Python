# IT Administration Dashboard (Python)

A web dashboard for IT administrators: Active Directory users, computers and groups, role-based access, a tamper-evident audit
trail, and Okta single sign-on. This is the **Python 3.13** edition: a FastAPI back end serving the React front end.
It exposes exactly the same JSON API as the original ASP.NET Core edition, so the front end is shared unchanged.

* **Back end:** FastAPI, SQLAlchemy 2 on SQLite (WAL), ldap3 (Active Directory over LDAPS), Authlib (Okta OpenID Connect, code flow + PKCE)
* **Front end:** React + TypeScript + Vite (in `frontend/`, built into `app/static/`)
* **Sign-in:** Okta in production, a "pick a test user" page in development
* **Directory:** a built-in **Fake** Active Directory (about 600 users, computers, groups) for development and tests, or a real domain over **LDAPS**

## Quick start (development)

Requirements: **Python 3.13**, **Node.js 22** (to build the front end once).

```bash
# 1. Back end
python3.13 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# 2. Front end (built into app/static)
cd frontend && npm install && npm run build && cd ..

# 3. Run
SD_ENVIRONMENT=Development python -m uvicorn app.main:app_factory --factory --port 8000
```

Windows PowerShell:

```powershell
$env:SD_ENVIRONMENT = "Development"
python -m uvicorn app.main:app_factory --factory --port 8000
```

Open **http://localhost:8000** and pick **Dev Admin**. Development data (SQLite database, logos, logs) is created under `data/` and `logs/`.

For front-end work, run `npm run dev` in `frontend/` as well and open **http://localhost:5173**: Vite proxies `/api` and the sign-in paths to port 8000.

### Development users

| User | Role |
| --- | --- |
| Dev Admin | Admins: every permission |
| Dev Auditor | Auditors and Security: read everything, export logs, no changes |
| Dev Helpdesk | "Helpdesk (sample)": search, unlock, reset password, add to groups |
| Dev User | Users: Home and own activity only |
| Dev No Access | Signs in, has no role |
| Dev Disabled | Disabled in the app: sign-in refused and audited |

## Tests

```bash
pytest                         # 165 back-end tests (API, security, AD change pipeline, Okta flow against a local identity provider)
cd frontend && npm test        # 83 front-end tests
```

The back-end tests start the real application with a temporary database and the Fake directory. The Okta tests run a small OpenID Connect
provider on localhost and walk the whole redirect, PKCE, token and sign-out round trip.

## Configuration

Settings are layered; later layers win:

1. `config/settings.json`: all keys, with `<PLACEHOLDER>` values (a placeholder counts as "not set")
2. `config/settings.<environment>.json` (for example `settings.development.json`)
3. `config/settings.local.json` (git-ignored: your machine or server)
4. environment variables `SD__Section__Key`, for example `SD__Okta__ClientSecret`
5. `SD_ENVIRONMENT` selects the environment (`Development`, `Production`, ...). The default is **Production**.

Secrets (the Okta client secret, local test bind passwords) belong in environment variables or the git-ignored `settings.local.json`, never in committed files.
In Production the application **refuses to start** with development sign-in on, the Fake directory, plain LDAP, disabled certificate checks, or unfilled placeholders.

Runtime settings that administrators edit in the UI (allowlists, banner, action policies, colours, logos) are stored in SQLite and audited.

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/CONNECT-REAL-AD-AND-OKTA.md](docs/CONNECT-REAL-AD-AND-OKTA.md) | Connect a real test AD and Okta on your own machine, step by step |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Run it for real: service, reverse proxy, HTTPS, backups |
| [docs/AD-DELEGATION.md](docs/AD-DELEGATION.md) | The least-privilege rights the service account needs |
| [docs/OKTA-SETUP.md](docs/OKTA-SETUP.md) | Okta application and groups claim |
| [docs/ADDING-A-MODULE.md](docs/ADDING-A-MODULE.md) | How a new module (Okta, Microsoft 365, ...) plugs in |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Design decisions, and how this edition differs from the .NET one |

## Safety model in one paragraph

Every change goes through one pipeline: permission, Action Policy checks (justification, ticket, typed confirmation), a fresh re-read of the
object from the directory, allowlists and protected objects (Domain Admins, adminCount=1, Tier 0, service-account and Domain Controller OUs are
always blocked), the role's own OU and group scope, a **dry run** that only reads, the change, and an audit row with a correlation id.
Passwords are never logged, audited or returned. Sessions are server-side; the cookie holds only an opaque id.

## Repository layout

```
app/                 FastAPI application
  main.py            application factory (middleware, routers, static files)
  routers/           HTTP endpoints (auth, admin, settings, logs, search, dashboard, ad)
  modules/ad/        Active Directory module: provider contract, Fake and LDAP providers, protection rules, change pipeline
  static/            the built front end (git-ignored; created by `npm run build`)
config/              layered JSON settings
docs/                documentation
frontend/            React front end and its tests
tests/               back-end tests
```
