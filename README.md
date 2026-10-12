# NULLFORGE

KeyAuth-integrated, server-authoritative anti-tampering license server with an
Electron desktop loader client.

The server is the single source of truth for license validity: keys are bound to
a device (HWID) using server-side HMAC peppers, short-lived JWT session tokens
are minted on activation, and integrity/security events from the client are
logged and fed through a graduated enforcement engine (monitor → restrict → ban).
License-key validation can additionally be proxied through the KeyAuth platform
server-side so the app secret never reaches the browser.

## Architecture

```
                  ┌─────────────────────────────────────────┐
                  │  NULLFORGE Loader  (Electron)          │
                  │  roblox-external/loader/                 │
                  │  main.js + nullforge-loader.html         │
                  └──────────────┬──────────────────────────┘
                                 │ license key + HWID
                                 ▼
                  ┌─────────────────────────────────────────┐
                  │  FastAPI Backend  (Python 3.13)         │
                  │  roblox-external/server/                │
                  │  • api/v1  — routers (licenses,           │
                  │                 sessions, keyauth,       │
                  │                 admin, health)           │
                  │  • services — business logic             │
                  │  • repositories — data access            │
                  │  • security — crypto / integrity         │
                  │  • alembic — schema migrations           │
                  └──────────────┬───────────────┬───────────┘
                                 │               │ optional
                                 ▼               ▼
                       ┌──────────────┐  ┌──────────────┐
                       │  SQLite /    │  │  KeyAuth     │
                       │  PostgreSQL   │  │  API         │
                       │  (alembic)    │  │  keyauth.win │
                       └──────────────┘  └──────────────┘
```

- **FastAPI backend** (`roblox-external/server/`) — the authoritative license
  server. It stores only HMAC-digested license keys and HWIDs (never plaintext),
  issues HS256 JWT session tokens, enforces per-IP rate limiting, and records
  anti-tamper events through a graduated enforcement engine.
- **Electron loader** (`roblox-external/loader/`) — the desktop shell the end
  user runs. It hosts the key-entry UI and talks to the server over HTTP.
- **KeyAuth integration** — license validation is forwarded to the KeyAuth API
  server-side (`/v1/keyauth/*`) so the `KEYAUTH_APP_SECRET` never appears in a
  client bundle.

## Development status

### Done
- KeyAuth configuration, schemas, and service layer (`keyauth_*` endpoints).
- Core schemas, ratelimiting, and request/body-size middleware.
- Integrity and crypto primitives (`app/security/`): HMAC peppers, JWT tokens,
  Argon2id password hashing.
- Security event model + service (`app/services/security_events.py`,
  `app/services/enforcement.py`).
- Alembic migration `0002_anti_tamper_schema.py`.
- `ruff` and `mypy` configuration wired through `pyproject.toml`.

### Pending (Wave 2)
- Server-issued JWT tokens for the KeyAuth session flow.
- Authenticated endpoints protected by bearer-token dependencies.
- Security event submission endpoint (`/v1/keyauth/security-event`).
- Integrity-check endpoints (`/v1/keyauth/integrity/*`).

### Pending (Wave 3)
- Test suite (`pytest` / `httpx`) covering services and API routes.

### Pending (loader)
- Final Electron shell packaging for the `exe` installer.
- Loader `main.js` and UI wiring updates for the Wave 2 endpoints.

> The loader shell and the core license/session endpoints are functional, but the
> end-to-end KeyAuth + anti-tamper flow is not yet complete until Wave 2 lands.

## Project structure

```
schoolproject/
├── .env                        # runtime secrets (gitignored)
├── .env.example                # KeyAuth credentials template
├── README.md
└── roblox-external/
    ├── .env.example            # repo-level pointer to server/.env.example
    ├── server/                 # FastAPI backend (Python 3.13)
    │   ├── app/
    │   │   ├── __init__.py     # version + package init
    │   │   ├── cli.py          # CLI: init-db, migrate, keygen, admin-create
    │   │   ├── config.py       # pydantic-settings Settings (env-driven)
    │   │   ├── db.py           # SQLAlchemy session wiring
    │   │   ├── deps.py         # FastAPI deps: auth, rate limit, client ctx
    │   │   ├── errors.py       # AppError / ErrorCode
    │   │   ├── keys.py         # license-key normalization
    │   │   ├── logging_config.py
    │   │   ├── main.py         # FastAPI app factory (`create_app`)
    │   │   ├── models.py       # SQLAlchemy ORM models
    │   │   ├── ratelimit.py    # per-IP fixed-window rate limiter
    │   │   ├── schemas.py      # pydantic request/response schemas
    │   │   ├── states.py       # license-status enums
    │   │   ├── api/v1/         # route routers
    │   │   │   ├── admin.py
    │   │   │   ├── health.py
    │   │   │   ├── keyauth.py
    │   │   │   ├── licenses.py
    │   │   │   └── sessions.py
    │   │   ├── security/       # integrity / crypto primitives
    │   │   │   ├── crypto.py
    │   │   │   ├── integrity.py
    │   │   │   ├── passwords.py
    │   │   │   └── tokens.py
    │   │   ├── services/       # business logic + enforcement engine
    │   │   │   ├── admin.py
    │   │   │   ├── audit_service.py
    │   │   │   ├── auth.py
    │   │   │   ├── enforcement.py
    │   │   │   ├── keyauth.py
    │   │   │   ├── license.py
    │   │   │   └── security_events.py
    │   │   ├── repositories/   # data access layer
    │   │   │   ├── activations.py
    │   │   │   ├── admins.py
    │   │   │   ├── audit.py
    │   │   │   ├── licenses.py
    │   │   │   ├── security_events.py
    │   │   │   └── sessions.py
    │   ├── alembic/            # schema migrations
    │   │   ├── env.py
    │   │   ├── script.py.mako
    │   │   └── versions/
    │   │       ├── 0001_initial_schema.py
    │   │       └── 0002_anti_tamper_schema.py
    │   ├── server/main.py      # `uvicorn app.main:app` entrypoint
    │   ├── alembic.ini
    │   ├── pyproject.toml
    │   ├── requirements.txt
    │   └── requirements-dev.txt
    └── loader/                 # Electron desktop client
        ├── main.js             # Electron main process (build 1.0.4)
        ├── nullforge-loader.html
        ├── package.json
        └── build/              # packaging resources (icon, etc.)
```

The repository also contains C++/user-mode components under `roblox-external/`
(`um/`, `km/`, `build/`, `KernelBridge.sln`) that are out of scope for the current
license-server/anti-tamper work.

## Setup

Requirements: Python 3.13+, Node.js 20+ (for the Electron loader).

```bash
# 1. Backend
cd roblox-external/server
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # ruff, mypy, pytest, httpx

# 2. Configure secrets (the server refuses to start without these)
cp .env.example .env             # then edit .env
#   - LICENSE_JWT_SECRET      (>= 32 chars, generated: python -c "import secrets; print(secrets.token_urlsafe(48))")
#   - LICENSE_KEY_PEPPER      (>= 16 chars)
#   - HWID_PEPPER             (>= 16 chars, must differ from the other two)
#   - KEYAUTH_OWNER_ID / KEYAUTH_APP_SECRET / KEYAUTH_APP_NAME   (for the KeyAuth proxy)

# KeyAuth credentials may alternatively live in the repo-root .env.example; the
# Settings object loads both .env and ../../.env.

# 3. Database migrations (Alembic)
alembic upgrade head
# or: python -m app.cli migrate

# 4. (optional) bootstrap an admin account from ADMIN_USERNAME/ADMIN_PASSWORD
python -m app.cli init-db

# 5. Run
uvicorn app.main:app --host 0.0.0.0 --port 8080
# or: python -m server.main
# docs: http://127.0.0.1:8080/docs  |  redoc: http://127.0.0.1:8080/redoc
```

```bash
# Loader (separate terminal)
cd roblox-external/loader
npm install            # only needed once; installs electron + electron-builder
npm start              # launches the NULLFORGE Loader window
```

### Configuration reference

All server options are read from environment variables; see
`roblox-external/server/.env.example` for the full documented list. Key toggles:

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./license.db` | SQLite or PostgreSQL |
| `LICENSE_JWT_SECRET` | *required* | HS256 signing secret (≥ 32 chars) |
| `LICENSE_KEY_PEPPER` / `HWID_PEPPER` | *required* | HMAC peppers (≥ 16 chars each) |
| `SESSION_TTL_SECONDS` | `900` | client session lifetime |
| `RATE_LIMIT_ENABLED` | `true` | per-IP rate limiting |
| `KEYAUTH_*` | — | enable KeyAuth validation proxy |
| `ANTI_TAMPER_ENABLED` | `true` | report/accept integrity events |
| `ANTI_TAMPER_ENFORCEMENT_MODE` | `monitor` | `monitor` / `restrict` / `enforce` |
| `ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD` | `5` | medium+ events → restriction |
| `ANTI_TAMPER_BAN_THRESHOLD` | `10` | medium+ events → permanent ban |

## License

UNLICENSED. See repository for license terms.
