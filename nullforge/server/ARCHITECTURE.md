# NULLFORGE Architecture

NULLFORGE is a self-hosted software licensing system. It mints license keys,
binds them to a device (HWID), issues short-lived session tokens, and exposes
an operator console for suspend / revoke / reset / delete. Every response
follows the `{"success": bool, "data" | "error": {"code", "message"}}` contract.

The server supports two deployment modes: a single-process **monolith**, and a
**multi-service** deployment in which a gateway plus five backend services run
as separate processes and discover each other through a file-backed service
registry.

## 1. Overview

### Components

| Layer | Responsibility |
|-------|----------------|
| Loader / client | KernelBridge client (C++ side). Derives HWID, presents client JWTs, submits integrity manifests and security events. |
| Gateway | Single public entry point. Validates client JWTs, mints short-lived service tokens, proxies to backends. |
| Backend services | license, session, security, integrity, admin. Each owns a bounded slice of the domain model. |
| Database | SQLite by default (PostgreSQL via SQLAlchemy URL). Schema managed by Alembic. |
| Service registry | `runtime/services.json`. File-backed runtime service discovery. |

### Design goals

- **Single public port.** Only the gateway listens on `GATEWAY_PORT` (8080).
  Backend services bind to localhost on random ports within their assigned
  ranges and are unreachable from outside the host.
- **No ambient trust.** Every inter-service call carries a short-lived service
  JWT (`typ == "service"`). Backends reject requests without one.
- **Fail loudly.** Missing or weak secrets cause a startup exit (code 2) rather
  than a silent fallback to guessable values.

## 2. Deployment Modes

### Monolith (`SERVICE_MODE=monolith`)

One FastAPI process serves every route: health, licenses, sessions, admin,
keyauth, integrity, and security. All middleware (CORS, maintenance mode, body
size limits) runs in-process. This is the default and the simplest operational
model — start one process, no service discovery needed.

Entry point: `python -m server.main` (builds the app via `app.main.create_app`,
which delegates to `create_monolith_app`).

### Multi-service (`SERVICE_MODE=gateway | license | session | security | integrity | admin`)

Seven independent uvicorn processes:

1. **gateway** — public entry point on `GATEWAY_PORT`.
2. **license** — license activation / status.
3. **session** — session validation / refresh / logout.
4. **security** — security events and enforcement.
5. **integrity** — integrity challenges and manifest checks.
6. **admin** — operator API.

Each backend process runs `uvicorn app.main:app` with `SERVICE_MODE` set to its
role. `app.main.create_app` routes to `app.service_base.create_service_app`,
which mounts only that service's router, installs service-token auth
middleware, registers the service in the registry, and picks a random port from
its configured range.

Orchestration: `scripts/start_services.py` loads `server/.env`, spawns all seven
processes, waits for every service to register in `runtime/services.json`, then
waits for all processes to exit. `SIGINT` triggers an orderly shutdown.

## 3. Services

### Gateway (`SERVICE_MODE=gateway`)

- Binds `SERVICE_HOST:GATEWAY_PORT` (default `127.0.0.1:8080`). This is the
  only service that accepts external traffic.
- Validates client JWTs (HS256, pinned issuer/audience, required claims).
- Mints short-lived service tokens (TTL = `SERVICE_TOKEN_TTL_SECONDS`) bearing
  client context (`sid`, `lid`) and forwards them to backends as `Authorization:
  Bearer <service token>`.
- Proxies: `/v1/licenses/activate`, `/v1/licenses/status`,
  `/v1/sessions/validate`, `/v1/sessions/logout`, `/v1/security/*`,
  `/v1/integrity/*`, `/v1/admin/{path}`.
- Handles `/v1/admin/login` directly (issues admin session token, no proxy).
- `/health` responds directly without proxying.
- Maintains a pooled `httpx.AsyncClient` for backend proxying.

### License service (`SERVICE_MODE=license`, port 18000–18999)

- `/v1/licenses/activate` — key activation: HMAC-SHA256 of the license key
  (keyed by `LICENSE_KEY_PEPPER`) is looked up, HWID bound, session minted.
- `/v1/licenses/status` — license state for an authenticated session.
- Owns license key lifecycle: minting, binding, suspension.

### Session service (`SERVICE_MODE=session`, port 19000–19999)

- `/v1/sessions/validate` — refresh an existing session (HWID re-bound).
- `/v1/sessions/logout` — revoke a session token.
- Owns session TTLs (`SESSION_TTL_SECONDS` for clients, `ADMIN_SESSION_TTL_SECONDS` for admins).

### Security service (`SERVICE_MODE=security`, port 20000–20999)

- `/v1/security/event` — ingest client-reported security events.
- `/v1/security/status` — current enforcement state for a session.
- Owns anti-tamper enforcement: unresolved medium+ event thresholds trigger
  temporary restriction (`ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD`) or permanent
  ban (`ANTI_TAMPER_BAN_THRESHOLD`).

### Integrity service (`SERVICE_MODE=integrity`, port 21000–21999)

- `/v1/integrity/challenge` — server-issued integrity nonce/challenge.
- `/v1/integrity/check` — verify client integrity manifests (HMAC-SHA256
  signed with `INTEGRITY_PEPPER`).
- A dedicated pepper isolates integrity signing from license-key and HWID
  peppers: compromise of one pepper does not let an attacker forge manifests
  for another domain.

### Admin service (`SERVICE_MODE=admin`, port 22000–22999)

- Operator API: license CRUD (suspend / revoke / reset / delete), key
  generation, admin management.
- Receives proxied requests from the gateway carrying an admin service token
  (`sid == "admin:<id>"`, `lid == 0`).

## 4. Trust Boundaries

### loader → gateway (client JWT)

The client presents a Bearer JWT on every authenticated request. The gateway
verifies signature (HS256), `iss`, `aud`, required claims (`exp`, `iat`, `sub`,
etc.), and expiry. Client tokens are short-lived (`SESSION_TTL_SECONDS`).
Activation (`/v1/licenses/activate`) is the one entry point that does not
require a pre-existing client token; it establishes the first session.

### gateway → backend (service JWT)

The gateway mints a service JWT for each proxied request:

- signed with `LICENSE_JWT_SECRET`, algorithm pinned to HS256
- `typ == "service"` so it can never be confused with a client/admin token
- `jti` nonce from `secrets.token_hex(16)` (never `random`)
- TTL = `SERVICE_TOKEN_TTL_SECONDS` (default 300s)
- embeds client context: `sid` (session id) and `lid` (license id); admin
  calls use `sid == "admin:<id>"`, `lid == 0`

Each backend's `_ServiceAuthMiddleware` rejects requests missing a valid
service token before any business logic runs. Service tokens are single-purpose
and short-lived; capture/replay is bounded by the TTL.

### backend → DB

Backend services (and the gateway for admin login) connect directly to
`DATABASE_URL`. Each backend configures its own SQLAlchemy engine at startup.
Backends are the data plane: they read/write license, session, security-event,
integrity, and admin rows. The gateway never bypasses a backend to touch the
DB except for admin login, which it handles directly before proxying the rest
of the admin API.

## 5. Security Controls vs Obfuscation

### Real security controls

- **Pinned JWT algorithm.** HS256 only; verification rejects `none` and
  asymmetric algorithms, preventing token downgrade.
- **Claim verification.** `iss`/`aud`/`exp`/`nbf`/`jti` are enforced on every
  token; client and service tokens are typed so they cannot be interchanged.
- **Server-side secrets never leave the host.** `LICENSE_JWT_SECRET` and the
  three peppers are never logged, never returned by any endpoint, and never
  sent to the client.
- **Pepper-keyed HMAC digests.** Only `HMAC-SHA256(key, pepper)` digests of
  license keys and HWIDs are stored; raw values are never persisted. Rotating a
  pepper orphans existing rows deliberately.
- **Argon2id admin passwords.** Named `BCRYPT_*` for C++ parity, but costs are
  argon2id `t`/`m`/`p`.
- **Per-IP fixed-window rate limiting** on auth, admin login, admin API, and
  key generation.
- **Request body size cap** (`MAX_REQUEST_BODY_BYTES`, default 16 KiB) before
  parsing.
- **Short-lived service tokens** (300s default) with random nonces for
  inter-service calls.
- **Backend CORS restricted to localhost** (`http://127.0.0.1`,
  `http://localhost`).
- **Anti-tamper enforcement** with restrict/ban escalation on unresolved
  security events.

### Not security (obfuscation / hygiene only)

- **Random service ports.** Each backend picks a random port within its range
  to avoid startup collisions. This is collision avoidance, not access control:
  ports are unguessable only by accident, and any local process can read
  `runtime/services.json` to learn them. The service registry — not port
  obscurity — is how services discover each other.
- **Binding to `127.0.0.1`.** Limits network exposure but is defense in depth;
  a compromised host or local malicious process bypasses it entirely.
- **`typ == "service"` claim.** Prevents token confusion between token classes;
  it does not by itself authenticate — the signature verification does.

## 6. Configuration

All multi-service settings live in `.env.example` (copy to `server/.env`).
`.env` is gitignored; never commit real secrets.

| Setting | Default | Meaning |
|---------|---------|---------|
| `SERVICE_MODE` | `monolith` | `monolith` or one of `gateway`, `license`, `session`, `security`, `integrity`, `admin`. |
| `SERVICE_HOST` | `127.0.0.1` | Bind address for every service. Never `0.0.0.0`. |
| `SERVICE_REGISTRY_PATH` | `runtime/services.json` | Path to the JSON service registry (created at startup). |
| `SERVICE_TOKEN_TTL_SECONDS` | `300` | TTL in seconds for short-lived inter-service JWTs. |
| `GATEWAY_PORT` | `8080` | Public port bound only by the gateway. |
| `LICENSE_PORT_RANGE_START/END` | `18000` / `18999` | License service random port range. |
| `SESSION_PORT_RANGE_START/END` | `19000` / `19999` | Session service random port range. |
| `SECURITY_PORT_RANGE_START/END` | `20000` / `20999` | Security service random port range. |
| `INTEGRITY_PORT_RANGE_START/END` | `21000` / `21999` | Integrity service random port range. |
| `ADMIN_PORT_RANGE_START/END` | `22000` / `22999` | Admin service random port range. |

Validation: `SERVICE_MODE` must be one of the allowed modes; every port range
start must not exceed its end; `GATEWAY_PORT` and range bounds must not be
negative. `validate_runtime()` additionally requires `LICENSE_JWT_SECRET`
(≥32 chars) and the three peppers (≥16 chars each, all distinct from each
other and from the JWT secret).

Pre-existing settings (unchanged by multi-service work): `DATABASE_URL`,
`SERVER_HOST`/`SERVER_PORT` (monolith only), JWT secrets/issuer/audience,
session TTLs, peppers, rate limits, CORS, maintenance mode, logging, body
limit, argon2id costs, KeyAuth, anti-tamper thresholds.

## 7. Startup

### Prerequisites

```bash
cp .env.example .env
# edit .env: set LICENSE_JWT_SECRET, LICENSE_KEY_PEPPER, HWID_PEPPER,
# INTEGRITY_PEPPER (all CHANGE_ME placeholders must be replaced)
python -m app.cli init-db        # Alembic migration + admin bootstrap
python -m app.cli keygen --count 5   # mint license keys (printed once)
```

### Monolith

```bash
python -m server.main
```

Serves all routes on `SERVER_HOST:SERVER_PORT` (default `127.0.0.1:8080`).

### Multi-service

```bash
python scripts/start_services.py
```

Loads `server/.env`, spawns gateway + 5 backend services as uvicorn subprocesses,
waits for all to register in the service registry (30s default timeout), then
waits for all processes to exit. `SIGINT` terminates all services.

Individual backends can also be started manually:

```bash
SERVICE_MODE=license SERVER_HOST=127.0.0.1 python -m uvicorn app.main:app
```

Each picks a random port from its range and registers itself at startup.

## 8. Service Registry

### File: `runtime/services.json`

Created at startup by each backend service (and readable by the gateway).
Writes are atomic: serialise to a `.tmp` file, then `os.replace` over the
target. The parent directory is created on demand.

Format — a JSON object keyed by service name:

```json
{
  "gateway": {
    "name": "gateway",
    "host": "127.0.0.1",
    "port": 8080,
    "registered_at": "2026-11-13T09:00:00Z",
    "ttl_seconds": 600
  },
  "license": {
    "name": "license",
    "host": "127.0.0.1",
    "port": 18342,
    "registered_at": "2026-11-13T09:00:01Z",
    "ttl_seconds": 600
  },
  "session": {
    "name": "session",
    "host": "127.0.0.1",
    "port": 19417,
    "registered_at": "2026-11-13T09:00:01Z",
    "ttl_seconds": 600
  },
  "security": {
    "name": "security",
    "host": "127.0.0.1",
    "port": 20103,
    "registered_at": "2026-11-13T09:00:02Z",
    "ttl_seconds": 600
  },
  "integrity": {
    "name": "integrity",
    "host": "127.0.0.1",
    "port": 21550,
    "registered_at": "2026-11-13T09:00:02Z",
    "ttl_seconds": 600
  },
  "admin": {
    "name": "admin",
    "host": "127.0.0.1",
    "port": 22291,
    "registered_at": "2026-11-13T09:00:03Z",
    "ttl_seconds": 600
  }
}
```

### Fields

- `name` — service role (`gateway`, `license`, `session`, `security`,
  `integrity`, `admin`).
- `host` — bind host (`SERVICE_HOST`, always `127.0.0.1`).
- `port` — bound port (random within the service's range; `8080` for gateway).
- `registered_at` — ISO-8601 UTC timestamp of registration / last heartbeat.
- `ttl_seconds` — registration TTL; default `SERVICE_TOKEN_TTL_SECONDS * 2`
  (600s).

### Discovery

The gateway resolves backend URLs via `ServiceRegistry.discover(name)`:
`http://<host>:<port>`. A missing or expired registration (now − registered_at >
ttl) returns `None`, and the gateway answers with a 500 "backend service
unavailable". Services call `heartbeat(name)` to refresh `registered_at`;
`cleanup_expired()` removes stale entries.

### Ports are not security

Backend ports are randomly chosen to prevent collisions. They are listed in
plaintext in `services.json`, readable by any local process. Discovery depends
on the registry file, not on port secrecy; access control depends on the
service JWT validated by `_ServiceAuthMiddleware`.
