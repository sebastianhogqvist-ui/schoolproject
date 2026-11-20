# roblox-license-server

HWID-bound license/key server for the KernelBridge client. A FastAPI service
that mints license keys, binds them to a device (HWID), issues short-lived
session tokens, and exposes an operator console for suspend / revoke / reset /
delete.

## Layout

- `app/` — application package (config, models, repositories, services, security,
  routes, CLI).
- `alembic/` — schema migrations (`alembic upgrade head`).
- `server/main.py` — Uvicorn entrypoint.

## Quick start

```bash
cp .env.example .env   # fill in the three secrets
python -m app.cli init-db          # migrate + bootstrap admin
python -m app.cli keygen --count 5 # mint keys (printed once)
python -m server.main              # serve on 0.0.0.0:8080
```

## Client contract

- `POST /v1/licenses/activate` body `{"key","hwid"}` -> session token + expiry.
- `POST /v1/sessions/validate` (bearer) body `{"hwid"}` -> refresh.
- `POST /v1/sessions/logout` (bearer) -> revoke.
- `GET /v1/health`, `/v1/health/heartbeat` -> liveness.
- `POST /v1/admin/login` -> admin token; `/v1/admin/licenses/*` -> operator ops.

Every response is `{"success": true/false, "data" | "error": {"code","message"}}`.
