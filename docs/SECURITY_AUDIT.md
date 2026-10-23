# Security Audit Report

**Audit Date:** 2026-10-23
**Scope:** NULLFORGE license server (`roblox-external/server/`), Electron loader (`roblox-external/loader/`)
**Methodology:** Adversarial code review — line-by-line inspection for exploitable vulnerabilities

## Previously Fixed Vulnerabilities (Commit 6d0b78d / 2f6ba67)

| Issue | Severity | Fix |
|-------|----------|-----|
| KeyAuth error message leakage | HIGH | Sanitized all user-facing KeyAuth errors via `_SANITIZED_KEYAUTH_ERROR` |
| XSS via innerHTML in log() | HIGH | Rewrote log() using createTextNode/appendChild for text-only output |
| Hardcoded plaintext HTTP API URL | MEDIUM | Changed API_BASE to relative URL |
| Insecure JSON import pattern | LOW | Replaced `__import__("json")` with proper `import json` |

## Newly Discovered Vulnerabilities (Fixed)

### 1. Missing Rate Limiting on KeyAuth Endpoints
- **Severity:** HIGH
- **Affected:** `app/api/v1/keyauth.py` (all 3 endpoints)
- **Impact:** No rate limiting allows brute-force key guessing and DoS
- **Fix:** Added `keyauth_rate_limit` dependency to all endpoints
- **Test:** `test_keyauth_activate_has_rate_limit`

### 2. CORS Defaults to Wildcard
- **Severity:** MEDIUM
- **Affected:** `app/main.py` — `allow_origins=... or ["*"]`
- **Impact:** Any web origin could make cross-origin requests
- **Fix:** Removed `["*"]` fallback; empty config = no cross-origin access
- **Test:** `test_cors_does_not_allow_all_when_empty`

### 3. Integrity Verification Reusing License Pepper
- **Severity:** MEDIUM
- **Affected:** `app/api/v1/integrity.py` — used `license_key_pepper` for manifest signing
- **Impact:** License pepper compromise allows integrity signature forgery
- **Fix:** Added dedicated `INTEGRITY_PEPPER` setting
- **Test:** `test_integrity_uses_dedicated_pepper`

### 4. Electron Security Hardening Gaps
- **Severity:** LOW
- **Affected:** `loader/main.js` — no dev tools prevention, no navigation blocking
- **Fix:** Added `app.isPackaged` check, navigation prevention, context-menu suppression
- **Test:** `test_electron_hardened_when_packaged`

### 5. Server Binds to All Interfaces
- **Severity:** LOW
- **Affected:** `server/main.py` — `host="0.0.0.0"`
- **Status:** Documented — requires reverse proxy in production

## Verification Results

| Check | Result |
|-------|--------|
| `ruff check app/ tests/` | All checks passed |
| `mypy app/ tests/` | Success: no issues in 48 source files |
| `pytest tests/` | 31 passed (27 + 4 regression) |

## Remaining Risks

1. **Server bind address:** `server/main.py` binds to `0.0.0.0`. Production must use reverse proxy with TLS.
2. **KeyAuth external dependency:** Network failures result in `SERVICE_MAINTENANCE`.
3. **Electron packaged build:** Only source-level checks; full EXE build not performed.

## Final Security Assessment

**Overall posture:** SECURE WITH MITIGATIONS. All HIGH and MEDIUM vulnerabilities remediated. LOW items documented as production concerns. Server uses fail-closed error handling, secrets never logged, HMAC key storage, JWT with pinned algorithms, and per-IP rate limiting across all endpoints.
