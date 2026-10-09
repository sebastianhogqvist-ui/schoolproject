"""Audit trail writing.

Every state-changing or security-relevant action lands here. Two rules are
enforced in code rather than left to reviewers:

* **No secrets, ever.** :func:`sanitize_metadata` drops any key that looks like a
  credential and coerces values to inert scalars, so a caller cannot accidentally
  park a token or a raw HWID in ``metadata_json``.
* **Audit rows are committed explicitly.** :func:`record_and_commit` commits
  before an error is raised, because the request dependency rolls the session
  back on any exception and would otherwise discard the record of the failure.
"""

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.logging_config import get_logger
from app.models import AuditLog
from app.repositories import audit as audit_repo

logger = get_logger("audit")

ACTOR_ADMIN = "ADMIN"
ACTOR_CLIENT = "CLIENT"
ACTOR_SYSTEM = "SYSTEM"

MAX_METADATA_LENGTH = 2000

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "pepper",
    "token",
    "jwt",
    "authorization",
    "credential",
    "apikey",
    "api_key",
    "key_hash",
    "hwid",
    "license_key",
    "licensekey",
    "plaintext",
)

_ACTIONS = (
    "CLIENT_ACTIVATE",
    "CLIENT_AUTHENTICATE",
    "CLIENT_REAUTHENTICATE",
    "CLIENT_HWID_MISMATCH",
    "CLIENT_KEY_MALFORMED",
    "CLIENT_VALIDATE",
    "CLIENT_LOGOUT",
    "CLIENT_SESSION_REJECTED",
    "ADMIN_LOGIN",
    "ADMIN_LOGIN_FAILED",
    "ADMIN_LICENSE_CREATE",
    "ADMIN_LICENSE_SUSPEND",
    "ADMIN_LICENSE_UNSUSPEND",
    "ADMIN_LICENSE_REVOKE",
    "ADMIN_LICENSE_RESET_HWID",
    "ADMIN_LICENSE_DELETE",
    "SYSTEM_STARTUP",
    "SYSTEM_MAINTENANCE",
)


def _is_sensitive(key: str) -> bool:
    """Return whether a metadata key name suggests it holds a credential."""
    lowered = key.strip().lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _coerce(value: Any) -> Any:
    """Reduce a value to an inert JSON scalar, or drop it."""
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    if isinstance(value, str):
        return value[:200]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_coerce(item) for item in value][:20]
    if isinstance(value, dict):
        return _clean(dict(value))
    return None


def _clean(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only non-sensitive, scalar-ish entries."""
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive(str(key)):
            continue
        coerced = _coerce(value)
        if coerced is None:
            continue
        cleaned[str(key)[:64]] = coerced
    return cleaned


def sanitize_metadata(metadata: dict[str, Any] | None) -> str | None:
    """Serialize audit context safely, or return ``None`` when there is nothing left."""
    if not metadata:
        return None
    cleaned = _clean(metadata)
    if not cleaned:
        return None
    serialized = json.dumps(cleaned, default=str, ensure_ascii=False, sort_keys=True)
    if len(serialized) > MAX_METADATA_LENGTH:
        serialized = serialized[:MAX_METADATA_LENGTH]
    return serialized


def record(
    session: Session,
    *,
    actor_type: str,
    action: str,
    target_type: str,
    success: bool,
    ip: str,
    user_agent: str,
    actor_id: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> AuditLog:
    """Append one audit row to the current transaction (no commit)."""
    return audit_repo.record(
        session,
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        success=success,
        ip=ip,
        user_agent=user_agent,
        actor_id=actor_id,
        target_id=target_id,
        metadata_json=sanitize_metadata(metadata),
        created_at=created_at,
    )


def record_and_commit(
    session: Session,
    *,
    actor_type: str,
    action: str,
    target_type: str,
    success: bool,
    ip: str,
    user_agent: str,
    actor_id: str | None = None,
    target_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Append and *commit* an audit row.

    Used on failure paths: the request dependency rolls the session back when an
    exception escapes, so the row has to reach the database first. Audit
    failures are logged and swallowed rather than masking the original error.
    """
    try:
        record(
            session,
            actor_type=actor_type,
            action=action,
            target_type=target_type,
            success=success,
            ip=ip,
            user_agent=user_agent,
            actor_id=actor_id,
            target_id=target_id,
            metadata=metadata,
        )
        session.commit()
    except Exception:  # noqa: BLE001 - auditing must never replace the caller's error
        session.rollback()
        logger.warning("failed to persist audit row", extra={"app_action": action})
