"""Operator-facing license management.

Every function here is the only place a license's status may change outside a
first client activation, and each change goes through
:func:`app.states.assert_transition` so an operator cannot resurrect a revoked
key by suspending or unsuspending it.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import AppError, ErrorCode
from app.keys import generate_license_key, hash_license_key, mask_license_key
from app.logging_config import get_logger
from app.models import Admin, License, utcnow
from app.repositories import activations as activation_repo
from app.repositories import licenses as license_repo
from app.repositories import sessions as session_repo
from app.services import audit_service
from app.states import LicenseStatus, assert_transition, effective_status

logger = get_logger("admin")

TARGET_LICENSE = "LICENSE"

KEYGEN_COLLISION_RETRIES = 5
MIN_EXPIRES_IN_DAYS = 1
MAX_EXPIRES_IN_DAYS = 3650
MAX_NOTE_LENGTH = 255
MAX_METADATA_BYTES = 4096


def _audit(
    session: Session,
    admin: Admin,
    *,
    action: str,
    target_id: str,
    success: bool,
    ip: str,
    user_agent: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Write an admin audit row and commit it with the change it describes."""
    audit_service.record(
        session,
        actor_type=audit_service.ACTOR_ADMIN,
        action=action,
        target_type=TARGET_LICENSE,
        success=success,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(admin.id),
        target_id=target_id,
        metadata=metadata,
    )


def resolve_expiry(
    *,
    expires_in_days: int | None,
    custom_expires_at: datetime | None,
) -> datetime | None:
    """Combine the two expiry inputs, rejecting a contradictory pair."""
    if expires_in_days is not None and custom_expires_at is not None:
        raise AppError(
            ErrorCode.VALIDATION_ERROR,
            "Provide either expires_in_days or custom_expires_at, not both.",
        )
    if expires_in_days is not None:
        if not MIN_EXPIRES_IN_DAYS <= expires_in_days <= MAX_EXPIRES_IN_DAYS:
            raise AppError(
                ErrorCode.VALIDATION_ERROR,
                f"expires_in_days must be between {MIN_EXPIRES_IN_DAYS} "
                f"and {MAX_EXPIRES_IN_DAYS}.",
            )
        return utcnow() + timedelta(days=expires_in_days)
    if custom_expires_at is not None:
        moment = (
            custom_expires_at.replace(tzinfo=UTC)
            if custom_expires_at.tzinfo is None
            else custom_expires_at.astimezone(UTC)
        )
        if moment <= utcnow():
            raise AppError(ErrorCode.VALIDATION_ERROR, "custom_expires_at must be in the future.")
        return moment
    return None


def _serialize_metadata(metadata: dict[str, Any] | None) -> str | None:
    """Serialize operator metadata, refusing oversized or unserializable input."""
    if not metadata:
        return None
    if len(metadata) > MAX_METADATA_BYTES:
        raise AppError(ErrorCode.VALIDATION_ERROR, "metadata is too large.")
    try:
        return json.dumps(metadata, default=str, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        raise AppError(ErrorCode.VALIDATION_ERROR, "metadata must be JSON serializable.") from None


def create_license(
    session: Session,
    admin: Admin,
    *,
    expires_in_days: int | None,
    custom_expires_at: datetime | None,
    note: str | None,
    metadata: dict[str, Any] | None,
    ip: str,
    user_agent: str,
    settings: Settings,
) -> tuple[License, str]:
    """Create a license and return ``(row, plaintext_key)``.

    The plaintext key exists only in this return value: only its HMAC is stored,
    so a lost key cannot be recovered and must be reissued. A collision on the
    UNIQUE ``key_hash`` index is resolved by generating a new key, not by
    overwriting the existing row.
    """
    expires_at = resolve_expiry(
        expires_in_days=expires_in_days, custom_expires_at=custom_expires_at
    )
    metadata_json = _serialize_metadata(metadata)
    clean_note = note.strip()[:MAX_NOTE_LENGTH] if note else None

    for _attempt in range(KEYGEN_COLLISION_RETRIES):
        plaintext = generate_license_key()
        key_hash = hash_license_key(settings.license_key_pepper, plaintext)
        license_row = license_repo.add_license(
            session,
            key_hash=key_hash,
            expires_at=expires_at,
            note=clean_note,
            metadata_json=metadata_json,
        )
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            continue

        _audit(
            session,
            admin,
            action="ADMIN_LICENSE_CREATE",
            target_id=str(license_row.id),
            success=True,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "expires_at": expires_at.isoformat() if expires_at else None,
                "has_note": bool(clean_note),
            },
        )
        session.commit()
        return license_row, plaintext

    raise AppError(ErrorCode.INTERNAL_ERROR, "Could not generate a unique license key.")


def serialize_license(license_row: License, *, now: datetime | None = None) -> dict[str, Any]:
    """Render a license for an operator. Still no key and no HWID hash."""
    moment = now or utcnow()
    return {
        "id": license_row.id,
        "status": effective_status(license_row.status, license_row.expires_at, moment).value,
        "declared_status": LicenseStatus(license_row.status).value,
        "bound": license_row.hwid_hash is not None,
        "note": license_row.note,
        "metadata": json.loads(license_row.metadata_json) if license_row.metadata_json else None,
        "created_at": license_row.created_at,
        "activated_at": license_row.activated_at,
        "expires_at": license_row.expires_at,
        "last_validated_at": license_row.last_validated_at,
        "activation_count": int(license_row.activation_count or 0),
        "revoked_at": license_row.revoked_at,
        "suspended_at": license_row.suspended_at,
        "updated_at": license_row.updated_at,
    }


def serialize_activation(row: Any) -> dict[str, Any]:
    """Render an activation trail entry. The HWID hash is deliberately omitted."""
    return {
        "id": row.id,
        "license_id": row.license_id,
        "activation_type": row.activation_type,
        "ip": row.ip,
        "user_agent": row.user_agent,
        "created_at": row.created_at,
    }


def _require_license(session: Session, license_id: int) -> License:
    """Fetch a license or raise the canonical not-found error."""
    license_row = license_repo.get_by_id(session, license_id)
    if license_row is None:
        raise AppError(ErrorCode.LICENSE_NOT_FOUND)
    return license_row


def _transition(
    session: Session,
    admin: Admin,
    license_row: License,
    target: LicenseStatus,
    *,
    action: str,
    ip: str,
    user_agent: str,
) -> License:
    """Apply a status change if the state machine permits it."""
    current = LicenseStatus(license_row.status)
    try:
        assert_transition(current, target)
    except ValueError:
        raise AppError(
            ErrorCode.VALIDATION_ERROR,
            f"A license that is {current.value} cannot become {target.value}.",
        ) from None

    license_repo.set_status(license_row, target)
    if target in (LicenseStatus.SUSPENDED, LicenseStatus.REVOKED):
        # A blocked license must lose its live sessions immediately, not at token
        # expiry, otherwise an operator's revoke would not take effect.
        session_repo.revoke_all_for_license(session, license_row.id)

    _audit(
        session,
        admin,
        action=action,
        target_id=str(license_row.id),
        success=True,
        ip=ip,
        user_agent=user_agent,
        metadata={"from": current.value, "to": target.value},
    )
    session.commit()
    return license_row


def suspend(
    session: Session, admin: Admin, license_id: int, *, ip: str, user_agent: str
) -> License:
    """Suspend a license and revoke its sessions."""
    license_row = _require_license(session, license_id)
    return _transition(
        session,
        admin,
        license_row,
        LicenseStatus.SUSPENDED,
        action="ADMIN_LICENSE_SUSPEND",
        ip=ip,
        user_agent=user_agent,
    )


def unsuspend(
    session: Session, admin: Admin, license_id: int, *, ip: str, user_agent: str
) -> License:
    """Return a suspended license to ACTIVE."""
    license_row = _require_license(session, license_id)
    return _transition(
        session,
        admin,
        license_row,
        LicenseStatus.ACTIVE,
        action="ADMIN_LICENSE_UNSUSPEND",
        ip=ip,
        user_agent=user_agent,
    )


def revoke(session: Session, admin: Admin, license_id: int, *, ip: str, user_agent: str) -> License:
    """Revoke a license permanently."""
    license_row = _require_license(session, license_id)
    return _transition(
        session,
        admin,
        license_row,
        LicenseStatus.REVOKED,
        action="ADMIN_LICENSE_REVOKE",
        ip=ip,
        user_agent=user_agent,
    )


def reset_hwid(
    session: Session, admin: Admin, license_id: int, *, ip: str, user_agent: str
) -> License:
    """Unbind a license from its device and revoke that license's sessions.

    Clearing ``hwid_hash`` alone would not be enough: a session issued to the old
    device would stay valid until it expired, so the sessions go too.
    """
    license_row = _require_license(session, license_id)
    was_bound = license_row.hwid_hash is not None
    license_repo.clear_hwid(license_row)
    revoked = session_repo.revoke_all_for_license(session, license_row.id)

    _audit(
        session,
        admin,
        action="ADMIN_LICENSE_RESET_HWID",
        target_id=str(license_row.id),
        success=True,
        ip=ip,
        user_agent=user_agent,
        metadata={"was_bound": was_bound, "sessions_revoked": revoked},
    )
    session.commit()
    return license_row


def delete_license(
    session: Session, admin: Admin, license_id: int, *, ip: str, user_agent: str
) -> None:
    """Delete a license; its activations and sessions cascade away."""
    license_row = _require_license(session, license_id)
    session_repo.revoke_all_for_license(session, license_row.id)
    license_repo.delete_license(session, license_row)
    _audit(
        session,
        admin,
        action="ADMIN_LICENSE_DELETE",
        target_id=str(license_id),
        success=True,
        ip=ip,
        user_agent=user_agent,
    )
    session.commit()


def list_licenses(
    session: Session,
    *,
    status: LicenseStatus | None,
    query: str | None,
    page: int,
    page_size: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return one page of licenses for the admin console."""
    rows, total = license_repo.list_licenses(
        session, status=status, query=query, page=page, page_size=page_size
    )
    pagination = {
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": (total + page_size - 1) // page_size if page_size else 0,
    }
    return pagination, [serialize_license(row) for row in rows]


def license_detail(
    session: Session, license_id: int, *, page: int, page_size: int
) -> dict[str, Any]:
    """Return one license plus a page of its activation trail."""
    license_row = _require_license(session, license_id)
    rows, total = activation_repo.list_for_license(
        session, license_id, page=page, page_size=page_size
    )
    detail = serialize_license(license_row)
    detail["active_sessions"] = session_repo.count_active(session, license_id)
    detail["activation_total"] = total
    detail["activations"] = [serialize_activation(row) for row in rows]
    return detail


def masked_reference(key: str) -> str:
    """Return the masked rendering of a key, for logs and audit metadata."""
    return mask_license_key(key)
