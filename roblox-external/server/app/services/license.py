"""Client-facing license lifecycle: activate, authenticate, validate, logout.

The decision order in :func:`activate` is fixed and deliberate, because it
controls what an attacker can learn:

1. Key shape (cheap, no database hit).
2. Key exists.
3. Revoked, then suspended, then expired. Terminal states are reported before
   anything that depends on the stored HWID, so a revoked key never reveals
   whether it is bound to the caller's device.
4. Only then the HWID comparison.

A client never changes a license's status except through the single
``UNACTIVATED -> ACTIVE`` step of a first activation.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import AppError, ErrorCode
from app.keys import hash_license_key, normalize_license_key
from app.logging_config import get_logger
from app.models import License, SessionRecord, utcnow
from app.repositories import activations as activation_repo
from app.repositories import licenses as license_repo
from app.repositories import sessions as session_repo
from app.security import tokens
from app.security.crypto import constant_time_equals, derive_stored_hwid
from app.services import audit_service
from app.states import LicenseStatus, effective_status

logger = get_logger("license")

ACTIVATE = "ACTIVATE"
AUTHENTICATE = "AUTHENTICATE"
REAUTHENTICATE = "REAUTHENTICATE"

TARGET_LICENSE = "LICENSE"
TARGET_SESSION = "SESSION"

_TERMINAL_ERRORS: dict[LicenseStatus, ErrorCode] = {
    LicenseStatus.REVOKED: ErrorCode.LICENSE_REVOKED,
    LicenseStatus.SUSPENDED: ErrorCode.LICENSE_SUSPENDED,
    LicenseStatus.EXPIRED: ErrorCode.LICENSE_EXPIRED,
}


@dataclass(frozen=True, slots=True)
class ActivationResult:
    """What a successful activate/authenticate call produced."""

    license_id: int
    status: LicenseStatus
    expires_at: datetime | None
    session_token: str
    session_expires_at: datetime
    activation_type: str


@dataclass(frozen=True, slots=True)
class SessionContext:
    """A verified bearer token bound to a live session and license."""

    session_id: str
    row: SessionRecord
    license: License
    claims: dict[str, Any]


def _status_payload(
    license_row: License,
    *,
    now: datetime,
    operator_fields: bool = False,
) -> dict[str, Any]:
    """Render the public view of a license. Never includes a key or an HWID hash."""
    payload: dict[str, Any] = {
        "license_id": license_row.id,
        "status": effective_status(license_row.status, license_row.expires_at, now).value,
        "declared_status": LicenseStatus(license_row.status).value,
        "expires_at": license_row.expires_at,
        "created_at": license_row.created_at,
        "activated_at": license_row.activated_at,
        "last_validated_at": license_row.last_validated_at,
        "activation_count": int(license_row.activation_count or 0),
        "bound": license_row.hwid_hash is not None,
        "revoked_at": license_row.revoked_at,
        "suspended_at": license_row.suspended_at,
    }
    if operator_fields:
        payload["note"] = license_row.note
    return payload


def describe(license_row: License, *, now: datetime | None = None) -> dict[str, Any]:
    """Return the client-facing status document for a license."""
    return _status_payload(license_row, now=now or utcnow())


def resolve_session(session: Session, token: str, settings: Settings) -> SessionContext:
    """Verify a client bearer token and load its session and license.

    Every rejection mode raises :class:`AppError` so the route can audit the
    outcome under the right code.
    """
    try:
        claims = tokens.decode_token(token, settings, expected_type=tokens.CLIENT_TOKEN_TYPE)
    except tokens.TokenError:
        raise AppError(ErrorCode.SESSION_INVALID) from None

    session_id = str(claims[tokens.SESSION_ID_CLAIM])
    row = session_repo.get_by_jti(session, session_id)
    if row is None:
        raise AppError(ErrorCode.SESSION_INVALID)

    now = utcnow()
    if row.revoked_at is not None:
        raise AppError(ErrorCode.SESSION_INVALID)
    if row.expires_at <= now:
        raise AppError(ErrorCode.SESSION_EXPIRED)

    license_row = license_repo.get_by_id(session, row.license_id)
    if license_row is None:
        raise AppError(ErrorCode.SESSION_INVALID)
    if int(claims[tokens.LICENSE_ID_CLAIM]) != license_row.id:
        raise AppError(ErrorCode.SESSION_INVALID)

    return SessionContext(session_id=session_id, row=row, license=license_row, claims=claims)


def assert_usable(
    session: Session,
    context: SessionContext,
    *,
    ip: str,
    user_agent: str,
    action: str,
) -> None:
    """Re-check the license state behind a live session.

    A token that was valid a minute ago may belong to a license an operator has
    since suspended, so every authenticated call re-derives the effective status.
    """
    now = utcnow()
    resolved = effective_status(context.license.status, context.license.expires_at, now)

    if resolved is not LicenseStatus.ACTIVE:
        code = _TERMINAL_ERRORS.get(resolved, ErrorCode.SESSION_INVALID)
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_CLIENT,
            action=action,
            target_type=TARGET_LICENSE,
            success=False,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(context.license.id),
            target_id=str(context.license.id),
            metadata={"reason": code.value},
        )
        raise AppError(code)

    session_repo.touch(session, context.row, now=now)
    license_repo.mark_validated(context.license, now=now)
    session.commit()


def _classify_binding(license_row: License, stored_hwid: str) -> str | None:
    """Return the activation type for this attempt, or ``None`` on an HWID mismatch."""
    if license_row.hwid_hash is None:
        if LicenseStatus(license_row.status) is LicenseStatus.UNACTIVATED:
            return ACTIVATE
        return REAUTHENTICATE
    if constant_time_equals(license_row.hwid_hash, stored_hwid):
        return AUTHENTICATE
    return None


def _apply_binding(
    session: Session,
    license_row: License,
    activation_type: str,
    stored_hwid: str,
    *,
    now: datetime,
) -> None:
    """Bind the HWID and perform the single status change a client may cause."""
    if activation_type == ACTIVATE:
        license_row.status = LicenseStatus.ACTIVE.value
        license_row.activated_at = now
    elif activation_type == REAUTHENTICATE:
        # A rebind must not leave sessions minted against the previous device
        # usable, so they are revoked as part of the same transaction.
        session_repo.revoke_all_for_license(session, license_row.id, now=now)

    license_row.hwid_hash = stored_hwid
    license_row.activated_at = license_row.activated_at or now
    license_row.updated_at = now


def activate(
    session: Session,
    *,
    raw_key: str,
    client_hwid: str,
    ip: str,
    user_agent: str,
    settings: Settings,
) -> ActivationResult:
    """Bind a key to a device on first use, or re-authenticate an existing binding."""
    try:
        canonical_key = normalize_license_key(raw_key)
    except ValueError:
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_CLIENT,
            action="CLIENT_KEY_MALFORMED",
            target_type=TARGET_LICENSE,
            success=False,
            ip=ip,
            user_agent=user_agent,
            metadata={"reason": ErrorCode.KEY_MALFORMED.value},
        )
        raise AppError(ErrorCode.KEY_MALFORMED) from None

    stored_hwid = derive_stored_hwid(settings.hwid_pepper, client_hwid)
    key_hash = hash_license_key(settings.license_key_pepper, canonical_key)
    license_row = license_repo.get_by_key_hash(session, key_hash)

    if license_row is None:
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_CLIENT,
            action="CLIENT_ACTIVATE",
            target_type=TARGET_LICENSE,
            success=False,
            ip=ip,
            user_agent=user_agent,
            metadata={"reason": ErrorCode.LICENSE_NOT_FOUND.value},
        )
        raise AppError(ErrorCode.LICENSE_NOT_FOUND)

    now = utcnow()
    resolved = effective_status(license_row.status, license_row.expires_at, now)
    if resolved in _TERMINAL_ERRORS:
        code = _TERMINAL_ERRORS[resolved]
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_CLIENT,
            action="CLIENT_ACTIVATE",
            target_type=TARGET_LICENSE,
            success=False,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(license_row.id),
            target_id=str(license_row.id),
            metadata={"reason": code.value},
        )
        raise AppError(code)

    activation_type = _classify_binding(license_row, stored_hwid)
    if activation_type is None:
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_CLIENT,
            action="CLIENT_HWID_MISMATCH",
            target_type=TARGET_LICENSE,
            success=False,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(license_row.id),
            target_id=str(license_row.id),
            metadata={"reason": ErrorCode.HWID_MISMATCH.value},
        )
        raise AppError(ErrorCode.HWID_MISMATCH)

    _apply_binding(session, license_row, activation_type, stored_hwid, now=now)
    activation_repo.record_activation(
        session,
        license_id=license_row.id,
        hwid_hash=stored_hwid,
        activation_type=activation_type,
        ip=ip,
        user_agent=user_agent,
    )
    activation_repo.increment_count(session, license_row)

    # The session id is minted here so the token's ``sid`` claim and the row's
    # unique index refer to the same value; the token's own ``jti`` claim stays
    # present for JWT hygiene but is not the lookup key.
    session_id = tokens.new_jti()
    token, _token_jti, expires_at = tokens.create_access_token(
        subject=str(license_row.id),
        session_id=session_id,
        license_id=license_row.id,
        ttl_seconds=settings.SESSION_TTL_SECONDS,
        settings=settings,
    )
    session_row = session_repo.create_session(
        session,
        jti=session_id,
        license_id=license_row.id,
        hwid_hash=stored_hwid,
        expires_at=expires_at,
    )
    session.flush()

    audit_service.record(
        session,
        actor_type=audit_service.ACTOR_CLIENT,
        action=f"CLIENT_{activation_type}",
        target_type=TARGET_LICENSE,
        success=True,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(license_row.id),
        target_id=str(license_row.id),
        metadata={"activation_type": activation_type, "session_ref": session_id[:8]},
    )
    session.commit()

    return ActivationResult(
        license_id=license_row.id,
        status=LicenseStatus.ACTIVE,
        expires_at=license_row.expires_at,
        session_token=token,
        session_expires_at=expires_at,
        activation_type=activation_type,
    )


def validate(
    session: Session,
    context: SessionContext,
    *,
    ip: str,
    user_agent: str,
) -> dict[str, Any]:
    """Refresh a session and the license's ``last_validated_at``."""
    assert_usable(session, context, ip=ip, user_agent=user_agent, action="CLIENT_VALIDATE")
    audit_service.record(
        session,
        actor_type=audit_service.ACTOR_CLIENT,
        action="CLIENT_VALIDATE",
        target_type=TARGET_SESSION,
        success=True,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(context.license.id),
        target_id=str(context.license.id),
        metadata={"session_ref": context.session_id[:8]},
    )
    session.commit()

    payload = _status_payload(context.license, now=utcnow())
    payload["session_expires_at"] = context.row.expires_at
    return payload


def logout(session: Session, context: SessionContext, *, ip: str, user_agent: str) -> None:
    """Revoke the presented session."""
    session_repo.revoke(session, context.row)
    audit_service.record(
        session,
        actor_type=audit_service.ACTOR_CLIENT,
        action="CLIENT_LOGOUT",
        target_type=TARGET_SESSION,
        success=True,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(context.license.id),
        target_id=str(context.license.id),
        metadata={"session_ref": context.session_id[:8]},
    )
    session.commit()


def license_status(context: SessionContext) -> dict[str, Any]:
    """Return the status document for the session's license without writing."""
    payload = _status_payload(context.license, now=utcnow())
    payload["session_expires_at"] = context.row.expires_at
    return payload
