"""Authentication of administrators and resolution of bearer tokens.

Both failure modes - unknown username and wrong password - return the same
``ADMIN_AUTH_FAILED`` error, and both take the same amount of work: an unknown
username is verified against a dummy hash so the response time does not reveal
which accounts exist.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import AppError, ErrorCode
from app.logging_config import get_logger
from app.models import Admin
from app.repositories import admins as admin_repo
from app.security import tokens
from app.security.passwords import dummy_hash, hash_password, needs_rehash, verify_password
from app.services import audit_service

logger = get_logger("auth")

TARGET_ADMIN = "ADMIN"


@dataclass(frozen=True, slots=True)
class AdminToken:
    """An issued administrator token and its identity."""

    admin: Admin
    token: str
    expires_at: datetime


def authenticate_admin(
    session: Session,
    *,
    username: str,
    password: str,
    settings: Settings,
    ip: str,
    user_agent: str,
) -> AdminToken:
    """Verify credentials and issue an admin token, or raise ``ADMIN_AUTH_FAILED``."""
    admin = admin_repo.get_by_username(session, username.strip())
    if admin is None:
        verify_password(dummy_hash(settings), password, settings)
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_ADMIN,
            action="ADMIN_LOGIN_FAILED",
            target_type=TARGET_ADMIN,
            success=False,
            ip=ip,
            user_agent=user_agent,
            metadata={"reason": ErrorCode.ADMIN_AUTH_FAILED.value},
        )
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED)

    if not verify_password(admin.password_hash, password, settings):
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_ADMIN,
            action="ADMIN_LOGIN_FAILED",
            target_type=TARGET_ADMIN,
            success=False,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(admin.id),
            target_id=str(admin.id),
            metadata={"reason": ErrorCode.ADMIN_AUTH_FAILED.value},
        )
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED)

    if not admin.is_active:
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_ADMIN,
            action="ADMIN_LOGIN_FAILED",
            target_type=TARGET_ADMIN,
            success=False,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(admin.id),
            target_id=str(admin.id),
            metadata={"reason": ErrorCode.FORBIDDEN.value},
        )
        raise AppError(ErrorCode.FORBIDDEN)

    if needs_rehash(admin.password_hash, settings):
        # The plaintext is available exactly once - here - so a cost-parameter
        # upgrade can be applied without ever storing the old hash's password.
        try:
            admin.password_hash = hash_password(password, settings)
        except ValueError:
            logger.warning("admin password is below policy; hash not upgraded")

    admin_repo.record_login(session, admin)
    token, _jti, expires_at = tokens.create_admin_token(
        admin_id=admin.id,
        username=admin.username,
        ttl_seconds=settings.ADMIN_SESSION_TTL_SECONDS,
        settings=settings,
    )
    audit_service.record(
        session,
        actor_type=audit_service.ACTOR_ADMIN,
        action="ADMIN_LOGIN",
        target_type=TARGET_ADMIN,
        success=True,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(admin.id),
        target_id=str(admin.id),
    )
    session.commit()

    return AdminToken(admin=admin, token=token, expires_at=expires_at)


def resolve_admin(session: Session, token: str, settings: Settings) -> Admin:
    """Resolve an admin bearer token to its account.

    Admin tokens are stateless (there is no session table for them); the token's
    ``exp`` plus the account's ``is_active`` flag are the revocation points, and
    an account disabled after issuance stops working immediately.
    """
    try:
        claims = tokens.decode_token(token, settings, expected_type=tokens.ADMIN_TOKEN_TYPE)
    except tokens.TokenError:
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED) from None

    try:
        admin_id = int(str(claims["sub"]))
    except (KeyError, ValueError):
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED) from None

    admin = admin_repo.get_by_id(session, admin_id)
    if admin is None or not admin.is_active:
        raise AppError(ErrorCode.FORBIDDEN)
    return admin
