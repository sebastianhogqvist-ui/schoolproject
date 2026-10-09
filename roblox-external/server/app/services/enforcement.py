"""Graduated anti-tampering enforcement engine.

The engine maps cumulative security-event counts to one of four enforcement
levels (0-3) and then translates the level into an action (none / warn /
restrict / ban) subject to the configured enforcement mode.

Thresholds (read from :class:`app.config.Settings`):

* ``ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD`` — unresolved medium+ events that
  trigger a temporary restriction.
* ``ANTI_TAMPER_BAN_THRESHOLD`` — unresolved medium+ events that trigger a
  permanent ban.
* ``ANTI_TAMPER_RESTRICTION_HOURS`` — how long a temporary restriction lasts.

Enforcement modes:

* ``"monitor"`` — event logging only; no license mutations.
* ``"restrict"`` — restrictions may be applied but licenses are never banned.
* ``"enforce"`` — full graduated response, including bans.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_config import get_logger
from app.models import SECURITY_LEVEL_CRITICAL, SECURITY_LEVEL_MEDIUM, License, utcnow
from app.repositories import licenses as license_repo
from app.repositories import security_events as security_event_repo
from app.states import LicenseStatus

logger = get_logger("enforcement")

TARGET_LICENSE = "LICENSE"

# A medium-or-higher event that has not been dismissed counts toward escalation.
ESCALATION_MIN_LEVEL = SECURITY_LEVEL_MEDIUM


class EnforcementAction(StrEnum):
    """Discrete actions the engine can take against a license."""

    NONE = "NONE"
    WARN = "WARN"
    RESTRICT = "RESTRICT"
    BAN = "BAN"


class EnforcementDecision:
    """The outcome of evaluating one security event."""

    __slots__ = ("action", "license_status", "reason", "restriction_expires_at")

    def __init__(
        self,
        action: EnforcementAction,
        *,
        restriction_expires_at: datetime | None = None,
        license_status: str | None = None,
        reason: str | None = None,
    ) -> None:
        self.action = action
        self.restriction_expires_at = restriction_expires_at
        self.license_status = license_status
        self.reason = reason

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serialisable view."""
        return {
            "action": self.action.value,
            "restriction_expires_at": (
                self.restriction_expires_at.isoformat()
                if self.restriction_expires_at
                else None
            ),
            "license_status": self.license_status,
            "reason": self.reason,
        }


def compute_level(settings: Settings, active_count: int) -> int:
    """Map an unresolved-event count to an enforcement level (0-3).

    Level 0 — no unresolved events of concern.
    Level 1 — one or more unresolved events, below the restrict threshold.
    Level 2 — at or above the restrict threshold (temporary restriction).
    Level 3 — at or above the ban threshold (permanent ban).
    """
    if active_count >= settings.ANTI_TAMPER_BAN_THRESHOLD:
        return SECURITY_LEVEL_CRITICAL
    if active_count >= settings.ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD:
        return SECURITY_LEVEL_MEDIUM
    if active_count > 0:
        return 1
    return 0


def enforcement_status_label(level: int) -> str:
    """Return a human-readable label for a numeric enforcement level."""
    labels: dict[int, str] = {
        0: "OK",
        1: "WARNED",
        2: "RESTRICTED",
        3: "BANNED",
    }
    return labels.get(level, "OK")


def _mode_cap(mode: str) -> int:
    """Return the highest enforcement level permitted by ``mode``."""
    if mode == "monitor":
        return 0
    if mode == "restrict":
        return SECURITY_LEVEL_MEDIUM
    return SECURITY_LEVEL_CRITICAL


def _action_for_level(level: int) -> EnforcementAction:
    """Translate an enforcement level into an enforcement action."""
    if level >= SECURITY_LEVEL_CRITICAL:
        return EnforcementAction.BAN
    if level >= SECURITY_LEVEL_MEDIUM:
        return EnforcementAction.RESTRICT
    if level >= 1:
        return EnforcementAction.WARN
    return EnforcementAction.NONE


def _count_active(session: Session, license_id: int, settings: Settings) -> int:
    """Count unresolved medium+ events within the retention window."""
    window = timedelta(days=settings.ANTI_TAMPER_RETENTION_DAYS)
    return security_event_repo.count_unresolved_recent(
        session, license_id, min_level=ESCALATION_MIN_LEVEL, window=window
    )


def get_restriction_expiry(
    session: Session, license_id: int, *, now: datetime | None = None
) -> datetime | None:
    """Return the ``restricted_until`` timestamp if the license is currently restricted.

    A restriction is active when ``restricted_until`` is set and lies in the
    future.  Returns ``None`` when the license is unrestricted, banned, or
    unknown.
    """
    moment = now or utcnow()
    license_row = license_repo.get_by_id(session, license_id)
    if license_row is None:
        return None
    if license_row.restricted_until and license_row.restricted_until > moment:
        return license_row.restricted_until
    return None


def is_currently_restricted(
    session: Session, license_id: int, *, now: datetime | None = None
) -> bool:
    """Return whether ``license_id`` has an active temporary restriction."""
    return get_restriction_expiry(session, license_id, now=now) is not None


def release_expired_restrictions(session: Session, *, now: datetime | None = None) -> int:
    """Lift temporary restrictions whose ``restricted_until`` has passed.

    Licenses are returned to ``ACTIVE`` and ``restricted_until`` is cleared.
    Permanently revoked licenses are never touched.  Returns the number of
    rows updated.
    """
    moment = now or utcnow()
    result = session.execute(
        update(License)
        .where(
            License.status == LicenseStatus.SUSPENDED.value,
            License.restricted_until.is_not(None),
            License.restricted_until <= moment,
        )
        .values(
            status=LicenseStatus.ACTIVE.value,
            restricted_until=None,
            suspended_at=None,
        )
        .execution_options(synchronize_session="fetch")
    )
    return int(cast(Any, result).rowcount or 0)


def evaluate_and_enforce(
    session: Session,
    *,
    settings: Settings,
    license_id: int | None,
    license_row: License | None,
    level: int,
    category: str,
    rule: str,
    ip: str,
    user_agent: str,
    now: datetime | None = None,
) -> EnforcementDecision:
    """Evaluate cumulative event counts and apply the graduated enforcement action.

    Returns an :class:`EnforcementDecision` describing what was done (or not).
    The decision is made before the event row is committed, so the enforcement
    engine sees the counts including the current event once ``record_event``
    flushes.

    Note:
        The ``license_row`` is mutated in place when an action changes
        license state.  The caller is responsible for committing.
    """
    moment = now or utcnow()

    if license_id is None:
        return EnforcementDecision(
            EnforcementAction.NONE,
            reason="no license_id attached to event",
        )

    mode = settings.ANTI_TAMPER_ENFORCEMENT_MODE
    mode_limit = _mode_cap(mode)

    # Count unresolved medium+ events (the event being recorded is not yet
    # flushed, so we evaluate based on prior state and then apply.
    active_count = _count_active(session, license_id, settings)

    # The event being recorded has not been flushed yet, so bump the count to
    # reflect it when it would itself contribute to escalation (i.e. when its
    # level is at or above the escalation minimum).
    if level >= ESCALATION_MIN_LEVEL:
        active_count += 1

    raw_level = compute_level(settings, active_count)
    capped_level = min(raw_level, mode_limit)
    action = _action_for_level(capped_level)

    if action is EnforcementAction.NONE:
        return EnforcementDecision(
            EnforcementAction.NONE,
            reason=f"level={capped_level} below enforcement threshold (mode={mode})",
        )

    if license_row is None:
        return EnforcementDecision(
            EnforcementAction.WARN,
            reason="license not found; cannot restrict or ban",
        )

    current_status = LicenseStatus(license_row.status)

    # A revoked license is terminal — there is nothing left to escalate.
    if current_status is LicenseStatus.REVOKED:
        return EnforcementDecision(
            action,
            license_status=license_row.status,
            reason="license already revoked",
        )

    if action is EnforcementAction.BAN:
        license_repo.set_status(license_row, LicenseStatus.REVOKED, now=moment)
        license_row.restricted_until = None
        logger.warning(
            "license banned due to security events",
            extra={
                "app_license_id": license_row.id,
                "app_level": capped_level,
                "app_count": active_count,
                "app_mode": mode,
            },
        )
        return EnforcementDecision(
            EnforcementAction.BAN,
            license_status=LicenseStatus.REVOKED.value,
            reason=f"ban threshold reached ({active_count} unresolved events)",
        )

    if action is EnforcementAction.RESTRICT:
        # If the license is already suspended with an active restriction,
        # refresh the expiry window rather than creating a duplicate.
        already_restricted = (
            current_status is LicenseStatus.SUSPENDED
            and license_row.restricted_until is not None
            and license_row.restricted_until > moment
        )
        restriction_expires_at = (
            license_row.restricted_until
            if already_restricted
            else moment + timedelta(hours=settings.ANTI_TAMPER_RESTRICTION_HOURS)
        )

        if not already_restricted:
            license_repo.set_status(license_row, LicenseStatus.SUSPENDED, now=moment)

        license_row.restricted_until = restriction_expires_at
        logger.warning(
            "license restricted due to security events",
            extra={
                "app_license_id": license_row.id,
                "app_level": capped_level,
                "app_count": active_count,
                "app_mode": mode,
            },
        )
        return EnforcementDecision(
            EnforcementAction.RESTRICT,
            restriction_expires_at=restriction_expires_at,
            license_status=LicenseStatus.SUSPENDED.value,
            reason=f"restrict threshold reached ({active_count} unresolved events)",
        )

    # EnforcementAction.WARN — record intent but do not mutate the license.
    return EnforcementDecision(
        EnforcementAction.WARN,
        license_status=license_row.status,
        reason=f"unresolved event count {active_count} below restrict threshold",
    )


__all__ = [
    "EnforcementAction",
    "EnforcementDecision",
    "compute_level",
    "enforcement_status_label",
    "evaluate_and_enforce",
    "get_restriction_expiry",
    "is_currently_restricted",
    "release_expired_restrictions",
]
