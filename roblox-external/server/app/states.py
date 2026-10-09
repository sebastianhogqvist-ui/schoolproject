"""License lifecycle state machine.

The persisted ``licenses.status`` column is the *declared* state. The state a
request should actually be judged against is :func:`effective_status`, which
folds in the ``expires_at`` timestamp without needing a background job to flip
rows to ``EXPIRED``.
"""

from datetime import UTC, datetime
from enum import StrEnum


class LicenseStatus(StrEnum):
    """Declared lifecycle state of a license."""

    UNACTIVATED = "UNACTIVATED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


ALLOWED_TRANSITIONS: dict[LicenseStatus, frozenset[LicenseStatus]] = {
    LicenseStatus.UNACTIVATED: frozenset({LicenseStatus.ACTIVE, LicenseStatus.REVOKED}),
    LicenseStatus.ACTIVE: frozenset(
        {LicenseStatus.SUSPENDED, LicenseStatus.REVOKED, LicenseStatus.EXPIRED}
    ),
    LicenseStatus.SUSPENDED: frozenset(
        {LicenseStatus.ACTIVE, LicenseStatus.REVOKED, LicenseStatus.EXPIRED}
    ),
    LicenseStatus.REVOKED: frozenset(),
    LicenseStatus.EXPIRED: frozenset(),
}

TERMINAL_STATUSES: frozenset[LicenseStatus] = frozenset(
    {LicenseStatus.REVOKED, LicenseStatus.EXPIRED}
)


class InvalidTransitionError(ValueError):
    """Raised when a requested lifecycle transition is not permitted."""

    def __init__(self, current: LicenseStatus, target: LicenseStatus) -> None:
        self.current = current
        self.target = target
        super().__init__(f"cannot transition from {current.value} to {target.value}")


def _as_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC so SQLite round-trips stay comparable."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def can_transition(current: LicenseStatus | str, target: LicenseStatus | str) -> bool:
    """Return whether ``current -> target`` is a permitted transition."""
    return LicenseStatus(target) in ALLOWED_TRANSITIONS[LicenseStatus(current)]


def assert_transition(current: LicenseStatus | str, target: LicenseStatus | str) -> None:
    """Raise :class:`InvalidTransitionError` unless the transition is permitted."""
    if not can_transition(current, target):
        raise InvalidTransitionError(LicenseStatus(current), LicenseStatus(target))


def is_expired(expires_at: datetime | None, now: datetime | None = None) -> bool:
    """Return whether ``expires_at`` is a non-null instant already in the past."""
    if expires_at is None:
        return False
    moment = _as_utc(now) if now is not None else datetime.now(UTC)
    return _as_utc(expires_at) <= moment


def effective_status(
    status: LicenseStatus | str,
    expires_at: datetime | None,
    now: datetime | None = None,
) -> LicenseStatus:
    """Resolve the status a request must be judged against.

    Precedence is REVOKED, then SUSPENDED, then EXPIRED, then the declared
    status, so a revoked license never reads as merely expired.
    """
    current = LicenseStatus(status)
    if current is LicenseStatus.REVOKED:
        return current
    if current is LicenseStatus.SUSPENDED:
        return current
    if is_expired(expires_at, now):
        return LicenseStatus.EXPIRED
    return current
