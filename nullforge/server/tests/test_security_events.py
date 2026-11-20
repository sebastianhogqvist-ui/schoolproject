"""Tests for security event recording and enforcement status."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import Settings
from app.keys import generate_license_key, hash_license_key, normalize_license_key
from app.models import License
from app.repositories import licenses as license_repo
from app.services import license as license_svc
from app.services import security_events as security_events_svc


def _create_activated_license(db: Session, settings: Settings) -> int:
    """Create and activate a license, returning its id."""
    raw_key = generate_license_key()
    canonical = normalize_license_key(raw_key)
    key_hash = hash_license_key(settings.license_key_pepper, canonical)
    row: License = license_repo.add_license(db, key_hash=key_hash)
    db.commit()
    db.refresh(row)
    activation = license_svc.activate(
        db,
        raw_key=raw_key,
        client_hwid="test-hwid-value-12345",
        ip="127.0.0.1",
        user_agent="TestClient/1.0",
        settings=settings,
    )
    return activation.license_id


def test_record_event_monitor_mode(db: Session, settings: Settings) -> None:
    license_id = _create_activated_license(db, settings)

    result = security_events_svc.record_event(
        db,
        settings=settings,
        license_id=license_id,
        level=2,
        category="MANIFEST",
        rule="MANIFEST_SIGNATURE_INVALID",
        reason="tamper detected in monitor mode",
        ip="127.0.0.1",
        user_agent="TestClient/1.0",
    )

    assert result.action_taken == "NONE"


def test_record_event_enforce_mode_restrict(db: Session, settings: Settings) -> None:
    settings.ANTI_TAMPER_ENFORCEMENT_MODE = "enforce"
    settings.ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD = 1
    settings.ANTI_TAMPER_BAN_THRESHOLD = 5

    license_id = _create_activated_license(db, settings)

    result = security_events_svc.record_event(
        db,
        settings=settings,
        license_id=license_id,
        level=2,
        category="MANIFEST",
        rule="MANIFEST_SIGNATURE_INVALID",
        reason="tamper detected in enforce mode",
        ip="127.0.0.1",
        user_agent="TestClient/1.0",
    )

    assert result.action_taken == "RESTRICT"
    assert result.license_status == "SUSPENDED"
    assert result.restriction_expires_at is not None


def test_get_enforcement_status(db: Session, settings: Settings) -> None:
    license_id = _create_activated_license(db, settings)

    status = security_events_svc.get_enforcement_status(
        db,
        settings,
        license_id=license_id,
    )

    assert status.level == 0
    assert status.status == "OK"
    assert status.event_count == 0
    assert status.active_count == 0
    assert status.license_status == "ACTIVE"
    assert status.restriction_expires_at is None
    assert status.last_event_at is None
