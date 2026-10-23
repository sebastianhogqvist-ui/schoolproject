"""Shared test fixtures for NULLFORGE server tests."""
from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_JWT_SECRET = "test-jwt-secret-key-min-32-chars-long!!"  # noqa: S105
TEST_KEY_PEPPER = "test-license-key-pepper-value"
TEST_HWID_PEPPER = "test-hwid-pepper-value"
TEST_INTEGRITY_PEPPER = "test-integrity-pepper-value"

os.environ.setdefault("LICENSE_JWT_SECRET", TEST_JWT_SECRET)
os.environ.setdefault("LICENSE_KEY_PEPPER", TEST_KEY_PEPPER)
os.environ.setdefault("HWID_PEPPER", TEST_HWID_PEPPER)
os.environ.setdefault("INTEGRITY_PEPPER", TEST_INTEGRITY_PEPPER)

from app.config import Settings, get_settings  # noqa: E402
from app.db import Base, SessionLocal, configure_database  # noqa: E402
from app.db import engine as _real_engine  # noqa: E402
from app.keys import generate_license_key, hash_license_key, normalize_license_key  # noqa: E402
from app.repositories import licenses as license_repo  # noqa: E402
from app.services.integrity import nonce_store  # noqa: E402


def _make_test_settings(**overrides: object) -> Settings:
    env: dict[str, Any] = {
        "DATABASE_URL": "sqlite:///:memory:",
        "LICENSE_JWT_SECRET": TEST_JWT_SECRET,
        "JWT_ALGORITHM": "HS256",
        "JWT_ISSUER": "test-issuer",
        "JWT_AUDIENCE": "test-audience",
        "LICENSE_KEY_PEPPER": TEST_KEY_PEPPER,
        "HWID_PEPPER": TEST_HWID_PEPPER,
        "INTEGRITY_PEPPER": TEST_INTEGRITY_PEPPER,
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": None,
        "RATE_LIMIT_ENABLED": False,
        "ANTI_TAMPER_ENABLED": True,
        "ANTI_TAMPER_ENFORCEMENT_MODE": "monitor",
        "ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD": 5,
        "ANTI_TAMPER_BAN_THRESHOLD": 10,
        "ANTI_TAMPER_RESTRICTION_HOURS": 24,
        "ANTI_TAMPER_RETENTION_DAYS": 30,
        "ANTI_TAMPER_MIN_CLIENT_BUILD": "1.0.0",
        "ANTI_TAMPER_REQUIRE_CLIENT_BUILD": False,
        "ANTI_TAMPER_NONCE_TTL_SECONDS": 300,
        "ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS": 120,
        "RATE_LIMIT_KEYAUTH_PER_MINUTE": 1000,
        "RATE_LIMIT_SECURITY_EVENT_PER_MINUTE": 1000,
        "RATE_LIMIT_INTEGRITY_PER_MINUTE": 1000,
        "KEYAUTH_OWNER_ID": "test-owner-id",
        "KEYAUTH_APP_SECRET": "test-app-secret-for-keyauth",
        "KEYAUTH_APP_NAME": "test-app-name",
        "CORS_ALLOWED_ORIGINS": "",
        "MAINTENANCE_MODE": False,
        "LOG_LEVEL": "WARNING",
        "MAX_REQUEST_BODY_BYTES": 16384,
        "SERVER_HOST": "127.0.0.1",
        "SERVER_PORT": 8080,
    }
    env.update(overrides)
    get_settings.cache_clear()
    return Settings(**env)


@pytest.fixture
def settings() -> Settings:
    return _make_test_settings()


@pytest.fixture
def db(settings: Settings) -> Iterator[Session]:
    configure_database(settings.DATABASE_URL)
    Base.metadata.create_all(_real_engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(_real_engine)


@pytest.fixture
def client(db: Session, settings: Settings) -> Iterator[TestClient]:
    from app.db import get_db
    from app.deps import settings_dep
    from app.main import create_app
    app = create_app(settings=settings)
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[settings_dep] = lambda: settings
    with TestClient(app) as c:
        yield c


@pytest.fixture
def license_key(db: Session, settings: Settings) -> str:
    raw_key = generate_license_key()
    canonical = normalize_license_key(raw_key)
    key_hash = hash_license_key(settings.license_key_pepper, canonical)
    row = license_repo.add_license(db, key_hash=key_hash)
    db.commit()
    db.refresh(row)
    return raw_key


@pytest.fixture
def auth_token(db: Session, settings: Settings, license_key: str) -> tuple[str, int]:
    from app.services import license as license_svc
    result = license_svc.activate(
        db,
        raw_key=license_key,
        client_hwid="test-hwid-value-12345",
        ip="127.0.0.1",
        user_agent="TestClient/1.0",
        settings=settings,
    )
    return result.session_token, result.license_id


@pytest.fixture(autouse=True)
def reset_nonce_store() -> Iterator[None]:
    nonce_store.reset()
    yield
    nonce_store.reset()
