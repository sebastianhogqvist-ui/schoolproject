"""Tests for the client integrity manifest authority."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.security.integrity import FileHash, IntegrityManifest, sign_manifest
from app.services.integrity import (
    NonceStore,
    assess_manifest,
    build_id_allowed,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_file_hash(
    path: str = "client.dll", digest: str | None = None
) -> FileHash:
    return FileHash(
        path=path,
        algorithm="sha256",
        digest=digest or "a" * 64,
        size=4096,
        mtime=1700000000.0,
    )


def _serialize_manifest(manifest: IntegrityManifest) -> str:
    return json.dumps(
        {
            "version": manifest.version,
            "client_build": manifest.client_build,
            "generated_at": manifest.generated_at,
            "nonce": manifest.nonce,
            "files": [f.to_dict() for f in manifest.files],
            "signature": manifest.signature,
        }
    )


def _build_signed_manifest(
    *,
    nonce: str,
    generated_at: str,
    client_build: str = "1.0.0",
    files: list[FileHash] | None = None,
    pepper: str,
    signature: str | None = None,
) -> str:
    manifest = IntegrityManifest(
        version=1,
        client_build=client_build,
        generated_at=generated_at,
        nonce=nonce,
        files=files or [_make_file_hash()],
    )
    if signature is None:
        signature = sign_manifest(manifest, pepper)
    manifest.signature = signature
    return _serialize_manifest(manifest)


# ---------------------------------------------------------------------------
# Nonce issuance & consumption
# ---------------------------------------------------------------------------

def test_nonce_issue_and_consume(settings: Settings) -> None:
    store = NonceStore()
    tt = settings.ANTI_TAMPER_NONCE_TTL_SECONDS

    record = store.issue(ttl_seconds=tt)
    assert record.nonce
    assert len(record.nonce) >= 8
    assert record.expires_at > record.issued_at

    consumed = store.consume(record.nonce)
    assert consumed is not None
    assert consumed.nonce == record.nonce
    assert store.bucket_count() == 0


def test_nonce_consume_twice_fails(settings: Settings) -> None:
    store = NonceStore()
    record = store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )

    assert store.consume(record.nonce) is not None
    assert store.consume(record.nonce) is None


def test_nonce_expired_rejected(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    record = store.issue(ttl_seconds=60, now=now)

    result = store.consume(
        record.nonce, now=now + timedelta(seconds=120)
    )
    assert result is None


# ---------------------------------------------------------------------------
# Build-id enforcement
# ---------------------------------------------------------------------------

def test_build_id_allowed_newer(settings: Settings) -> None:
    assert build_id_allowed("2.0.0", settings) is True


def test_build_id_allowed_exact_min(settings: Settings) -> None:
    assert build_id_allowed("1.0.0", settings) is True


def test_build_id_allowed_older(settings: Settings) -> None:
    assert build_id_allowed("0.9.0", settings) is False


# ---------------------------------------------------------------------------
# Manifest assessment
# ---------------------------------------------------------------------------

def test_assess_valid_manifest_no_expectations(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    pepper = settings.LICENSE_KEY_PEPPER.get_secret_value()

    record = store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )
    raw = _build_signed_manifest(
        nonce=record.nonce,
        generated_at=now.isoformat(),
        pepper=pepper,
    )

    result = assess_manifest(
        raw_manifest=raw,
        nonce=record.nonce,
        client_build="1.0.0",
        settings=settings,
        pepper=pepper,
        store=store,
        now=now,
    )

    assert result.accepted is True
    assert result.level == 0
    assert result.rule == "OK"


def test_assess_bad_signature_level3(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    pepper = settings.LICENSE_KEY_PEPPER.get_secret_value()

    record = store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )
    raw = _build_signed_manifest(
        nonce=record.nonce,
        generated_at=now.isoformat(),
        pepper=pepper,
        signature="0" * 64,
    )

    result = assess_manifest(
        raw_manifest=raw,
        nonce=record.nonce,
        client_build="1.0.0",
        settings=settings,
        pepper=pepper,
        store=store,
        now=now,
    )

    assert result.accepted is False
    assert result.level == 3
    assert result.rule == "MANIFEST_SIGNATURE_INVALID"


def test_assess_unknown_nonce_rejected(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    pepper = settings.LICENSE_KEY_PEPPER.get_secret_value()

    fake_nonce = "x" * 32
    raw = _build_signed_manifest(
        nonce=fake_nonce,
        generated_at=now.isoformat(),
        pepper=pepper,
    )

    result = assess_manifest(
        raw_manifest=raw,
        nonce=fake_nonce,
        client_build="1.0.0",
        settings=settings,
        pepper=pepper,
        store=store,
        now=now,
    )

    assert result.accepted is False
    assert result.level == 2
    assert result.rule == "NONCE_INVALID"


def test_assess_stale_timestamp(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    pepper = settings.LICENSE_KEY_PEPPER.get_secret_value()

    record = store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )
    stale_at = now - timedelta(seconds=300)
    raw = _build_signed_manifest(
        nonce=record.nonce,
        generated_at=stale_at.isoformat(),
        pepper=pepper,
    )

    result = assess_manifest(
        raw_manifest=raw,
        nonce=record.nonce,
        client_build="1.0.0",
        settings=settings,
        pepper=pepper,
        store=store,
        now=now,
    )

    assert result.accepted is False
    assert result.level == 2
    assert result.rule == "MANIFEST_STALE"


def test_assess_digest_mismatch(settings: Settings) -> None:
    store = NonceStore()
    now = datetime.now(UTC)
    pepper = settings.LICENSE_KEY_PEPPER.get_secret_value()

    record = store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )
    raw = _build_signed_manifest(
        nonce=record.nonce,
        generated_at=now.isoformat(),
        files=[_make_file_hash(digest="a" * 64)],
        pepper=pepper,
    )

    result = assess_manifest(
        raw_manifest=raw,
        nonce=record.nonce,
        client_build="1.0.0",
        settings=settings,
        pepper=pepper,
        store=store,
        now=now,
        expected_hashes={"client.dll": "b" * 64},
    )

    assert result.accepted is False
    assert result.level == 2
    assert result.rule == "FILE_DIGEST_MISMATCH"
    assert "client.dll" in result.mismatches
