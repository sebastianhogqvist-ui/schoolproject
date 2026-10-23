"""Client integrity manifest authority.

The server issues single-use nonces, verifies manifest signatures, enforces the
client build version, and compares reported file hashes against expected
baselines.  When no expected-hash baseline is loaded the server runs in
*monitoring* mode: a passing manifest is accepted at level 0, an unsigned or
badly-signed manifest is treated as suspicious, but the absence of expectations
never by himself confirms tampering at level 3.

Absence of expected hashes -> MONITORING (level 1), never confirmed tamper (level 3).
A digest mismatch alone = level 2 (suspicious).  A bad signature = level 3
(confirmed tamper).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import Settings
from app.logging_config import get_logger
from app.security.integrity import (
    IntegrityVerdict,
    ManifestParseError,
    generate_nonce,
    parse_submitted_manifest,
    verify_against_expected,
    verify_manifest_signature,
)

logger = get_logger("integrity")
EXPECTATION_FILE_ENV = "NULLFORGE_EXPECTED_HASHES"


@dataclass(frozen=True, slots=True)
class NonceRecord:
    """A server-issued nonce and its validity window."""
    nonce: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IntegrityAssessment:
    """The server's verdict on a submitted manifest."""
    accepted: bool
    level: int
    rule: str
    reason: str
    mismatches: list[str]
    missing: list[str]
    build_ok: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "level": self.level,
            "rule": self.rule,
            "reason": self.reason,
            "mismatches": self.mismatches,
            "missing": self.missing,
            "build_ok": self.build_ok,
        }


class NonceStore:
    """Thread-safe single-use, expiring nonce store."""

    def __init__(self) -> None:
        self._store: dict[str, NonceRecord] = {}
        self._lock = threading.Lock()

    def issue(self, *, ttl_seconds: int = 300, now: datetime | None = None) -> NonceRecord:
        now = now or datetime.now(UTC)
        nonce = generate_nonce(32)
        record = NonceRecord(
            nonce=nonce,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._store[nonce] = record
        return record

    def consume(self, nonce: str, *, now: datetime | None = None) -> NonceRecord | None:
        now = now or datetime.now(UTC)
        with self._lock:
            record = self._store.get(nonce)
            if record is None:
                return None
            del self._store[nonce]
            if now > record.expires_at:
                return None
            return record

    def reset(self) -> None:
        with self._lock:
            self._store.clear()

    def bucket_count(self) -> int:
        with self._lock:
            return len(self._store)


nonce_store = NonceStore()


def build_id_allowed(client_build: str, settings: Settings) -> bool:
    """Return whether *client_build* meets or exceeds the minimum enforced build.

    Comparison is component-wise numeric (so ``1.0.10 >= 1.0.9``); when the
    values are not purely numeric the function falls back to string comparison.
    """
    minimum = settings.ANTI_TAMPER_MIN_CLIENT_BUILD.strip()
    try:
        def to_tuple(v: str) -> tuple[int, ...]:
            parts: list[int] = []
            for p in v.split("."):
                p = p.strip()
                if p.isdigit():
                    parts.append(int(p))
                else:
                    parts.append(0)
            return tuple(parts)
        return to_tuple(client_build) >= to_tuple(minimum)
    except (ValueError, TypeError):
        return client_build >= minimum


def load_expected_hashes(settings: Settings) -> dict[str, str]:
    """Load the expected file-hash map from the JSON file named by env var.

    Returns an empty dict when the env var is unset or the file is missing /
    unreadable.  No exception is ever raised to the caller.
    """
    env_path = os.environ.get(EXPECTATION_FILE_ENV, "")
    if not env_path:
        return {}
    try:
        with open(env_path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
        return {}
    except (OSError, ValueError, json.JSONDecodeError):
        logger.warning("expected hashes file %s could not be loaded", env_path)
        return {}


def assess_manifest(
    *,
    raw_manifest: str,
    nonce: str,
    client_build: str,
    settings: Settings,
    pepper: str | None = None,
    store: NonceStore,
    now: datetime | None = None,
    expected_hashes: dict[str, str] | None = None,
) -> IntegrityAssessment:
    """Verify a submitted manifest against nonce, signature, build, and hashes.

    Checks are applied in order and fail closed.  The first failure produces the
    verdict; only a manifest that passes every check is ``accepted`` at level 0.
    """
    if pepper is None:
        pepper = settings.integrity_pepper
    now = now or datetime.now(UTC)
    expected = expected_hashes if expected_hashes is not None else load_expected_hashes(settings)

    # Step 1: nonce must be single-use and valid
    if not nonce or len(nonce) < 8:
        return IntegrityAssessment(
            accepted=False, level=2, rule="NONCE_INVALID",
            reason="nonce is missing or too short", mismatches=[], missing=[], build_ok=False,
        )
    record = store.consume(nonce, now=now)
    if record is None:
        return IntegrityAssessment(
            accepted=False, level=2, rule="NONCE_INVALID",
            reason="nonce is unknown, already used, or expired",
            mismatches=[], missing=[], build_ok=False,
        )

    # Step 2: parse manifest
    try:
        manifest = parse_submitted_manifest(raw_manifest)
    except ManifestParseError as e:
        return IntegrityAssessment(
            accepted=False, level=2, rule="MANIFEST_MALFORMED",
            reason=str(e), mismatches=[], missing=[], build_ok=False,
        )

    # Step 3: signature presence
    if not manifest.signature:
        return IntegrityAssessment(
            accepted=False, level=2, rule="MANIFEST_UNSIGNED",
            reason="signature is empty", mismatches=[], missing=[], build_ok=False,
        )

    # Step 4: signature verification (bad signature = level 3)
    if not verify_manifest_signature(manifest, pepper):
        return IntegrityAssessment(
            accepted=False, level=3, rule="MANIFEST_SIGNATURE_INVALID",
            reason="manifest signature does not verify", mismatches=[], missing=[], build_ok=True,
        )

    # Step 5: build enforcement
    build_ok = build_id_allowed(client_build, settings)
    if settings.ANTI_TAMPER_REQUIRE_CLIENT_BUILD and not build_ok:
        return IntegrityAssessment(
            accepted=False, level=3, rule="BUILD_TOO_OLD",
            reason=(
                f"client build {client_build} is below minimum "
                f"{settings.ANTI_TAMPER_MIN_CLIENT_BUILD}"
            ),
            mismatches=[], missing=[], build_ok=False,
        )

    # Step 6: manifest client_build must match request client_build
    if manifest.client_build and manifest.client_build != client_build:
        return IntegrityAssessment(
            accepted=False, level=2, rule="BUILD_MISMATCH",
            reason="manifest client_build does not match request client_build",
            mismatches=[], missing=[], build_ok=build_ok,
        )

    # Step 7: timestamp freshness
    try:
        gen_time_str = manifest.generated_at.rstrip("Z")
        gen_time = datetime.fromisoformat(gen_time_str).replace(tzinfo=UTC)
        skew = abs((now - gen_time).total_seconds())
        if skew > settings.ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS:
            return IntegrityAssessment(
                accepted=False, level=2, rule="MANIFEST_STALE",
                reason=(
                    f"manifest is {int(skew)}s old, max skew "
                    f"{settings.ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS}s"
                ),
                mismatches=[], missing=[], build_ok=build_ok,
            )
    except (ValueError, AttributeError):
        return IntegrityAssessment(
            accepted=False, level=2, rule="MANIFEST_STALE",
            reason="could not parse generated_at timestamp",
            mismatches=[], missing=[], build_ok=build_ok,
        )

    # Step 8: digest comparison
    verdict: IntegrityVerdict = verify_against_expected(manifest, expected)

    if verdict.mismatches:
        return IntegrityAssessment(
            accepted=False, level=2, rule="FILE_DIGEST_MISMATCH",
            reason="one or more file hashes do not match expected values",
            mismatches=verdict.mismatches, missing=verdict.missing, build_ok=build_ok,
        )

    if verdict.missing:
        return IntegrityAssessment(
            accepted=False, level=2, rule="FILE_MISSING",
            reason="one or more expected files are not present in manifest",
            mismatches=[], missing=verdict.missing, build_ok=build_ok,
        )

    return IntegrityAssessment(
        accepted=True, level=0, rule="OK",
        reason="manifest verified successfully",
        mismatches=[], missing=[], build_ok=build_ok,
    )


__all__ = [
    "EXPECTATION_FILE_ENV",
    "IntegrityAssessment",
    "NonceRecord",
    "NonceStore",
    "assess_manifest",
    "build_id_allowed",
    "load_expected_hashes",
    "nonce_store",
]
