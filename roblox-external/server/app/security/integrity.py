"""Client-side file integrity verification utilities.

The client builds a manifest of file hashes (its running binary, loaded
modules, injected libraries) and signs it before sending it to the server.
This module provides the hashing, signing and parsing primitives that both
sides use to agree on what constitutes a tampered file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

HASH_ALGORITHM = "sha256"
HASH_HEX_LENGTH = 64
MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB guard against pathological inputs
MANIFEST_VERSION = 1
MAX_MANIFEST_ENTRIES = 200
MIN_MANIFEST_NONCE_LENGTH = 8

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@dataclass(slots=True)
class FileHash:
    """One file's integrity record."""

    path: str
    algorithm: str
    digest: str
    size: int
    mtime: float

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serialisable view of this record."""
        return asdict(self)


@dataclass(slots=True)
class IntegrityManifest:
    """A signed set of file hashes that the client proves it controls."""

    version: int = MANIFEST_VERSION
    client_build: str = ""
    generated_at: str = ""
    nonce: str = ""
    files: list[FileHash] = field(default_factory=list)
    signature: str = ""


def hash_bytes(data: bytes | str, *, algorithm: str = HASH_ALGORITHM) -> str:
    """Return the hex digest of ``data`` using ``algorithm``.

    Accepts either bytes or str (encoded as UTF-8).
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    hasher = hashlib.new(algorithm)
    hasher.update(raw)
    return hasher.hexdigest()


def hash_file(
    path: str, *, algorithm: str = HASH_ALGORITHM, max_bytes: int = MAX_FILE_BYTES
) -> FileHash:
    """Read ``path`` in chunks and return its :class:`FileHash`.

    Raises :class:`FileNotFoundError` if the file does not exist, and
    :class:`ValueError` if it exceeds ``max_bytes`` (defence in depth against
    memory exhaustion).
    """
    hasher = hashlib.new(algorithm)
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"file at {path} exceeds {max_bytes} bytes")
            hasher.update(chunk)
    mtime = os.path.getmtime(path)
    return FileHash(
        path=path,
        algorithm=algorithm,
        digest=hasher.hexdigest(),
        size=size,
        mtime=mtime,
    )


def build_manifest(
    paths: list[str],
    *,
    client_build: str = "",
    include_missing: bool = False,
    algorithm: str = HASH_ALGORITHM,
) -> IntegrityManifest:
    """Build an :class:`IntegrityManifest` covering every path in ``paths``."""
    files: list[FileHash] = []
    for path in paths:
        try:
            files.append(hash_file(path, algorithm=algorithm))
        except FileNotFoundError:
            if include_missing:
                files.append(
                    FileHash(
                        path=path,
                        algorithm=algorithm,
                        digest="",
                        size=-1,
                        mtime=0.0,
                    )
                )
            continue
        except (OSError, ValueError):
            continue
    return IntegrityManifest(
        version=MANIFEST_VERSION,
        client_build=client_build,
        generated_at=datetime.now(UTC).isoformat(),
        files=files,
    )


def manifest_signing_payload(manifest: IntegrityManifest) -> str:
    """Return the deterministic JSON string covered by the signature.

    Everything that proves *which* files the client was running is covered:
    the client build, the generation timestamp, the single-use nonce, the
    manifest version and each file's path/digest/size.  The signature itself
    is excluded so either side can recompute it over the same payload.
    """
    payload: dict[str, Any] = {
        "client_build": manifest.client_build,
        "files": [
            {"path": record.path, "digest": record.digest, "size": record.size}
            for record in manifest.files
        ],
        "generated_at": manifest.generated_at,
        "nonce": manifest.nonce,
        "version": manifest.version,
    }
    return json.dumps(payload, sort_keys=True)


def sign_manifest(manifest: IntegrityManifest, pepper: str) -> str:
    """Return the hex HMAC-SHA256 of the signing payload under ``pepper``."""
    if not pepper:
        raise ValueError("pepper must not be empty")
    return hmac.new(
        pepper.encode("utf-8"),
        manifest_signing_payload(manifest).encode("utf-8"),
        HASH_ALGORITHM,
    ).hexdigest()


def verify_manifest_signature(manifest: IntegrityManifest, pepper: str) -> bool:
    """Return whether ``manifest.signature`` verifies under ``pepper``.

    The comparison is constant-time.  An empty pepper always fails: a
    deployment without the signing secret must never treat a manifest as
    authentic.
    """
    if not pepper:
        return False
    expected = sign_manifest(manifest, pepper)
    return hmac.compare_digest(expected.encode("utf-8"), manifest.signature.encode("utf-8"))


class ManifestParseError(ValueError):
    """Raised when a client-submitted manifest fails strict validation."""


def _is_hex_digest(digest: str) -> bool:
    """Return whether ``digest`` is a hex string of exactly ``HASH_HEX_LENGTH``."""
    return len(digest) == HASH_HEX_LENGTH and all(char in _HEX_DIGITS for char in digest)


def parse_submitted_manifest(raw: str) -> IntegrityManifest:
    """Strictly parse a client-submitted manifest string.

    Raises :class:`ManifestParseError` when the payload is not a JSON object,
    ``files`` is missing or not a list, there are more than
    ``MAX_MANIFEST_ENTRIES`` entries, an entry lacks ``path``/``digest`` or
    carries a malformed digest, the ``nonce`` is shorter than
    ``MIN_MANIFEST_NONCE_LENGTH`` characters, or the ``signature`` is missing
    or empty.
    """
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ManifestParseError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestParseError("manifest must be a JSON object")

    raw_files = data.get("files")
    if not isinstance(raw_files, list):
        raise ManifestParseError("manifest 'files' must be a list")
    if len(raw_files) > MAX_MANIFEST_ENTRIES:
        raise ManifestParseError(f"manifest carries more than {MAX_MANIFEST_ENTRIES} entries")

    files: list[FileHash] = []
    for index, item in enumerate(raw_files):
        if not isinstance(item, dict):
            raise ManifestParseError(f"file entry {index} must be an object")
        path = item.get("path")
        if not isinstance(path, str) or not path:
            raise ManifestParseError(f"file entry {index} is missing 'path'")
        digest = item.get("digest")
        if not isinstance(digest, str):
            raise ManifestParseError(f"file entry {index} is missing 'digest'")
        if not _is_hex_digest(digest):
            raise ManifestParseError(f"file entry {index} has a malformed digest")

        size = item.get("size", 0)
        if isinstance(size, bool) or not isinstance(size, int):
            size = 0
        algorithm = item.get("algorithm", HASH_ALGORITHM)
        if not isinstance(algorithm, str) or not algorithm:
            algorithm = HASH_ALGORITHM
        mtime = item.get("mtime", 0.0)
        if isinstance(mtime, bool) or not isinstance(mtime, (int, float)):
            mtime = 0.0
        files.append(
            FileHash(
                path=path,
                algorithm=algorithm,
                digest=digest,
                size=size,
                mtime=float(mtime),
            )
        )

    nonce = data.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < MIN_MANIFEST_NONCE_LENGTH:
        raise ManifestParseError(
            f"manifest 'nonce' must be at least {MIN_MANIFEST_NONCE_LENGTH} characters"
        )

    signature = data.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ManifestParseError("manifest is missing a signature")

    version = data.get("version", MANIFEST_VERSION)
    if isinstance(version, bool) or not isinstance(version, int):
        version = MANIFEST_VERSION
    generated_at = data.get("generated_at", "")
    if not isinstance(generated_at, str):
        generated_at = ""
    client_build = data.get("client_build", "")
    if not isinstance(client_build, str):
        client_build = ""

    return IntegrityManifest(
        version=version,
        client_build=client_build,
        generated_at=generated_at,
        nonce=nonce,
        files=files,
        signature=signature,
    )


@dataclass(slots=True)
class IntegrityVerdict:
    """The result of comparing a manifest against expected digests."""

    ok: bool
    mismatches: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)


def verify_against_expected(
    manifest: IntegrityManifest, expected: dict[str, str]
) -> IntegrityVerdict:
    """Compare a manifest against a ``path -> digest`` expectations map.

    ``mismatches`` lists paths whose digest differs, ``missing`` lists
    expected paths absent from the manifest, and ``unexpected`` lists paths
    the manifest reported that the server did not ask about.  Unexpected
    paths are reported but never fail the verdict on their own.
    """
    observed: dict[str, FileHash] = {record.path: record for record in manifest.files}
    mismatches: list[str] = []
    missing: list[str] = []

    for path, digest in expected.items():
        record = observed.get(path)
        if record is None:
            missing.append(path)
        elif record.digest.lower() != digest.lower():
            mismatches.append(path)

    unexpected = [path for path in observed if path not in expected]
    return IntegrityVerdict(
        ok=not mismatches and not missing,
        mismatches=mismatches,
        missing=missing,
        unexpected=unexpected,
    )


def generate_nonce(length: int = 32) -> str:
    """Return a fresh URL-safe single-use nonce."""
    return secrets.token_urlsafe(length)


def iter_file_hashes(manifest: IntegrityManifest) -> Iterator[FileHash]:
    """Yield each file record in a manifest, for incremental scanning."""
    yield from manifest.files


__all__ = [
    "HASH_ALGORITHM",
    "HASH_HEX_LENGTH",
    "MANIFEST_VERSION",
    "MAX_FILE_BYTES",
    "MAX_MANIFEST_ENTRIES",
    "MIN_MANIFEST_NONCE_LENGTH",
    "FileHash",
    "IntegrityManifest",
    "IntegrityVerdict",
    "ManifestParseError",
    "build_manifest",
    "generate_nonce",
    "hash_bytes",
    "hash_file",
    "iter_file_hashes",
    "manifest_signing_payload",
    "parse_submitted_manifest",
    "sign_manifest",
    "verify_against_expected",
    "verify_manifest_signature",
]
