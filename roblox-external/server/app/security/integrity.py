"""Client-side file integrity verification utilities.

The client builds a manifest of file hashes (its running binary, loaded
modules, injected libraries) and signs it before sending it to the server.
This module provides the hashing and manifest construction primitives that
both sides use to agree on what constitutes a tampered file.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

HASH_ALGORITHM = "sha256"
HASH_HEX_LENGTH = 64
MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB guard against pathological inputs
MANIFEST_VERSION = 1


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
    generated_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds") + "Z"
    )
    client_id: str = ""
    files: list[FileHash] = field(default_factory=list)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serialisable view of this manifest."""
        return asdict(self)


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
            hasher.update(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"file at {path} exceeds {max_bytes} bytes")
    import os

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
    client_id: str = "",
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
        client_id=client_id,
        files=files,
    )


def serialize_manifest(manifest: IntegrityManifest) -> str:
    """Serialise a manifest to canonical JSON (sorted keys, no trailing newline)."""
    return json.dumps(manifest.to_dict(), sort_keys=True, ensure_ascii=False)


def parse_manifest(raw: str) -> IntegrityManifest:
    """Parse a canonical-JSON manifest string back into an :class:`IntegrityManifest`."""
    data = json.loads(raw)
    files = [
        FileHash(
            path=item["path"],
            algorithm=item["algorithm"],
            digest=item["digest"],
            size=item["size"],
            mtime=item["mtime"],
        )
        for item in data.get("files", [])
    ]
    return IntegrityManifest(
        version=data.get("version", MANIFEST_VERSION),
        generated_at=data.get("generated_at", ""),
        client_id=data.get("client_id", ""),
        files=files,
        signature=data.get("signature", ""),
    )


def verify_manifest(
    manifest: IntegrityManifest,
    expected: dict[str, str],
    *,
    ignore_mtime: bool = True,
) -> tuple[bool, list[str]]:
    """Check every file hash in ``manifest`` against the ``expected`` map.

    ``expected`` maps *path* -> *digest*.  Returns ``(ok, mismatches)`` where
    ``mismatches`` lists the paths whose digest differs (or is empty when the
    file is missing from the manifest entirely).
    """
    observed: dict[str, FileHash] = {f.path: f for f in manifest.files}
    mismatches: list[str] = []

    for path, digest in expected.items():
        if path not in observed:
            mismatches.append(path)
            continue
        record = observed[path]
        if record.digest != digest:
            mismatches.append(path)

    if not ignore_mtime:
        for path, record in observed.items():
            if record.size < 0 and expected.get(path):
                mismatches.append(path)

    return (len(mismatches) == 0, mismatches)


def iter_file_hashes(manifest: IntegrityManifest) -> Iterator[FileHash]:
    """Yield each file record in a manifest, for incremental scanning."""
    yield from manifest.files


__all__ = [
    "HASH_ALGORITHM",
    "HASH_HEX_LENGTH",
    "MANIFEST_VERSION",
    "MAX_FILE_BYTES",
    "FileHash",
    "IntegrityManifest",
    "build_manifest",
    "hash_bytes",
    "hash_file",
    "iter_file_hashes",
    "parse_manifest",
    "serialize_manifest",
    "verify_manifest",
]
