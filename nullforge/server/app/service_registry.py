"""File-backed service port registration and discovery.

Services register their bound host and port in a JSON file so the gateway and
other backends can locate them at runtime. Writes are atomic (temp file plus
``os.replace``) and the runtime directory is created on demand. File locking
prevents race conditions when multiple services start simultaneously.
"""

from __future__ import annotations

import json
import logging
import os
import fcntl
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("app.service_registry")

DEFAULT_REGISTRY_PATH = "runtime/services.json"


@dataclass
class ServiceInfo:
    """Describes a single registered backend service."""

    name: str
    host: str
    port: int
    registered_at: str
    ttl_seconds: int

    @property
    def expired(self) -> bool:
        """Whether the registration's TTL has elapsed without a heartbeat."""
        registered = datetime.fromisoformat(self.registered_at)
        return (datetime.now(UTC) - registered).total_seconds() > self.ttl_seconds


class ServiceRegistry:
    """Persist service locations to a JSON registry file with file locking."""

    def __init__(self, path: str = DEFAULT_REGISTRY_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read_all(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                # Shared lock for reading
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(fh)
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("registry file unreadable (%s): %s", self.path, exc)
            return {}
        return data if isinstance(data, dict) else {}

    def _write_all(self, data: dict[str, dict[str, Any]]) -> None:
        # Write to temp file then atomically replace
        tmp = self.path.with_name(self.path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            # Exclusive lock for writing
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        os.replace(tmp, self.path)

    def _read_write_locked(self) -> tuple[dict[str, dict[str, Any]], int]:
        """Open registry with exclusive lock for read-modify-write operations.

        Returns (data, file_descriptor). Caller must close the fd.
        """
        # Ensure file exists
        self.path.touch(exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(fd, "r+", encoding="utf-8") as fh:
                try:
                    data = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    data = {}
                return data if isinstance(data, dict) else {}, fd
        except Exception:
            os.close(fd)
            raise

    def _commit_locked(self, fd: int, data: dict[str, dict[str, Any]]) -> None:
        """Write data and release lock."""
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            fh.seek(0)
            fh.truncate()
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        # Lock released on fd close

    def register(
        self, name: str, host: str, port: int, ttl_seconds: int
    ) -> ServiceInfo:
        """Write (or overwrite) service info to the registry."""
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        info = ServiceInfo(
            name=name,
            host=host,
            port=port,
            registered_at=now,
            ttl_seconds=ttl_seconds,
        )
        data, fd = self._read_write_locked()
        try:
            data[name] = asdict(info)
            self._commit_locked(fd, data)
        except Exception:
            os.close(fd)
            raise
        logger.info("registered service %s at %s:%d", name, host, port)
        return info

    def discover(self, name: str) -> ServiceInfo | None:
        """Return the registered service info, or None if missing/expired."""
        self.cleanup_expired()
        data = self._read_all()
        raw = data.get(name)
        if not raw:
            return None
        try:
            info = ServiceInfo(**raw)
        except TypeError:
            return None
        if info.expired:
            return None
        return info

    def list_all(self) -> dict[str, ServiceInfo]:
        """List all non-expired registered services."""
        data = self._read_all()
        result: dict[str, ServiceInfo] = {}
        for name, raw in data.items():
            try:
                info = ServiceInfo(**raw)
            except TypeError:
                continue
            if not info.expired:
                result[name] = info
        return result

    def heartbeat(self, name: str) -> bool:
        """Refresh the ``registered_at`` timestamp for a service.

        Returns ``True`` if the service existed and was refreshed.
        """
        data, fd = self._read_write_locked()
        try:
            raw = data.get(name)
            if not raw:
                os.close(fd)
                return False
            try:
                info = ServiceInfo(**raw)
            except TypeError:
                os.close(fd)
                return False
            info.registered_at = datetime.now(UTC).replace(microsecond=0).isoformat()
            data[name] = asdict(info)
            self._commit_locked(fd, data)
        except Exception:
            os.close(fd)
            raise
        return True

    def cleanup_expired(self) -> int:
        """Remove expired registrations. Returns the number removed."""
        data, fd = self._read_write_locked()
        try:
            remaining: dict[str, dict[str, Any]] = {}
            removed = 0
            for name, raw in data.items():
                try:
                    info = ServiceInfo(**raw)
                except TypeError:
                    removed += 1
                    continue
                if info.expired:
                    removed += 1
                    continue
                remaining[name] = raw
            if removed:
                self._commit_locked(fd, remaining)
                logger.info("cleaned up %d expired registry entries", removed)
            else:
                os.close(fd)
            return removed
        except Exception:
            os.close(fd)
            raise
