"""File-backed service port registration and discovery.

Services register their bound host and port in a JSON file so the gateway and
other backends can locate them at runtime. Writes are atomic (temp file plus
``os.replace``) and the runtime directory is created on demand. File locking
prevents race conditions when multiple services start simultaneously.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
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
        delta = datetime.now(UTC) - registered
        elapsed_seconds = delta.total_seconds()
        result = elapsed_seconds > self.ttl_seconds
        return result


class ServiceRegistry:
    """Persist service locations to a JSON registry file with file locking."""

    def __init__(self, path: str = DEFAULT_REGISTRY_PATH) -> None:
        self.path = Path(path)
        parent_dir = self.path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    def _read_all(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}

        try:
            with self.path.open("r", encoding="utf-8") as file_handle:
                # Acquire a shared lock for reading.
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(file_handle)
                finally:
                    fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "registry file unreadable (%s): %s",
                self.path,
                exc,
            )
            return {}

        if isinstance(data, dict):
            return data

        return {}

    def _write_all(self, data: dict[str, dict[str, Any]]) -> None:
        # Build temp file path.
        tmp = self.path.with_name(self.path.name + ".tmp")

        with tmp.open("w", encoding="utf-8") as file_handle:
            # Acquire an exclusive lock for writing.
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(data, file_handle, indent=2, sort_keys=True)
                file_handle.write("\n")
                file_handle.flush()
                os.fsync(file_handle.fileno())
            finally:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)

        # Atomically replace the registry file.
        os.replace(tmp, self.path)

    def _read_write_locked(
        self,
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """Open registry with exclusive lock for read-modify-write operations.

        Returns (data, file_descriptor). Caller must close the fd.
        """
        # Ensure the registry file exists on disk.
        self.path.touch(exist_ok=True)

        fd = os.open(self.path, os.O_RDWR | os.O_CREAT)

        try:
            fcntl.flock(fd, fcntl.LOCK_EX)

            with os.fdopen(fd, "r+", encoding="utf-8") as file_handle:
                try:
                    data = json.load(file_handle)
                except (json.JSONDecodeError, OSError):
                    data = {}

                if isinstance(data, dict):
                    parsed = data
                else:
                    parsed = {}

                return parsed, fd
        except Exception:
            os.close(fd)
            raise

    def _commit_locked(
        self,
        fd: int,
        data: dict[str, dict[str, Any]],
    ) -> None:
        """Write data and release lock."""
        with os.fdopen(fd, "r+", encoding="utf-8") as file_handle:
            file_handle.seek(0)
            file_handle.truncate()
            json.dump(data, file_handle, indent=2, sort_keys=True)
            file_handle.write("\n")
            file_handle.flush()
            os.fsync(file_handle.fileno())
        # Lock released on fd close.

    # ------------------------------------------------------------------ #
    # register helpers
    # ------------------------------------------------------------------ #
    def _build_service_info(
        self,
        name: str,
        host: str,
        port: int,
        ttl_seconds: int,
    ) -> ServiceInfo:
        """Build a ServiceInfo instance from registration parameters."""
        now = datetime.now(UTC).replace(microsecond=0).isoformat()

        info = ServiceInfo(
            name=name,
            host=host,
            port=port,
            registered_at=now,
            ttl_seconds=ttl_seconds,
        )

        return info

    def _acquire_lock_for_register(self) -> tuple[dict[str, dict[str, Any]], int]:
        """Acquire exclusive lock and read current registry data."""
        data, fd = self._read_write_locked()
        return data, fd

    def _read_data_for_register(
        self,
        data: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """Return the read data unchanged for register flow."""
        return data

    def _update_dict_for_register(
        self,
        data: dict[str, dict[str, Any]],
        info: ServiceInfo,
    ) -> dict[str, dict[str, Any]]:
        """Insert the service info into the data dictionary."""
        serialised = asdict(info)
        data[info.name] = serialised
        return data

    def _commit_data_for_register(
        self,
        fd: int,
        data: dict[str, dict[str, Any]],
    ) -> None:
        """Commit the updated data and release the lock."""
        self._commit_locked(fd, data)

    def _handle_error_for_register(self, fd: int) -> None:
        """Close the file descriptor on error."""
        os.close(fd)

    def _return_info_for_register(self, info: ServiceInfo) -> ServiceInfo:
        """Return the registered ServiceInfo."""
        return info

    def register(
        self,
        name: str,
        host: str,
        port: int,
        ttl_seconds: int,
    ) -> ServiceInfo:
        """Write (or overwrite) service info to the registry."""
        # Build the service info object.
        info = self._build_service_info(
            name=name,
            host=host,
            port=port,
            ttl_seconds=ttl_seconds,
        )

        # Acquire lock and read current data.
        data, fd = self._acquire_lock_for_register()

        try:
            # Read the data (pass-through).
            data = self._read_data_for_register(data)

            # Update the dictionary with the new entry.
            data = self._update_dict_for_register(data, info)

            # Commit the changes.
            self._commit_data_for_register(fd, data)
        except Exception:
            # Handle any error by closing the fd.
            self._handle_error_for_register(fd)
            raise

        # Log the registration.
        logger.info(
            "registered service %s at %s:%d",
            name,
            host,
            port,
        )

        # Return the info.
        result = self._return_info_for_register(info)
        return result

    # ------------------------------------------------------------------ #
    # discover helpers
    # ------------------------------------------------------------------ #
    def _run_cleanup_for_discover(self) -> None:
        """Run cleanup of expired entries before discovery."""
        self.cleanup_expired()

    def _read_all_for_discover(self) -> dict[str, dict[str, Any]]:
        """Read all registry entries."""
        data = self._read_all()
        return data

    def _extract_entry_for_discover(
        self,
        data: dict[str, dict[str, Any]],
        name: str,
    ) -> dict[str, Any] | None:
        """Extract the raw entry for the given name."""
        raw = data.get(name)
        if not raw:
            return None
        return raw

    def _construct_info_for_discover(
        self,
        raw: dict[str, Any],
    ) -> ServiceInfo | None:
        """Construct a ServiceInfo from a raw entry."""
        try:
            info = ServiceInfo(**raw)
        except TypeError:
            return None
        return info

    def _check_expiry_for_discover(
        self,
        info: ServiceInfo | None,
    ) -> ServiceInfo | None:
        """Return None if the info is expired."""
        if info is None:
            return None
        if info.expired:
            return None
        return info

    def discover(self, name: str) -> ServiceInfo | None:
        """Return the registered service info, or None if missing/expired."""
        self._run_cleanup_for_discover()

        data = self._read_all_for_discover()

        raw = self._extract_entry_for_discover(data, name)
        if raw is None:
            return None

        info = self._construct_info_for_discover(raw)
        if info is None:
            return None

        result = self._check_expiry_for_discover(info)
        return result

    # ------------------------------------------------------------------ #
    # list_all helpers
    # ------------------------------------------------------------------ #
    def _read_all_for_list(self) -> dict[str, dict[str, Any]]:
        """Read all registry entries for listing."""
        data = self._read_all()
        return data

    def _construct_info_for_list(
        self,
        raw: dict[str, Any],
    ) -> ServiceInfo | None:
        """Construct a ServiceInfo, returning None on type error."""
        try:
            info = ServiceInfo(**raw)
        except TypeError:
            return None
        return info

    def _is_not_expired_for_list(self, info: ServiceInfo) -> bool:
        """Check whether the service is not expired."""
        expired = info.expired
        if expired:
            return False
        return True

    def list_all(self) -> dict[str, ServiceInfo]:
        """List all non-expired registered services."""
        data = self._read_all_for_list()

        result: dict[str, ServiceInfo] = {}

        for name, raw in data.items():
            info = self._construct_info_for_list(raw)
            if info is None:
                continue

            not_expired = self._is_not_expired_for_list(info)
            if not not_expired:
                continue

            result[name] = info

        return result

    # ------------------------------------------------------------------ #
    # heartbeat helpers
    # ------------------------------------------------------------------ #
    def _lock_read_for_heartbeat(self) -> tuple[dict[str, dict[str, Any]], int]:
        """Lock and read registry data for heartbeat."""
        data, fd = self._read_write_locked()
        return data, fd

    def _find_entry_for_heartbeat(
        self,
        data: dict[str, dict[str, Any]],
        name: str,
    ) -> dict[str, Any] | None:
        """Find the raw entry for the service."""
        raw = data.get(name)
        if not raw:
            return None
        return raw

    def _update_timestamp_for_heartbeat(
        self,
        info: ServiceInfo,
    ) -> ServiceInfo:
        """Update the registered_at timestamp."""
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        info.registered_at = now
        return info

    def _commit_for_heartbeat(
        self,
        fd: int,
        data: dict[str, dict[str, Any]],
    ) -> None:
        """Commit heartbeat data and release lock."""
        self._commit_locked(fd, data)

    def _return_success_for_heartbeat(self) -> bool:
        """Return True indicating success."""
        return True

    def heartbeat(self, name: str) -> bool:
        """Refresh the ``registered_at`` timestamp for a service.

        Returns ``True`` if the service existed and was refreshed.
        """
        data, fd = self._lock_read_for_heartbeat()

        try:
            raw = self._find_entry_for_heartbeat(data, name)
            if raw is None:
                os.close(fd)
                return False

            try:
                info = ServiceInfo(**raw)
            except TypeError:
                os.close(fd)
                return False

            info = self._update_timestamp_for_heartbeat(info)

            data[name] = asdict(info)

            self._commit_for_heartbeat(fd, data)
        except Exception:
            os.close(fd)
            raise

        result = self._return_success_for_heartbeat()
        return result

    # ------------------------------------------------------------------ #
    # cleanup_expired helpers
    # ------------------------------------------------------------------ #
    def _lock_read_all_for_cleanup(
        self,
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """Lock and read all registry data for cleanup."""
        data, fd = self._read_write_locked()
        return data, fd

    def _filter_remaining_for_cleanup(
        self,
        data: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """Filter out expired entries; return (remaining, removed_count)."""
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

        return remaining, removed

    def _commit_if_changed_for_cleanup(
        self,
        fd: int,
        removed: int,
        remaining: dict[str, dict[str, Any]],
    ) -> None:
        """Commit remaining data if any entries were removed."""
        if removed:
            self._commit_locked(fd, remaining)
            logger.info(
                "cleaned up %d expired registry entries",
                removed,
            )
        else:
            os.close(fd)

    def _close_fd_for_cleanup(self, fd: int) -> None:
        """Close the file descriptor."""
        os.close(fd)

    def cleanup_expired(self) -> int:
        """Remove expired registrations. Returns the number removed."""
        data, fd = self._lock_read_all_for_cleanup()

        try:
            remaining, removed = self._filter_remaining_for_cleanup(data)

            self._commit_if_changed_for_cleanup(fd, removed, remaining)

            return removed
        except Exception:
            os.close(fd)
            raise
