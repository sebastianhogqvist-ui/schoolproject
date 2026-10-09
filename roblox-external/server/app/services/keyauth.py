"""KeyAuth integration service.

Provides server-side validation of license keys through the KeyAuth platform.
Credentials are read from environment variables via the Settings object and
are never logged or returned to clients.

KeyAuth API base: https://keyauth.win/api/1.3/
API style: GET requests with query parameters.
"""
from __future__ import annotations

from typing import Any

from httpx import AsyncClient, HTTPStatusError, RequestError

from app.config import Settings
from app.keys import normalize_license_key
from app.logging_config import get_logger

logger = get_logger("keyauth")

KEYAUTH_API_BASE = "https://keyauth.win/api/1.3/"


class KeyAuthError(Exception):
    """Raised when the KeyAuth API returns an error or is unreachable."""


class KeyAuthResult:
    """Normalized result from a KeyAuth API call."""

    def __init__(
        self,
        success: bool,
        message: str,
        data: dict[str, Any] | None = None,
    ):
        self.success = success
        self.message = message
        self.data = data or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation."""
        return {"success": self.success, "message": self.message, "data": self.data}


def is_keyauth_configured(settings: Settings) -> bool:
    """Return whether all required KeyAuth credentials are present."""
    return bool(
        settings.KEYAUTH_OWNER_ID
        and settings.KEYAUTH_APP_SECRET
        and settings.KEYAUTH_APP_NAME
    )


def _mask_secret(text: str) -> str:
    """Mask a secret value for logging - shows only first and last char."""
    if len(text) <= 2:
        return "*" * len(text)
    return f"{text[0]}{'*' * (len(text) - 2)}{text[-1]}"


async def _keyauth_request(
    settings: Settings,
    client: AsyncClient,
    params: dict[str, str],
) -> dict[str, Any]:
    """Make a request to the KeyAuth API and return the JSON payload."""
    try:
        resp = await client.get(KEYAUTH_API_BASE, params=params, timeout=10.0)
        resp.raise_for_status()
        payload = resp.json()
    except (RequestError, HTTPStatusError, ValueError) as exc:
        raise KeyAuthError("KeyAuth service is unreachable") from exc

    return payload


async def _keyauth_init(settings: Settings, client: AsyncClient) -> str:
    """Initialize a KeyAuth session and return the session ID.

    Raises KeyAuthError if initialization fails.
    """
    secret = settings.KEYAUTH_APP_SECRET.get_secret_value() if settings.KEYAUTH_APP_SECRET else ""
    params = {
        "type": "init",
        "name": settings.KEYAUTH_APP_NAME or "",
        "ownerid": settings.KEYAUTH_OWNER_ID or "",
        "secret": secret,
    }
    payload = await _keyauth_request(settings, client, params)

    if not payload.get("success"):
        msg = payload.get("message", "KeyAuth initialization failed")
        logger.warning("keyauth init rejected: %s", msg)
        raise KeyAuthError(msg)

    sessionid = payload.get("sessionid")
    if not sessionid:
        logger.warning("keyauth returned no session id")
        raise KeyAuthError("KeyAuth returned an invalid session")

    logger.info("keyauth session initialized")
    return sessionid


async def validate_license_key(
    settings: Settings,
    raw_key: str,
    hwid: str | None = None,
) -> KeyAuthResult:
    """Validate a license key through KeyAuth.

    Returns a KeyAuthResult with the validation outcome and key metadata.
    Never raises to the caller on KeyAuth-side failures.
    """
    if not is_keyauth_configured(settings):
        return KeyAuthResult(
            success=False,
            message="KeyAuth is not configured on this server",
        )

    # Validate key format locally first
    try:
        canonical = normalize_license_key(raw_key)
    except ValueError:
        return KeyAuthResult(
            success=False,
            message="License key format is invalid",
        )

    async with AsyncClient() as client:
        try:
            sessionid = await _keyauth_init(settings, client)
        except KeyAuthError as exc:
            return KeyAuthResult(success=False, message=str(exc))

        params = {
            "type": "license",
            "name": settings.KEYAUTH_APP_NAME or "",
            "ownerid": settings.KEYAUTH_OWNER_ID or "",
            "sessionid": sessionid,
            "key": canonical,
        }
        if hwid:
            params["hwid"] = hwid

        try:
            payload = await _keyauth_request(settings, client, params)
        except KeyAuthError as exc:
            return KeyAuthResult(success=False, message=str(exc))

    success = payload.get("success", False)
    message = payload.get("message", "")

    # Build keyInfo from KeyAuth response data
    key_info: dict[str, Any] = {}
    raw_data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    key_info = {
        "plan": raw_data.get("plan", raw_data.get("level", "basic")),
        "devices": raw_data.get("devices", raw_data.get("maxDevices", "—")),
        "format": "XXXX-XXXX-XXXX-XXXX",
        "hwid": "yes" if hwid else "no",
        "status": "active" if success else "invalid",
        "expires_at": raw_data.get("expires", raw_data.get("expiry", "")),
        "created_at": raw_data.get("createdate", ""),
    }

    return KeyAuthResult(
        success=success,
        message=message or (
            "License validated successfully" if success else "License validation failed"
        ),
        data={
            "sessionId": sessionid,
            "keyInfo": key_info if success else None,
        },
    )


async def validate_session(settings: Settings) -> KeyAuthResult:
    """Check if a KeyAuth session is valid by initializing a fresh session.

    KeyAuth doesn't have a dedicated session validate endpoint; we use init
    to verify the app configuration is working and the service is reachable.
    """
    if not is_keyauth_configured(settings):
        return KeyAuthResult(
            success=False,
            message="KeyAuth is not configured on this server",
        )

    async with AsyncClient() as client:
        try:
            sessionid = await _keyauth_init(settings, client)
        except KeyAuthError as exc:
            return KeyAuthResult(success=False, message=str(exc))

    key_info: dict[str, Any] = {
        "plan": "—",
        "devices": "—",
        "format": "XXXX-XXXX-XXXX-XXXX",
        "hwid": "—",
        "status": "ready",
    }

    return KeyAuthResult(
        success=True,
        message="KeyAuth service is reachable",
        data={"sessionId": sessionid, "keyInfo": key_info},
    )


async def heartbeat(settings: Settings) -> KeyAuthResult:
    """Check if the KeyAuth service is reachable."""
    if not is_keyauth_configured(settings):
        return KeyAuthResult(
            success=True,
            message="KeyAuth configured but not initialized",
        )

    async with AsyncClient() as client:
        try:
            sessionid = await _keyauth_init(settings, client)
        except KeyAuthError as exc:
            return KeyAuthResult(success=False, message=str(exc))

    return KeyAuthResult(
        success=True,
        message="KeyAuth service is reachable",
        data={"sessionId": sessionid},
    )
