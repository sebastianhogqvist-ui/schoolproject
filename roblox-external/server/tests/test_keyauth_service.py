"""Tests for the KeyAuth integration service."""

from __future__ import annotations

import asyncio

from pydantic import SecretStr

from app.config import Settings
from app.keys import generate_license_key
from app.services.integrity import build_id_allowed
from app.services.keyauth import (
    KeyAuthError,
    KeyAuthResult,
    is_keyauth_configured,
    validate_license_key,
)


def test_is_keyauth_configured_with_values(settings: Settings) -> None:
    assert is_keyauth_configured(settings) is True


def test_is_keyauth_configured_no_values(settings: Settings) -> None:
    none_settings = settings.model_copy(
        update={
            "KEYAUTH_OWNER_ID": None,
            "KEYAUTH_APP_SECRET": None,
            "KEYAUTH_APP_NAME": None,
        }
    )
    assert is_keyauth_configured(none_settings) is False

    empty_settings = settings.model_copy(
        update={
            "KEYAUTH_OWNER_ID": "",
            "KEYAUTH_APP_SECRET": SecretStr(""),
            "KEYAUTH_APP_NAME": "",
        }
    )
    assert is_keyauth_configured(empty_settings) is False


def test_keyauth_result_to_dict_success() -> None:
    result = KeyAuthResult(
        success=True,
        message="License validated successfully",
        data={"sessionId": "abc123", "keyInfo": {"plan": "premium"}},
    )
    d = result.to_dict()
    assert d == {
        "success": True,
        "message": "License validated successfully",
        "data": {"sessionId": "abc123", "keyInfo": {"plan": "premium"}},
    }


def test_keyauth_result_to_dict_failure() -> None:
    error = KeyAuthError("KeyAuth service is unreachable")
    result = KeyAuthResult(success=False, message=str(error))
    d = result.to_dict()
    assert d == {
        "success": False,
        "message": "KeyAuth service is unreachable",
        "data": {},
    }


def test_validate_key_build_enforcement(settings: Settings) -> None:
    enforced = settings.model_copy(update={"ANTI_TAMPER_REQUIRE_CLIENT_BUILD": True})
    assert build_id_allowed("0.9.0", enforced) is False

    result = asyncio.run(
        validate_license_key(enforced, raw_key=generate_license_key(), client_build="0.9.0")
    )

    assert isinstance(result, KeyAuthResult)
    assert result.success is False
    assert result.message == "Client build is not permitted on this server"
