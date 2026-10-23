"""Source-level security regression tests for the license server and loader.

These checks assert on the *source code* (and exported module attributes) so they
guard against accidental security degradation (a removed rate limit, a swapped
pepper, a wildcard CORS fallback, or an unhardened packaged build) independently
of the runtime test fixtures.
"""

from __future__ import annotations

from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent

_KEYAUTH_SRC = (SERVER_DIR / "app" / "api" / "v1" / "keyauth.py").read_text()
_INTEGRITY_API_SRC = (SERVER_DIR / "app" / "api" / "v1" / "integrity.py").read_text()
_MAIN_SRC = (SERVER_DIR / "app" / "main.py").read_text()
_LOADER_MAIN_JS = (SERVER_DIR.parent / "loader" / "main.js").read_text()


def test_keyauth_activate_has_rate_limit() -> None:
    """The /activate endpoint must depend on the keyauth rate limiter."""
    assert "keyauth_rate_limit" in _KEYAUTH_SRC

    activate_chunk = _KEYAUTH_SRC.split('@router.post("/activate")', 1)[1]
    activate_chunk = activate_chunk.split('@router.post("/session/validate")', 1)[0]
    assert "_keyauth_rate_limit" in activate_chunk


def test_integrity_uses_dedicated_pepper() -> None:
    """assess_manifest must be called with the integrity pepper, not the key pepper."""
    assert "pepper=settings.integrity_pepper" in _INTEGRITY_API_SRC
    assert "license_key_pepper" not in _INTEGRITY_API_SRC

    import inspect

    from app.services import integrity as integrity_svc

    sig = inspect.signature(integrity_svc.assess_manifest)
    assert "pepper" in sig.parameters


def test_cors_does_not_allow_all_when_empty() -> None:
    """CORS origins must never fall back to a wildcard ['*']."""
    for line in _MAIN_SRC.splitlines():
        if "allow_origins" in line:
            assert '"*"' not in line
            assert "'*'" not in line

    from app.config import Settings

    settings = Settings.model_construct(
        CORS_ALLOWED_ORIGINS=[],
    )
    assert settings.CORS_ALLOWED_ORIGINS != ["*"]
    assert settings.CORS_ALLOWED_ORIGINS == []


def test_electron_hardened_when_packaged() -> None:
    """The packaged loader must gate dev behaviour on app.isPackaged and block navigation."""
    assert "app.isPackaged" in _LOADER_MAIN_JS
    assert "will-navigate" in _LOADER_MAIN_JS
    assert "preventDefault" in _LOADER_MAIN_JS or "returnValue" in _LOADER_MAIN_JS
    assert "setWindowOpenHandler" in _LOADER_MAIN_JS
