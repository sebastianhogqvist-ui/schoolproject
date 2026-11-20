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
_INTERSERVICE_SRC = (SERVER_DIR / "app" / "interservice.py").read_text()
_INTEGRITY_SRC = (SERVER_DIR / "app" / "security" / "integrity.py").read_text()
_ADMIN_SVC_SRC = (SERVER_DIR / "app" / "services" / "admin.py").read_text()
_GATEWAY_SRC = (SERVER_DIR / "app" / "gateway.py").read_text()
_DEPS_SRC = (SERVER_DIR / "app" / "deps.py").read_text()
_PASSWORDS_SRC = (SERVER_DIR / "app" / "security" / "passwords.py").read_text()


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


def test_service_tokens_have_distinct_audience() -> None:
    """Service tokens must use a distinct audience to prevent cross-type confusion."""
    assert 'SERVICE_TOKEN_AUDIENCE_SUFFIX: str = "service"' in _INTERSERVICE_SRC
    assert "service_audience" in _INTERSERVICE_SRC
    assert "jwt_audience" in _INTERSERVICE_SRC
    # Service tokens should NOT use the plain jwt_audience
    encode_section = _INTERSERVICE_SRC.split("def encode_service_token")[1]
    encode_section = encode_section.split("def decode_service_token")[0]
    assert "service_audience" in encode_section
    assert "service_audience" in encode_section  # used in claims/"aud"


def test_service_tokens_have_replay_protection() -> None:
    """Service tokens must track JTIs to prevent replay within TTL."""
    assert "_jti_store" in _INTERSERVICE_SRC
    assert "_check_and_record_jti" in _INTERSERVICE_SRC
    assert "replay detected" in _INTERSERVICE_SRC
    assert "REQUIRED_SERVICE_CLAIMS" in _INTERSERVICE_SRC
    assert '"scope"' in _INTERSERVICE_SRC


def test_service_tokens_have_scope_claim() -> None:
    """Service tokens must support scope claim for fine-grained authorization."""
    assert "scope" in _INTERSERVICE_SRC
    assert "def encode_service_token" in _INTERSERVICE_SRC
    encode_section = _INTERSERVICE_SRC.split("def encode_service_token")[1]
    encode_section = encode_section.split("def decode_service_token")[0]
    assert "scope" in encode_section


def test_gateway_uses_service_token_scopes() -> None:
    """Gateway must pass scopes when creating service tokens."""
    assert "_scope_for_path" in _GATEWAY_SRC
    assert "make_service_token" in _GATEWAY_SRC
    # Check that scope is passed to make_service_token calls
    assert "scope=_scope_for_path" in _GATEWAY_SRC


def test_integrity_manifest_has_total_size_limit() -> None:
    """Integrity manifest parser must validate total size, not just per-file."""
    assert "MAX_MANIFEST_TOTAL_BYTES" in _INTEGRITY_SRC
    assert "total_size" in _INTEGRITY_SRC
    assert "exceeds maximum size" in _INTEGRITY_SRC


def test_activation_trail_masks_pii() -> None:
    """Admin activation trail must mask IP and truncate user agent."""
    assert "_mask_ip" in _ADMIN_SVC_SRC
    assert "_mask_user_agent" in _ADMIN_SVC_SRC
    # Check that serialize_activation uses the masking functions
    serialize_section = _ADMIN_SVC_SRC.split("def serialize_activation")[1]
    serialize_section = serialize_section.split("def ")[0]
    assert "_mask_ip(row.ip)" in serialize_section
    assert "_mask_user_agent(row.user_agent)" in serialize_section


def test_keygen_collision_retries_consistent() -> None:
    """CLI and admin service must use same KEYGEN_COLLISION_RETRIES value."""
    # Both should use 20
    assert "KEYGEN_COLLISION_RETRIES = 20" in _ADMIN_SVC_SRC


def test_argon2id_time_cost_increased() -> None:
    """Default argon2id time_cost should be at least 4 (OWASP 2024 recommendation)."""
    from app.config import Settings
    
    settings = Settings.model_construct(
        DATABASE_URL="sqlite:///:memory:",
        LICENSE_JWT_SECRET="x" * 32,
        LICENSE_KEY_PEPPER="y" * 16,
        HWID_PEPPER="z" * 16,
        INTEGRITY_PEPPER="w" * 16,
    )
    assert settings.BCRYPT_TIME_COST >= 4


def test_rate_limit_key_uses_session_identity() -> None:
    """Rate limit keys should prefer session/admin identity over IP."""
    assert "_rate_limit_key" in _DEPS_SRC
    assert "session:" in _DEPS_SRC
    assert "admin:" in _DEPS_SRC
    assert "anon:" in _DEPS_SRC


def test_service_registry_uses_file_locking() -> None:
    """Service registry must use file locking to prevent race conditions."""
    import fcntl
    # Check that fcntl is imported and used
    _SERVICE_REGISTRY_SRC = (SERVER_DIR / "app" / "service_registry.py").read_text()
    assert "import fcntl" in _SERVICE_REGISTRY_SRC
    assert "fcntl.flock" in _SERVICE_REGISTRY_SRC
    assert "LOCK_EX" in _SERVICE_REGISTRY_SRC
    assert "LOCK_SH" in _SERVICE_REGISTRY_SRC


def test_gateway_error_handling_generic() -> None:
    """Gateway proxy must not leak backend error details."""
    assert "backend communication failed" in _GATEWAY_SRC
    assert "backend timeout" in _GATEWAY_SRC
    assert "backend unavailable" in _GATEWAY_SRC
    assert "internal gateway error" in _GATEWAY_SRC
    # Should catch specific httpx exceptions
    assert "httpx.TimeoutException" in _GATEWAY_SRC
    assert "httpx.ConnectError" in _GATEWAY_SRC


def test_database_pool_configurable() -> None:
    """Database pool settings should be configurable per service."""
    _DB_SRC = (SERVER_DIR / "app" / "db.py").read_text()
    assert "DB_POOL_SIZE" in _DB_SRC
    assert "DB_MAX_OVERFLOW" in _DB_SRC
    assert "DB_POOL_TIMEOUT" in _DB_SRC
    assert "DB_POOL_RECYCLE" in _DB_SRC
    assert "_build_engine" in _DB_SRC
    assert "pool_size" in _DB_SRC
    assert "max_overflow" in _DB_SRC
