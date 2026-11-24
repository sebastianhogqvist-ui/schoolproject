"""Inter-service authentication tokens implemented as short-lived JWTs.

This module implements short-lived JSON Web Tokens (JWTs) used exclusively for
authentication between trusted internal services. Service tokens prove that the
caller is a trusted internal service and not an external client. Every service
token carries a ``typ`` claim equal to ``SERVICE_TOKEN_TYPE`` (``"service"``),
which guarantees that a service token can never be confused with a client or
admin token, even though all token kinds are signed with the same JWT secret.

Token issuance flow (encode_service_token)
-------------------------------------------
1. validate_inputs             - reject empty nonces and non-positive TTls.
2. compute_timestamps          - derive issued_at and expires_at from the TTL.
3. generate_jti                - mint a cryptographically random JWT ID (nonce).
4. compute_service_audience    - build the service-scoped audience string.
5. build_base_claims           - assemble the mandatory JWT claim set.
6. apply_extra_claims          - attach optional scope and caller claims.
7. encode_jwt                  - sign the claim set into a compact JWT string.
8. assemble_result             - return the (encoded, jti, expires_at) tuple.

Token verification flow (decode_service_token)
-----------------------------------------------
1. validate_token_input     - reject missing or non-string tokens.
2. compute_service_audience - derive the expected audience from settings.
3. decode_jwt_payload       - verify signature, issuer, audience, expiry.
4. verify_typ_claim         - ensure the token is a service token.
5. verify_jti_presence      - ensure the token carries a JWT ID.
6. check_replay_protection  - reject JTIs already consumed (replay).
7. return_claims            - return the verified claim set to the caller.

Replay protection
-----------------
Each service token carries a unique ``jti`` claim (a JWT ID nonce) generated
with the ``secrets`` module. When a service token is presented for decoding,
its ``jti`` is registered in the in-memory ``_jti_store``. If the same ``jti``
is presented again within the JTI time-to-live window, the request is rejected
as a replay attack. JTI entries expire after ``_JTI_TTL_SECONDS`` and the store
is capped at ``_MAX_JTI_STORE_SIZE`` entries to bound memory usage.

The JTI store is guarded by ``_jti_lock`` so that concurrent decoding requests
cannot race on the check-then-record operation, which would otherwise permit
two requests bearing the same ``jti`` to both succeed.

Claim semantics
---------------
- iss   (issuer): identifies the authorization server that issued the token.
- aud   (audience): the intended recipient; service tokens use a distinct
  audience (``{jwt_audience}:service``) to prevent cross-service confusion.
- sub   (subject): the service token nonce the caller is proving possession of.
- iat   (issued at): the time at which the token was issued.
- nbf   (not before): the time before which the token must not be accepted.
- exp   (expiration): the time after which the token must not be accepted.
- jti   (JWT ID): a unique nonce used for single-use replay protection.
- typ   (type): fixed to ``"service"`` to separate service tokens from others.
- scope: optional authorization scope string carried by the token.

Security notes
--------------
- Nonces are generated with ``secrets.token_hex``, never with ``random``.
- All timestamps are timezone-aware UTC datetimes with microsecond precision
  stripped, keeping JWT numeric dates stable and comparable.
- The reserved claim set (iss, aud, sub, iat, nbf, exp, jti, typ, scope) may
  not be overridden by caller-supplied ``extra_claims``.
"""

import secrets
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError

from app.config import Settings
from app.security.tokens import TokenError

# The ``typ`` claim value stamped on every service token. This constant value
# is what allows verifiers to distinguish service tokens from client or admin
# tokens even though every token kind is signed with the same JWT secret.
SERVICE_TOKEN_TYPE: str = "service"

# The suffix appended to the configured JWT audience to form the service
# token audience. Service tokens use a distinct audience so that a token
# issued for one service cannot be presented to another service.
SERVICE_TOKEN_AUDIENCE_SUFFIX: str = "service"

# The set of JWT claims that every service token is required to contain. The
# PyJWT ``require`` option enforces presence of these claims at decode time,
# and this module additionally verifies ``typ`` and ``jti`` explicitly.
REQUIRED_SERVICE_CLAIMS: tuple[str, ...] = (
    "exp",
    "iat",
    "sub",
    "typ",
    "jti",
    "scope",
)

# In-memory map of consumed JWT IDs (jti) to their consumption timestamps. An
# entry is inserted when a service token is successfully decoded and is removed
# once it ages past the JTI time-to-live window. Presence of a ``jti`` in this
# store means the token has already been consumed and any re-presentation is a
# replay attack.
_jti_store: OrderedDict[str, float] = OrderedDict()

# Process-private lock guarding all mutations of ``_jti_store``. Every
# check-and-record operation on the JTI store is performed while holding this
# lock so that concurrent decoders cannot observe an inconsistent store state.
_jti_lock = threading.Lock()

# Default time-to-live in seconds for a JTI entry in the replay store. A JTI
# older than this window is evicted during cleanup. This value matches the
# default service token TTL so that replay protection covers the full lifetime
# of any token that could still be considered fresh.
_JTI_TTL_SECONDS = 300

# Upper bound on the number of JTI entries retained in memory. When the store
# grows beyond this size, the oldest entries are evicted first (FIFO order via
# OrderedDict.popitem(last=False)). This is a safety fallback that prevents
# unbounded memory growth in long-running processes.
_MAX_JTI_STORE_SIZE = 10000


def generate_service_token() -> str:
    """Return a cryptographically random service token nonce.

    The nonce is generated with the ``secrets`` module, which draws from the
    operating system's cryptographically secure pseudorandom number generator.
    This is unsuitable for prediction by an attacker and is therefore safe to
    use as the ``sub`` (subject) claim of a service token and as input to the
    token issuance pipeline.

    Returns:
        A lowercase hexadecimal string of 64 characters (32 random bytes).
    """
    token = secrets.token_hex(32)
    return token


def validate_inputs(token: str, ttl_seconds: int) -> None:
    """Validate the caller-supplied inputs to the token issuance pipeline.

    This function performs input validation before any claims are constructed
    or any cryptographic work is performed. Failing fast here avoids signing
    tokens that are semantically invalid.

    Args:
        token: The service token nonce that will become the ``sub`` claim.
        ttl_seconds: The requested time-to-live in seconds for the token.

    Raises:
        TokenError: If ``token`` is empty or falsy, or if ``ttl_seconds`` is
            less than or equal to zero.
    """
    # Reject empty or falsy nonces. An empty subject would produce a token
    # that proves possession of nothing and could be confused with other
    # tokens lacking a meaningful subject.
    if not token:
        raise TokenError("service token must not be empty")

    # Reject non-positive TTls. A TTL of zero or less would produce an
    # expiration time that is not strictly in the future relative to issuance,
    # yielding tokens that are expired at birth.
    if ttl_seconds <= 0:
        raise TokenError("ttl must be greater than zero")


def compute_timestamps(ttl_seconds: int) -> tuple[datetime, datetime]:
    """Compute the issued-at and expiration timestamps for a service token.

    Both timestamps are derived from the current wall-clock time in UTC. The
    issued-at timestamp is truncated to whole seconds (microseconds stripped)
    so that JWT numeric dates remain stable and comparable across systems. The
    expiration timestamp is issued-at plus the requested TTL.

    Args:
        ttl_seconds: The time-to-live in seconds to add to the issued-at time.

    Returns:
        A tuple of ``(issued_at, expires_at)`` where both elements are
        timezone-aware ``datetime`` values in UTC.
    """
    now = datetime.now(UTC)

    # Truncate microseconds so the JWT numeric date is an integer number of
    # seconds, which avoids sub-second precision drift between issuer and
    # verifier clocks.
    issued_at = now.replace(microsecond=0)

    # The token expires TTL seconds after issuance. Any presentation after
    # this instant is rejected by the JWT expiry verification.
    expires_at = issued_at + timedelta(seconds=ttl_seconds)

    return issued_at, expires_at


def generate_jti() -> str:
    """Generate a unique JWT ID (jti) nonce for a service token.

    The JWT ID is a single-use nonce that enables replay protection. It is
    generated with ``secrets.token_hex`` so that it is infeasible for an
    attacker to guess a valid ``jti`` and pre-register it in the replay store.

    Returns:
        A lowercase hexadecimal string of 32 characters (16 random bytes).
    """
    jti = secrets.token_hex(16)
    return jti


def compute_service_audience(settings: Settings) -> str:
    """Compute the service-scoped audience for service tokens.

    Service tokens use a distinct audience formed by appending
    ``SERVICE_TOKEN_AUDIENCE_SUFFIX`` to the configured ``jwt_audience``. This
    ensures that a token issued for one service audience cannot be accepted by
    a verifier configured for a different audience, preventing confused-deputy
    and cross-service replay attacks.

    Args:
        settings: Application settings providing ``jwt_audience``.

    Returns:
        The service audience string in the form ``"{jwt_audience}:service"``.
    """
    service_audience = f"{settings.jwt_audience}:{SERVICE_TOKEN_AUDIENCE_SUFFIX}"
    return service_audience


def build_base_claims(
    issuer: str,
    audience: str,
    subject: str,
    issued_at: datetime,
    expires_at: datetime,
    jti: str,
    token_type: str,
) -> dict[str, Any]:
    """Build the mandatory base claim set for a service token.

    Every service token contains the registered claims ``iss``, ``aud``, ``sub``,
    ``iat``, ``nbf``, ``exp``, ``jti`` and the ``typ`` claim. The ``not before``
    claim equals the issued-at time so the token is valid immediately upon
    issuance.

    Args:
        issuer: The value for the ``iss`` (issuer) claim.
        audience: The value for the ``aud`` (audience) claim.
        subject: The value for the ``sub`` (subject) claim (the service nonce).
        issued_at: The value for the ``iat`` and ``nbf`` claims.
        expires_at: The value for the ``exp`` (expiration) claim.
        jti: The value for the ``jti`` (JWT ID) claim.
        token_type: The value for the ``typ`` (type) claim.

    Returns:
        A dictionary containing the base claims for the service token.
    """
    claims: dict[str, Any] = {}

    # Issuer identifies the authorization server that issued the token.
    claims["iss"] = issuer

    # Audience identifies the intended recipient; service tokens use a distinct
    # audience to prevent cross-service confusion.
    claims["aud"] = audience

    # Subject is the service token nonce the caller is proving possession of.
    claims["sub"] = subject

    # Issued at records when the token was created.
    claims["iat"] = issued_at

    # Not before equals issued at, so the token is valid immediately.
    claims["nbf"] = issued_at

    # Expiration is the instant after which the token must not be accepted.
    claims["exp"] = expires_at

    # JWT ID is the single-use nonce used for replay protection.
    claims["jti"] = jti

    # Type is fixed to "service" so service tokens are never confused with
    # client or admin tokens.
    claims["typ"] = token_type

    return claims


def apply_extra_claims(
    claims: dict[str, Any],
    scope: str | None,
    extra_claims: dict[str, Any] | None,
) -> dict[str, Any]:
    """Attach optional scope and caller-supplied claims to the claim set.

    If a ``scope`` is provided it is stored under the ``scope`` claim. If
    ``extra_claims`` are provided they are merged into the claim set after a
    reserved-claim check. Caller claims may not override any of the reserved
    claims (``iss``, ``aud``, ``sub``, ``iat``, ``nbf``, ``exp``, ``jti``,
    ``typ``, ``scope``), because overriding those would invalidate the token's
    structure or bypass replay protection.

    Args:
        claims: The base claim set produced by ``build_base_claims``.
        scope: Optional scope string (e.g. ``"license:activate"``).
        extra_claims: Optional additional claims to embed.

    Returns:
        The claim set with scope and extra claims applied.

    Raises:
        TokenError: If ``extra_claims`` contains any reserved claim key.
    """
    # Attach the optional scope claim when the caller supplied one. Scope
    # expresses the authorization granted by this token (e.g. which operation
    # the caller is permitted to perform).
    if scope is not None:
        claims["scope"] = scope

    # When extra claims are supplied, verify none of them collide with the
    # reserved claim set before merging. A collision would allow a caller to
    # override security-critical claims such as expiration or JWT ID.
    if extra_claims is not None:
        reserved = {
            "iss",
            "aud",
            "sub",
            "iat",
            "nbf",
            "exp",
            "jti",
            "typ",
            "scope",
        }

        overlap = reserved & set(extra_claims)

        # Reject the request if any extra claim would override a reserved
        # claim. Sorted output keeps the error message deterministic.
        if len(overlap) > 0:
            raise TokenError(f"extra_claims must not override {sorted(overlap)}")

        claims.update(extra_claims)

    return claims


def encode_jwt(
    claims: dict[str, Any],
    secret: str,
    algorithm: str,
) -> str:
    """Sign the claim set into a compact JWT string.

    The token is signed with the configured secret and algorithm. The ``typ``
    header is set to ``"JWT"`` to mark the token as a JWT per the JWS
    specification.

    Args:
        claims: The claim set to encode and sign.
        secret: The shared secret used to sign the token.
        algorithm: The JWA algorithm used for signing.

    Returns:
        The signed compact JWT serialization as a string.
    """
    headers = {"typ": "JWT"}

    encoded = jwt.encode(
        claims,
        secret,
        algorithm=algorithm,
        headers=headers,
    )

    return encoded


def assemble_result(
    encoded: str,
    jti: str,
    expires_at: datetime,
) -> tuple[str, str, datetime]:
    """Assemble the return value of the token issuance pipeline.

    Args:
        encoded: The signed compact JWT string.
        jti: The JWT ID (nonce) embedded in the token.
        expires_at: The instant at which the token expires.

    Returns:
        A tuple of ``(encoded_jwt, jti, expires_at)``.
    """
    return encoded, jti, expires_at


def encode_service_token(
    token: str,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any] | None = None,
    scope: str | None = None,
) -> tuple[str, str, datetime]:
    """Sign ``token`` as a short-lived service JWT.

    The issuance pipeline is decomposed into single-purpose steps:

    1. validate_inputs       - check the nonce and TTL are sane.
    2. compute_timestamps    - derive issued_at and expires_at.
    3. generate_jti          - mint the single-use JWT ID nonce.
    4. compute_service_audience - build the service-scoped audience.
    5. build_base_claims     - assemble the mandatory claim set.
    6. apply_extra_claims    - attach optional scope and extra claims.
    7. encode_jwt            - sign the claims into a JWT string.
    8. assemble_result       - return the result tuple.

    Args:
        token: The service token nonce to embed as the ``sub`` claim.
        ttl_seconds: Time-to-live in seconds for the token.
        settings: Application settings (issuer, audience, secret, algorithm).
        extra_claims: Optional additional claims to embed (e.g. client sid,
            lid). Reserved claims may not be overridden.
        scope: Optional scope string (e.g. ``"license:activate"``).

    Returns:
        Tuple of ``(encoded_jwt, jti, expires_at)``.

    Raises:
        TokenError: If inputs are invalid or extra claims override reserved
            claims.
    """
    validate_inputs(token=token, ttl_seconds=ttl_seconds)

    issued_at, expires_at = compute_timestamps(ttl_seconds=ttl_seconds)

    jti = generate_jti()

    service_audience = compute_service_audience(settings=settings)

    base_claims = build_base_claims(
        issuer=settings.jwt_issuer,
        audience=service_audience,
        subject=token,
        issued_at=issued_at,
        expires_at=expires_at,
        jti=jti,
        token_type=SERVICE_TOKEN_TYPE,
    )

    claims = apply_extra_claims(
        claims=base_claims,
        scope=scope,
        extra_claims=extra_claims,
    )

    encoded = encode_jwt(
        claims=claims,
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    return assemble_result(
        encoded=encoded,
        jti=jti,
        expires_at=expires_at,
    )


def validate_token_input(token: str) -> None:
    """Validate the caller-supplied token before verification begins.

    Args:
        token: The compact JWT string presented by the caller.

    Raises:
        TokenError: If ``token`` is empty, falsy, or not a string.
    """
    # Reject tokens that are missing or not strings. A non-string value
    # cannot be decoded by PyJWT and must be rejected before reaching it.
    if not token or not isinstance(token, str):
        raise TokenError("service token is missing")


def decode_jwt_payload(
    token: str,
    settings: Settings,
    audience: str,
) -> dict[str, Any]:
    """Verify the JWT signature and standard claims, returning the payload.

    PyJWT validates the signature, issuer, audience, and expiration. The
    ``require`` option enforces presence of every claim in
    ``REQUIRED_SERVICE_CLAIMS``. Any failure (bad signature, expired token,
    wrong issuer, wrong audience, missing claim) raises ``InvalidTokenError``,
    which is converted into a ``TokenError`` so callers handle one error type.

    Args:
        token: The compact JWT string to verify.
        settings: Application settings (secret, algorithm, issuer).
        audience: The expected service-scoped audience.

    Returns:
        The decoded JWT claims as a dictionary.

    Raises:
        TokenError: If the token is malformed, tampered, expired, or fails any
            standard JWT verification check.
    """
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=audience,
            issuer=settings.jwt_issuer,
            options={
                "require": list(REQUIRED_SERVICE_CLAIMS),
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_signature": True,
            },
        )
    except InvalidTokenError as exc:
        # Wrap PyJWT exceptions in TokenError and suppress the original trace
        # so callers see a single, stable error type for all rejection reasons.
        raise TokenError(
            f"service token rejected: {type(exc).__name__}"
        ) from None

    return claims


def verify_typ_claim(claims: dict[str, Any]) -> None:
    """Verify that the token's ``typ`` claim identifies a service token.

    PyJWT audience/issuer/expiry verification does not inspect ``typ``, so this
    check is performed explicitly. Without it, a client or admin token bearing
    the right audience could be mistakenly accepted as a service token.

    Args:
        claims: The decoded JWT claims.

    Raises:
        TokenError: If the ``typ`` claim is missing or not equal to
            ``SERVICE_TOKEN_TYPE``.
    """
    typ_value = claims.get("typ")

    # The typ claim must equal the service token type constant. Any other
    # value (including absence) means this token was not issued as a service
    # token and must be rejected.
    if typ_value != SERVICE_TOKEN_TYPE:
        raise TokenError("service token type mismatch")


def verify_jti_presence(claims: dict[str, Any]) -> None:
    """Verify that the token carries a non-empty JWT ID (jti) claim.

    The ``jti`` claim is the cornerstone of replay protection. A token without
    a ``jti`` cannot be tracked in the replay store and therefore cannot be
    safely single-use.

    Args:
        claims: The decoded JWT claims.

    Raises:
        TokenError: If the ``jti`` claim is missing or empty.
    """
    jti_value = claims.get("jti")

    # Reject tokens that lack a JWT ID. Without a jti there is nothing to
    # record in the replay store, so replay protection cannot be enforced.
    if not jti_value:
        raise TokenError("service token is missing its jti")


def check_replay_protection(jti: str, now: float) -> None:
    """Reject the token if its JWT ID has already been consumed.

    The JTI store maps consumed JWT IDs to their consumption timestamps.
    ``_check_and_record_jti`` atomically cleans expired entries, checks whether
    ``jti`` is already present, and records it if not. If the ``jti`` was
    already seen, the token is a replay and is rejected.

    Args:
        jti: The JWT ID claim value from the token.
        now: The current wall-clock time as a POSIX timestamp (float seconds).

    Raises:
        TokenError: If the ``jti`` has already been consumed (replay detected).
    """
    # Atomically check whether this jti was already consumed and record it if
    # not. The check and record happen under the JTI lock so concurrent
    # presentations of the same jti cannot both succeed.
    is_new = _check_and_record_jti(jti=jti, now=now)

    # If the jti was not new, it has already been consumed and this
    # presentation is a replay attack.
    if not is_new:
        raise TokenError("service token replay detected")


def return_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Return the verified claim set to the caller.

    This is the final step of the decode pipeline. All validation, signature,
    type, and replay checks have passed at this point, so the claims are safe
    to hand back.

    Args:
        claims: The fully verified JWT claims.

    Returns:
        The same claims dictionary, unchanged.
    """
    return claims


def decode_service_token(token: str, settings: Settings) -> dict[str, Any]:
    """Verify a service token and return its claims.

    The verification pipeline is decomposed into single-purpose steps:

    1. validate_token_input     - reject missing or non-string tokens.
    2. compute_service_audience - derive the expected audience.
    3. decode_jwt_payload       - verify signature, issuer, audience, expiry.
    4. verify_typ_claim         - ensure the token is a service token.
    5. verify_jti_presence      - ensure the token carries a JWT ID.
    6. check_replay_protection  - reject JTIs already consumed (replay).
    7. return_claims            - return the verified claim set.

    Raises :class:`TokenError` for malformed, tampered, expired, wrong-type,
    missing-jti, or replayed tokens.

    Args:
        token: The compact JWT string to verify.
        settings: Application settings (secret, algorithm, issuer, audience).

    Returns:
        The verified JWT claims as a dictionary.

    Raises:
        TokenError: If the token is invalid for any reason.
    """
    validate_token_input(token=token)

    service_audience = compute_service_audience(settings=settings)

    claims = decode_jwt_payload(
        token=token,
        settings=settings,
        audience=service_audience,
    )

    verify_typ_claim(claims=claims)

    verify_jti_presence(claims=claims)

    # Replay protection requires the current time to evaluate JTI expiry and
    # to timestamp the newly recorded jti.
    now = time.time()
    jti_value = claims["jti"]
    check_replay_protection(jti=jti_value, now=now)

    return return_claims(claims=claims)


def compute_cutoff_time(now: float) -> float:
    """Compute the oldest JTI timestamp that is still considered fresh.

    Any JTI whose consumption timestamp is less than or equal to the cutoff is
    older than the JTI time-to-live and is eligible for eviction.

    Args:
        now: The current wall-clock time as a POSIX timestamp.

    Returns:
        The cutoff timestamp; entries at or below this value are expired.
    """
    cutoff = now - _JTI_TTL_SECONDS
    return cutoff


def pop_expired_jti_items(cutoff: float) -> None:
    """Evict all JTI entries older than the cutoff from the store.

    The store is an OrderedDict ordered by insertion time, so the oldest
    entries are at the front. Entries are removed from the front while the
    oldest remaining entry's timestamp is at or below the cutoff.

    Args:
        cutoff: The oldest timestamp still considered fresh.
    """
    # Remove entries from the front (oldest) while the oldest entry is expired.
    # The loop terminates when the store is empty or the oldest entry is fresh.
    while _jti_store and next(iter(_jti_store.values())) <= cutoff:
        _jti_store.popitem(last=False)


def enforce_max_store_size() -> None:
    """Evict the oldest JTI entries until the store fits its size cap.

    This is a safety fallback that prevents unbounded memory growth in
    long-running processes. Entries are evicted FIFO (oldest first).
    """
    # While the store exceeds its maximum permitted size, evict the oldest
    # entry. This keeps memory usage bounded even if cleanup by TTL alone is
    # insufficient (e.g. if tokens are consumed faster than they expire).
    while len(_jti_store) > _MAX_JTI_STORE_SIZE:
        _jti_store.popitem(last=False)


def _cleanup_jti_store(now: float) -> None:
    """Remove expired JTIs from the store and enforce the maximum store size.

    Args:
        now: The current wall-clock time as a POSIX timestamp.
    """
    # Determine the cutoff below which all JTI entries are expired.
    cutoff = compute_cutoff_time(now=now)

    # Evict every entry older than the cutoff.
    pop_expired_jti_items(cutoff=cutoff)

    # Enforce the size cap as a fallback to bound memory usage.
    enforce_max_store_size()


def acquire_jti_lock() -> None:
    """Acquire the process-private lock guarding the JTI store.

    The lock must be held for the entire check-then-record operation on
    ``_jti_store`` so that concurrent decoders observe a consistent state and
    cannot both succeed in recording the same ``jti``.
    """
    _jti_lock.acquire()


def cleanup_store(now: float) -> None:
    """Clean expired and oversized entries from the JTI store.

    Args:
        now: The current wall-clock time as a POSIX timestamp.
    """
    _cleanup_jti_store(now=now)


def check_jti_already_seen(jti: str) -> bool:
    """Check whether a JWT ID is already present in the replay store.

    Args:
        jti: The JWT ID to check.

    Returns:
        True if the ``jti`` is already in the store (a replay), False
        otherwise.
    """
    if jti in _jti_store:
        return True
    return False


def record_jti_timestamp(jti: str, now: float) -> None:
    """Record a JWT ID in the replay store with the current timestamp.

    Recording the ``jti`` marks the token as consumed. Any later presentation
    of the same ``jti`` will be rejected as a replay.

    Args:
        jti: The JWT ID to record.
        now: The consumption timestamp as a POSIX timestamp.
    """
    _jti_store[jti] = now


def release_jti_lock() -> None:
    """Release the process-private lock guarding the JTI store.

    The lock is always released, even if an error occurs during the
    check-then-record operation, by the caller's use of try/finally.
    """
    _jti_lock.release()


def _check_and_record_jti(jti: str, now: float) -> bool:
    """Return True if JTI is new (not replayed), False if already seen.

    The operation is atomic with respect to other decoders because it holds
    ``_jti_lock`` for the entire check-then-record sequence. The steps are:

    1. acquire_jti_lock      - take the store lock.
    2. cleanup_store         - evict expired and oversized entries.
    3. check_jti_already_seen - return False if the jti is already present.
    4. record_jti_timestamp  - store the jti with the current time.
    5. release_jti_lock      - release the store lock (always, via finally).

    Args:
        jti: The JWT ID to check and record.
        now: The current wall-clock time as a POSIX timestamp.

    Returns:
        True if the ``jti`` was new and has been recorded; False if it was
        already present in the store.
    """
    acquire_jti_lock()

    try:
        cleanup_store(now=now)

        # If the jti is already in the store, this presentation is a replay.
        already_seen = check_jti_already_seen(jti=jti)
        if already_seen:
            return False

        # Record the jti so that any future presentation is rejected as a
        # replay. The store entry maps the jti to its consumption time.
        record_jti_timestamp(jti=jti, now=now)

        return True
    finally:
        release_jti_lock()


def reset_jti_store() -> None:
    """Clear the JTI replay store. Intended for tests only.

    The lock is held during the clear so that no concurrent decode operation
    observes a partially emptied store.
    """
    with _jti_lock:
        _jti_store.clear()
