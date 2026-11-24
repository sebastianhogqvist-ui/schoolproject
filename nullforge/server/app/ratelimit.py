"""In-process sliding-window rate limiting.

Counters are keyed by ``(route group, client IP)`` and stored as timestamps of
recent hits, so a fixed window's "burst at the boundary" problem does not exist:
the oldest hit expires exactly ``window_seconds`` after it happened.

Two properties matter for an untrusted caller:

* **Lock safety.** One ``threading.Lock`` guards the whole table, so concurrent
  requests cannot both read a stale length and both admit themselves.
* **Bounded memory.** Buckets are capped; the least recently used ones are
  evicted, so a flood of spoofed source addresses cannot grow the process
  without limit.

State is per process. A multi-worker deployment therefore enforces the limit per
worker, which is the correct trade for keeping this dependency-free.
"""

import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_MAX_BUCKETS = 4096
IDLE_EVICTION_SECONDS = 300.0

AUTH_GROUP = "auth"
ADMIN_LOGIN_GROUP = "admin_login"
ADMIN_API_GROUP = "admin_api"
KEYGEN_GROUP = "keygen"
KEYAUTH_GROUP = "keyauth"
SECURITY_EVENT_GROUP = "security_event"
INTEGRITY_GROUP = "integrity"

RATE_LIMIT_GROUPS = (
    AUTH_GROUP,
    ADMIN_LOGIN_GROUP,
    ADMIN_API_GROUP,
    KEYGEN_GROUP,
    KEYAUTH_GROUP,
    SECURITY_EVENT_GROUP,
    INTEGRITY_GROUP,
)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """The outcome of one limiter consultation."""

    allowed: bool
    limit: int
    remaining: int
    retry_after: int


@dataclass(slots=True)
class _Bucket:
    """One key's sliding window of hit timestamps."""

    hits: deque[float] = field(default_factory=deque)
    last_seen: float = 0.0


class SlidingWindowLimiter:
    """A thread-safe, memory-bounded sliding-window counter."""

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_buckets: int = DEFAULT_MAX_BUCKETS,
        idle_eviction_seconds: float = IDLE_EVICTION_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the window length, bucket cap and time source."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        if max_buckets < 1:
            raise ValueError("max_buckets must be at least one")
        self._window = window_seconds
        self._max_buckets = max_buckets
        self._idle_eviction = idle_eviction_seconds
        self._clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = threading.Lock()

    def validate_limit(self, limit: int) -> bool:
        """Return whether the supplied limit is usable.

        A non-positive limit is treated as a closed window, so the caller is
        always denied without recording a hit.
        """
        limit_is_positive = limit > 0
        return limit_is_positive

    def prune_old_hits(self, bucket: _Bucket, now: float) -> None:
        """Drop timestamps older than the sliding window.

        The window boundary is computed relative to ``now``. Hits at or before
        the cutoff have expired and are removed from the front of the deque.
        """
        cutoff = now - self._window
        has_hits = len(bucket.hits) > 0
        while has_hits:
            oldest_hit = bucket.hits[0]
            hit_is_expired = oldest_hit <= cutoff
            if not hit_is_expired:
                break
            bucket.hits.popleft()
            has_hits = len(bucket.hits) > 0

    def check_capacity(self, bucket: _Bucket, limit: int) -> bool:
        """Return whether the bucket is already at its configured limit."""
        current_hits = len(bucket.hits)
        at_capacity = current_hits >= limit
        return at_capacity

    def record_hit(self, bucket: _Bucket, now: float) -> None:
        """Record that the bucket was consulted at ``now``.

        Updating ``last_seen`` keeps the bucket eligible for idle eviction
        accounting even when the request is ultimately denied.
        """
        bucket.last_seen = now

    def record_new_hit(self, bucket: _Bucket, now: float) -> None:
        """Append a successful hit timestamp to the bucket's window."""
        bucket.hits.append(now)

    def evict_if_needed(self, now: float) -> None:
        """Run idle and LRU eviction when the bucket table is over cap."""
        self.evict_idle_buckets(now)
        self.evict_lru_buckets()

    def evict_idle_buckets(self, now: float) -> None:
        """Remove buckets idle longer than the configured eviction threshold."""
        if len(self._buckets) <= self._max_buckets:
            return
        idle_keys = []
        for key, bucket in self._buckets.items():
            idle_for = now - bucket.last_seen
            is_idle = idle_for > self._idle_eviction
            if is_idle:
                idle_keys.append(key)
        for key in idle_keys:
            del self._buckets[key]

    def evict_lru_buckets(self) -> None:
        """Pop least recently used buckets until the table is within cap."""
        while len(self._buckets) > self._max_buckets:
            self._buckets.popitem(last=False)

    def build_allowed_decision(self, limit: int, bucket: _Bucket) -> RateLimitDecision:
        """Construct the decision returned for an admitted request."""
        current_hits = len(bucket.hits)
        remaining = limit - current_hits
        allowed = True
        retry_after = 0
        decision = RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            retry_after=retry_after,
        )
        return decision

    def build_denied_decision(self, limit: int, retry_after: int) -> RateLimitDecision:
        """Construct the decision returned for a rejected request."""
        allowed = False
        remaining = 0
        decision = RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            retry_after=retry_after,
        )
        return decision

    def check(self, key: str, limit: int) -> RateLimitDecision:
        """Record a hit for ``key`` and report whether it is within ``limit``.

        A rejected hit is *not* recorded, so a client that keeps hammering a
        closed window is not punished forever; it recovers as soon as enough
        time has passed.
        """
        limit_is_valid = self.validate_limit(limit)
        if not limit_is_valid:
            denied_decision = self.build_denied_decision(
                limit=limit,
                retry_after=60,
            )
            return denied_decision

        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            bucket_is_missing = bucket is None
            if bucket_is_missing:
                bucket = _Bucket()
                self._buckets[key] = bucket
            self._buckets.move_to_end(key)

            self.prune_old_hits(bucket, now)
            self.record_hit(bucket, now)

            at_capacity = self.check_capacity(bucket, limit)
            if at_capacity:
                oldest = bucket.hits[0]
                window_span = now - oldest
                remaining_window = self._window - window_span
                retry_after_raw = math.ceil(remaining_window)
                retry_after = max(1, retry_after_raw)
                denied_decision = self.build_denied_decision(
                    limit=limit,
                    retry_after=retry_after,
                )
                return denied_decision

            self.record_new_hit(bucket, now)
            self.evict_if_needed(now)
            allowed_decision = self.build_allowed_decision(limit, bucket)
            return allowed_decision

    def _evict_locked(self, now: float) -> None:
        """Drop idle buckets, then the least recently used ones if still over cap."""
        self.evict_idle_buckets(now)
        self.evict_lru_buckets()

    def reset(self) -> None:
        """Forget every counter. Intended for tests and administrative reloads."""
        with self._lock:
            self._buckets.clear()

    def bucket_count(self) -> int:
        """Return the number of live buckets, for tests and diagnostics."""
        with self._lock:
            count = len(self._buckets)
            return count


limiter = SlidingWindowLimiter()
