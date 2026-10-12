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

    def check(self, key: str, limit: int) -> RateLimitDecision:
        """Record a hit for ``key`` and report whether it is within ``limit``.

        A rejected hit is *not* recorded, so a client that keeps hammering a
        closed window is not punished forever; it recovers as soon as enough
        time has passed.
        """
        if limit <= 0:
            return RateLimitDecision(allowed=True, limit=limit, remaining=limit, retry_after=0)

        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket()
                self._buckets[key] = bucket
            self._buckets.move_to_end(key)

            cutoff = now - self._window
            while bucket.hits and bucket.hits[0] <= cutoff:
                bucket.hits.popleft()

            bucket.last_seen = now
            if len(bucket.hits) >= limit:
                oldest = bucket.hits[0]
                retry_after = max(1, math.ceil(self._window - (now - oldest)))
                return RateLimitDecision(
                    allowed=False, limit=limit, remaining=0, retry_after=retry_after
                )

            bucket.hits.append(now)
            self._evict_locked(now)
            remaining = limit - len(bucket.hits)
            return RateLimitDecision(
                allowed=True, limit=limit, remaining=remaining, retry_after=0
            )

    def _evict_locked(self, now: float) -> None:
        """Drop idle buckets, then the least recently used ones if still over cap."""
        if len(self._buckets) <= self._max_buckets:
            return

        for key in [k for k, b in self._buckets.items() if now - b.last_seen > self._idle_eviction]:
            del self._buckets[key]

        while len(self._buckets) > self._max_buckets:
            self._buckets.popitem(last=False)

    def reset(self) -> None:
        """Forget every counter. Intended for tests and administrative reloads."""
        with self._lock:
            self._buckets.clear()

    def bucket_count(self) -> int:
        """Return the number of live buckets, for tests and diagnostics."""
        with self._lock:
            return len(self._buckets)


limiter = SlidingWindowLimiter()
