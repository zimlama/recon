"""Token-bucket rate limiter (per-target, per-module)."""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from app.config import get_settings

settings = get_settings()


@dataclass
class _Bucket:
    """Token bucket state."""

    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float  # tokens per second


class RateLimiter:
    """Async token-bucket rate limiter.

    Usage:
        limiter = RateLimiter()
        await limiter.acquire("example.com", "subdomain_enum")
        # ... make the actual request
    """

    def __init__(self, default_rps: int | None = None, default_burst: int | None = None) -> None:
        self.default_rps = default_rps or settings.RATE_LIMIT_RECON_RPS
        self.default_burst = default_burst or settings.RATE_LIMIT_RECON_BURST
        self._buckets: dict[tuple[str, str], _Bucket] = defaultdict(self._new_bucket)
        # Initialize locks eagerly to prevent the race where two coroutines
        # missing on the same key each get a different asyncio.Lock and
        # bypass mutual exclusion. Creation is guarded by a sync lock so
        # concurrent coroutines (and threads) share the same per-key Lock.
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._lock_init_lock = threading.Lock()

    def _new_bucket(self) -> _Bucket:
        """Create a new token bucket with default settings."""
        now = time.monotonic()
        return _Bucket(
            tokens=float(self.default_burst),
            last_refill=now,
            capacity=float(self.default_burst),
            refill_rate=float(self.default_rps),
        )

    def _get_lock(self, key: tuple[str, str]) -> asyncio.Lock:
        """Return the asyncio.Lock for `key`, creating it under a sync lock.

        Without the sync lock, two coroutines that miss on `key` would each
        create a distinct asyncio.Lock, breaking mutual exclusion.
        """
        # Fast path: already initialized
        lock = self._locks.get(key)
        if lock is not None:
            return lock
        with self._lock_init_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
            return lock

    def _key(self, target: str, action: str) -> tuple[str, str]:
        """Build the bucket key."""
        return (target.lower(), action)

    async def acquire(self, target: str, action: str, tokens: int = 1) -> None:
        """Acquire `tokens` permits, blocking if necessary.

        Args:
            target: The target identifier (domain, IP)
            action: The action name (module name, or generic action)
            tokens: Number of permits to acquire (default 1)
        """
        key = self._key(target, action)
        async with self._get_lock(key):
            bucket = self._buckets[key]
            now = time.monotonic()

            # Refill
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + elapsed * bucket.refill_rate,
            )
            bucket.last_refill = now

            # Wait if not enough tokens
            if bucket.tokens < tokens:
                wait_time = (tokens - bucket.tokens) / bucket.refill_rate
                await asyncio.sleep(wait_time)
                bucket.tokens = 0
            else:
                bucket.tokens -= tokens

    def reset(self, target: str | None = None, action: str | None = None) -> None:
        """Reset buckets (for testing)."""
        if target is None and action is None:
            self._buckets.clear()
            return
        if target is not None and action is not None:
            key = self._key(target, action)
            self._buckets.pop(key, None)
            return
        # Partial reset not implemented; clear all
        self._buckets.clear()


__all__ = ["RateLimiter"]
