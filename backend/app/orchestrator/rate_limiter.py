# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Token-bucket rate limiter (per-target, per-module).

Backed by an `OrderedDict` with an LRU cap on distinct
``(target, module)`` keys (audit R4-H5). Long-running processes that
acquire on thousands of different targets no longer grow the bucket
map without bound — when ``max_keys`` is reached, the least-recently-
used entry is evicted before a new one is inserted.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

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
    """Async token-bucket rate limiter with bounded LRU bucket dict.

    Usage::

        limiter = RateLimiter()
        await limiter.acquire("example.com", "subdomain_enum")

    The internal bucket map holds at most ``max_keys`` entries
    (default 10_000). When an ``acquire`` call would exceed the cap,
    the oldest un-accessed entry is evicted first.
    """

    def __init__(
        self,
        default_rps: int | None = None,
        default_burst: int | None = None,
        max_keys: int | None = None,
    ) -> None:
        self.default_rps = default_rps or settings.RATE_LIMIT_RECON_RPS
        self.default_burst = default_burst or settings.RATE_LIMIT_RECON_BURST
        # OrderedDict preserves insertion order; ``move_to_end()`` at
        # touch time keeps the LRU at the front of the dict.
        self._buckets: "OrderedDict[tuple[str, str], _Bucket]" = OrderedDict()
        # Per-key asyncio.Lock to serialize acquire() calls on a key.
        # Created lazily + guarded by a sync lock to avoid the
        # ``defaultdict(asyncio.Lock)`` race (each coroutine that
        # misses would otherwise get its own Lock).
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._lock_init_lock = threading.Lock()
        # Audit R4-H5 cap — read from settings if not supplied so tests
        # can override either side.
        self._max_keys: int = max_keys or settings.RATE_LIMITER_MAX_KEYS

    # ---- Internal helpers ----

    def _new_bucket(self) -> _Bucket:
        """Create a new token bucket with default settings."""
        now = time.monotonic()
        return _Bucket(
            tokens=float(self.default_burst),
            last_refill=now,
            capacity=float(self.default_burst),
            refill_rate=float(self.default_rps),
        )

    def _touch(self, key: tuple[str, str]) -> None:
        """Mark ``key`` as recently used (move to end of OrderedDict)."""
        if key in self._buckets:
            self._buckets.move_to_end(key)

    def _evict_lru(self) -> None:
        """Pop the least-recently-used bucket to honor ``_max_keys`` cap."""
        if self._buckets:
            oldest_key, _ = self._buckets.popitem(last=False)
            self._locks.pop(oldest_key, None)

    def _get_bucket(self, key: tuple[str, str]) -> _Bucket:
        """Return the bucket for ``key``, creating + LRU-evicting if needed."""
        bucket = self._buckets.get(key)
        if bucket is not None:
            self._touch(key)
            return bucket
        # Cap enforcement: evict one if we're at the boundary.
        if len(self._buckets) >= self._max_keys:
            self._evict_lru()
        bucket = self._new_bucket()
        self._buckets[key] = bucket
        self._touch(key)
        return bucket

    def _get_lock(self, key: tuple[str, str]) -> asyncio.Lock:
        """Return the asyncio.Lock for ``key``, creating it under a sync lock.

        Without the sync lock, two coroutines that miss on ``key`` would each
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

    # ---- Public API ----

    async def acquire(
        self, target: str, action: str, tokens: int = 1
    ) -> None:
        """Acquire ``tokens`` permits, blocking if necessary.

        Args:
            target: The target identifier (domain, IP)
            action: The action name (module name, or generic action)
            tokens: Number of permits to acquire (default 1)
        """
        key = self._key(target, action)
        async with self._get_lock(key):
            bucket = self._get_bucket(key)
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

    def reset(
        self, target: str | None = None, action: str | None = None
    ) -> None:
        """Reset buckets (for testing)."""
        if target is None and action is None:
            self._buckets.clear()
            self._locks.clear()
            return
        if target is not None and action is not None:
            key = self._key(target, action)
            self._buckets.pop(key, None)
            self._locks.pop(key, None)
            return
        # Partial reset not implemented; clear all
        self._buckets.clear()
        self._locks.clear()

    def __len__(self) -> int:
        """Return the current number of tracked buckets."""
        return len(self._buckets)


__all__ = ["RateLimiter"]
