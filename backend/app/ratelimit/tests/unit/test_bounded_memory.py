# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Bounded-memory invariant (REQ-INB-013 / decision K).

The deque's ``maxlen = requests_limit * 2`` is the only memory ceiling
(no lifespan sweep per design.md §Decision K). This file proves the
invariant holds against:

1. A single (key, endpoint) hammered harder than the limit.
2. A flood of distinct keys hitting the same endpoint.
3. Cross-(scope, endpoint) isolation under flood (per-IP and per-user
   buckets stay disjoint).
"""
from __future__ import annotations

from app.ratelimit import RateLimiter


def test_single_deque_never_exceeds_maxlen() -> None:
    """REQ-INB-013: a single (scope, key, endpoint) deque caps at
    ``limit * 2`` regardless of how many requests fire.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (3, 60)},
    )
    # 10 000 requests, all on the same key, all at the same
    # frozen-clock tick — the deque should NEVER exceed ``3 * 2 = 6``
    # because `maxlen` auto-evicts on append.
    for _ in range(10_000):
        rl.is_allowed("ip", "1.2.3.4", "/x")
    dq = rl.buckets[("ip", "1.2.3.4", "/x")]
    assert dq.maxlen == 6
    assert len(dq) <= 6, f"Dequeued len should be <= 6, got {len(dq)}"


def test_ten_thousand_distinct_ips_remain_bounded() -> None:
    """REQ-INB-013: 10 000 distinct IPs → bounded total bucket count.

    Decision K / design.md tables worst-case memory at ~800 KB for
    N=10 000. We do not measure bytes — we measure the count of
    deques created, which must equal the count of distinct IPs (one
    deque per (scope, key, endpoint) triple).
    """
    rl = RateLimiter(policies={("ip", "/x"): (5, 60)})
    for i in range(10_000):
        ip = f"10.0.{i // 256}.{i % 256}"
        rl.is_allowed("ip", ip, "/x")
    # 10 000 deques, each with maxlen=10 → very rough upper bound.
    assert len(rl.buckets) == 10_000, (
        f"Expected 10 000 deques, got {len(rl.buckets)}"
    )
    # Each deque must respect maxlen.
    for dq in rl.buckets.values():
        assert dq.maxlen == 10, f"maxlen mismatch: {dq.maxlen}"
        assert len(dq) <= 10


def test_cross_scope_disjoint_buckets() -> None:
    """Per-user ticks do not extend the per-IP deque and vice-versa.

    Spec REQ-INB-005 dual-counter: a single request can touch BOTH
    scopes (pre-auth per-IP, post-auth per-user), but the storage
    remains disjoint so 100 per-user hits don't drain the per-IP
    budget.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (3, 60), ("user", "/x"): (5, 60)},
    )
    rl.is_allowed("ip", "1.2.3.4", "/x")
    rl.is_allowed("user", "u-1", "/x")
    rl.is_allowed("user", "u-1", "/x")
    rl.is_allowed("user", "u-1", "/x")
    assert len(rl.buckets[("ip", "1.2.3.4", "/x")]) == 1
    assert len(rl.buckets[("user", "u-1", "/x")]) == 3


def test_deque_recycled_under_clock_advance() -> None:
    """A long-running limiter does not balloon — the deques stay
    small because lazy eviction + maxlen collaborate.

    Drive 1 000 requests in waves of (limit + 10). After each wave,
    the deque MUST be re-populated but never exceed maxlen.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (5, 60)},
    )
    for wave in range(10):
        # Wave — fire ``limit + 10`` requests, all reject.
        for _ in range(15):
            rl.is_allowed("ip", "1.2.3.4", "/x")
        # Advance the clock beyond the window so the deque drains.
        clock[0] += 120
        # Refill — exactly ``limit`` are accepted, the ``limit+1``th rejects.
        for _ in range(5):
            allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
            assert allowed is True, f"Wave {wave}: refill tick should pass"
        allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
        assert allowed is False, f"Wave {wave}: limit+1 must reject"
        dq = rl.buckets[("ip", "1.2.3.4", "/x")]
        assert dq.maxlen == 10
        assert len(dq) <= 10


__all__: list[str] = []
