# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Strict-TDD tests for ``RateLimiter`` storage (REQ-INB-002, 003, 013).

The storage contract is the foundation: a per-(scope, key, endpoint)
``deque`` with ``maxlen = requests_limit * 2``, lazy-eviction at insert
time, and the reject-iff-len condition. Every REQ-INB-NNN that touches
counting relies on these properties, so they get their own file.
"""
from __future__ import annotations

from collections import deque

import pytest

from app.ratelimit import RateLimiter


def test_buckets_is_dict_keyed_by_triple() -> None:
    """REQ-INB-002: ``_buckets`` is the canonical key-triple dict."""
    rl = RateLimiter(policies={("ip", "/x"): (5, 60)})
    rl.is_allowed("ip", "1.2.3.4", "/x")
    key = ("ip", "1.2.3.4", "/x")
    assert key in rl.buckets
    assert isinstance(rl.buckets[key], deque)


def test_deque_has_maxlen_equal_to_limit_times_two() -> None:
    """REQ-INB-013: ``maxlen = requests_limit * 2`` per deque.

    Hard memory bound — even a flood of distinct IPs cannot push a
    single deque past ``2 * limit`` timestamps.
    """
    rl = RateLimiter(policies={("ip", "/x"): (5, 60)})
    rl.is_allowed("ip", "1.2.3.4", "/x")
    dq = rl.buckets[("ip", "1.2.3.4", "/x")]
    assert dq.maxlen == 5 * 2, f"maxlen={dq.maxlen!r}"


def test_lazy_evict_drops_stale_entries_before_check() -> None:
    """REQ-INB-003: entries older than ``now - window`` are popleft'd
    on every call. Walk a deque forward one window then re-assert
    allowed — proves eviction actually happened.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (3, 60)},
    )
    # Three requests at t=100 fill the limit.
    for _ in range(3):
        allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
        assert allowed is True
    # Fourth at t=100 is over limit.
    allowed, retry = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False
    assert retry == 60
    # Advance beyond the window — lazy eviction should drain the deque.
    clock[0] += 61
    allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is True, "Lazy eviction should reset the bucket"


def test_reject_iff_len_at_or_over_limit() -> None:
    """REQ-INB-003: the reject condition is ``len(dq) >= limit``.

    Boundary behavior — exactly ``limit`` accepts, ``limit+1`` rejects.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (2, 60)},
    )
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False, "Third request must reject at limit=2"


def test_retry_after_floor_is_one() -> None:
    """REQ-INB-007 / MED-4: ``retry_after_seconds`` is always ``>= 1``.

    When the deque is nearly full and ``now`` is close to ``dq[0] +
    window``, raw ``ceil`` could yield 0 or negative — those MUST be
    clamped to 1.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (1, 60)},
    )
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    # t=159.9 → retry = ceil(100+60-159.9) = ceil(0.1) = 1
    clock[0] = 159.9
    allowed, retry = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False
    assert retry >= 1, f"retry_after_seconds must be >= 1 (got {retry})"


def test_retry_after_exact_window() -> None:
    """At the exact boundary, ``retry_after`` is ``window`` seconds."""
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (1, 60)},
    )
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    # Same clock — retry = ceil(100 + 60 - 100) = 60
    allowed, retry = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False
    assert retry == 60, f"retry should be exactly 60 at t=100, got {retry}"


def test_per_key_isolation() -> None:
    """REQ-INB-004 / 005 outline: a fresh key starts with an empty deque."""
    rl = RateLimiter(policies={("ip", "/x"): (1, 60)})
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    assert rl.is_allowed("ip", "5.6.7.8", "/x")[0] is True
    # First key now exhausted; second one still alive.
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is False
    assert rl.is_allowed("ip", "5.6.7.8", "/x")[0] is False


def test_unknown_scope_endpoint_is_fail_open() -> None:
    """REQ-INB-016 #3: a (scope, endpoint) NOT in the policy map fails open.

    The middleware must NOT raise when an endpoint is missing from
    ``Settings.RATE_LIMITS`` — it routes around the limiter.
    """
    rl = RateLimiter(policies={("ip", "/x"): (1, 60)})
    allowed, retry = rl.is_allowed("ip", "1.2.3.4", "/unmatched")
    assert allowed is True
    assert retry is None
    # No bucket was created for the unmatched path.
    assert ("ip", "1.2.3.4", "/unmatched") not in rl.buckets


@pytest.mark.parametrize("scope", ["ip", "user"])
def test_count_it_false_skips_append(scope: str) -> None:
    """REQ-INB-009 (G2) + design.md §Decision K: ``count_it=False`` does
    not extend the deque.

    Used by the per-user post-call phase so 4xx responses don't
    count against the limit.
    """
    rl = RateLimiter(policies={(scope, "/x"): (5, 60)})
    rl.is_allowed(scope, "k", "/x", count_it=False)
    rl.is_allowed(scope, "k", "/x", count_it=False)
    rl.is_allowed(scope, "k", "/x", count_it=False)
    # Deque stays empty — three attempts shouldn't burn budget.
    dq = rl.buckets[(scope, "k", "/x")]
    assert len(dq) == 0, f"count_it=False must not append; dq has {len(dq)}"


__all__: list[str] = []
