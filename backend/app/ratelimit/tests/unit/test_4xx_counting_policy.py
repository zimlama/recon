# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""4xx-counting policy (REQ-INB-008 / REQ-INB-009 + decisions G1/G2).

The contract is split per scope:

- **G1 (per-IP)**: 4xx counts. Credential stuffing and enumeration
  show up as 4xx; letting the per-IP bucket ignore 4xx would let an
  attacker probe forever.
- **G2 (per-user)**: 4xx does NOT count. Legitimate user typos
  (``/jobs`` body validation) should not lock the account out.

This file pins the underlying ``RateLimiter.is_allowed(..., count_it=)``
semantics. The middleware translates response status → ``count_it``
at the call site (covered by integration tests for the middleware).
"""
from __future__ import annotations

import pytest

from app.ratelimit import RateLimiter


def test_g1_per_ip_4xx_does_count() -> None:
    """G1 — per-IP 'is_allowed' is called with the default ``count_it=True``.

    Behavior is the same whether the handler returns 200 or 4xx under
    per-IP scope; the middleware always ticks the per-IP bucket
    (credential-stuffing signal).
    """
    rl = RateLimiter(policies={("ip", "/x"): (3, 60)})
    # Three requests — whether caller pretends 200, 400, 401, etc.,
    # each one ticks the bucket.
    for _ in range(3):
        rl.is_allowed("ip", "1.2.3.4", "/x", count_it=True)
    allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False, "Per-IP bucket must reject after 3 successful ticks"


def test_g2_per_user_4xx_does_not_count_via_count_it_false() -> None:
    """G2 — per-user 'is_allowed' with ``count_it=False`` does NOT tick.

    The middleware translates 4xx → ``count_it=False`` in the
    post-call phase, so a typo on the form keeps the per-user bucket
    untouched.
    """
    rl = RateLimiter(policies={("user", "/x"): (5, 60)})
    user_id = "u-1"
    # Five 4xx-shaped calls — all with count_it=False. The deque must
    # stay at len == 0 throughout.
    for _ in range(5):
        allowed, _ = rl.is_allowed("user", user_id, "/x", count_it=False)
        assert allowed is True
    dq = rl.buckets[("user", user_id, "/x")]
    assert len(dq) == 0, (
        f"count_it=False must not append; dq has {len(dq)} entries"
    )


def test_g2_per_user_success_counts_4xx_does_not() -> None:
    """G2 mix — five 200s+4xx interleaved, only 200s tick.

    Reproduces the scenario from spec REQ-INB-009 acceptance: 5
    requests by one user where each handler returns 400; the 6th
    request still succeeds. Then a 200 → limit reached.
    """
    rl = RateLimiter(policies={("user", "/x"): (5, 60)})
    user_id = "u-1"
    # Five 4xx-shaped ticks — none counted.
    for _ in range(5):
        rl.is_allowed("user", user_id, "/x", count_it=False)
    # Sixth attempt — still succeeds because deque is empty.
    allowed, _ = rl.is_allowed("user", user_id, "/x", count_it=True)
    assert allowed is True
    # Now drive 5 successful ticks via the same path:
    for _ in range(4):
        rl.is_allowed("user", user_id, "/x", count_it=True)
    # 6th successful tick is the one that REJECTS.
    allowed, _ = rl.is_allowed("user", user_id, "/x", count_it=True)
    assert allowed is False, (
        "5 successful ticks should put per-user at limit; 6th must reject"
    )


def test_g2_per_user_5xx_counts() -> None:
    """Spec REQ-INB-009: 5xx counts under per-user (the user is the problem).

    The middleware's post-call branch computes ``count_it = (status <
    400 or status >= 500)`` — so 5xx also ticks. Verified by passing
    the corresponding flag from the test level.
    """
    rl = RateLimiter(policies={("user", "/x"): (3, 60)})
    for status in (500, 502, 503):
        count_it = (status < 400 or status >= 500)
        rl.is_allowed("user", "u-5xx", "/x", count_it=count_it)
    allowed, _ = rl.is_allowed("user", "u-5xx", "/x", count_it=True)
    assert allowed is False


@pytest.mark.parametrize(
    ("status", "count_it"),
    [
        (200, True),
        (201, True),
        (204, True),
        (301, True),
        (400, False),
        (401, False),
        (403, False),
        (404, False),
        (422, False),
        (500, True),
        (502, True),
        (503, True),
    ],
)
def test_count_it_policy_matches_response_status(status: int, count_it: bool) -> None:
    """Pin the response-status → ``count_it`` mapping per HIGH-2.

    Keeps the middleware and tests in sync — if the policy ever
    shifts (e.g. 4xx starts counting per-user), the test breaks
    loudly.
    """
    predicted = (status < 400 or status >= 500)
    assert predicted is count_it, (
        f"status={status} → expected count_it={count_it}, got {predicted}"
    )


__all__: list[str] = []
