# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Inbound rate limiting (PR-J3.6 — sec-auth-jwt follow-up).

Public surface re-exported so callers do::

    from app.ratelimit import RateLimiter, RateLimitMiddleware, get_clock

The actual storage + middleware live in :mod:`app.ratelimit.inbound`.
The outbound token-bucket concern (init ``REQ-004``) is unchanged and
intentionally NOT exposed by this package — it lives at
:mod:`app.orchestrator.rate_limiter` per the project convention.
"""
from __future__ import annotations

from app.ratelimit.inbound import (
    RateLimiter,
    RateLimitMiddleware,
    compile_rate_limit_patterns,
    get_clock,
)

__all__ = [
    "RateLimitMiddleware",
    "RateLimiter",
    "compile_rate_limit_patterns",
    "get_clock",
]
