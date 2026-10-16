# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the inbound rate-limit test suite (PR-J3.6).

Three fixtures the per-test files reuse:

- ``frozen_clock`` — a callable ``() -> float`` whose value advances
  only via ``.advance(seconds)``. Lets unit tests skip wall-clock time
  entirely (spec REQ-INB-014 — no ``freezegun`` / ``time-machine``).
- ``tiny_rate_limiter`` — a ``RateLimiter`` constructed against the
  frozen clock with a 5-request / 60-second policy so the
  4xx-counting-policy and dual-counter tests have a consistent budget.
- ``app_with_rate_limit`` — minimal FastAPI app with one default
  endpoint (``/api/v1/auth/login``) plus a per-test ``Clock``
  dependency override. Returns ``(app, frozen_clock)`` so the test
  can advance the clock mid-test.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI, Request

from app.ratelimit import RateLimiter, get_clock


class FrozenClock:
    """Mutable monotonic clock. Tests call ``.advance(seconds)``."""

    def __init__(self, initial: float = 1_000.0) -> None:
        self.now = float(initial)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


@pytest.fixture
def frozen_clock() -> FrozenClock:
    """A clock that only moves when a test asks."""
    return FrozenClock(initial=1_000.0)


@pytest.fixture
def tiny_rate_limiter(frozen_clock: FrozenClock) -> RateLimiter:
    """A ``RateLimiter`` with a tiny 5-request / 60-second budget."""
    return RateLimiter(clock=frozen_clock)


@pytest.fixture
def app_with_rate_limit(
    frozen_clock: FrozenClock,
) -> Iterator[tuple[FastAPI, FrozenClock]]:
    """Yield ``(app, frozen_clock)`` for tests that exercise middleware.

    Wires a single dummy POST route at ``/api/v1/auth/login`` plus the
    ``get_clock`` dependency override so the middleware reads the
    frozen clock instead of ``time.monotonic``. Returns the clock so
    the test can advance time without monkey-patching.
    """
    app = FastAPI()

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    # Inline import — the package may not exist at conftest load time
    # in CI environments that collect tests in isolation.
    from app.ratelimit.inbound import RateLimitMiddleware

    app.add_middleware(
        RateLimitMiddleware,
        clock=lambda: frozen_clock(),
    )
    app.dependency_overrides[get_clock] = lambda: lambda: frozen_clock()
    yield app, frozen_clock
    app.dependency_overrides.clear()


__all__: list[Any] = ["FrozenClock", "app_with_rate_limit", "frozen_clock", "tiny_rate_limiter"]
