# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""429 response shape (REQ-INB-007).

Spec REQ-INB-007 acceptance:

> 429 response carries ``Retry-After`` header with integer ≥ 1;
> body JSON has exactly ``{"error", "retry_after_seconds",
> "endpoint", "scope"}``; ``endpoint`` matches the route path
> (e.g., ``/api/v1/auth/login``), not the raw URL.

Spec REQ-INB-007 also specifies:

> ``retry_after_seconds`` SHALL equal
> ``ceil((oldest_timestamp_in_deque + window_seconds) - now)``,
> lower-bounded at 1.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns


@pytest.fixture
def reject_app() -> Iterator[FastAPI]:
    """Tiny app at ``/api/v1/auth/login`` with a 2/min limit so 3rd call rejects."""
    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/api/v1/auth/login": (2, 60)})
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_429_has_retry_after_header(reject_app: FastAPI) -> None:
    """The 429 carries a ``Retry-After`` header with an integer ≥ 1.

    RFC 7231 §7.1.3 compliance — clients wait for seconds.
    """
    async with AsyncClient(
        transport=ASGITransport(app=reject_app), base_url="http://test"
    ) as ac:
        # Two requests succeed.
        for _ in range(2):
            assert (await ac.post("/api/v1/auth/login")).status_code == 200
        # Third rejects.
        r = await ac.post("/api/v1/auth/login")
        assert r.status_code == 429
        assert "Retry-After" in r.headers, f"Missing Retry-After in headers {dict(r.headers)!r}"
        retry = int(r.headers["Retry-After"])
        assert retry >= 1, f"Retry-After must be >= 1, got {retry}"


@pytest.mark.asyncio
async def test_429_body_has_four_exact_keys(reject_app: FastAPI) -> None:
    """Body JSON has exactly ``{error, retry_after_seconds, endpoint, scope}``."""
    async with AsyncClient(
        transport=ASGITransport(app=reject_app), base_url="http://test"
    ) as ac:
        for _ in range(2):
            await ac.post("/api/v1/auth/login")
        r = await ac.post("/api/v1/auth/login")
        assert r.status_code == 429
        body = r.json()
        assert set(body.keys()) == {"error", "retry_after_seconds", "endpoint", "scope"}, (
            f"Expected exactly 4 keys, got {set(body.keys())}"
        )
        assert body["error"] == "rate_limited"
        assert isinstance(body["retry_after_seconds"], int)
        assert body["retry_after_seconds"] >= 1


@pytest.mark.asyncio
async def test_429_endpoint_is_matched_route_path_not_raw_url(reject_app: FastAPI) -> None:
    """``endpoint`` is the matched-template regex key — not the request URL."""
    async with AsyncClient(
        transport=ASGITransport(app=reject_app), base_url="http://test"
    ) as ac:
        for _ in range(2):
            await ac.post("/api/v1/auth/login")
        r = await ac.post("/api/v1/auth/login?injected=true")  # query string
        body = r.json()
        # No query string in the response — only the matched pattern.
        assert "?" not in body["endpoint"], (
            f"endpoint must not include query string; got {body['endpoint']}"
        )
        # The endpoint is the regex pattern itself (the canonical
        # lookup key for the per-endpoint policy).
        assert body["endpoint"] == r"^/api/v1/auth/login$"


@pytest.mark.asyncio
async def test_429_retry_after_exact_when_window_unelapsed() -> None:
    """At the reject moment, ``retry_after_seconds == window``.

    With a 30-second window: first request ticks, second at the same
    frozen clock instant rejects with retry_after=30.
    """
    from app.ratelimit import RateLimiter
    from app.ratelimit import RateLimitMiddleware as _RateLimitMiddleware

    clock = [100.0]
    limiter = RateLimiter(clock=lambda: clock[0])
    limiter.configure({("ip", "^/api/v1/auth/login$"): (1, 30)})

    app = FastAPI()
    app.state.rate_limit_patterns = compile_rate_limit_patterns(
        {"/api/v1/auth/login": (1, 30)},
    )

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(_RateLimitMiddleware, clock=lambda: clock[0], limiter=limiter)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r1 = await ac.post("/api/v1/auth/login")
        r2 = await ac.post("/api/v1/auth/login")
        assert r1.status_code == 200
        assert r2.status_code == 429
        body = r2.json()
        assert body["retry_after_seconds"] == 30
        assert r2.headers["Retry-After"] == "30"


__all__: list[str] = []
