# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""DOS harness for the handoff rate-limit (PR-J3.6.5, Issue #60).

Threat T2 (worker starvation via repeated ``FileResponse`` of ~MB
JSON) drives the per-user cap on ``/api/v1/jobs/{job_id}/handoff/download``
to ``(10, 60)`` — the tightest entry in the inbound rate-limit
table. The DOS harness proves that cap by hammering the route from
a single authenticated user; the 11th request MUST reject with 429.

Tests are scoped to the limiter alone — no real handoff exports, no
DB. The route handler returns a 200 JSON stub; the middleware does
not care about the payload. The 200/429 transitions are what we
pin.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns

# Default cap from ``Settings.RATE_LIMITS`` for the download route.
# The proposal pins ``(10, 60)`` — exactly 10 requests per minute.
DOWNLOAD_LIMIT = 10
WINDOW_SECONDS = 60


@pytest.fixture
def handoff_download_app() -> Iterator[FastAPI]:
    """Handoff download route at the proposal-pinned ``(10, 60)`` cap.

    The middleware is the only thing under test — the handler is a
    JSON stub. Per-IP is permissive (100) so the per-user side is
    the binding constraint for a SINGLE user behind a SINGLE IP.
    """
    app = FastAPI()
    # Two-route policy: the download route has the production
    # ``(10, 60)`` cap; the cancel route is the permissive per-IP
    # decoy so the per-IP side never binds the test (the per-IP
    # bucket would otherwise reject after 10 ticks and obscure the
    # per-user rejection on the 11th).
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/handoff/download": (DOWNLOAD_LIMIT, WINDOW_SECONDS),
        "/api/v1/jobs/{job_id}/cancel": (100, 60),
    })
    app.state.rate_limit_patterns = patterns

    class _JWTMiddleware:
        def __init__(self, app, *, user_id: str) -> None:
            self.app = app
            self._user_id = user_id

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] == "http":
                from starlette.requests import Request as StarletteRequest

                req = StarletteRequest(scope, receive)
                req.state.user_id = self._user_id
                req.state.auth_method = "jwt"
                req.state.username = "alice"
                req.state.jwt_jti = None
            await self.app(scope, receive, send)

    @app.get("/api/v1/jobs/{job_id}/handoff/download")
    async def _download(request: Request, job_id: str) -> dict[str, str]:
        # Stub body — production uses FileResponse (~MB JSON) but the
        # middleware cares about status codes, not payload size.
        return {"status": "ok", "job_id": job_id}

    # Decoy cancel route — never called by this test, but the
    # presence of an unrelated permissive route keeps per-IP from
    # rebinding the limit. Without it, the per-IP bucket would
    # also hit limit at 10 ticks and the test could not distinguish
    # per-user vs per-IP 429s.
    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    app.add_middleware(_JWTMiddleware, user_id="u-dos")
    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_eleventh_handoff_download_request_returns_429(
    handoff_download_app: FastAPI,
) -> None:
    """PR-J3.6.5 (Issue #60): the 11th ``/handoff/download`` request
    from one authenticated user MUST reject with 429.

    Pins the production cap ``(10, 60)`` for the download route.
    The first 10 requests succeed (200); the 11th rejects (429)
    with the documented body shape.
    """
    async with AsyncClient(
        transport=ASGITransport(app=handoff_download_app), base_url="http://test"
    ) as ac:
        statuses: list[int] = []
        bodies: list[dict[str, object]] = []
        for _ in range(11):
            r = await ac.get("/api/v1/jobs/abc/handoff/download")
            statuses.append(r.status_code)
            if r.status_code == 429:
                bodies.append(r.json())
        # First 10 pass; 11th rejects.
        assert statuses[:DOWNLOAD_LIMIT] == [200] * DOWNLOAD_LIMIT, (
            f"First {DOWNLOAD_LIMIT} requests must succeed; got {statuses!r}"
        )
        assert statuses[DOWNLOAD_LIMIT] == 429, (
            f"The 11th request must reject with 429; got status={statuses[DOWNLOAD_LIMIT]!r} "
            f"full sequence: {statuses!r}"
        )
        # Pin the body shape on the first 429.
        body = bodies[0]
        assert body["error"] == "rate_limited"
        assert int(body["retry_after_seconds"]) >= 1
        # Endpoint key matches the proposal — the regex string, not
        # the raw URL (decision M / spec REQ-INB-007).
        assert body["endpoint"] == r"^/api/v1/jobs/[^/]+/handoff/download$", (
            f"Endpoint key must be the regex string; got {body['endpoint']!r}"
        )
        assert body["scope"] in ("ip", "user")


@pytest.mark.asyncio
async def test_burst_beyond_cap_stays_rejected(
    handoff_download_app: FastAPI,
) -> None:
    """Beyond the cap, ALL further requests reject with 429 — the
    bucket does not drain until the window elapses.

    Fires 25 requests from one user in a single instant (no clock
    advance). The first 10 pass; the remaining 15 MUST all be 429.
    """
    async with AsyncClient(
        transport=ASGITransport(app=handoff_download_app), base_url="http://test"
    ) as ac:
        statuses: list[int] = []
        for _ in range(25):
            r = await ac.get("/api/v1/jobs/abc/handoff/download")
            statuses.append(r.status_code)
        n_ok = sum(1 for s in statuses if s == 200)
        n_429 = sum(1 for s in statuses if s == 429)
        assert n_ok == DOWNLOAD_LIMIT, (
            f"Exactly {DOWNLOAD_LIMIT} 200s allowed per window; got {n_ok}: {statuses!r}"
        )
        assert n_429 == 15, (
            f"Remaining 15 must all 429; got {n_429}: {statuses!r}"
        )


@pytest.mark.asyncio
async def test_handoff_packet_route_caps_at_120_per_minute() -> None:
    """PR-J3.6.5 (Issue #60): the packet endpoint has the most
    permissive cap ``(120, 60)`` — large enough for normal UI
    polling but tight enough to bound T3 (re-export amplification
    via missing ``file_path`` on packet route).

    The DOS harness above pins the 10/min download cap; this test
    pins the 120/min packet cap as a positive control. At 121
    requests, the 121st MUST reject.
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/handoff": (120, 60),
        # Decoy route keeps per-IP out of the way.
        "/api/v1/jobs/{job_id}/cancel": (1000, 60),
    })
    app.state.rate_limit_patterns = patterns

    class _JWTMiddleware:
        def __init__(self, app, *, user_id: str) -> None:
            self.app = app
            self._user_id = user_id

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] == "http":
                from starlette.requests import Request as StarletteRequest

                req = StarletteRequest(scope, receive)
                req.state.user_id = self._user_id
                req.state.auth_method = "jwt"
                req.state.username = "alice"
                req.state.jwt_jti = None
            await self.app(scope, receive, send)

    @app.get("/api/v1/jobs/{job_id}/handoff")
    async def _packet(request: Request, job_id: str) -> dict[str, str]:
        return {"status": "ok", "job_id": job_id}

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    app.add_middleware(_JWTMiddleware, user_id="u-pkt")
    app.add_middleware(RateLimitMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # 120 must succeed; 121st must reject.
        statuses: list[int] = []
        for _ in range(121):
            r = await ac.get("/api/v1/jobs/abc/handoff")
            statuses.append(r.status_code)
        assert statuses[:120] == [200] * 120, (
            f"First 120 packet requests must succeed; got {statuses!r}"
        )
        assert statuses[120] == 429, (
            f"The 121st packet request must reject with 429; got {statuses[120]!r}"
        )


__all__: list[str] = []
