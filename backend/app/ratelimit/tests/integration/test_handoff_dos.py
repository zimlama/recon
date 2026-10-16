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


@pytest.mark.asyncio
async def test_download_sliding_window_recovers_after_clock_advance() -> None:
    """REQ-INB-019 Scenario 2: sliding-window eviction allows
    recovery after the window passes.

    Acceptance: with the per-user bucket at limit (10 entries for
    user U within 0..60s), advancing the clock by ``window+1`` (an
    injected clock per REQ-INB-014) causes the next request to be
    accepted — the lazy-evict step in ``RateLimiter.is_allowed``
    (REQ-INB-013) drops all 10 stale timestamps and the new request
    lands in an empty deque.

    Implementation note: the limiter is constructed with
    ``clock=lambda: clock[0]`` (the same pattern as
    ``test_429_retry_after_exact_when_window_unelapsed`` and
    ``test_injected_clock_drives_window_decisions``) so the
    advance is deterministic — no wall-clock dependency. The
    middleware is constructed with the same injected limiter via
    the ``limiter=...`` kwarg so both the pre-call per-IP check
    and the post-call per-user check consult the frozen clock.
    """
    from app.ratelimit import RateLimiter

    clock = [100.0]
    limiter = RateLimiter(clock=lambda: clock[0])

    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/handoff/download": (DOWNLOAD_LIMIT, WINDOW_SECONDS),
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
        return {"status": "ok", "job_id": job_id}

    user_id = "u-dos-clock"
    app.add_middleware(_JWTMiddleware, user_id=user_id)
    # ``limiter=limiter`` shares the clock-injected limiter with the
    # middleware; ``clock=...`` is also passed so the middleware's
    # own ``RateLimiter`` would honor the clock if a fallback path
    # exercised it (defensive — the limiter is the one actually used).
    app.add_middleware(RateLimitMiddleware, clock=lambda: clock[0], limiter=limiter)

    endpoint_key = r"^/api/v1/jobs/[^/]+/handoff/download$"

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Phase 1: fill the bucket with DOWNLOAD_LIMIT (= 10)
        # successful requests at frozen clock = 100. Both per-IP and
        # per-user buckets tick in lock-step.
        for _ in range(DOWNLOAD_LIMIT):
            r = await ac.get("/api/v1/jobs/abc/handoff/download")
            assert r.status_code == 200, (
                f"First {DOWNLOAD_LIMIT} download requests must succeed; "
                f"got {r.status_code}: {r.text}"
            )
        # 11th request at the SAME frozen clock — bucket full, reject.
        # This is a sanity check that the limiter is actually using the
        # injected clock (a non-injected limiter would auto-advance
        # and let the request through).
        r = await ac.get("/api/v1/jobs/abc/handoff/download")
        assert r.status_code == 429, (
            f"11th download at frozen clock={clock[0]} must reject with 429; "
            f"got {r.status_code}: {r.text}"
        )
        # Phase 2: advance the clock past the window boundary. The
        # lazy-evict step in ``RateLimiter.is_allowed`` (REQ-INB-013)
        # drops every timestamp older than ``now - window``; with
        # ``now=161`` and ``window=60`` the threshold is 101 — every
        # entry at t=100 is stale and gets popleft'd.
        clock[0] += WINDOW_SECONDS + 1  # 100 -> 161, past the 60s window
        # Next request — bucket drained, allowed. This is the
        # recovery acceptance (REQ-INB-019 Scenario 2).
        r = await ac.get("/api/v1/jobs/abc/handoff/download")
        assert r.status_code == 200, (
            f"After clock advance by window+1 ({WINDOW_SECONDS + 1}s), "
            f"lazy eviction must drain the bucket and accept. "
            f"Got {r.status_code}: {r.text}"
        )
        # Phase 3: pin the bucket state. After 10 stale entries were
        # evicted and 1 fresh entry appended at t=161, the per-user
        # deque MUST contain exactly 1 entry — proves the recovery
        # went through the same lazy-evict path that REQ-INB-013
        # guarantees (and that no stale entries leak through).
        user_bucket = limiter.buckets[("user", user_id, endpoint_key)]
        assert user_bucket is not None, (
            f"Per-user bucket must exist after recovery; buckets={list(limiter.buckets)!r}"
        )
        assert len(user_bucket) == 1, (
            f"After lazy eviction + 1 new entry, per-user bucket must have "
            f"exactly 1 entry. Got {len(user_bucket)}: {list(user_bucket)!r}"
        )
        # And the single remaining entry must be at the post-advance
        # timestamp (proves the stale entries were actually dropped,
        # not silently retained).
        remaining = next(iter(user_bucket))
        assert remaining == clock[0], (
            f"Single remaining entry must be at post-advance clock={clock[0]}; "
            f"got {remaining!r}"
        )


__all__: list[str] = []
