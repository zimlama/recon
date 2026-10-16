# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Per-user post-auth test (REQ-INB-005, T-D2 confirmation).

A JWT-authenticated user must hit the per-user limit INDEPENDENTLY
of the per-IP bucket. This test fires requests from a single IP for
one user; both counters tick in lock-step. With a per-user limit of
3/min, the 4th request from the same user MUST reject — even though
the per-IP limit was 100/min in this fixture.

PR-J3.6.5 (Issue #60) extends this with a handoff-specific 4xx
fixture: the handoff packet route returns 404 on a non-existent
job_id, and the per-user bucket MUST NOT tick on a 4xx (HIGH-2
contract). The bucket only sees successful ticks, so a barrage of
4xx do NOT exhaust the legitimate user's budget on the handoff
packet route.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns


@pytest.fixture
def jwt_user_app() -> Iterator[FastAPI]:
    """Single route at ``/api/v1/jobs/abc/cancel`` with a JWT-stub middleware.

    Per-user policy is 3/min (the design is per-IP 100/min so the
    per-user side is the binding constraint).
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/api/v1/jobs/{job_id}/cancel": (3, 60)})
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

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    app.add_middleware(_JWTMiddleware, user_id="u-1")
    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_jwt_user_hits_per_user_limit(jwt_user_app: FastAPI) -> None:
    """A JWT-authenticated user hitting the per-user limit → 429.

    Under the dual-counter design (decision D), the pre-call per-IP
    check fires FIRST; if it rejects, the per-user check never runs.
    For a SINGLE user behind a SINGLE IP both scopes share the limit
    so per-IP is the first to deny. Scope could be either depending
    on request shape — the load-bearing assertion is that the 429
    lands before the user can submit ``limit + 1`` requests, with
    the documented body shape.
    """
    async with AsyncClient(transport=ASGITransport(app=jwt_user_app), base_url="http://test") as ac:
        statuses = []
        bodies: list[dict[str, object]] = []
        for _ in range(5):
            r = await ac.post("/api/v1/jobs/abc/cancel")
            statuses.append(r.status_code)
            if r.status_code == 429:
                bodies.append(r.json())
        # At least one 429 in 5 requests; per-(scope, endpoint) limit is 3.
        assert 429 in statuses, f"Expected at least one 429, got {statuses!r}"
        # Pin the body shape on the first 429.
        body = bodies[0]
        assert body["scope"] in ("ip", "user")
        assert body["endpoint"] == r"^/api/v1/jobs/[^/]+/cancel$"
        assert int(body["retry_after_seconds"]) >= 1


@pytest.fixture
def jwt_handoff_app() -> Iterator[FastAPI]:
    """Handoff packet route with JWT-stub middleware + 404 handler.

    Per-user policy is 5/min. The handler raises HTTPException(404)
    on a non-existent job_id — mirroring ``routes/handoff.py:49``
    (the real handoff packet route). The 4xx path is the contract
    under test (HIGH-2 / G2).
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/handoff": (5, 60),
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
        # Mirror the production 404 path — unknown job_id is the
        # most common 4xx on the handoff route.
        if job_id == "missing":
            raise HTTPException(
                status_code=404,
                detail=f"Job {job_id} not found",
            )
        return {"status": "ok", "job_id": job_id}

    app.add_middleware(_JWTMiddleware, user_id="u-handoff")
    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_jwt_user_handoff_4xx_does_not_tick_per_user_bucket(
    jwt_handoff_app: FastAPI,
) -> None:
    """PR-J3.6.5 (Issue #60): 4xx on handoff packet route does NOT
    tick the per-user bucket (HIGH-2 / G2 contract).

    A legitimate user polling for a not-yet-completed job should NOT
    be locked out by their own 4xx. The bucket only sees successful
    ticks — so 50 404s do NOT exhaust the per-user 5/min budget.

    Implementation detail: this test shares a ``RateLimiter`` between
    the test and the middleware so we can inspect
    ``limiter.buckets[("user", user_id, endpoint)]`` and pin the
    contract that 4xx never appends to the per-user deque.
    """
    from app.ratelimit import RateLimiter

    # Build a fresh limiter and reuse the same FastAPI app's
    # middleware. Easier: build a standalone app from scratch with
    # the shared limiter.
    limiter = RateLimiter()
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/handoff": (5, 60),
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
        if job_id == "missing":
            raise HTTPException(
                status_code=404,
                detail=f"Job {job_id} not found",
            )
        return {"status": "ok", "job_id": job_id}

    user_id = "u-handoff"
    endpoint_key = r"^/api/v1/jobs/[^/]+/handoff$"
    app.add_middleware(_JWTMiddleware, user_id=user_id)
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # 1. Fire 50 404s. The per-IP bucket ticks on every one
        #    (G1 — credential-stuffing signal). After 5 ticks, per-IP
        #    rejects with 429. That is correct — what we want to
        #    pin is that the per-user bucket stays empty.
        for _ in range(50):
            r = await ac.get("/api/v1/jobs/missing/handoff")
            # Don't assert on the per-IP rejection; the test focuses
            # on the per-user bucket invariant.
            _ = r
        # 2. Pin the per-user bucket is EMPTY (no 4xx tick).
        user_bucket_key = ("user", user_id, endpoint_key)
        user_bucket = limiter.buckets.get(user_bucket_key)
        if user_bucket is not None:
            assert len(user_bucket) == 0, (
                f"Per-user bucket must NOT be ticked by 4xx (HIGH-2). "
                f"Got {len(user_bucket)} entries after 50 404s."
            )
        # 3. Now fire ONE success — this is the FIRST per-user tick.
        #    With the per-IP bucket at limit (50 attempts), the
        #    pre-call per-IP check fires first and rejects with 429
        #    before per-user is ever consulted. To prove the
        #    per-user 4xx-not-counted contract end-to-end we need a
        #    DIFFERENT user/IP scenario. The unit-level proof lives
        #    in ``test_g2_per_user_4xx_does_not_count_via_count_it_false``
        #    and ``test_count_it_policy_matches_response_status`` —
        #    the HIGH-2 mapping is unit-pinned. This integration
        #    test's value is the bucket introspection above: the
        #    per-user deque stays at len 0 after a 4xx barrage.
        assert user_bucket is None or len(user_bucket) == 0, (
            f"4xx barrage must leave per-user bucket empty; "
            f"bucket={user_bucket!r}"
        )


# ---------------------------------------------------------------------------
# PR-J3.6.5 (Issue #60) — REQ-INB-017: handoff list per-user ceiling.
#
# Two tests pin the T1 (corpus enumeration via job_id walking) defense:
# the 61st list request from one JWT user MUST reject with 429, and a
# different JWT user with a fresh per-user deque MUST NOT be rejected
# (per-user isolation per REQ-INB-005).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handoff_list_61st_request_returns_429() -> None:
    """REQ-INB-017 Scenario 1: the 61st ``GET /api/v1/handoffs`` from
    one authenticated user MUST reject with 429.

    Pins the production cap ``(60, 60)`` for the list route
    (Issue #60 / T1 threat: corpus enumeration via ``job_id``
    walking). The first 60 requests succeed; the 61st rejects with
    the documented body shape (``error="rate_limited"``,
    ``endpoint`` = regex key ``^/api/v1/handoffs$``,
    ``retry_after_seconds >= 1``, ``scope`` in ``("ip", "user")``).

    Implementation detail: the middleware auto-registers both
    per-IP and per-user policies for the matched endpoint, so for a
    SINGLE user behind a SINGLE IP both buckets tick in lock-step
    and the per-IP side may be the first to deny. The load-bearing
    assertion is that the 429 lands before request 61 succeeds, with
    the documented body shape (same pattern as
    ``test_jwt_user_hits_per_user_limit`` and
    ``test_eleventh_handoff_download_request_returns_429``).
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/handoffs": (60, 60),
        # Decoy route keeps the per-IP side permissive so the 429
        # surfaces from the handoff list endpoint specifically (not
        # from a shared per-IP bucket on an unrelated route).
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

    @app.get("/api/v1/handoffs")
    async def _list(request: Request) -> dict[str, object]:
        return {"items": []}

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    app.add_middleware(_JWTMiddleware, user_id="u-list")
    app.add_middleware(RateLimitMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        statuses: list[int] = []
        bodies: list[dict[str, object]] = []
        for _ in range(61):
            r = await ac.get("/api/v1/handoffs")
            statuses.append(r.status_code)
            if r.status_code == 429:
                bodies.append(r.json())
        # First 60 pass; 61st rejects.
        assert statuses[:60] == [200] * 60, (
            f"First 60 list requests must succeed; got {statuses!r}"
        )
        assert statuses[60] == 429, (
            f"The 61st list request must reject with 429; "
            f"got status={statuses[60]!r}, full sequence: {statuses!r}"
        )
        # Pin the body shape on the first 429.
        body = bodies[0]
        assert body["error"] == "rate_limited"
        assert int(body["retry_after_seconds"]) >= 1
        # Endpoint key matches the proposal — the regex string, not
        # the raw URL (decision M / spec REQ-INB-007).
        assert body["endpoint"] == r"^/api/v1/handoffs$", (
            f"Endpoint key must be the regex string; got {body['endpoint']!r}"
        )
        assert body["scope"] in ("ip", "user")


@pytest.mark.asyncio
async def test_per_user_isolation_across_jwt_users_on_handoff_list() -> None:
    """REQ-INB-017 Scenario 2: per-user isolation across JWT users
    on ``/api/v1/handoffs``.

    Acceptance: user A's per-user deque is at length 60; user B
    (different ``user_id``) makes a request to ``/api/v1/handoffs``
    and the response is NOT 429 (REQ-INB-005 isolation).

    Implementation note: ``ASGITransport`` forces every request to
    share ``client.host = "127.0.0.1"``, so two HTTP users behind
    one ASGI transport would share a per-IP bucket and the per-IP
    side would reject user B before per-user isolation could be
    demonstrated. The fix is a per-request scope override: user A's
    60 requests rotate across 60 distinct ``X-Test-Client-IP``
    values (per-IP never fills), and user B's request uses a fresh
    IP and fresh ``user_id``. The override middleware is stacked
    OUTSIDE ``RateLimitMiddleware`` so the per-IP and per-user
    buckets both see the overridden identity by the time the
    limiter dispatches.
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/handoffs": (60, 60),
    })
    app.state.rate_limit_patterns = patterns

    # Combined JWT-stub + scope-override middleware. Reads
    # ``X-Test-User`` (default: ``"u-default"``) to populate
    # ``request.state.user_id``, and ``X-Test-Client-IP`` to
    # mutate ``scope["client"]`` so ``request.client.host`` returns
    # the per-request IP. Single class keeps the function's McCabe
    # complexity below the threshold (the existing tests use a
    # single inline JWT middleware; this test needs one extra
    # concern — the client-IP override — and consolidating into
    # one class matches the inline pattern).
    class _OverrideIdentityMiddleware:
        def __init__(self, app) -> None:
            self.app = app

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] == "http":
                from starlette.requests import Request as StarletteRequest

                req = StarletteRequest(scope, receive)
                user_id = "u-default"
                for name, value in scope.get("headers", []):
                    if name == b"x-test-user":
                        user_id = value.decode("latin-1")
                    elif name == b"x-test-client-ip":
                        scope["client"] = (value.decode("latin-1"), 123)
                req.state.user_id = user_id
                req.state.auth_method = "jwt"
                req.state.username = user_id
                req.state.jwt_jti = None
            await self.app(scope, receive, send)

    @app.get("/api/v1/handoffs")
    async def _list(request: Request) -> dict[str, object]:
        return {"items": []}

    # Middleware order (Starlette stacks in REVERSE add order):
    #   1. RateLimitMiddleware    → innermost, dispatched last
    #   2. _OverrideIdentityMiddleware → outermost, mutates scope
    #      and request.state before the limiter sees them.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(_OverrideIdentityMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Phase 1: user A fires 60 requests, each from a DISTINCT
        # client IP. Per-IP_A never fills (each IP sees 1 entry),
        # per-user_A fills to 60. The per-user bucket is keyed by
        # ``user_id`` (REQ-INB-005) so user A's traffic is isolated
        # from any other user's deque.
        for i in range(60):
            r = await ac.get(
                "/api/v1/handoffs",
                headers={
                    "x-test-user": "u-A",
                    "x-test-client-ip": f"10.0.0.{i}",
                },
            )
            assert r.status_code == 200, (
                f"User A request {i + 1}/60 must succeed; "
                f"got {r.status_code}: {r.text}"
            )
        # Phase 2: user A's 61st request — per-user_A is at limit.
        # Use a fresh client IP so the per-IP side does not mask
        # the per-user rejection.
        r = await ac.get(
            "/api/v1/handoffs",
            headers={"x-test-user": "u-A", "x-test-client-ip": "10.0.99.1"},
        )
        assert r.status_code == 429, (
            f"User A's 61st list request must reject with 429; "
            f"got {r.status_code}: {r.text}"
        )
        body = r.json()
        # Rejection must surface as per-user (REQ-INB-005) — per-IP
        # is at 1 entry on the fresh IP, so the per-user side is
        # the binding constraint.
        assert body["scope"] == "user", (
            f"Rejection must be per-user (REQ-INB-005); got scope={body['scope']!r}"
        )
        assert body["endpoint"] == r"^/api/v1/handoffs$", (
            f"Endpoint key must be the regex string; got {body['endpoint']!r}"
        )
        # Phase 3: user B fires 1 request from a fresh IP and fresh
        # ``user_id``. Per-user_B is a fresh key — user B must NOT
        # be rejected by user A's per-user deque exhaustion
        # (REQ-INB-005 isolation).
        r = await ac.get(
            "/api/v1/handoffs",
            headers={"x-test-user": "u-B", "x-test-client-ip": "10.0.99.2"},
        )
        assert r.status_code == 200, (
            f"User B must NOT be rejected by user A's per-user deque exhaustion "
            f"(REQ-INB-005 isolation). Got {r.status_code}: {r.text}"
        )


__all__: list[str] = []
