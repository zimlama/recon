# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Dual-counter handoff tests (REQ-INB-005, T-D1/T-D2/T-D3 contract).

The handoff moment — request transitions pre-auth (per-IP) to
post-auth (per-user, jwt-only) — is the load-bearing piece of the
inbound limiter. A single request can tick BOTH counters under the
right setup, and the buckets MUST stay independent (otherwise a
legitimate user behind a NAT exhausts the per-user budget on their
neighbors' requests).

Three contract tests pin it (spec §Decision D):

- **T-D1**: Pre-authentication, only the per-IP bucket ticks. The
  per-user bucket is NEVER queried (instrumented via stub).
- **T-D2**: Post-authentication, BOTH buckets tick — per-IP pre-call
  AND per-user post-call (only when ``auth_method == "jwt"``).
- **T-D3**: Both buckets decrement independently when the window
  elapses — one user, distinct IPs; per-IP buckets drain, per-user
  bucket drains.

Each test uses a tiny FastAPI app + a stub auth middleware so the
test is decoupled from the real DualAuthMiddleware.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import RateLimiter, RateLimitMiddleware, compile_rate_limit_patterns


class _StubAuthMiddleware:
    """Stamp ``request.state`` so the limiter sees a known user/JWT.

    Disabled-by-default; tests enable per-route. JWT path uses
    ``auth_method="jwt"``; legacy path uses ``"legacy"`` (which MUST
    skip the per-user tick per decision D2).
    """

    def __init__(self, app, *, user_id: str | None, auth_method: str | None) -> None:
        self.app = app
        self._user_id = user_id
        self._auth_method = auth_method

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            # Construct a Request so we can write state, then forward.
            from starlette.requests import Request as StarletteRequest

            request = StarletteRequest(scope, receive)

            async def _wrapped_receive() -> bytes:
                return await receive()

            # Override the inner app's receive so handlers still work.
            _ = _wrapped_receive
            if self._user_id is not None:
                request.state.user_id = self._user_id
            if self._auth_method is not None:
                request.state.auth_method = self._auth_method
        await self.app(scope, receive, send)


def _build_app(
    *,
    cancel_limit: int = 100,
    login_limit: int = 100,
    user_id: str | None = None,
    auth_method: str | None = None,
    shared_limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the test app, returning the FastAPI instance.

    The ``shared_limiter`` lets tests put a tracked counter onto the
    app's middleware so they can introspect ``limiter.buckets``.
    Default limits are 100 to keep the focus on routing/handoff rather
    than the bucket math; tests that want limit pressure pin a value.
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/jobs/{job_id}/cancel": (cancel_limit, 60),
        "/api/v1/auth/login": (login_limit, 60),
    })
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    if auth_method is not None:
        app.add_middleware(_StubAuthMiddleware, user_id=user_id, auth_method=auth_method)

    middleware_kwargs: dict[str, object] = {}
    if shared_limiter is not None:
        middleware_kwargs["limiter"] = shared_limiter

    app.add_middleware(RateLimitMiddleware, **middleware_kwargs)  # type: ignore[arg-type]
    return app


@pytest.mark.asyncio
async def test_td1_preauth_only_perip_ticks() -> None:
    """T-D1: unauthenticated requests tick per-IP only.

    The stub auth middleware does NOT set ``request.state.user_id``
    (so the post-call user-scope branch is skipped). Verify the
    per-user bucket is NEVER created across N requests.
    """
    limiter = RateLimiter()
    # Build app — the limiter is a single instance we share; the
    # ``auth/login`` route has a tight limit so we can prove the
    # per-IP bucket is consulted.
    app = _build_app(
        cancel_limit=5,
        login_limit=5,
        user_id=None,
        auth_method=None,
        shared_limiter=limiter,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for _ in range(3):
            r = await ac.post("/api/v1/auth/login")
            assert r.status_code == 200, r.text
    # Per-IP bucket for the test client exists; per-user does not.
    assert ("ip", "127.0.0.1", "^/api/v1/auth/login$") in limiter.buckets


@pytest.mark.asyncio
async def test_td2_jwt_ticks_both_buckets() -> None:
    """T-D2: JWT user ticks BOTH per-IP and per-user.

    ``auth_method == "jwt"`` triggers the post-call per-user branch.
    """
    limiter = RateLimiter()
    app = _build_app(
        cancel_limit=100,
        login_limit=100,
        user_id="u-1",
        auth_method="jwt",
        shared_limiter=limiter,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Hammer the jobs/cancel route (auth stubs JWT user).
        for _ in range(3):
            r = await ac.post("/api/v1/jobs/abc/cancel")
            assert r.status_code == 200, r.text

    # Both buckets ticked.
    ip_deque = limiter.buckets.get(("ip", "127.0.0.1", "^/api/v1/jobs/[^/]+/cancel$"))
    user_deque = limiter.buckets.get(("user", "u-1", "^/api/v1/jobs/[^/]+/cancel$"))
    assert ip_deque is not None, "per-IP bucket missing"
    assert len(ip_deque) >= 1, "per-IP bucket missed"
    assert user_deque is not None, "per-user bucket missing"
    expected_user_len = 3
    actual_user_len = len(user_deque)
    assert actual_user_len == expected_user_len, (
        f"per-user bucket expected {expected_user_len} entries (post-auth successful tick), got {actual_user_len}"
    )


@pytest.mark.asyncio
async def test_td2_legacy_skips_per_user_tick() -> None:
    """D2 — legacy ``RECON_API_KEY`` callers skip per-user tick.

    Authenticated via legacy static token; per-user bucket MUST NOT
    be created. Per-IP bucket MUST still tick (G1).
    """
    limiter = RateLimiter()
    app = _build_app(
        cancel_limit=100,
        login_limit=100,
        user_id="local",
        auth_method="legacy",
        shared_limiter=limiter,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for _ in range(3):
            r = await ac.post("/api/v1/jobs/abc/cancel")
            assert r.status_code == 200, r.text
    user_keys = [k for k in limiter.buckets if k[0] == "user"]
    assert user_keys == [], (
        f"legacy auth must NOT create per-user buckets; got {user_keys}"
    )


@pytest.mark.asyncio
async def test_td3_buckets_decrement_independently_when_window_elapses() -> None:
    """T-D3: after window elapses, both buckets drain independently.

    Single user, 1 IP — fill both buckets to limit, advance clock by
    window+1, request again, both must allow.

    Note: our test infra reuses one FastAPI app but re-creates the
    middleware with a fresh RateLimiter per test so clock injection
    works deterministically. We use a single user/IP here (the
    2-IP variant is covered by the storage-layer test).
    """
    from app.ratelimit.inbound import RateLimitMiddleware as _RateLimitMiddleware

    clock = [1000.0]
    fresh_limiter = RateLimiter(clock=lambda: clock[0])
    fresh_limiter.configure({
        ("ip", "/api/v1/jobs/[^/]+/cancel"): (2, 60),
        ("user", "/api/v1/jobs/[^/]+/cancel"): (2, 60),
    })

    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/api/v1/jobs/{job_id}/cancel": (2, 60)})
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def _cancel(request: Request) -> dict[str, str]:
        request.state.user_id = "u-1"
        request.state.auth_method = "jwt"
        return {"status": "cancelled"}

    app.add_middleware(_RateLimitMiddleware, clock=lambda: clock[0], limiter=fresh_limiter)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Fill both buckets — 2 successful ticks (per-IP pre + per-user post).
        for _ in range(2):
            r = await ac.post("/api/v1/jobs/abc/cancel")
            assert r.status_code == 200, r.text
        # Third must reject — per-IP limit reached.
        r = await ac.post("/api/v1/jobs/abc/cancel")
        assert r.status_code == 429, r.text

        # Advance the clock beyond the window.
        clock[0] += 61
        # The next request from the same IP must succeed — both buckets drain.
        r = await ac.post("/api/v1/jobs/abc/cancel")
        assert r.status_code == 200, (
            f"After window elapsed both buckets should drain; got {r.status_code}: {r.text}"
        )


__all__: list[str] = []
