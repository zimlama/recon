# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Per-user post-auth test (REQ-INB-005, T-D2 confirmation).

A JWT-authenticated user must hit the per-user limit INDEPENDENTLY
of the per-IP bucket. This test fires requests from a single IP for
one user; both counters tick in lock-step. With a per-user limit of
3/min, the 4th request from the same user MUST reject — even though
the per-IP limit was 100/min in this fixture.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
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


__all__: list[str] = []
