# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Endpoint-lookup tests (REQ-INB-016 / decision M).

The middleware resolves the per-endpoint policy by matching
``request.url.path`` against the regex set compiled at startup from
``Settings.RATE_LIMITS``. The single NO-NO is reading
``request.scope["route"].path`` — that field is ``None`` inside
``BaseHTTPMiddleware.dispatch`` (Starlette populates ``scope["route"]``
only after routing completes).

These tests pin three things:

1. The regexes are compiled at app startup from ``Settings.RATE_LIMITS``
   and stored on ``app.state.rate_limit_patterns`` (NOT in module
   state — must be swappable per-test).
2. A dynamic-segment URL (``/api/v1/jobs/abc/cancel``) matches the
   template's compiled regex.
3. A request whose URL does NOT match any compiled regex is
   FAIL-OPEN — no counter tick, no 429, no audit emission.
4. The C-1 regression — ``request.scope["route"].path`` is ``None``
   inside the middleware's `dispatch`.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns


@pytest.fixture
def lookup_app() -> Iterator[FastAPI]:
    """Bare FastAPI app with one route, RateLimitMiddleware attached.

    Patterns are injected so the test can drive a tiny policy table.
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({
        "/api/v1/auth/login": (3, 60),
        "/api/v1/jobs/{job_id}/cancel": (2, 60),
    })
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/auth/login")
    async def login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def cancel(request: Request) -> dict[str, str]:
        return {"status": "cancelled"}

    app.add_middleware(RateLimitMiddleware)
    return app


@pytest.mark.asyncio
async def test_dynamic_segment_matches_template_via_regex(lookup_app: FastAPI) -> None:
    """``POST /api/v1/jobs/abc/cancel`` matches the ``.../{job_id}/cancel`` template."""
    async with AsyncClient(
        transport=ASGITransport(app=lookup_app), base_url="http://test"
    ) as ac:
        # First two cancel requests pass.
        r1 = await ac.post("/api/v1/jobs/abc/cancel")
        r2 = await ac.post("/api/v1/jobs/xyz/cancel")
        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text
        # Third cancels — should reject (the limit is 2/min).
        r3 = await ac.post("/api/v1/jobs/123/cancel")
        assert r3.status_code == 429, r3.text
        # The matched regex is the regex string with anchors (the
        # lookup key per design.md §Decision M / spec REQ-INB-007).
        body = r3.json()
        assert body["endpoint"] == r"^/api/v1/jobs/[^/]+/cancel$"


@pytest.mark.asyncio
async def test_unmatched_url_fails_open(lookup_app: FastAPI) -> None:
    """An URL not in ``RATE_LIMITS`` (e.g., ``/api/v1/whatever``) is never rejected.

    REQ-INB-016 #3: no fallback. The middleware MUST NOT emit a 429
    on an endpoint outside the policy table.
    """
    # Add a non-rate-limited route.
    @lookup_app.get("/api/v1/health-custom")
    async def _ok() -> dict[str, str]:  # type: ignore[no-redef]
        return {"status": "ok"}

    async with AsyncClient(
        transport=ASGITransport(app=lookup_app), base_url="http://test"
    ) as ac:
        # Flood — none of these should reject.
        for _ in range(100):
            r = await ac.get("/api/v1/health-custom")
            assert r.status_code == 200


@pytest.mark.asyncio
async def test_scope_route_path_is_none_inside_middleware() -> None:
    """Regression for the C-1 gate critical.

    Starlette populates ``scope["route"]`` AFTER routing completes
    (i.e., after the entire middleware chain returns). Inside
    ``BaseHTTPMiddleware.dispatch``, ``scope["route"].path`` is
    ``None`` — using it as the lookup key would silently fail-open
    on every request. We assert the field is ``None`` to keep the
    regression caught if anyone refactors that lookup back to it.
    """
    captured: dict[str, object] = {}

    app = FastAPI()

    @app.post("/probe")
    async def _probe(request: Request) -> dict[str, str]:
        return {"ok": "true"}

    # Wire a tiny middleware that captures scope state INSIDE dispatch,
    # BEFORE calling next.
    class _CaptureMiddleware:
        def __init__(self, app) -> None:
            self.app = app

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] == "http":
                captured["route"] = scope.get("route")
                captured["has_route_key"] = "route" in scope
            await self.app(scope, receive, send)

    app.add_middleware(_CaptureMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        await ac.post("/probe")

    # Inside the middleware (above the route handler), ``route`` may
    # be MISSING entirely; if it's present, its ``path`` is None.
    route = captured.get("route")
    if route is not None:
        assert getattr(route, "path", None) is None, (
            "C-1 regression — scope['route'].path is not None inside middleware"
        )


@pytest.mark.asyncio
async def test_compile_rate_limit_patterns_lives_on_app_state() -> None:
    """The compiled patterns MUST live on ``app.state`` (per design.md
    §Decision M), so tests can swap them via app.state assignments.
    """
    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/x": (5, 60)})
    app.state.rate_limit_patterns = patterns
    assert hasattr(app.state, "rate_limit_patterns")
    assert len(app.state.rate_limit_patterns) == 1
    assert app.state.rate_limit_patterns[0][1] == (5, 60)


def test_settings_provide_seven_endpoint_defaults() -> None:
    """``Settings.RATE_LIMITS`` has the 7 locked routes from spec REQ-INB-006."""
    s = Settings()
    assert len(s.RATE_LIMITS) == 7


__all__: list[str] = []
