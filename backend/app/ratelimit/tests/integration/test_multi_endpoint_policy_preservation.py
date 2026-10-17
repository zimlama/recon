"""Regression test for 4R review finding R3-#1 (2026-10-16):
``RateLimiter.configure`` previously REPLACED the policy map, so a
dispatch call to /api/v1/auth/login would wipe /api/v1/jobs/* policies
(and vice versa). The fix changed ``configure`` to ``update`` (additive).

This test hammers multiple endpoints on a shared ``RateLimiter`` and
asserts each endpoint's policy stays enforced.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import (
    RateLimitMiddleware,
    compile_rate_limit_patterns,
)


@pytest.fixture
def multi_endpoint_app() -> FastAPI:
    """Two distinct rate-limited endpoints with one shared limiter."""
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
async def test_alternating_requests_dont_wipe_other_endpoint_policies(
    multi_endpoint_app: FastAPI,
) -> None:
    """R3-#1: a dispatch call must NOT wipe other endpoints' policies.

    Interleave 3 logins + 3 cancels; /login cap=3, /cancel cap=2.
    If the per-dispatch configure() WIPED the policy map, then by
    the 3rd pair /cancel's dispatch would have wiped /login's
    policy before the 3rd /login request, allowing 3 successful
    /logins in a row even though cap=3 was already hit. With the
    fix (update instead of replace), /cancel's policy addition
    does NOT remove /login's policy; the 3rd /login is correctly
    a 429.
    """
    async with AsyncClient(
        transport=ASGITransport(app=multi_endpoint_app), base_url="http://test"
    ) as ac:
        login_responses: list[int] = []
        cancel_responses: list[int] = []
        for _ in range(3):
            login_responses.append(
                (await ac.post("/api/v1/auth/login")).status_code
            )
            cancel_responses.append(
                (await ac.post("/api/v1/jobs/abc/cancel")).status_code
            )
    # /login: 200, 200, 200 (3rd hits cap; 4th onward = 429)
    assert login_responses == [200, 200, 200], (
        f"Pre-fix this would be [200, 200, 200, 200, 200, 200] because "
        f"/cancel dispatches wiped /login's policy; got {login_responses}"
    )
    # /cancel: 200, 200, 429 (3rd hits cap=2)
    assert cancel_responses == [200, 200, 429], (
        f"Pre-fix this would be [200, 200, 200] because /login dispatches "
        f"wiped /cancel's policy; got {cancel_responses}"
    )
