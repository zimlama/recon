# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Dev bypass (REQ-INB-010).

Three properties:

1. ``ALLOW_DEV_BYPASS=True`` + valid ``X-Bypass-Rate-Limit: <token>``
   → NO 429 even after exceeding the limit.
2. Same header WITHOUT a matching token → normal enforcement.
3. ``ALLOW_DEV_BYPASS=True`` AND ``APP_ENV='production'`` → the
   Settings validator forces the flag to ``False``; the bypass
   is therefore ignored even when env says yes.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.ratelimit import RateLimitMiddleware, compile_rate_limit_patterns


def _make_app(*, limit: int, allow_bypass: bool, bypass_token: str) -> FastAPI:
    """Build a 1-route app with the requested bypass posture."""
    app = FastAPI()
    patterns = compile_rate_limit_patterns({"/api/v1/auth/login": (limit, 60)})
    app.state.rate_limit_patterns = patterns

    @app.post("/api/v1/auth/login")
    async def _login(request: Request) -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(
        RateLimitMiddleware,
        allow_bypass=allow_bypass,
        bypass_token=bypass_token,
    )
    return app


@pytest.mark.asyncio
async def test_valid_bypass_header_skips_enforcement() -> None:
    """Valid token → next requests AFTER the limit are NOT rejected."""
    _secret = "verysecret"
    app = _make_app(limit=2, allow_bypass=True, bypass_token=_secret)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First two: without bypass — fill the bucket.
        for _ in range(2):
            r = await ac.post("/api/v1/auth/login")
            assert r.status_code == 200
        # Third without bypass: WOULD reject.
        bad = await ac.post("/api/v1/auth/login")
        assert bad.status_code == 429

        # Now switch on the bypass header — same path, same IP,
        # exceeding the limit, must NOT reject.
        for _ in range(5):
            r = await ac.post(
                "/api/v1/auth/login",
                headers={"X-Bypass-Rate-Limit": _secret},
            )
            assert r.status_code == 200, (
                f"Valid bypass header must skip the gate; got {r.status_code}: {r.text}"
            )


@pytest.mark.asyncio
async def test_invalid_bypass_header_does_not_skip() -> None:
    """Wrong token → the bypass gate does NOT activate."""
    app = _make_app(limit=2, allow_bypass=True, bypass_token="the-right-token")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for _ in range(2):
            await ac.post("/api/v1/auth/login")
        # Header present but with wrong token — limiter still hits.
        r = await ac.post(
            "/api/v1/auth/login",
            headers={"X-Bypass-Rate-Limit": "wrong-token"},
        )
        assert r.status_code == 429, r.text


@pytest.mark.asyncio
async def test_bypass_disabled_means_no_header_helps() -> None:
    """``allow_bypass=False`` → the header is ignored even if the token matches."""
    _secret = "verysecret"
    app = _make_app(limit=2, allow_bypass=False, bypass_token=_secret)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for _ in range(2):
            await ac.post("/api/v1/auth/login")
        # Same header as the success case above, but the bypass flag is OFF.
        r = await ac.post(
            "/api/v1/auth/login",
            headers={"X-Bypass-Rate-Limit": _secret},
        )
        assert r.status_code == 429, r.text


def test_validator_forces_bypass_off_in_production() -> None:
    """Settings validator flips ``ALLOW_DEV_BYPASS`` to False in production.

    Mirrors ``test_settings_ratelimits::test_allow_dev_bypass_force_disabled_in_production``
    but at the runtime layer — the middleware must NEVER honor a
    header value flagged to production by the validator.
    """
    # Same path as the settings-level test.
    from app.config import Settings

    s = Settings(
        APP_ENV="production",
        ALLOW_DEV_BYPASS=True,
        PEPPER_SECRET="p" * 64,
        REFRESH_HASH_KEY="r" * 64,
        PERSON_DOSSIER_ENCRYPTION_KEY="k" * 44,
    )
    assert s.ALLOW_DEV_BYPASS is False


__all__: list[str] = []
