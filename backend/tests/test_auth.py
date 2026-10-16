"""Tests for the API-key authentication middleware (audit finding C1).

These tests cover two scenarios:
  - Dev mode (RECON_API_KEY unset): all routes are open.
  - Auth-on mode (RECON_API_KEY set): business routes require the header.

We swap `app.main.settings` per-test with `monkeypatch` so we don't have to
reload the module. `verify_api_key` resolves `settings` from the module
namespace at request time, so the patch is picked up on the next call.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings_with_api_key(api_key: str | None):
    """Build a Settings instance suitable for monkey-patching into main."""
    from app.config import Settings

    # All other fields use Settings defaults — no env vars needed.
    return Settings(RECON_API_KEY=api_key)


def _enable_auth(monkeypatch: pytest.MonkeyPatch, api_key: str = "testkey") -> None:
    """Swap `app.main.settings` for one that requires auth (legacy path)."""
    import app.main as main_mod

    s = _settings_with_api_key(api_key)
    # PR-J3.8: DualAuthMiddleware only honors the legacy path when
    # ALLOW_LEGACY_API_KEY=true. The previous verify_api_key didn't
    # have this guard. Enable it so the test still exercises the
    # Bearer-token flow it was written for.
    monkeypatch.setattr(s, "ALLOW_LEGACY_API_KEY", True)
    monkeypatch.setattr(main_mod, "settings", s)


# ---------------------------------------------------------------------------
# Dev mode (RECON_API_KEY unset) — auth must be bypassed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_skipped_when_no_api_key_set(client: AsyncClient) -> None:
    """In dev mode (RECON_API_KEY unset), no header is required."""
    # Conftest does NOT set RECON_API_KEY, so dev mode applies.
    response = await client.get("/api/v1/modules")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_endpoint_doesnt_require_auth(client: AsyncClient) -> None:
    """/health stays open even when RECON_API_KEY is set."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_docs_endpoint_doesnt_require_auth(
    monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    """/docs is NOT registered as a router, so verify_api_key never runs."""
    _enable_auth(monkeypatch)  # turn auth ON
    response = await client.get("/docs")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_endpoint_doesnt_require_auth(
    monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    """/openapi.json stays open even when auth is required."""
    _enable_auth(monkeypatch)  # turn auth ON
    response = await client.get("/openapi.json")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Auth-on mode (RECON_API_KEY set) — header is required
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_required_when_key_set(
    monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    """No Authorization header → 401 on a business route."""
    _enable_auth(monkeypatch)  # turn auth ON, RECON_API_KEY="testkey"
    response = await client.get("/api/v1/modules")
    assert response.status_code == 401
    # DualAuthMiddleware body shape: {"error": "unauthorized", "message": "..."}
    body = response.json()
    assert "Authorization" in body.get("message", "") or "Authorization" in body.get("detail", "")


@pytest.mark.asyncio
async def test_auth_rejects_non_bearer_scheme(
    monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    """Authorization without the 'Bearer ' prefix is rejected."""
    _enable_auth(monkeypatch)
    response = await client.get(
        "/api/v1/modules",
        headers={"Authorization": "testkey"},  # missing Bearer prefix
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_with_wrong_key(monkeypatch: pytest.MonkeyPatch, client: AsyncClient) -> None:
    """Wrong token → 401."""
    _enable_auth(monkeypatch)
    response = await client.get(
        "/api/v1/modules",
        headers={"Authorization": "Bearer wrongkey"},
    )
    assert response.status_code == 401
    # DualAuthMiddleware body shape: {"error": "unauthorized", "message": "..."}
    body = response.json()
    assert body.get("error") == "unauthorized" or "Invalid API key" in body.get("message", "")


@pytest.mark.asyncio
async def test_auth_with_correct_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Correct token → 200 (with fresh app + settings; conftest's `client`
    fixture is avoided because the shared `app` instance caches settings
    at construction time, so monkeypatching `app.main.settings` after
    the fact has no effect on the dual-auth middleware that was built
    during the conftest's import)."""
    import os
    from app.config import Settings

    # Force ALLOW_LEGACY_API_KEY=true for this test's fresh app.
    monkeypatch.setenv("ALLOW_LEGACY_API_KEY", "true")
    monkeypatch.setenv("RECON_API_KEY", "testkey")

    # Build a fresh Settings + fresh app on demand.
    s = Settings()
    assert s.RECON_API_KEY == "testkey"
    assert s.ALLOW_LEGACY_API_KEY is True

    from app.main import create_app
    from app.database import Base, engine
    from httpx import ASGITransport, AsyncClient

    fresh_app = create_app()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=fresh_app), base_url="http://test"
        ) as ac:
            response = await ac.get(
                "/api/v1/modules",
                headers={"Authorization": "Bearer testkey"},
            )
        assert response.status_code == 200
    finally:
        Base.metadata.drop_all(bind=engine)


@pytest.mark.asyncio
async def test_auth_protects_all_business_routers(
    monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    """Auth gate applies to every business router (jobs, findings, reports, ...)."""
    _enable_auth(monkeypatch)
    # List a representative endpoint from each business router.
    paths = [
        "/api/v1/jobs",
        "/api/v1/modules",
    ]
    for path in paths:
        response = await client.get(path)
        assert response.status_code == 401, (
            f"{path} should require auth, got {response.status_code}"
        )
