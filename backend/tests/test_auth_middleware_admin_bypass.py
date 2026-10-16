"""Tests for DualAuthMiddleware dev-mode admin bypass gating (R1 Risk).

R1 Risk review 2026-10-16: ``app/auth/middleware.py`` lines 159-172
hardcoded ``role='admin'`` whenever both JWT keys and ``RECON_API_KEY``
are unconfigured. A production deployment that forgets to set either
secret boots as an admin-open system — every request authenticates as
``role=admin``.

The fix gates the bypass on ``settings.APP_ENV != "production"``. When
``APP_ENV='production'`` AND both secrets are missing the middleware
MUST refuse the request (HTTP 503 'auth subsystem not configured') so
the operator notices at first request rather than discovering the
misconfig after a security incident.

These tests pin:
  1. production + no secrets → 503 (fail-loud)
  2. development + no secrets → 200 (dev posture preserved)
  3. regression — a valid JWT still authenticates against the
     middleware's JWT path regardless of APP_ENV
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import DualAuthMiddleware

# ---------------------------------------------------------------------------
# Helpers — build a standalone app wrapped in DualAuthMiddleware
# ---------------------------------------------------------------------------


def _build_settings(*, app_env: str):
    """Construct a Settings instance suitable for the bypass tests.

    Why so many required fields: when ``app_env='production'``,
    pydantic field validators for PERSON_DOSSIER_ENCRYPTION_KEY,
    PEPPER_SECRET and REFRESH_HASH_KEY all fire and require real
    values. We feed them valid 32+ byte strings so the test focuses on
    DualAuthMiddleware's gating logic, not the unrelated validators.
    """
    from app.config import Settings

    person_dossier_key = Fernet.generate_key().decode()
    pepper = "p" * 64
    refresh = "x" * 64
    return Settings(
        APP_ENV=app_env,
        RECON_API_KEY=None,
        ALLOW_LEGACY_API_KEY=True,
        PERSON_DOSSIER_ENCRYPTION_KEY=person_dossier_key,
        PEPPER_SECRET=pepper,
        REFRESH_HASH_KEY=refresh,
    )


def _build_app(
    *,
    app_env: str,
    legacy_api_key: str | None,
    jwt_keys_configured: bool,
) -> FastAPI:
    """Tiny FastAPI app wrapped in DualAuthMiddleware with the supplied
    configuration. The single route ``/echo`` returns the role assigned
    by the middleware so tests can assert on it.
    """

    s = _build_settings(app_env=app_env)

    app = FastAPI()

    @app.get("/echo")
    async def echo(request: Request) -> dict[str, str]:
        # Read the role the middleware wrote to request.state. If the
        # middleware raises (fail-loud path), this handler never runs.
        return {
            "user_id": getattr(request.state, "user_id", ""),
            "role": getattr(request.state, "role", ""),
            "auth_method": getattr(request.state, "auth_method", ""),
        }

    app.add_middleware(
        DualAuthMiddleware,
        jwt_keys_factory=lambda _req: _NoJwtKeys(),  # never reached on dev-bypass
        allow_legacy_api_key=True,
        legacy_api_key=legacy_api_key,
        jwt_keys_configured=jwt_keys_configured,
        settings_provider=lambda: s,
    )
    return app


class _NoJwtKeys:
    """Sentinel — the dev-bypass path never reaches verify(), so this
    object's verify() should NEVER be called. If tests fail here, the
    gating regressed and the production path is being executed.
    """

    def verify(self, *args, **kwargs):  # pragma: no cover - safety
        raise AssertionError(
            "DualAuthMiddleware reached the JWT path under dev-bypass "
            "— production gating regressed"
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_production_no_secrets_returns_503_fail_loud() -> None:
    """APP_ENV=production + no RECON_API_KEY + no JWT keys → 503.

    R1 Risk finding: previously the bypass gave the request 200 with
    role='admin'. A misconfigured production deployment looked like a
    working server — operators couldn't tell at first request that the
    auth subsystem was missing. The fix refuses with 503 + a message
    naming both secret names so the operator knows what to set.
    """
    app = _build_app(
        app_env="production",
        legacy_api_key=None,
        jwt_keys_configured=False,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/echo")

    # Fail-loud, NOT 200+admin. Middleware must refuse the request.
    assert resp.status_code == 503, (
        f"production + no secrets must return 503, got {resp.status_code} "
        f"body={resp.text!r}"
    )


@pytest.mark.asyncio
async def test_development_no_secrets_preserves_dev_bypass() -> None:
    """APP_ENV=development + no RECON_API_KEY + no JWT keys → 200 with role=admin.

    Regression — single-user local installs (docker compose up with
    zero env vars) MUST keep working without ceremony. R1's fix MUST
    NOT clobber the dev convenience bypass.
    """
    app = _build_app(
        app_env="development",
        legacy_api_key=None,
        jwt_keys_configured=False,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/echo")

    assert resp.status_code == 200, (
        f"dev + no secrets must return 200, got {resp.status_code}"
    )
    body = resp.json()
    assert body["role"] == "admin", (
        f"dev bypass should assign role='admin', got {body['role']!r}"
    )
    assert body["auth_method"] == "dev"


@pytest.mark.asyncio
async def test_production_secrets_present_still_authenticates() -> None:
    """Regression: production + a configured RECON_API_KEY + a valid
    Bearer token → 200 with the caller's role preserved.

    Ensures the new gating does NOT block legitimate production
    traffic. The legacy path is the easiest to exercise here because
    constructing a real JWT keypair in this unit test would re-create
    the JwtKeyManager test rig; the legacy path is sufficient to prove
    the middleware is reachable past the dev-bypass block.
    """
    # legacy_api_key IS configured — bypass must NOT fire; the
    # Bearer path must match and return a synthetic admin role.
    app = _build_app(
        app_env="production",
        legacy_api_key="prod-secret-key",
        jwt_keys_configured=False,  # legacy-only in this regression
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/echo", headers={"Authorization": "Bearer prod-secret-key"})

    assert resp.status_code == 200, (
        f"production+configured legacy key should reach the handler, got "
        f"{resp.status_code} body={resp.text!r}"
    )
    body = resp.json()
    assert body["auth_method"] == "legacy"
