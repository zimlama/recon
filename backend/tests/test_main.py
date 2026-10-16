"""Tests for the FastAPI app entrypoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """/health returns 200 with status ok."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient) -> None:
    """/ returns service info."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "zimlama-recon"
    assert "docs" in data


@pytest.mark.asyncio
async def test_openapi_schema_available(client: AsyncClient) -> None:
    """/openapi.json is available."""
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "openapi" in schema
    assert schema["info"]["title"] == "zimlama recon API"


@pytest.mark.asyncio
async def test_modules_list(client: AsyncClient) -> None:
    """/api/v1/modules returns the 15 modules (PR 4 added person_dossier)."""
    response = await client.get("/api/v1/modules")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 15
    module_names = {m["name"] for m in data["modules"]}
    assert "subdomain_enum" in module_names
    assert "whois_rdap" in module_names
    assert "dark_web_osint" in module_names
    assert "person_dossier" in module_names


@pytest.mark.asyncio
async def test_get_unknown_module_404(client: AsyncClient) -> None:
    """/api/v1/modules/{name} returns 404 for unknown module."""
    response = await client.get("/api/v1/modules/does_not_exist")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Security regressions — CORS hardening + path traversal (Fix #1, #3)
# ---------------------------------------------------------------------------


def test_create_app_rejects_wildcard_cors_with_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """'*' in CORS_ORIGINS must fail closed when allow_credentials=True."""
    import app.config as cfg_mod
    import app.main as main_mod

    # PR-J3.8: create_app now re-reads settings via get_settings(). Patch
    # the reference imported into main_mod (not cfg_mod) so the call site
    # sees the wildcard CORS_ORIGINS.
    wildcard_settings = cfg_mod.Settings(CORS_ORIGINS="*")
    monkeypatch.setattr(main_mod, "get_settings", lambda: wildcard_settings)
    # Belt-and-suspenders: also patch the module-level reference for
    # any code path that still reads it.
    monkeypatch.setattr(main_mod, "settings", wildcard_settings)

    with pytest.raises(RuntimeError, match="CORS misconfiguration"):
        main_mod.create_app()


def test_create_app_accepts_explicit_cors_origin_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit allowlist boots without error."""
    import app.main as main_mod

    # Explicit allowlist (the conftest default) — keep the original settings.
    main_mod.get_settings.cache_clear()
    monkeypatch.setattr(main_mod, "settings", main_mod.get_settings())
    app = main_mod.create_app()
    assert app is not None


def test_resolve_under_reports_rejects_traversal(tmp_path: Path) -> None:
    """Path traversal escapes from REPORTS_DIR return 403."""
    from fastapi import HTTPException

    from app.config import Settings
    from app.routes.reports import _resolve_under_reports

    cfg = Settings(REPORTS_DIR=str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir()

    # Inside root → returned as a resolved Path
    inside = tmp_path / "reports" / "abc.md"
    assert _resolve_under_reports(str(inside), cfg) == inside.resolve()

    # Outside root (parent traversal) → 403
    evil = tmp_path / "reports" / ".." / "secret.md"
    with pytest.raises(HTTPException) as exc:
        _resolve_under_reports(str(evil), cfg)
    assert exc.value.status_code == 403


def test_resolve_under_reports_rejects_absolute_escape(tmp_path: Path) -> None:
    """Absolute paths outside REPORTS_DIR return 403."""
    from fastapi import HTTPException

    from app.config import Settings
    from app.routes.reports import _resolve_under_reports

    cfg = Settings(REPORTS_DIR=str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir()

    with pytest.raises(HTTPException) as exc:
        _resolve_under_reports("/etc/passwd", cfg)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# B3 — sec-auth-jwt R4 fail-loud lifespan (PR #56 B3)
# ---------------------------------------------------------------------------
# R4 Resilience review 2026-10-16: app/main.py lifespan wraps the
# JwtKeyManager() and RefreshService() constructors in try/except +
# logger.warning, silently swallowing the failure. A misconfigured
# production deployment (missing JWT_PRIVATE_KEY_PATH, empty
# REFRESH_HASH_KEY, etc.) would boot happily and only fail at the
# first /auth/login call — violating the PR-J1 B-2 fail-loud contract.
#
# The fix raises RuntimeError at startup in APP_ENV=production so the
# container orchestrator (Docker Compose / K8s) restarts the pod until
# it boots cleanly. Dev/test keep the warning behavior so single-user
# local installs can launch without ceremony.


def _production_settings(**overrides):
    """Build a Settings instance valid for APP_ENV=production, with the
    supplied attribute overrides. All required secret validators
    (PERSON_DOSSIER_ENCRYPTION_KEY, PEPPER_SECRET, REFRESH_HASH_KEY)
    are populated with 32+ byte values so the focus is on the
    lifespan-level failure, not the unrelated pydantic validators.
    """
    from cryptography.fernet import Fernet

    from app.config import Settings

    base = {
        "APP_ENV": "production",
        "PERSON_DOSSIER_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "PEPPER_SECRET": "p" * 64,
        "REFRESH_HASH_KEY": "x" * 64,
        # Default — tests that want a misconfig override these.
        "JWT_PRIVATE_KEY_PATH": None,
        "JWT_PUBLIC_KEY_PATH": None,
    }
    base.update(overrides)
    return Settings(**base)


def _ephemeral_rsa_pem_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Generate an ephemeral RSA keypair on disk and return its paths.

    Used so the lifespan has a working JwtKeyManager when the test
    wants the healthy-config baseline to start cleanly.
    """
    priv_path = tmp_path / "priv.pem"
    pub_path = tmp_path / "pub.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def _drive_lifespan(monkeypatch: pytest.MonkeyPatch, settings):
    """Enter ``create_app()`` and trigger its lifespan startup.

    Returns the app inside an ``asyncio.run`` boundary so the lifespan
    generator can yield. Raises whatever the lifespan raises.
    """
    import asyncio

    import app.main as main_mod

    # PR-J3.8 fix: create_app() re-reads settings via get_settings()
    # each call. Patch it so the test's settings object is honored.
    monkeypatch.setattr(main_mod, "get_settings", lambda: settings)
    monkeypatch.setattr(main_mod, "settings", settings)

    app = main_mod.create_app()

    async def _enter_lifespan():
        async with app.router.lifespan_context(app):
            return app

    # If the lifespan raises on startup (the B3 contract), it surfaces
    # out of run() rather than getting swallowed.
    return asyncio.run(_enter_lifespan())


def test_lifespan_production_missing_jwt_keys_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """APP_ENV=production + JWT_PRIVATE_KEY_PATH unset → RuntimeError.

    Reproduces R4 finding: previously the lifespan logged a warning and
    continued, leaving app.state.jwt_keys unset. The first /auth/login
    surfaced the misconfig, which violates the PR-J1 B-2 fail-loud
    contract (fails the boot, not the first request).
    """
    settings = _production_settings(
        JWT_PRIVATE_KEY_PATH=None,  # explicit
        JWT_PUBLIC_KEY_PATH=None,
    )

    with pytest.raises(RuntimeError, match="JWT_PRIVATE_KEY_PATH"):
        _drive_lifespan(monkeypatch, settings)


def test_lifespan_production_missing_jwt_key_files_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """APP_ENV=production + JWT paths point at nonexistent files → RuntimeError.

    Belt-and-suspenders: even if both env vars are set but the files
    don't exist (typo in the deploy manifest), the lifespan refuses.
    Catches the "RECON_API_KEY pointed at /dev/null" failure mode.
    """
    settings = _production_settings(
        JWT_PRIVATE_KEY_PATH=str(tmp_path / "does-not-exist-priv.pem"),
        JWT_PUBLIC_KEY_PATH=str(tmp_path / "does-not-exist-pub.pem"),
    )

    with pytest.raises(RuntimeError):
        _drive_lifespan(monkeypatch, settings)


def test_lifespan_development_missing_jwt_keys_warns_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """APP_ENV=development + JWT_PRIVATE_KEY_PATH unset → lifespan completes.

    Regression — single-user local installs must continue booting with
    zero JWT env vars. R4's fix MUST NOT clobber this convenience.
    """
    from cryptography.fernet import Fernet

    from app.config import Settings

    settings = Settings(
        APP_ENV="development",
        PEPPER_SECRET="p" * 64,
        REFRESH_HASH_KEY="x" * 64,
        PERSON_DOSSIER_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    )

    # Should NOT raise; the app boots with no JWT subsystem.
    app = _drive_lifespan(monkeypatch, settings)
    assert app is not None


def test_lifespan_healthy_config_completes_normally(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: production + valid JWT keys → lifespan completes cleanly."""
    priv_path, pub_path = _ephemeral_rsa_pem_pair(tmp_path)
    settings = _production_settings(
        JWT_PRIVATE_KEY_PATH=str(priv_path),
        JWT_PUBLIC_KEY_PATH=str(pub_path),
    )

    app = _drive_lifespan(monkeypatch, settings)
    assert app is not None
