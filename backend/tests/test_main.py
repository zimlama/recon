"""Tests for the FastAPI app entrypoint."""

from __future__ import annotations

from pathlib import Path

import pytest
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
    """/api/v1/modules returns the 14 modules."""
    response = await client.get("/api/v1/modules")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 14
    module_names = {m["name"] for m in data["modules"]}
    assert "subdomain_enum" in module_names
    assert "whois_rdap" in module_names
    assert "dark_web_osint" in module_names


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

    # Swap the module-level ``settings`` for a fresh Settings whose
    # CORS_ORIGINS is the dangerous wildcard. Using a fresh Settings
    # avoids lru_cache / module-reload side effects.
    wildcard_settings = cfg_mod.Settings(CORS_ORIGINS="*")
    monkeypatch.setattr(main_mod, "settings", wildcard_settings)

    with pytest.raises(RuntimeError, match="CORS misconfiguration"):
        main_mod.create_app()


def test_create_app_accepts_explicit_cors_origin_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit allowlist boots without error."""
    import app.main as main_mod

    # Explicit allowlist (the conftest default) — keep the original settings.
    monkeypatch.setattr(
        main_mod, "settings", main_mod.get_settings.__wrapped__()
    )
    app = main_mod.create_app()
    assert app is not None


def test_resolve_under_reports_rejects_traversal(tmp_path: "Path") -> None:
    """Path traversal escapes from REPORTS_DIR return 403."""
    from fastapi import HTTPException

    from app.routes.reports import _resolve_under_reports
    from app.config import Settings

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


def test_resolve_under_reports_rejects_absolute_escape(tmp_path: "Path") -> None:
    """Absolute paths outside REPORTS_DIR return 403."""
    from fastapi import HTTPException

    from app.routes.reports import _resolve_under_reports
    from app.config import Settings

    cfg = Settings(REPORTS_DIR=str(tmp_path / "reports"))
    (tmp_path / "reports").mkdir()

    with pytest.raises(HTTPException) as exc:
        _resolve_under_reports("/etc/passwd", cfg)
    assert exc.value.status_code == 403
