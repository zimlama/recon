"""Tests for the FastAPI app entrypoint."""

from __future__ import annotations

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
