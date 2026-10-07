"""Tests for jobs routes + job lifecycle."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_job_requires_consent(client: AsyncClient) -> None:
    """Job creation requires user_consent=true."""
    response = await client.post(
        "/api/v1/jobs",
        json={
            "target": "example.com",
            "selected_modules": ["whois_rdap"],
            "user_consent": False,
            "typed_confirmation": "example.com",
        },
    )
    # Should fail validation (user_consent must be true)
    assert response.status_code in (400, 422)


@pytest.mark.asyncio
async def test_create_job_typed_confirmation_mismatch(client: AsyncClient) -> None:
    """Job creation fails if typed_confirmation doesn't match target."""
    response = await client.post(
        "/api/v1/jobs",
        json={
            "target": "example.com",
            "selected_modules": ["whois_rdap"],
            "user_consent": True,
            "typed_confirmation": "wrong-domain.com",
        },
    )
    assert response.status_code == 400
    assert "Typed confirmation" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_job_unknown_module(client: AsyncClient) -> None:
    """Job creation fails for unknown module names."""
    response = await client.post(
        "/api/v1/jobs",
        json={
            "target": "example.com",
            "selected_modules": ["not_a_real_module"],
            "user_consent": True,
            "typed_confirmation": "example.com",
        },
    )
    assert response.status_code == 400
    assert "Unknown module" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_job_success(client: AsyncClient) -> None:
    """Valid job creation succeeds."""
    response = await client.post(
        "/api/v1/jobs",
        json={
            "target": "example.com",
            "selected_modules": ["whois_rdap"],
            "user_consent": True,
            "typed_confirmation": "example.com",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["target"] == "example.com"
    assert data["status"] == "pending"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_jobs_empty(client: AsyncClient) -> None:
    """Empty job list returns total=0."""
    response = await client.get("/api/v1/jobs")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_get_unknown_job_404(client: AsyncClient) -> None:
    """GET /jobs/{id} returns 404 for unknown IDs."""
    response = await client.get("/api/v1/jobs/nonexistent-id")
    assert response.status_code == 404
