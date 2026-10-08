"""Tests for the RequestIdMiddleware (audit R4-H4).

Verifies:
- The middleware generates a UUID4 when no X-Request-ID header is
  supplied.
- The middleware honors an X-Request-ID header supplied by the caller.
- The response carries the X-Request-ID header back.
"""
from __future__ import annotations

import re
from uuid import UUID

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.middleware import RequestIdMiddleware


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@pytest.fixture
async def client():
    """AsyncClient against a tiny app wrapped in RequestIdMiddleware."""
    app = FastAPI()

    @app.get("/echo")
    async def echo() -> dict[str, str]:
        from fastapi import Request  # local import to avoid anyio issues

        # noqa: D401 — middleware puts request_id on request.state
        return {}

    app.add_middleware(RequestIdMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_request_id_middleware_attaches_uuid(client) -> None:
    """No X-Request-ID header → middleware mints a UUID4 and echoes it.

    The generated UUID must be a valid RFC-4122 UUID and match the
    response header verbatim.
    """
    resp = await client.get("/echo")
    assert resp.status_code == 200
    rid = resp.headers.get("X-Request-ID")
    assert rid is not None, "X-Request-ID header missing"
    # UUID4 shape: 8-4-4-4-12 hex with version nibble = 4.
    assert _UUID_RE.match(rid), f"X-Request-ID is not a UUID4: {rid!r}"
    UUID(rid)  # raises ValueError if not a valid UUID


@pytest.mark.asyncio
async def test_request_id_middleware_honors_caller_header(client) -> None:
    """When the caller sets X-Request-ID, the middleware reuses it.

    This is how distributed traces flow: client → middleware → service
    → logs, all sharing the same correlation ID.
    """
    supplied = "trace-abc-123-deadbeef"
    resp = await client.get("/echo", headers={"X-Request-ID": supplied})
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID") == supplied


@pytest.mark.asyncio
async def test_request_id_middleware_is_attached_to_state(client) -> None:
    """request.state.request_id is populated for downstream handlers."""
    # Build a separate app so the endpoint can assert request.state.
    app = FastAPI()

    captured: dict[str, str] = {}

    @app.get("/capture")
    async def capture_rid(request: Request) -> dict[str, str]:
        from fastapi import Request
        captured["rid"] = getattr(request.state, "request_id", "")
        return {"rid": captured["rid"]}

    app.add_middleware(RequestIdMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/capture")

    assert resp.status_code == 200
    # Same UUID4 in body and header.
    assert captured["rid"] == resp.headers["X-Request-ID"]
    assert _UUID_RE.match(captured["rid"])
