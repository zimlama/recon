"""Tests for /health and /health/ready.

Audit finding R4-H1: the v0.2.0 release had a /health/ready endpoint
that returned 200 unconditionally without probing any dependency.
K8s readinessProbes pointing there would route traffic to a process
that can't reach its DB or whose LLM client fails to construct.

These tests verify:
  - /health is the liveness probe - 200 unconditionally
  - /health/ready actually probes DB and LLMClient
  - DB failure -> 503 (not 200)
  - LLMClient construction failure -> 503 (not 200)
"""
from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.database import Base, engine


@pytest.fixture
async def client():
    """Yield an AsyncClient against the FastAPI app, with lifespan active.

    AsyncClient + ASGITransport does NOT run the FastAPI lifespan by
    default; we drive it manually so init_db() + app.state.llm_client
    are populated for the readiness probe.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    @asynccontextmanager
    async def _lifespan_runner():
        # Run the FastAPI lifespan context manager — it handles
        # startup (init_db + LLMClient) and teardown (close LLMClient).
        async with app.router.lifespan_context(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                yield ac

    async with _lifespan_runner() as ac:
        yield ac

    Base.metadata.drop_all(bind=engine)


@pytest.mark.asyncio
async def test_health_returns_200_when_alive(client) -> None:
    """/health returns 200 even when deps are missing.

    Liveness is "the process is up". K8s livenessProbe must not
    kill the pod unless the Python interpreter itself is dead.
    """
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


@pytest.mark.asyncio
async def test_ready_returns_200_when_db_ok(client) -> None:
    """/health/ready probes the DB and returns 200 when reachable.

    Uses the lifespan-managed engine so SELECT 1 succeeds against the
    actual SQLite database.
    """
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["env"] in ("development", "staging", "production", "test")


@pytest.mark.asyncio
async def test_ready_returns_503_when_db_down(client) -> None:
    """/health/ready returns 503 when the DB round-trip fails.

    We monkey-patch SessionLocal so the readiness probe's `with
    SessionLocal() as db` block returns a mock whose execute() raises
    OperationalError. K8s readinessProbe will then steer traffic away.
    """
    from sqlalchemy.exc import OperationalError

    class _BoomSession:
        def execute(self, statement, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("db down"))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    @contextmanager
    def _boom_session_local():
        yield _BoomSession()

    with patch("app.main.SessionLocal", _boom_session_local):
        resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["reason"] == "database_unreachable"
    assert resp.headers["Retry-After"] == "5"


@pytest.mark.asyncio
async def test_ready_returns_503_when_llm_client_fails(client) -> None:
    """/health/ready returns 503 when LLMClient construction fails.

    We patch LLMClient in the app.main namespace so the readiness probe
    raises. The endpoint must catch the exception, return 503, and
    signal retry-after.
    """
    def _boom_init(*args, **kwargs):
        raise RuntimeError("MINIMAX_API_KEY malformed")

    # Patch the symbol that `app.main` uses inside the closure. We
    # patch `app.main.LLMClient` because that's the binding the
    # /health/ready handler calls.
    with patch("app.main.LLMClient", side_effect=_boom_init):
        resp = await client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["reason"] == "llm_client_unconstructible"
    assert resp.headers["Retry-After"] == "5"
