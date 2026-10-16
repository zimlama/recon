"""Tests for AuditLogMiddleware writing details.ip + details.auth_method (PR-J3.7).

Spec coverage (engram #1431, REQ-013 mod): every authenticated request
MUST have ``details.ip`` equal to ``request.client.host`` (or
``"unknown"`` when ``request.client is None``) AND ``details.auth_method``
equal to ``request.state.auth_method`` (or ``"unknown"`` when absent).

These tests extend the AuditLogMiddleware contract (see
``test_audit_middleware_jwt.py`` for the user_id / username / jti base
cases) and pin REQ-013 — the cross-cutting change that gives every
endpoint the IP + auth-method signal needed by the new
``GET /api/v1/auth/legacy-usage-stats`` aggregation (REQ-LEG-003).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.audit.middleware import AuditLogMiddleware
from app.database import Base, SessionLocal, engine
from app.models import AuditLog


def _build_test_app(
    *,
    user_id: str | None,
    username: str | None,
    auth_method: str | None,
    path: str = "/probe",
) -> FastAPI:
    """Build a tiny FastAPI app seeding ``request.state`` so the audit
    middleware can pick up the auth signals. Mirrors DualAuthMiddleware's
    contract — the audit row only sees what the request handler wrote
    onto ``request.state``."""

    app = FastAPI()

    @app.get(path)
    async def set_state(request: Request) -> dict[str, str]:
        if user_id is not None:
            request.state.user_id = user_id
        if username is not None:
            request.state.username = username
        if auth_method is not None:
            request.state.auth_method = auth_method
        return {"ok": "true"}

    app.add_middleware(AuditLogMiddleware)
    return app


def _build_minimal_app(*, path: str = "/open") -> FastAPI:
    """No state seeding at all — used for the request.client=None path."""

    app = FastAPI()

    @app.get(path)
    async def open_endpoint() -> dict[str, str]:
        return {"ok": "true"}

    app.add_middleware(AuditLogMiddleware)
    return app


@pytest_asyncio.fixture
async def db_ready() -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    yield


@pytest_asyncio.fixture
async def db_session(db_ready) -> AsyncIterator:
    db = SessionLocal()
    try:
        db.query(AuditLog).delete()
        db.commit()
        yield db
    finally:
        db.query(AuditLog).delete()
        db.commit()
        db.close()


@pytest.mark.asyncio
async def test_audit_middleware_writes_ip(db_session) -> None:
    """Legacy request with ``client.host='1.2.3.4'`` → ``details.ip='1.2.3.4'``.

    Spec REQ-013 scenario: the audit row's ``details.ip`` must mirror
    ``request.client.host`` so the legacy-usage aggregation can GROUP BY
    the real client IP without resorting to X-Forwarded-For parsing.
    """
    app = _build_test_app(
        user_id="local",
        username="legacy",
        auth_method="legacy",
    )
    transport = ASGITransport(app=app, client=("1.2.3.4", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/probe")
    assert resp.status_code == 200

    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    details = rows[0].details
    assert details["ip"] == "1.2.3.4", (
        f"details.ip should mirror request.client.host '1.2.3.4', "
        f"got {details.get('ip')!r}"
    )
    assert details["auth_method"] == "legacy", (
        f"details.auth_method should be 'legacy', got "
        f"{details.get('auth_method')!r}"
    )


@pytest.mark.asyncio
async def test_audit_middleware_writes_unknown_when_no_client(
    db_session,
) -> None:
    """``request.client is None`` → ``details.ip='unknown'``; no exception.

    Spec REQ-013 second scenario: some ASGI test harnesses (and ASGI
    servers behind misconfigured proxies) surface requests with
    ``request.client = None``. The middleware must NOT raise — a single
    uncaught exception would silently break audit logging for every
    downstream endpoint.
    """
    app = _build_minimal_app()
    # ``ASGITransport(client=("??"))`` won't render client=None reliably,
    # so we use the default transport (TestClient peer='testclient') and
    # explicitly strip the client scope via a tiny no-op middleware.
    from starlette.types import ASGIApp, Receive, Scope, Send

    class _StripClient:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            # Drop the client tuple so AuditLogMiddleware sees None.
            if scope["type"] == "http":
                scope = {**scope, "client": None}
            await self.app(scope, receive, send)

    app.add_middleware(_StripClient)  # type: ignore[arg-type]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/open")
    assert resp.status_code == 200

    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    details = rows[0].details
    assert details["ip"] == "unknown", (
        f"missing request.client must yield details.ip='unknown', "
        f"got {details.get('ip')!r}"
    )
    # auth_method falls back to "unknown" when DualAuthMiddleware never ran
    # (e.g. health probes).
    assert details["auth_method"] == "unknown"


@pytest.mark.asyncio
async def test_audit_middleware_writes_jwt_auth_method(db_session) -> None:
    """JWT-authenticated request → ``details.auth_method='jwt'``.

    Pairs with the legacy case above: every reachable ``auth_method``
    from DualAuthMiddleware (``"jwt"`` / ``"legacy"`` / ``"dev"``) MUST
    propagate to ``details`` so post-hoc analytics can filter the
    audit_log cleanly. Forward-compat — the legacy-usage endpoint
    filters on ``username='legacy'`` today but the auth_method column
    keeps future queries schema-stable.
    """
    app = _build_test_app(
        user_id="user-uuid-1",
        username="alice",
        auth_method="jwt",
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/probe")
    assert resp.status_code == 200

    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    details = rows[0].details
    assert details["auth_method"] == "jwt"
    # ASGITransport's default peer is the local loopback; pinned loosely
    # so the test survives httpx version bumps that change the default
    # peer tuple.
    assert details["ip"] in {"127.0.0.1", "testclient"}
