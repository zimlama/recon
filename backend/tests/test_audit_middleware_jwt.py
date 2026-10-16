"""Tests for AuditLogMiddleware reading request.state populated by DualAuthMiddleware.

Spec background (sec-auth-jwt Issue #29, §5 audit_log extension):
    Every authenticated request MUST persist ``user_id``, ``username`` and
    ``request_jwt_jti`` in the ``audit_log`` row, NOT the legacy
    hardcoded ``user_id='local'`` fallback.

These tests pin the contract end-to-end: a tiny FastAPI app wrapped in
the real ``AuditLogMiddleware``, with ``request.state`` populated by a
hand-rolled middleware layer (mirroring ``DualAuthMiddleware``).

The middleware is the source of truth for what gets logged, so the unit
boundary is between the request, the middleware, and the
``AuditLog`` row — not the router. The auth routing layer is exercised
elsewhere (``test_auth_flow.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.audit.middleware import AuditLogMiddleware
from app.database import Base, SessionLocal, engine
from app.models import AuditLog


def _new_jti() -> str:
    """Return a UUID-formatted string for the JWT ``jti`` claim."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _StateSeedingMiddleware:
    """Tiny test middleware that populates ``request.state`` BEFORE the
    AuditLogMiddleware sees it. Mirrors what DualAuthMiddleware does in
    production for the JWT path / legacy path / unauthenticated path.
    """

    def __init__(self, app, *, user_id: str | None, username: str | None, jwt_jti: str | None) -> None:
        self.app = app
        self._user_id = user_id
        self._username = username
        self._jwt_jti = jwt_jti

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            # Inject via MutableHeaders-style surrogate: starlette provides
            # request.state via the ASGI scope. The simplest way is to wrap
            # the receive/send to set request.state once Request is built.
            # We patch via a downstream _set_state route handler instead.
            pass
        await self.app(scope, receive, send)


def _build_test_app(
    *,
    user_id: str | None,
    username: str | None,
    jwt_jti: str | None,
    path: str = "/probe",
) -> FastAPI:
    """Build a tiny FastAPI app where GET <path> populates request.state
    with the supplied credentials, then AuditLogMiddleware logs them.

    The endpoint explicitly sets ``request.state.<attr>`` because
    BaseHTTPMiddleware-style middlewares run OUTSIDE the request handler
    in the same chain — using a test-only StateSeedingHandler is the
    reliable way to exercise the contract without depending on the
    real DualAuthMiddleware.
    """

    app = FastAPI()

    @app.get(path)
    async def set_state(request: Request) -> dict[str, str]:
        # Mirror DualAuthMiddleware behavior on the request.state contract.
        if user_id is not None:
            request.state.user_id = user_id
        if username is not None:
            request.state.username = username
        if jwt_jti is not None:
            request.state.jwt_jti = jwt_jti
        return {"ok": "true"}

    # AuditLogMiddleware sits OUTERMOST so it always sees the request
    # after the route handler populates state, then on the way back out.
    app.add_middleware(AuditLogMiddleware)
    return app


@pytest_asyncio.fixture
async def db_ready() -> AsyncIterator[None]:
    """Ensure audit_log table exists for the in-process engine."""
    # NB: conftest already initialised tables globally, but be defensive
    # so this file is also runnable in isolation.
    Base.metadata.create_all(bind=engine)
    yield
    # Don't drop_all here — conftest's session-scoped DB might share state.


@pytest_asyncio.fixture
async def db_session(db_ready) -> AsyncIterator:
    """Yield a session and clean the audit_log table between tests."""
    db = SessionLocal()
    try:
        # Clear any rows from prior tests.
        db.query(AuditLog).delete()
        db.commit()
        yield db
    finally:
        db.query(AuditLog).delete()
        db.commit()
        db.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_records_user_id_and_username_from_jwt(
    db_session,
) -> None:
    """JWT-authenticated request → AuditLog row carries the JWT-issued
    ``user_id`` and ``username`` — not the legacy hardcoded "local".

    Reproduces R4 R-Audit finding: login as alice@example.com used to be
    logged with ``user_id='local'`` because AuditLogMiddleware ignored
    ``request.state``. After PR-J3.7 the row carries the JWT subject.
    """
    user_id = str(uuid.uuid4())
    username = "alice"

    app = _build_test_app(
        user_id=user_id,
        username=username,
        jwt_jti=_new_jti(),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/probe")

    assert resp.status_code == 200
    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1, f"expected 1 audit_log row, got {len(rows)}"
    row = rows[0]
    assert row.user_id == user_id, (
        f"AuditLog.user_id should be the JWT subject {user_id!r}, "
        f"got {row.user_id!r}"
    )
    assert row.username == username, (
        f"AuditLog.username should be {username!r}, got {row.username!r}"
    )


@pytest.mark.asyncio
async def test_audit_log_records_jwt_jti_claim(db_session) -> None:
    """JWT with ``jti`` claim → AuditLog row carries ``request_jwt_jti``.

    Spec §5 requires every JWT-authenticated request to be linked back to
    its ``jti`` for revocation tracking. Without this, the audit chain
    loses the per-token replay / revocation evidence.
    """
    jti = _new_jti()
    user_id = str(uuid.uuid4())

    app = _build_test_app(
        user_id=user_id,
        username="bob",
        jwt_jti=jti,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/probe")

    assert resp.status_code == 200
    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.request_jwt_jti == jti, (
        f"AuditLog.request_jwt_jti should be {jti!r}, got "
        f"{row.request_jwt_jti!r}"
    )


@pytest.mark.asyncio
async def test_audit_log_legacy_bearer_path_is_distinguishable(
    db_session,
) -> None:
    """Legacy Bearer (``ALLOW_LEGACY_API_KEY``) path → AuditLog row
    carries the synthetic legacy marker; ``request_jwt_jti`` is NULL.

    The DualAuthMiddleware contract sets ``request.state.username =
    "legacy"`` on the legacy path with no JWT subject available. The
    audit row MUST distinguish that path from a JWT-authenticated row
    so post-hoc analyses (revocation, replay, who-did-what) are accurate.
    """
    app = _build_test_app(
        user_id="local",
        username="legacy",
        jwt_jti=None,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/probe")

    assert resp.status_code == 200
    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.user_id == "local"
    assert row.username == "legacy"
    assert row.request_jwt_jti is None, (
        "Legacy Bearer auth must NOT set request_jwt_jti"
    )


@pytest.mark.asyncio
async def test_audit_log_unauthenticated_request_does_not_crash(
    db_session,
) -> None:
    """Unauthenticated request (no request.state set) → middleware
    gracefully falls back to the "local" placeholder and does not raise.

    Regression — the /health, /ready, /docs and /openapi.json endpoints
    bypass DualAuthMiddleware entirely, so AuditLogMiddleware sees a
    request with no ``request.state.user_id`` set. It MUST default to
    the legacy placeholder rather than raising AttributeError, otherwise
    audit logging crashes and the request never completes.
    """
    # No state seeded → request.state has no user_id/username/jwt_jti.
    app = FastAPI()

    @app.get("/open")
    async def open_endpoint() -> dict[str, str]:
        return {"ok": "true"}

    app.add_middleware(AuditLogMiddleware)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/open")

    assert resp.status_code == 200
    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    row = rows[0]
    # Default fallback to "local" preserves pre-PR-J3.7 behavior.
    assert row.user_id == "local", (
        f"Unauthenticated request should default user_id='local', got {row.user_id!r}"
    )
    assert row.username == "local"
    assert row.request_jwt_jti is None
