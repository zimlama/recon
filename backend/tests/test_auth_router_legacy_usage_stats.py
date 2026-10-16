"""Tests for the legacy-usage-stats endpoint (PR-J3.7, REQ-LEG-001..007 + PR-J4).

Spec coverage (engram #1431):

- REQ-LEG-001 — admin GET → 200 + ``LegacyUsageStatsResponse``.
- REQ-LEG-002 — the ``X-Admin-Gate-Best-Effort: true`` response header
  is REMOVED (PR-J4): the admin gate is now JWT-verified, no caveat.
  Tests assert the header is NOT present.
- REQ-LEG-004 — ``?since`` param parsing: malformed → 400
  ``invalid_since``; ``>365d`` ago → 400 ``since_too_old``.
- REQ-LEG-006 — ``X-Forwarded-For`` is NOT parsed; only
  ``request.client.host`` is used.
- REQ-LEG-007 — admin GET writes an audit_log row (audit-of-audit).
- Auth gating — non-admin → 403 ``forbidden``; no token → 401.

PR-J4 change: drop the synthetic ``_AuthStubMiddleware`` and the
``_FakeJwtKeys`` stub. Mount the real ``DualAuthMiddleware`` with a
test-only ``JwtKeyManager`` (writes a temp PEM per-test) so the dep
chain re-verifies the JWT signature at every call. Tests sign real
admin / operator JWTs and pass them via ``Authorization: Bearer`` —
no ``state.role`` seeding. The dep must surface the freshly-decoded
``role`` claim.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from app.audit.middleware import AuditLogMiddleware
from app.auth.errors import AuthError, to_http_response
from app.auth.jwt import JwtKeyManager
from app.auth.middleware import DualAuthMiddleware
from app.auth.router import router as auth_router
from app.database import Base, SessionLocal, engine
from app.models import AuditLog

# ---------------------------------------------------------------------------
# Test rig — real RSA keypair + real JwtKeyManager
# ---------------------------------------------------------------------------


@pytest.fixture
def rsa_pem_pair() -> tuple[bytes, bytes]:
    """Generate a fresh 2048-bit RSA keypair as (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture
def jwt_keys(
    tmp_path: Path, rsa_pem_pair: tuple[bytes, bytes]
) -> Iterator[JwtKeyManager]:
    """Live ``JwtKeyManager`` wired to a temp keypair.

    Lifetime is per-test so token rotations / state changes can't
    leak between cases.
    """
    priv, pub = rsa_pem_pair
    priv_path = tmp_path / "priv.pem"
    pub_path = tmp_path / "pub.pem"
    priv_path.write_bytes(priv)
    pub_path.write_bytes(pub)
    mgr = JwtKeyManager(
        private_path=priv_path,
        public_path=pub_path,
        kid="k1",
        issuer="recon-auth",
    )
    return mgr


def _make_token(
    jwt_keys: JwtKeyManager,
    *,
    sub: str,
    role: str,
) -> str:
    """Sign a fresh access JWT with the test ``JwtKeyManager``."""
    return jwt_keys.sign(
        {"sub": sub, "role": role, "scopes": ["jobs:read"]},
        ttl_seconds=900,
    )


def _make_app(jwt_keys: JwtKeyManager) -> FastAPI:
    """Build an app that mounts the auth router under the REAL
    ``DualAuthMiddleware`` with the test ``JwtKeyManager`` (no
    synthetic stubs).

    The middleware writes ``request.state`` from the freshly-decoded
    JWT; the dep then re-verifies that JWT on every admin-gated
    request (PR-J4). No ``_AuthStubMiddleware`` — the test exercises
    the production code path end-to-end.
    """

    app = FastAPI()
    app.include_router(auth_router)

    @app.exception_handler(AuthError)
    async def _handler(_request, exc):  # type: ignore[no-untyped-def]
        status, headers, body = to_http_response(exc)
        return JSONResponse(
            status_code=status, content=body, headers=headers
        )

    # Lifecycle: the real ``DualAuthMiddleware`` factory reads
    # ``app.state.jwt_keys`` (per the middleware's
    # ``_jwt_keys_factory`` contract).
    app.state.db_session_factory = SessionLocal
    app.state.refresh_service = None  # not used by the new endpoint
    app.state.jwt_keys = jwt_keys

    def _jwt_keys_factory(request):  # type: ignore[no-untyped-def]
        return request.app.state.jwt_keys

    # Audit log middleware — required for the audit-of-audit test
    # (REQ-LEG-007): the GET itself must write one audit_log row.
    app.add_middleware(AuditLogMiddleware)

    app.add_middleware(
        DualAuthMiddleware,
        jwt_keys_factory=_jwt_keys_factory,
        allow_legacy_api_key=False,
        legacy_api_key=None,
        jwt_keys_configured=True,
    )
    return app


@pytest_asyncio.fixture
async def db_ready() -> AsyncIterator[None]:
    Base.metadata.drop_all(bind=engine)
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


# ---------------------------------------------------------------------------
# T5.1 (RED → GREEN) — the X-Admin-Gate-Best-Effort header is gone.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_get_returns_200_with_response_body_no_best_effort_header(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """T5.1 — admin GET → 200 + ``LegacyUsageStatsResponse``; the
    ``X-Admin-Gate-Best-Effort`` header is NOT present (PR-J4 removed it).

    Mirrors the operator happy path: an admin reads the legacy-key
    consumer list before the PR-J8 cutoff.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            "/api/v1/auth/legacy-usage-stats",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    # PR-J4 (REQ-ADM-005): the best-effort header is gone.
    assert "X-Admin-Gate-Best-Effort" not in resp.headers
    assert resp.headers.get("x-admin-gate-best-effort") is None
    body = resp.json()
    assert body["window_days"] in {30, 31}  # default 30 d
    assert body["total_legacy_requests"] == 0
    assert body["unique_ips"] == 0
    assert body["rows"] == []
    # Caveat MUST NOT leak into the body either.
    assert "best_effort" not in body
    assert "X-Admin-Gate-Best-Effort" not in body


@pytest.mark.asyncio
async def test_operator_get_returns_403_forbidden_real_jwt(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """T5.1 — operator GET → 403 ``{"error": "forbidden"}`` via
    ``AdminForbiddenError`` mapped by the exception handler.

    Real JWT signed with the test ``JwtKeyManager`` — operator
    ``role`` claim fails the ``require_admin`` gate.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-op", role="operator")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            "/api/v1/auth/legacy-usage-stats",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "forbidden"
    assert body["required_role"] == "admin"
    # The best-effort header is NOT set on errors — it's reserved
    # for the 200 admin path.
    assert "X-Admin-Gate-Best-Effort" not in resp.headers


@pytest.mark.asyncio
async def test_no_token_returns_401_real_jwt(jwt_keys: JwtKeyManager, db_session) -> None:
    """T5.1 — no ``Authorization`` header → 401.

    The dep re-verifies the JWT; without one the gate refuses.
    """

    app = _make_app(jwt_keys)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/api/v1/auth/legacy-usage-stats")
    assert resp.status_code == 401
    assert "X-Admin-Gate-Best-Effort" not in resp.headers


@pytest.mark.asyncio
async def test_malformed_since_returns_400(jwt_keys: JwtKeyManager, db_session) -> None:
    """``?since=garbage`` → 400 ``invalid_since``.

    Pydantic's datetime parser emits a ``detail`` string which the
    router forwards verbatim.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            "/api/v1/auth/legacy-usage-stats?since=garbage",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_since"
    assert "detail" in body


@pytest.mark.asyncio
async def test_since_too_old_returns_400(jwt_keys: JwtKeyManager, db_session) -> None:
    """``?since`` older than 365 d → 400 ``since_too_old`` with
    ``max_lookback_days``.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    too_old = datetime(2020, 1, 1, tzinfo=UTC).isoformat()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            f"/api/v1/auth/legacy-usage-stats?since={too_old}",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "since_too_old"
    assert body["max_lookback_days"] == 365


@pytest.mark.asyncio
async def test_since_z_suffix_returns_200(jwt_keys: JwtKeyManager, db_session) -> None:
    """``?since=2024-01-01T00:00:00Z`` (Z-suffix) → 200 (parsed correctly).

    Coverage for the ``normalised.endswith("Z")`` branch in
    ``_parse_since`` — the router accepts ISO 8601 with the ``Z``
    suffix and normalises it to ``+00:00``.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    # A recent Z-suffixed timestamp that's within the 365-day window.
    recent = datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            f"/api/v1/auth/legacy-usage-stats?since={recent}",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_since_naive_datetime_returns_200(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """``?since=YYYY-MM-DDTHH:MM:SS`` (naive, no TZ) → 200.

    Coverage for the ``if parsed.tzinfo is None`` branch in
    ``_parse_since`` — naive datetimes are coerced to UTC.
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    # A recent naive ISO 8601 (no TZ); the router fills in UTC.
    naive_recent = datetime.now(tz=UTC).replace(microsecond=0, tzinfo=None).isoformat()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            f"/api/v1/auth/legacy-usage-stats?since={naive_recent}",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Coverage exercises for router.py exception paths (REQ-ADM-006 helper).
# These pre-existing routes share the same exception-handler wiring; a
# targeted coverage test exercises the ``except AuthError → raise`` line
# that the legacy-usage-stats test does not. Out of scope for PR-J4's
# functional surface — only the COVERAGE-90 gate is served.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_missing_user_returns_401(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """``GET /api/v1/auth/me`` without auth → 401.

    Coverage for ``router.py:216-217`` (the ``except AuthError → raise``
    branch in ``me_route``).
    """
    app = _make_app(jwt_keys)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_xff_not_parsed_as_distinct_ip(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """``X-Forwarded-For`` is NOT consulted — only
    ``request.client.host`` counts.

    The test seeds an audit row with ``ip='1.2.3.4'`` (matching the
    test client's host) and sends an XFF header pretending to be
    ``8.8.8.8``; the response rows must NOT include 8.8.8.8 because
    the audit middleware uses ``request.client.host`` only.
    """

    db_session.add(
        AuditLog(
            timestamp=datetime.now(tz=UTC),
            action="GET_/api/v1/jobs",
            user_id="local",
            username="legacy",
            details={
                "method": "GET",
                "path": "/api/v1/jobs",
                "status_code": 200,
                "duration_ms": 1.0,
                "ip": "127.0.0.1",  # matches httpx ASGI default
                "auth_method": "legacy",
                "user_agent": "ua",
            },
        )
    )
    db_session.commit()

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            "/api/v1/auth/legacy-usage-stats",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "8.8.8.8",
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    ips = [r["ip"] for r in body["rows"]]
    # Must contain the audit-row IP, NOT the XFF IP.
    assert "127.0.0.1" in ips
    assert "8.8.8.8" not in ips


@pytest.mark.asyncio
async def test_audit_of_audit_writes_one_audit_row(
    jwt_keys: JwtKeyManager, db_session
) -> None:
    """Admin GET writes one ``audit_log`` row (REQ-LEG-007).

    Mirrors the audit-chain principle: every authenticated request
    MUST log itself; the admin read of the legacy-usage list is no
    exception. The action label is the spec-prescribed
    ``GET_<full_path>`` shape (``AuditLogMiddleware`` formats it
    that way).
    """

    app = _make_app(jwt_keys)
    token = _make_token(jwt_keys, sub="u-admin", role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get(
            "/api/v1/auth/legacy-usage-stats",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200

    rows = db_session.query(AuditLog).all()
    legacy_stats_rows = [
        r for r in rows if r.action.endswith("/api/v1/auth/legacy-usage-stats")
    ]
    assert len(legacy_stats_rows) == 1, (
        f"expected exactly one audit_log row for GET_/api/v1/auth/"
        f"legacy-usage-stats, got {len(legacy_stats_rows)}"
    )
    row = legacy_stats_rows[0]
    assert row.user_id == "u-admin"
    assert row.details.get("auth_method") == "jwt"
    assert row.details.get("ip") in {"127.0.0.1", "testclient"}
