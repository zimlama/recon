"""Tests for the FastAPI RoE enforcement middleware.

The middleware is OFF by default — it reads `ROE_ENABLED=true` from the
environment on construction. When disabled, it is a transparent pass-
through. When enabled, it gates POST requests to protected URLs on the
existence of an active RoE for the target declared in the request body.
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.middleware.roe import RoEMiddleware
from app.models import RoE, RoEStatus, ScopeType, SignOff, _now

# ---------------------------------------------------------------------------
# Fixtures — local, self-contained private engine. See `tests/test_models.py`
# for the same pattern: the global engine in `app.database` interacts badly
# with `coverage` instrumentation under SQLAlchemy 2.1.x (Cython cache-key
# compilation errors). Using a private per-test engine keeps these tests
# stable under `--cov` and avoids cross-test contamination.
# ---------------------------------------------------------------------------


@pytest.fixture
def session_factory(tmp_path):  # type: ignore[no-untyped-def]
    """Yield (session, session_factory) tuple backed by a private engine.

    The middleware takes a `session_factory` callable; the validator
    uses the same. Returning both keeps the tests aligned with the
    middleware's constructor signature while still letting the test
    inspect rows directly.
    """
    db_path = tmp_path / "roe_middleware_test.db"
    if db_path.exists():
        db_path.unlink()

    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    RoE.__table__.create(bind=eng, checkfirst=True)
    SignOff.__table__.create(bind=eng, checkfirst=True)
    Session_ = sessionmaker(
        bind=eng, autoflush=False, autocommit=False, expire_on_commit=False
    )

    db = Session_()

    def factory() -> Session:
        return Session_()

    try:
        yield db, factory
    finally:
        db.close()
        SignOff.__table__.drop(bind=eng, checkfirst=True)
        RoE.__table__.drop(bind=eng, checkfirst=True)
        eng.dispose()
        try:
            db_path.unlink()
        except FileNotFoundError:
            pass

def _make_test_app(session_factory):  # type: ignore[no-untyped-def]
    """A tiny FastAPI app with the RoE middleware mounted.

    Two endpoints:
      - `POST /api/v1/jobs` — protected by RoE when middleware is enabled.
      - `POST /health` — NOT in the protected list; always passes through.

    The middleware reads `ROE_ENABLED` from the env at construction time
    (the user spec). Per-test enable/disable is handled by the fixture
    below.
    """
    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=session_factory,
        protected_paths=["/api/v1/jobs"],
    )

    @app.post("/api/v1/jobs")
    async def create_job(payload: dict[str, Any]) -> dict[str, Any]:
        return {"created": True, "echo": payload}

    @app.post("/health")
    async def health(payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "echo": payload}

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_active_roe(session: Session, target: str = "example.com") -> RoE:
    """Insert an ACTIVE RoE + active signoff for the target."""
    now = _now()
    roe = RoE(
        target=target,
        scope_type=ScopeType.DOMAIN,
        scope_value=target,
        authorized_by="alice@example.com",
        status=RoEStatus.ACTIVE,
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=24),
    )
    session.add(roe)
    session.commit()
    session.refresh(roe)

    session.add(
        SignOff(
            roe_id=roe.id,
            signer_name="Bob",
            signer_email="bob@example.com",
            signer_role="CEO",
        )
    )
    session.commit()
    return roe


# ---------------------------------------------------------------------------
# Disabled-by-default behaviour
# ---------------------------------------------------------------------------


def test_middleware_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
    session_factory,  # type: ignore[no-untyped-def]
) -> None:
    """When `ROE_ENABLED` is unset, `_enabled` is False at construction.

    We construct the middleware in isolation (no `add_middleware` — just
    `RoEMiddleware(app, ...)`) so we can read its private flag without
    spinning up the full ASGI app.
    """
    monkeypatch.delenv("ROE_ENABLED", raising=False)

    app = FastAPI()
    _db, factory = session_factory
    mw = RoEMiddleware(app, session_factory=factory)
    assert mw._enabled is False


def test_middleware_enabled_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
    session_factory,  # type: ignore[no-untyped-def]
) -> None:
    """`ROE_ENABLED=true` flips `_enabled` to True at construction."""
    monkeypatch.setenv("ROE_ENABLED", "true")

    app = FastAPI()
    _db, factory = session_factory
    mw = RoEMiddleware(app, session_factory=factory)
    assert mw._enabled is True


@pytest.mark.asyncio
async def test_middleware_passes_when_disabled(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A protected POST with NO RoE in the DB still gets through.

    Disabled middleware must not change any response shape. We hit
    `/api/v1/jobs` with a body, no RoE exists, and we expect a 200
    with the echoed payload.
    """
    # No RoE in DB on purpose.
    monkeypatch.delenv("ROE_ENABLED", raising=False)

    _db, factory = session_factory
    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            json={"target": "example.com"},
        )
    assert resp.status_code == 200
    assert resp.json()["echo"] == {"target": "example.com"}


# ---------------------------------------------------------------------------
# Enabled + protected behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_blocks_when_enabled_and_no_roe(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enabled middleware with no matching RoE returns 403."""
    # No RoE seeded.
    monkeypatch.setenv("ROE_ENABLED", "true")

    _db, factory = session_factory
    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            json={"target": "example.com"},
        )
    assert resp.status_code == 403
    body = resp.json()
    # Some kind of "not authorized" message — the exact key/wording is
    # not part of the spec, just the outcome.
    detail_blob = json.dumps(body).lower()
    assert "no roe" in detail_blob or "not authorized" in detail_blob or "roe" in detail_blob


@pytest.mark.asyncio
async def test_middleware_passes_when_enabled_and_valid_roe(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enabled middleware with a matching active RoE returns 200.

    We also verify that the body is forwarded intact — the middleware
    must re-inject the cached body into the request so the downstream
    handler can still parse it.
    """
    db, factory = session_factory
    _seed_active_roe(db, target="example.com")
    monkeypatch.setenv("ROE_ENABLED", "true")

    app = _make_test_app(factory)
    payload = {"target": "example.com", "extra": "field"}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/api/v1/jobs", json=payload)

    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] is True
    assert body["echo"] == payload


@pytest.mark.asyncio
async def test_middleware_skips_non_protected_endpoints(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSTs to paths outside the protected list pass through, even when enabled.

    `ROE_ENABLED=true` does NOT mean "reject every request" — only
    protected paths are gated. We POST to `/health` (not in the list)
    with no RoE in the DB and expect a 200.
    """
    # No RoE seeded.
    monkeypatch.setenv("ROE_ENABLED", "true")

    _db, factory = session_factory
    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/health", json={"any": "body"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Body forwarding — sanity check that we cache + replay the request body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_forwards_body_bytes_correctly(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The middleware caches the body and replays it downstream.

    Even though we read `await request.body()` to parse the target, the
    downstream FastAPI handler must still see the SAME bytes — not an
    empty stream. We verify by sending a complex payload and checking
    round-trip equality.
    """
    db, factory = session_factory
    _seed_active_roe(db, target="example.com")
    monkeypatch.setenv("ROE_ENABLED", "true")

    app = _make_test_app(factory)
    payload = {"target": "example.com", "list": [1, 2, 3], "nested": {"a": 1}}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    assert resp.json()["echo"] == payload


# ---------------------------------------------------------------------------
# Input-validation edge cases (the middleware must NEVER silently allow
# a request through when it couldn't parse the body — that would be a
# silent foot-gun for the operator trying to debug "why is my job
# running without an RoE?").
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_rejects_malformed_json(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed JSON body returns 400 — the RoE gate stays closed.

    A `json.loads` failure is exactly the kind of input that must
    produce an explicit 400, not a silent 403 (which would hide the
    real cause from the operator).
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_body"


@pytest.mark.asyncio
async def test_middleware_rejects_missing_target(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POST with valid JSON but no `target` field returns 400.

    Without a target we have no key for the RoE lookup, so the gate
    cannot authorize. The middleware must surface this explicitly
    rather than treating it as "no RoE → 403" (which would be
    misleading: the real problem is a bad request).
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/api/v1/jobs", json={"other": "field"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "missing_target"


@pytest.mark.asyncio
async def test_middleware_rejects_non_string_target(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`target` of any non-string type (int, list, bool) is treated as missing.

    We accept only strings for the target — everything else is a
    contract violation from the client.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/api/v1/jobs", json={"target": 12345})
    assert resp.status_code == 400
    assert resp.json()["error"] == "missing_target"


@pytest.mark.asyncio
async def test_middleware_rejects_non_dict_body(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JSON array (or other non-object) body returns 400.

    The RoE lookup assumes a `target` field on an object. A list or
    scalar body can't possibly carry it — fail closed.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            content=b'["just", "an", "array"]',
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_body"


@pytest.mark.asyncio
async def test_middleware_falls_back_to_domain_on_bad_scope_type(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown `scope_type` value falls back to DOMAIN rather than 400.

    A bad `scope_type` is a malformed-but-recoverable input. The
    middleware coerces it to DOMAIN and continues — denial-of-service
    via malformed-scope_type must not be possible.
    """
    db, factory = session_factory
    _seed_active_roe(db, target="example.com")
    monkeypatch.setenv("ROE_ENABLED", "true")

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            json={"target": "example.com", "scope_type": "not_a_real_scope"},
        )
    # Coerced to DOMAIN — should match the seeded one and pass.
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_middleware_skips_disabled_path_with_invalid_body(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the middleware is disabled, an invalid body still passes through.

    The middleware must NOT pre-validate the body when it's a no-op —
    that would change the response shape for unaffected requests. With
    the middleware disabled, the route handler is responsible for the
    body (FastAPI may return 422 from its own JSON parsing, or 200 if
    the handler is permissive). The point is the middleware did not
    emit a 400 from its own body-validation branch.
    """
    monkeypatch.delenv("ROE_ENABLED", raising=False)
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
    # Must NOT be a 400 from the middleware's body-validation branch.
    assert resp.status_code != 400
    # FastAPI's own JSON parsing returns 422 here — that's the
    # handler's call, not the middleware's.
    assert resp.status_code in (200, 422)


@pytest.mark.asyncio
async def test_middleware_rejects_empty_body(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty body is a request without a target — return 400, not 403.

    An empty POST has no `target` to look up. The middleware must
    reject it explicitly so the operator sees "you forgot to send the
    target" instead of "no RoE found".
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = _make_test_app(factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post(
            "/api/v1/jobs",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "missing_target"


# ---------------------------------------------------------------------------
# Contract hardening — extra branches not strictly needed but useful as
# regression guards: target normalization, env-flag case sensitivity,
# non-POST protected paths.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_normalizes_target_case_for_lookup(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target with surrounding whitespace + mixed case still matches an
    `example.com` RoE.

    The validator applies `target.strip().lower()`; the middleware
    must forward the raw string (so the validator sees it) rather than
    pre-normalizing and breaking the round-trip.
    """
    db, factory = session_factory
    _seed_active_roe(db, target="example.com")
    monkeypatch.setenv("ROE_ENABLED", "true")

    app = _make_test_app(factory)
    payload = {"target": "  EXAMPLE.com  "}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.post("/api/v1/jobs", json=payload)
    assert resp.status_code == 200
    assert resp.json()["echo"] == payload


@pytest.mark.asyncio
async def test_middleware_case_insensitive_env_flag_uppercase(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ROE_ENABLED=TRUE` (uppercase) also enables the middleware.

    The flag is parsed with `.lower() == "true"`, so any casing of
    "true" enables it. Common in container/CI env files.
    """
    monkeypatch.setenv("ROE_ENABLED", "TRUE")
    _db, factory = session_factory

    app = FastAPI()
    mw = RoEMiddleware(app, session_factory=factory)
    assert mw._enabled is True


@pytest.mark.asyncio
async def test_middleware_env_flag_invalid_value_stays_off(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid env value (`1`, `yes`, `enabled`) keeps the middleware OFF.

    We accept literal "true" (case-insensitive) and nothing else.
    Operators who set `ROE_ENABLED=1` get the safe default — they must
    set the canonical value to flip the gate on.
    """
    monkeypatch.setenv("ROE_ENABLED", "1")
    _db, factory = session_factory

    app = FastAPI()
    mw = RoEMiddleware(app, session_factory=factory)
    assert mw._enabled is False


@pytest.mark.asyncio
async def test_middleware_does_not_gate_get_requests(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET on a protected path is not gated even when middleware is on.

    The middleware filters by state-changing methods (POST/PUT/PATCH/DELETE);
    GETs are read-only and pass straight through. Confirm by adding a
    GET endpoint in the test app and posting a request with method
    GET — no RoE means a 200, not a 403.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=factory,
        protected_paths=["/api/v1/jobs"],
    )

    @app.get("/api/v1/jobs")
    async def list_jobs() -> dict[str, Any]:
        return {"jobs": []}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.get("/api/v1/jobs")
    assert resp.status_code == 200
    assert resp.json() == {"jobs": []}


@pytest.mark.asyncio
async def test_middleware_gates_delete_requests(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELETE /api/v1/jobs/{id} must be gated by RoE (audit R1-H1).

    Without an active RoE the middleware must reject DELETE with
    ``roe_not_authorized`` (403) — same shape as a rejected POST.
    Cascading DELETE removes Job, ModuleRun, Finding, AIValidation,
    IdentityMap, SignOff, and RoE rows; bypassing RoE here lets any
    operator wipe engagements they never had sign-off for.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=factory,
        protected_paths=["/api/v1/jobs/"],
    )

    @app.delete("/api/v1/jobs/{job_id}")
    async def delete_job(job_id: str) -> dict[str, str]:
        return {"deleted": job_id}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        resp = await ac.request(
            "DELETE",
            "/api/v1/jobs/abc-123",
            content=json.dumps({"target": "example.com"}),
            headers={"Content-Type": "application/json"},
        )

    assert resp.status_code == 403
    assert resp.json()["error"] == "roe_not_authorized"


@pytest.mark.asyncio
async def test_middleware_gates_put_and_patch_too(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PUT / PATCH on protected paths must also be gated by RoE.

    Both methods change server state. Without RoE coverage the
    middleware must reject them with 403, just like POST.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=factory,
        protected_paths=["/api/v1/jobs/"],
    )

    @app.put("/api/v1/jobs/{job_id}")
    async def put_job(job_id: str) -> dict[str, str]:
        return {"updated": job_id}

    @app.patch("/api/v1/jobs/{job_id}")
    async def patch_job(job_id: str) -> dict[str, str]:
        return {"patched": job_id}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        put_resp = await ac.put(
            "/api/v1/jobs/abc-123", json={"target": "example.com"}
        )
        patch_resp = await ac.patch(
            "/api/v1/jobs/abc-123", json={"target": "example.com"}
        )

    assert put_resp.status_code == 403
    assert put_resp.json()["error"] == "roe_not_authorized"
    assert patch_resp.status_code == 403
    assert patch_resp.json()["error"] == "roe_not_authorized"


@pytest.mark.asyncio
async def test_middleware_returns_503_on_db_failure(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RoE DB lookup must surface as 503, not 500.

    Audit finding R4-C2: a transient OperationalError (DB down,
    connection pool exhausted) used to bubble from
    ``validator.is_authorized()`` straight to Starlette and returned a
    raw 500 with no Retry-After. Now the middleware catches
    ``SQLAlchemyError`` at the dispatch boundary and returns a 503 with
    ``rules_of_engagement_unavailable`` plus a ``Retry-After`` header.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=factory,
        protected_paths=["/api/v1/jobs"],
    )

    @app.post("/api/v1/jobs")
    async def create_job() -> dict[str, str]:
        return {"created": "job"}

    # Patch the validator to raise OperationalError — simulates DB down.
    from app.orchestrator.roe import RoEValidator

    boom = OperationalError("SELECT", {}, Exception("connection refused"))

    def _raise(*_args: Any, **_kwargs: Any) -> tuple[bool, str, list[Any]]:
        raise boom

    with patch.object(RoEValidator, "is_authorized", side_effect=_raise):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/api/v1/jobs",
                json={"target": "example.com"},
            )

    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "rules_of_engagement_unavailable"
    assert body["retry_after"] == 30
    assert resp.headers["Retry-After"] == "30"


@pytest.mark.asyncio
async def test_middleware_503_on_disconnection(
    session_factory,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``DisconnectionError`` (``SQLAlchemyError`` subclass) is also 503."""
    monkeypatch.setenv("ROE_ENABLED", "true")
    _db, factory = session_factory

    app = FastAPI()
    app.add_middleware(
        RoEMiddleware,
        session_factory=factory,
        protected_paths=["/api/v1/jobs"],
    )

    @app.post("/api/v1/jobs")
    async def create_job() -> dict[str, str]:
        return {"created": "job"}

    from sqlalchemy.exc import DisconnectionError

    boom = DisconnectionError("connection invalidated")

    from app.orchestrator.roe import RoEValidator

    def _raise(*_args: Any, **_kwargs: Any) -> tuple[bool, str, list[Any]]:
        raise boom

    with patch.object(RoEValidator, "is_authorized", side_effect=_raise):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/api/v1/jobs",
                json={"target": "example.com"},
            )

    assert resp.status_code == 503
    assert resp.json()["error"] == "rules_of_engagement_unavailable"
