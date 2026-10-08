# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Wiring tests for `create_app()` — proves RoEMiddleware is mounted when
`ROE_ENABLED=true` and is absent when disabled.

These tests are the RED-then-GREEN anchor for PR 1 REQ-021a (wire
`RoEMiddleware` into the live app) and REQ-028 (expose `ROE_ENABLED` in
`Settings` for operator visibility).

Two layers of coverage:

1. **In-process wiring** — build the app, inspect `app.user_middleware`,
   assert the middleware is/isn't there. No HTTP, no DB. Fast.
2. **End-to-end integration** — spin up a fresh app with `ROE_ENABLED=true`,
   POST to `/api/v1/jobs`, verify the 403 / 201 outcome against a seeded
   RoE table. Slower but proves the wiring actually fires on real requests.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models import RoE, RoEStatus, ScopeType, SignOff, _now

# ---------------------------------------------------------------------------
# Helpers — local module imports to keep reload/swap order deterministic
# ---------------------------------------------------------------------------


def _swap_settings(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> object:
    """Reset the lru_cache on `get_settings` and swap the module-level
    `settings` in `app.main` with a fresh `Settings(**overrides)`.

    Why both? `app.main.settings` is captured at import time from the
    cached `get_settings()` result. The middleware itself reads
    `os.getenv("ROE_ENABLED")` at construction, so we ALSO set the env
    var (the test does that before calling this helper). Returning the
    fresh settings object lets assertions inspect it directly.
    """
    import app.config as cfg_mod
    import app.main as main_mod

    cfg_mod.get_settings.cache_clear()
    fresh = cfg_mod.Settings(**overrides)
    monkeypatch.setattr(main_mod, "settings", fresh)
    return fresh


# ===========================================================================
# Layer 1 — In-process wiring (no HTTP, no DB)
# ===========================================================================


def test_roe_middleware_loaded_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """`ROE_ENABLED=true` -> `RoEMiddleware` is in `app.user_middleware`.

    RED: this fails before PR 1's wiring is in place because the
    middleware is never registered. GREEN once `create_app()` calls
    `app.add_middleware(RoEMiddleware, session_factory=SessionLocal)`.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _swap_settings(monkeypatch, ROE_ENABLED=True)

    from app.main import create_app

    app = create_app()
    middleware_names = [m.cls.__name__ for m in app.user_middleware]
    assert "RoEMiddleware" in middleware_names, (
        f"RoEMiddleware missing from app.user_middleware: {middleware_names}"
    )


def test_roe_middleware_not_loaded_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default (ROE_ENABLED unset) -> `RoEMiddleware` is absent.

    AC-021a.2: backward compat. Operators who don't opt in keep the
    no-op behavior.
    """
    monkeypatch.delenv("ROE_ENABLED", raising=False)
    _swap_settings(monkeypatch, ROE_ENABLED=False)

    from app.main import create_app

    app = create_app()
    middleware_names = [m.cls.__name__ for m in app.user_middleware]
    assert "RoEMiddleware" not in middleware_names


def test_roe_middleware_absent_on_invalid_env_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ROE_ENABLED=NotABool` -> middleware absent, app boots without error.

    Mirrors the existing middleware's `os.getenv(...).lower() == "true"`
    parse: anything other than the literal `"true"` leaves the middleware
    as a no-op. The wiring code must not crash on a typo in `.env`.
    """
    monkeypatch.setenv("ROE_ENABLED", "NotABool")
    _swap_settings(monkeypatch, ROE_ENABLED=False)

    from app.main import create_app

    app = create_app()  # must NOT raise
    middleware_names = [m.cls.__name__ for m in app.user_middleware]
    assert "RoEMiddleware" not in middleware_names


def test_session_factory_passed_is_session_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-021a.3: the middleware's `session_factory` IS the global `SessionLocal`
    (a callable that returns fresh sessions), not a `Session` instance.

    `app.user_middleware` is a list of Starlette `Middleware(cls, *args,
    **kwargs)` namedtuples (Starlette 1.0+ — `.kwargs`, not `.options`).
    We assert the callable identity is the global `SessionLocal`.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _swap_settings(monkeypatch, ROE_ENABLED=True)

    from app.main import create_app

    app = create_app()
    roe_mw = next(m for m in app.user_middleware if m.cls.__name__ == "RoEMiddleware")
    sf = roe_mw.kwargs["session_factory"]
    assert sf is SessionLocal, (
        f"session_factory must be SessionLocal (got {sf!r})"
    )
    # And it must be a zero-arg callable, not a live Session.
    assert callable(sf)
    assert not isinstance(sf, Session)


def test_roe_middleware_positioned_between_cors_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Execution order: AuditLogMiddleware (outer) -> RoEMiddleware -> CORSMiddleware (inner).

    FastAPI's `add_middleware` INSERTS at position 0, so `user_middleware`
    is the reverse of the registration order. Registration was:
    CORS first (innermost), RoE second (middle), Audit third (outermost).
    The list therefore reads [Audit, RoE, CORS] when all three are enabled.

    Why this order matters (design.md §9):
    - Audit outermost -> it sees the 403 response when RoE rejects and
      still writes an `AuditLog` row for the denial.
    - CORS innermost -> OPTIONS preflight is handled by CORS itself
      before reaching the route, never touches RoE (which fast-paths
      non-POST anyway).
    - RoE in the middle -> gates POSTs, sees the same body bytes that
      reach the route handler.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    monkeypatch.setenv("AUDIT_LOGGING_ENABLED", "true")
    _swap_settings(monkeypatch, ROE_ENABLED=True, AUDIT_LOGGING_ENABLED=True)

    from app.main import create_app

    app = create_app()
    names = [m.cls.__name__ for m in app.user_middleware]
    audit_idx = names.index("AuditLogMiddleware")
    roe_idx = names.index("RoEMiddleware")
    cors_idx = names.index("CORSMiddleware")
    assert audit_idx < roe_idx < cors_idx, (
        f"Wrong execution order: {names} "
        f"(expected AuditLog < RoE < CORS, i.e. Audit outermost, CORS innermost)"
    )


def test_roe_enabled_default_is_false() -> None:
    """REQ-028 AC-028.1: `Settings.ROE_ENABLED` defaults to False.

    Backward compat — anyone already running with no `.env` entry keeps
    the pass-through behavior.
    """
    from app.config import Settings

    s = Settings()
    assert s.ROE_ENABLED is False


# ===========================================================================
# Layer 2 — End-to-end integration (real HTTP, real DB)
# ===========================================================================


def _seed_active_roe(
    session: Session,
    target: str = "example.com",
    *,
    status: RoEStatus = RoEStatus.ACTIVE,
    valid_from_offset_hours: int = -1,
    valid_until_offset_hours: int = 24,
) -> RoE:
    """Insert an RoE + one un-revoked signoff for the target.

    Defaults give a happy-path ACTIVE RoE valid now+24h. Pass
    `valid_until_offset_hours=-1` for an expired RoE,
    `status=RoEStatus.DRAFT` for a not-yet-active one, and revoke the
    signoff manually for the "all signoffs revoked" case.
    """
    now = _now()
    roe = RoE(
        target=target,
        scope_type=ScopeType.DOMAIN,
        scope_value=target,
        authorized_by="ops@example.com",
        status=status,
        valid_from=now + timedelta(hours=valid_from_offset_hours),
        valid_until=now + timedelta(hours=valid_until_offset_hours),
    )
    session.add(roe)
    session.commit()
    session.refresh(roe)
    session.add(
        SignOff(
            roe_id=roe.id,
            signer_name="Alice",
            signer_email="alice@example.com",
            signer_role="CISO",
        )
    )
    session.commit()
    return roe


def _valid_job_body(target: str = "example.com") -> dict[str, object]:
    """A payload that passes `JobCreate` schema validation in `routes/jobs.py`.

    Note: `selected_modules=["subdomain_enum"]` matches a real module in
    the registry (verified via `test_modules_list` in test_main.py). The
    typed confirmation must equal the target verbatim (the route checks
    case-insensitive equality at `routes/jobs.py:45`).
    """
    return {
        "target": target,
        "target_type": "domain",
        "selected_modules": ["subdomain_enum"],
        "user_consent": True,
        "typed_confirmation": target,
        "consent_modal_version": "v1.0",
    }


@pytest_asyncio.fixture
async def client_with_roe(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    """AsyncClient backed by a FRESH `create_app()` with `ROE_ENABLED=true`.

    Why a fresh app? The module-level `app` in `app/main.py` is built at
    import time, so flipping `ROE_ENABLED` post-hoc requires either
    reloading the module or swapping `settings` — neither of which
    changes the already-registered middleware stack. Building a fresh
    app per test guarantees the wiring matches the current env.

    DB is reset before yield so the test seeds whatever RoE rows it
    needs and the rest is empty.

    Note: `_run_job_background` is stubbed to a no-op so the
    BackgroundTask doesn't try to invoke the LLM/RPC stack. There is
    a pre-existing stdlib-logger misuse in
    `app/orchestrator/job_runner.py:91, 126, 145, 158, 166` that fires
    under these conditions; that bug is out of scope for PR 1 and is
    tracked in the session log for a follow-up.
    """
    monkeypatch.setenv("ROE_ENABLED", "true")
    _swap_settings(monkeypatch, ROE_ENABLED=True)

    import app.routes.jobs as jobs_routes
    from app.main import create_app

    async def _no_op(job_id: str) -> None:
        return None

    monkeypatch.setattr(jobs_routes, "_run_job_background", _no_op)

    fresh_app = create_app()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    async with AsyncClient(
        transport=ASGITransport(app=fresh_app), base_url="http://test"
    ) as ac:
        yield ac

    Base.metadata.drop_all(bind=engine)


@pytest_asyncio.fixture
async def client_default(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    """AsyncClient with `ROE_ENABLED` unset (backward-compat baseline).

    Mirrors the production behavior pre-PR-1: middleware is a no-op,
    requests pass through to the route handler. The background-task
    stub keeps the test isolated from the pre-existing logger bug
    noted in `client_with_roe`.
    """
    monkeypatch.delenv("ROE_ENABLED", raising=False)
    _swap_settings(monkeypatch, ROE_ENABLED=False)

    import app.routes.jobs as jobs_routes
    from app.main import create_app

    async def _no_op(job_id: str) -> None:
        return None

    monkeypatch.setattr(jobs_routes, "_run_job_background", _no_op)

    fresh_app = create_app()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    async with AsyncClient(
        transport=ASGITransport(app=fresh_app), base_url="http://test"
    ) as ac:
        yield ac

    Base.metadata.drop_all(bind=engine)


@pytest.mark.asyncio
async def test_roe_blocks_job_creation_without_roe(
    client_with_roe: AsyncClient,
) -> None:
    """Enabled middleware, empty RoE DB, POST /api/v1/jobs -> 403.

    AC-021a.4: the wiring is the gate. With nothing in the DB the
    validator returns `(False, "no RoE matches target+scope", [])` and
    the middleware returns 403 with `{"error": "roe_not_authorized", ...}`.
    """
    response = await client_with_roe.post(
        "/api/v1/jobs", json=_valid_job_body("example.com")
    )
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == "roe_not_authorized"
    # The validator's reason string is "no RoE matches target+scope".
    # We test against the original casing so a future change to the
    # reason (e.g. lowercasing) is a deliberate operator-visible change.
    assert "no roe" in body["detail"].lower()


@pytest.mark.asyncio
async def test_roe_allows_job_creation_with_roe(
    client_with_roe: AsyncClient,
) -> None:
    """Enabled middleware, ACTIVE RoE seeded -> 201 (job created).

    The middleware passes the request through; the route handler at
    `routes/jobs.py:26` then validates the body and creates the Job row.
    """
    db = SessionLocal()
    try:
        _seed_active_roe(db, target="example.com")
    finally:
        db.close()

    response = await client_with_roe.post(
        "/api/v1/jobs", json=_valid_job_body("example.com")
    )
    # 201 = route handler accepted; NOT 403 (would mean RoE blocked) and
    # NOT 500 (would mean the middleware threw on the request).
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["target"] == "example.com"


@pytest.mark.asyncio
async def test_roe_blocks_expired_roe(
    client_with_roe: AsyncClient,
) -> None:
    """RoE with `valid_until` in the past -> 403 with 'expired' detail.

    Validator returns `(False, "RoE has expired (valid_until is in the
    past)", [])` for an out-of-window ACTIVE RoE.
    """
    db = SessionLocal()
    try:
        # Started yesterday, expired an hour ago.
        _seed_active_roe(
            db,
            target="example.com",
            valid_from_offset_hours=-24,
            valid_until_offset_hours=-1,
        )
    finally:
        db.close()

    response = await client_with_roe.post(
        "/api/v1/jobs", json=_valid_job_body("example.com")
    )
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == "roe_not_authorized"
    assert "expired" in body["detail"].lower()


@pytest.mark.asyncio
async def test_roe_blocks_with_disabled_env(
    client_default: AsyncClient,
) -> None:
    """`ROE_ENABLED` unset -> middleware is a no-op, route handler runs.

    Backward-compat guard: existing deployments without `ROE_ENABLED`
    set MUST keep the pre-PR-1 behavior (job gets created). This test
    fails if someone accidentally flips the default to True in
    `create_app()`.
    """
    response = await client_default.post(
        "/api/v1/jobs", json=_valid_job_body("example.com")
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["target"] == "example.com"
