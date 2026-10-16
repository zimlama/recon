"""FastAPI router for auth lifecycle endpoints (PR-J3.5 + PR-J4).

Routes mounted under ``/api/v1/auth``:

- POST /login   → TokenPairResponse | 401 | 423
- POST /refresh → TokenPairResponse | 401 | 423
- POST /logout  → LogoutResponse    | 204
- GET  /me      → UserResponse      | 401
- POST /keys    → 204               | 403 (admin-only — implemented in PR-J4)
- DELETE /keys  → 204               | 403 (admin-only — implemented in PR-J4)
- GET  /legacy-usage-stats → JSON   | 403 (admin-only — PR-J3.7)

The dual-auth wrapper (PR-J3.8) extracts ``request.state.user_id`` and
writes it onto the Request so router handlers don't need to re-decode.
PR-J4: the admin gate ``require_admin`` re-verifies the JWT signature
at every call (REQ-ADM-001); ``request.state.role`` is NOT trusted
for the gate decision.

Errors
------
Every catchable error is an ``AuthError`` subclass; we route them
through a FastAPI exception handler registered in the lifespan hook.
The handler converts to ``HTTPException(status, detail=body)`` and adds
the response headers (e.g. ``Retry-After`` on 423).

PR-J3.7 ``GET /legacy-usage-stats`` adds three exception types:
``AdminForbiddenError`` (403), ``InvalidSinceError`` (400) and
``SinceTooOldError`` (400). The handler emits the same shape as the
rest of the auth subsystem so operators get a stable parseable body.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.auth.deps import get_current_user_id, require_admin
from app.auth.errors import (
    AuthError,
    InvalidSinceError,
    SinceTooOldError,
)
from app.auth.refresh import RefreshService
from app.auth.schemas import (
    LegacyUsageStatsResponse,
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshRequest,
    TokenPairResponse,
    UserResponse,
)
from app.auth.service import AuthService
from app.auth.usage import query_legacy_usage

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# PR-J3.7 — defaults & cap for the ``?since`` query parameter.
# Default 30 d lookback per spec REQ-LEG-004; hard cap at 365 d so
# operators can't DoS the audit-log scan with an unbounded query.
_LOOKBACK_DEFAULT_DAYS = 30
_LOOKBACK_MAX_DAYS = 365


def _to_http_exception(err: AuthError) -> HTTPException:
    """Convert an AuthError to a FastAPI HTTPException with headers."""
    status, headers, body = err.to_http_response()
    return HTTPException(status_code=status, detail=body, headers=headers)


def _auth_service(request: Request) -> AuthService:
    """Build the AuthService from ``request.app.state`` (set in lifespan)."""
    state = request.app.state
    db_session_factory = state.db_session_factory
    refresh: RefreshService = state.refresh_service
    jwt_keys = state.jwt_keys

    # Open a fresh session per request.
    db = db_session_factory()

    async def _do_login(email: str, password: str):
        svc = AuthService(db_session=db, jwt_keys=jwt_keys, refresh=refresh)
        return await asyncio.to_thread(svc.login, email, password)

    async def _do_refresh(refresh_token: str):
        svc = AuthService(db_session=db, jwt_keys=jwt_keys, refresh=refresh)
        return await asyncio.to_thread(svc.refresh, refresh_token)

    async def _do_logout(refresh_token: str):
        svc = AuthService(db_session=db, jwt_keys=jwt_keys, refresh=refresh)
        return await asyncio.to_thread(svc.logout, refresh_token)

    async def _do_me(user_id: str):
        svc = AuthService(db_session=db, jwt_keys=jwt_keys, refresh=refresh)
        return await asyncio.to_thread(svc.me, user_id)

    # Stash the helpers on the request so handlers can call them.
    request.state._auth_async = {
        "login": _do_login,
        "refresh": _do_refresh,
        "logout": _do_logout,
        "me": _do_me,
    }
    return AuthService(db_session=db, jwt_keys=jwt_keys, refresh=refresh)


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=TokenPairResponse)
async def login_route(body: LoginRequest, request: Request) -> dict[str, Any]:
    """Authenticate via email + password."""
    state = request.app.state
    refresh: RefreshService = state.refresh_service
    db = state.db_session_factory()
    svc = AuthService(db_session=db, jwt_keys=state.jwt_keys, refresh=refresh)
    try:
        pair = await asyncio.to_thread(
            svc.login,
            body.email,
            body.password,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthError as e:
        raise _to_http_exception(e) from e
    finally:
        db.close()

    return TokenPairResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_plaintext,
        expires_in=pair.expires_in,
        user=pair.user,
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# POST /refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh_route(body: RefreshRequest, request: Request) -> dict[str, Any]:
    """Rotate refresh token; mint new access + refresh pair."""
    state = request.app.state
    refresh: RefreshService = state.refresh_service
    db = state.db_session_factory()
    svc = AuthService(db_session=db, jwt_keys=state.jwt_keys, refresh=refresh)
    try:
        pair = await asyncio.to_thread(
            svc.refresh,
            body.refresh_token,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthError as e:
        raise _to_http_exception(e) from e
    finally:
        db.close()

    return TokenPairResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_plaintext,
        expires_in=pair.expires_in,
        user=pair.user,
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------


@router.post("/logout", response_model=LogoutResponse)
async def logout_route(body: LogoutRequest, request: Request) -> dict[str, Any]:
    """Revoke the entire family for the presented refresh token."""
    state = request.app.state
    refresh: RefreshService = state.refresh_service
    db = state.db_session_factory()
    svc = AuthService(db_session=db, jwt_keys=state.jwt_keys, refresh=refresh)
    try:
        revoked = await asyncio.to_thread(svc.logout, body.refresh_token)
    except AuthError as e:
        raise _to_http_exception(e) from e
    finally:
        db.close()
    return LogoutResponse(family_revoked_count=revoked).model_dump()


# ---------------------------------------------------------------------------
# GET /me
# ---------------------------------------------------------------------------


@router.get("/me", response_model=UserResponse)
async def me_route(
    request: Request,
    user_id: str = Depends(get_current_user_id),
) -> dict[str, Any]:
    """Return the current user. Uses the middleware-set request.state.user_id."""
    state = request.app.state
    refresh: RefreshService = state.refresh_service
    db = state.db_session_factory()
    svc = AuthService(db_session=db, jwt_keys=state.jwt_keys, refresh=refresh)
    try:
        user = await asyncio.to_thread(svc.me, user_id)
    except AuthError as e:
        raise _to_http_exception(e) from e
    finally:
        db.close()
    return user.model_dump(mode="json")


# ---------------------------------------------------------------------------
# GET /legacy-usage-stats — PR-J3.7 (REQ-LEG-001..007)
# ---------------------------------------------------------------------------


def _parse_since(
    since_raw: str | None,
    now: datetime,
) -> datetime:
    """Parse the ``?since`` query parameter (REQ-LEG-004).

    Default: ``now - 30 d``. Cap: ``now - 365 d`` — anything older
    raises ``SinceTooOldError`` to prevent an unbounded audit_log
    scan. Malformed values raise ``InvalidSinceError`` with the
    parser's detail verbatim.

    URL note: ``+`` is encoded as a space in query strings, so
    ISO 8601 offsets like ``+00:00`` arrive as `` 00:00``. We
    restore the ``+`` to keep Pydantic / ``fromisoformat`` happy.
    """
    if since_raw is None or since_raw == "":
        return now - timedelta(days=_LOOKBACK_DEFAULT_DAYS)
    normalised = since_raw.replace(" ", "+") if " " in since_raw else since_raw
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError as e:
        raise InvalidSinceError(detail=str(e)) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    floor = now - timedelta(days=_LOOKBACK_MAX_DAYS)
    if parsed < floor:
        raise SinceTooOldError(max_lookback_days=_LOOKBACK_MAX_DAYS)
    return parsed


@router.get(
    "/legacy-usage-stats",
    response_model=LegacyUsageStatsResponse,
)
async def legacy_usage_stats_route(
    request: Request,
    since: str | None = Query(
        default=None,
        description=(
            "ISO 8601 lower bound for the lookback window. "
            "Default: now-30d. Max: now-365d."
        ),
    ),
    user_id: str = Depends(require_admin),
) -> JSONResponse:
    """Admin-only legacy-key usage stats (PR-J3.7 + PR-J4).

    Aggregation rules (engram #1431, REQ-LEG-003):

    - Pure read from ``audit_log`` where ``username == 'legacy'``.
    - Group by ``json_extract(details, '$.ip')`` (the additive
      field written by ``AuditLogMiddleware`` since PR-J3.7).
    - Per-IP ``sample_paths`` = top-5 distinct ``details.path``
      by per-IP frequency DESC.

    The admin gate is JWT-verified (PR-J4 / REQ-ADM-001) — no
    ``X-Admin-Gate-Best-Effort`` response header is emitted.
    """
    now = datetime.now(tz=UTC)
    since_dt = _parse_since(since, now)
    state = request.app.state
    db = state.db_session_factory()
    try:
        try:
            rows, totals = await asyncio.to_thread(
                query_legacy_usage, db, since=since_dt
            )
        except AuthError:
            raise
        except SQLAlchemyError:
            raise
    finally:
        db.close()

    window_days = (now - since_dt).days
    response = LegacyUsageStatsResponse(
        since=since_dt,
        as_of=now,
        window_days=window_days,
        total_legacy_requests=totals["total_legacy_requests"],
        unique_ips=totals["unique_ips"],
        rows=rows,
    )
    payload = response.model_dump(mode="json")
    return JSONResponse(content=payload)


__all__ = ["router"]
