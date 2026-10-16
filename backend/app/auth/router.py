"""FastAPI router for auth lifecycle endpoints (PR-J3.5).

Routes mounted under ``/api/v1/auth``:

- POST /login   → TokenPairResponse | 401 | 423
- POST /refresh → TokenPairResponse | 401 | 423
- POST /logout  → LogoutResponse    | 204
- GET  /me      → UserResponse      | 401
- POST /keys    → 204               | 403 (admin-only — implemented in PR-J4)
- DELETE /keys  → 204               | 403 (admin-only — implemented in PR-J4)
- GET  /legacy-usage-stats → JSON   | 403 (admin-only — implemented in PR-J5)

The dual-auth wrapper (PR-J3.8) extracts ``request.state.user_id`` and
writes it onto the Request so router handlers don't need to re-decode.

Errors
------
Every catchable error is an ``AuthError`` subclass; we route them
through a FastAPI exception handler registered in the lifespan hook.
The handler converts to ``HTTPException(status, detail=body)`` and adds
the response headers (e.g. ``Retry-After`` on 423).
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import get_current_user_id
from app.auth.errors import AuthError
from app.auth.refresh import RefreshService
from app.auth.schemas import (
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshRequest,
    TokenPairResponse,
    UserResponse,
)
from app.auth.service import AuthService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


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


__all__ = ["router"]
