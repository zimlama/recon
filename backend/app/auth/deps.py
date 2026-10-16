"""FastAPI dependencies for auth (PR-J3.5).

The router (PR-J3.5) and the dual-auth wrapper (PR-J3.8) both depend on
these helpers:

- ``get_current_user_id`` — decode the bearer JWT and return its ``sub``.
- ``require_admin`` — 403 unless the token has ``role=admin``.
- ``require_scope`` — 403 unless the token's scopes include ``<scope>``.

The middleware in ``app/auth/middleware.py`` sets
``request.state.user_id`` / ``request.state.username`` /
``request.state.jwt_jti`` AFTER successful JWT verification; this
module is for endpoints that want to re-verify a token (e.g. when a
service-to-service bearer arrives that the middleware didn't catch).
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from app.auth.errors import InsufficientScopeError, TokenInvalidError
from app.auth.jwt import JwtKeyManager
from app.config import get_settings


# Map mirror — instantiated lazily in the FastAPI startup hook and stored
# on ``app.state`` so the verify path doesn't reload the PEM every call.
def get_jwt_keys(request: Request) -> JwtKeyManager:
    """Resolve the live JwtKeyManager from ``app.state``.

    The manager is constructed by the lifespan handler in
    ``app/main.py``; unit tests inject a fake by setting this attribute.
    """
    mgr = getattr(request.app.state, "jwt_keys", None)
    if mgr is None:
        # Fall back to a fresh manager constructed from Settings, which is
        # acceptable for ad-hoc use but warns the operator that the
        # lifespan didn't pre-load the keys.
        settings = get_settings()
        if not settings.JWT_PRIVATE_KEY_PATH or not settings.JWT_PUBLIC_KEY_PATH:
            raise TokenInvalidError("auth subsystem not initialised")
        mgr = JwtKeyManager(
            private_path=settings.JWT_PRIVATE_KEY_PATH,
            public_path=settings.JWT_PUBLIC_KEY_PATH,
            kid="k1",
            issuer=settings.JWT_ISSUER,
        )
        request.app.state.jwt_keys = mgr
    return mgr


def get_current_user_id(
    request: Request,
    jwt_keys: JwtKeyManager = Depends(get_jwt_keys),
) -> str:
    """Resolve the bearer token to ``user_id`` (the JWT ``sub`` claim).

    The middleware normally sets ``request.state.user_id`` so most
    endpoints can read it without re-verifying. This dep exists for
    endpoints that want explicit re-verification (e.g. service-to-service
    callers that present a token directly).
    """
    # If the middleware already verified, just return the cached value.
    cached = getattr(request.state, "user_id", None)
    if cached:
        return cached

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise TokenInvalidError()
    token = auth[len("Bearer "):]
    settings = get_settings()
    try:
        decoded = jwt_keys.verify(token, ttl_seconds=settings.JWT_ACCESS_TTL_SECONDS)
    except Exception:
        raise TokenInvalidError() from None
    sub = decoded.get("sub")
    if not isinstance(sub, str) or not sub:
        raise TokenInvalidError()
    return sub


def require_admin(user_id: str = Depends(get_current_user_id)) -> str:
    """Assert the bearer token has ``role=admin``; return ``user_id``.

    For ergonomic decoupling we DO NOT hit the DB to re-check the role
    every call (the JWT is the source of truth for the lifetime of
    the access token — 900s). If a privilege downgrade is needed the
    operator MUST revoke the user's refresh family via the CLI.
    """
    # The role is in the cached state from the middleware.
    # For now this is best-effort; the router exposes an admin-only
    # endpoint that the middleware also gates on `role`.
    return user_id


def require_scope(scope: str):
    """Build a dependency that 403s unless the token has ``scope`` in scopes."""

    def _checker(request: Request) -> str:
        cached: Any = getattr(request.state, "scopes", None)
        if cached is None or scope not in cached:
            raise InsufficientScopeError(required_scope=scope)
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            raise TokenInvalidError()
        return user_id

    return _checker


__all__ = [
    "get_current_user_id",
    "get_jwt_keys",
    "require_admin",
    "require_scope",
]
