"""FastAPI dependencies for auth (PR-J3.5 + PR-J4).

The router (PR-J3.5) and the dual-auth wrapper (PR-J3.8) both depend on
these helpers:

- ``get_current_user_id`` — re-verify the bearer JWT and return its ``sub``.
- ``require_admin`` — re-verify the bearer JWT; 403 unless ``role=admin``.
- ``require_scope`` — 403 unless the token's scopes include ``<scope>``.

PR-J4 (admin-tier hardening): ``require_admin`` is now the trust
boundary for the admin gate. It re-verifies the JWT signature via
``JwtKeyManager.verify()`` and reads the freshly-decoded ``role``
claim — ``request.state.role`` is NOT trusted for the authz decision
(REQ-ADM-001). Missing / unverifiable bearer → ``TokenInvalidError``
(401); role mismatch → ``AdminForbiddenError`` (403). Dev-bypass
(``state.auth_method == "dev"``) and legacy-bypass
(``state.auth_method == "legacy"``) fallback applies for single-user
local installs and the PR-J8 dual-auth window (REQ-ADM-003); see
``_resolve_effective_role`` for the fallback truth-table.

The DB-backed ``auth_users.role`` lookup is deferred to PR-J4.x —
this module is DB-free per REQ-ADM-004
(``inspect.signature(require_admin) == (request, jwt_keys=Depends(...))``
and no DB / ORM imports).
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Request

from app.auth.errors import (
    AdminForbiddenError,
    InsufficientScopeError,
    TokenInvalidError,
)
from app.auth.jwt import InvalidTokenError, JwtKeyManager
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


def _resolve_effective_role(
    request: Request,
    jwt_keys: JwtKeyManager,
) -> tuple[str, str]:
    """Return ``(sub, role)`` from a freshly-verified JWT, with fallback.

    1. Extract the bearer from the ``Authorization`` header and re-verify
       via ``jwt_keys.verify(token, ttl_seconds=...)``. On success →
       returns ``(decoded["sub"], decoded["role"])``.
    2. On any ``InvalidTokenError`` (or missing/non-Bearer header):
       - If ``request.state.auth_method`` ∈ ``{"dev", "legacy"}`` → return
         ``(request.state.user_id, request.state.role)`` so single-user
         local installs and the PR-J8 legacy window still pass through
         ``require_admin``. Production never hits this branch because
         ``DualAuthMiddleware`` only sets ``auth_method == "dev"`` under
         ``APP_ENV != "production"``.
       - Otherwise → raise ``TokenInvalidError(401)``.

    All ``pyjwt.exceptions.*`` are caught locally and re-raised as
    ``TokenInvalidError`` so no pyjwt string leaks into the response
    body (no oracle — REQ-ADM-002).
    """
    settings = get_settings()
    auth = request.headers.get("Authorization", "")
    token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""

    if token:
        try:
            decoded = jwt_keys.verify(
                token,
                ttl_seconds=settings.JWT_ACCESS_TTL_SECONDS,
            )
            sub = decoded.get("sub")
            role = decoded.get("role") or "operator"
            if not isinstance(sub, str) or not sub:
                # JWT missing/empty sub claim → 401, not 200.
                raise TokenInvalidError()
            return sub, role
        except InvalidTokenError:
            # Propagate as-is so the fallback branch (or the 401) can
            # read the precise reason if needed. Caught again below.
            pass
        except Exception:
            # Catch-all for any non-pyjwt exception surfaced by the
            # verify path (file I/O on PEM reload, etc.) — never leak
            # the raw reason to the response body.
            pass

    # JWT path failed (or no bearer). Fallback branch when middleware
    # matched a dev-bypass / legacy-bypass path.
    auth_method = getattr(request.state, "auth_method", None)
    if auth_method in {"dev", "legacy"}:
        sub = getattr(request.state, "user_id", None) or ""
        role = getattr(request.state, "role", None) or "operator"
        return sub, role

    raise TokenInvalidError()


def get_current_user_id(
    request: Request,
    jwt_keys: JwtKeyManager = Depends(get_jwt_keys),
) -> str:
    """Resolve the bearer token to ``user_id`` (the JWT ``sub`` claim).

    The dep re-verifies the JWT signature via
    ``_resolve_effective_role``; ``request.state.user_id`` is NOT
    trusted. The middleware may still write ``request.state.user_id``
    for downstream consumers (audit-log rows, rate-limit per-user
    caps); this dep just ignores it.
    """
    sub, _role = _resolve_effective_role(request, jwt_keys)
    return sub


def require_admin(
    request: Request,
    jwt_keys: JwtKeyManager = Depends(get_jwt_keys),
) -> str:
    """Assert freshly-decoded ``role == "admin"``; return ``user_id``.

    The dep re-verifies the JWT signature via
    ``_resolve_effective_role``; ``request.state.role`` is NOT trusted
    for the authz decision. Raises ``AdminForbiddenError`` (403, body
    carries ``required_role="admin"``) on role mismatch. Raises
    ``TokenInvalidError`` (401) when the bearer is missing / expired /
    otherwise unverifiable AND the dev/legacy fallback does not apply
    (see ``_resolve_effective_role`` for fallback semantics).

    Trust boundary per REQ-ADM-001; fallback per REQ-ADM-003. The
    pre-PR-J4 cached-state posture is gone — the dep is the gate.
    """
    sub, role = _resolve_effective_role(request, jwt_keys)
    if role != "admin":
        raise AdminForbiddenError()
    return sub


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
