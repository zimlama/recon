"""Dual-auth wrapper for the API (PR-J3.8).

Replaces the pre-existing static ``RECON_API_KEY`` Bearer gate in
``backend/app/main.py:40-64`` (``verify_api_key``) with a flow that:

1. Accepts a JWT access token (preferred path; verifies with the live
   JwtKeyManager).
2. Falls back to the legacy ``RECON_API_KEY`` static token IF the JWT
   path fails AND ``ALLOW_LEGACY_API_KEY=True`` (config; auto-true for
   2 releases per the sec-auth-jwt spec section 6 migration window).
3. Returns 401 with ``WWW-Authenticate: Bearer`` otherwise.

The middleware writes ``request.state`` for downstream handlers:

- ``request.state.user_id`` — UUID string of the authenticated user.
- ``request.state.username`` — email prefix (for audit-row friendliness).
- ``request.state.jwt_jti`` — the JWT's ``jti`` claim (UUID) for the
  audit chain. ``None`` when the legacy path matched.
- ``request.state.scopes`` — list[str] from the JWT.
- ``request.state.role`` — ``admin`` / ``operator`` / ``service``.
- ``request.state.auth_method`` — ``"jwt"`` or ``"legacy"``.

Health-check routes (``/health``, ``/ready``, ``/docs``, ``/openapi.json``)
are explicitly bypassed so they stay open even in production.

Logging
-------
The path used (``auth.jwt`` vs ``auth.legacy``) is logged at INFO for
visibility. The body of the token / API key is NEVER logged — spec
section 5 keeps it out.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


# Routes that NEVER need authentication. Keep this list TIGHT — adding to
# it is a security-relevant change requiring PR review.
_OPEN_PATHS = frozenset(
    {
        "/health",
        "/ready",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/favicon.ico",
    }
)


# Paths UNDER /api/v1/auth that are part of the auth lifecycle itself
# (login, refresh, logout). The middleware MUST NOT block these — that
# would lock everyone out on cold-start. Logout authenticates the
# request via the refresh_token in the body, not the Authorization
# header, so it is open at the middleware layer.
_AUTH_OPEN_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
)


class DualAuthMiddleware(BaseHTTPMiddleware):
    """Per-request JWT-or-legacy-Key dispatch.

    Falls back to legacy ``RECON_API_KEY`` if JWT fails. If neither
    matches, returns 401 with a structured error body.
    """

    def __init__(
        self,
        app,
        *,
        jwt_keys_factory,
        allow_legacy_api_key: bool,
        legacy_api_key: str | None,
        jwt_keys_configured: bool = True,
        settings_provider=None,
    ) -> None:
        super().__init__(app)
        self._jwt_keys_factory = jwt_keys_factory
        self._allow_legacy_api_key = bool(allow_legacy_api_key)
        # ``legacy_api_key`` may be re-resolved per request via
        # ``settings_provider`` so tests that monkey-patch settings
        # (e.g. test_auth.py) can flip the auth posture on/off.
        self._initial_legacy_api_key = legacy_api_key
        self._settings_provider = settings_provider
        self._jwt_keys_configured = bool(jwt_keys_configured)

    def _legacy_api_key_now(self) -> str | None:
        """Resolve the current legacy API key, honouring a settings provider.

        Test compatibility: tests that monkey-patch ``app.main.settings``
        (the original verify_api_key contract) are honoured because we
        also check ``app.main.settings.RECON_API_KEY`` after the
        provider.
        """
        # 1. Explicit provider (preferred in production wiring).
        if self._settings_provider is not None:
            try:
                value = self._settings_provider().RECON_API_KEY
                if value is not None:
                    return value
            except Exception:
                pass
        # 2. Backward-compat: app.main.settings.RECON_API_KEY
        try:
            import app.main as _main_mod
            value = getattr(getattr(_main_mod, "settings", None), "RECON_API_KEY", None)
            if value is not None:
                return value
        except Exception:
            pass
        # 3. Initial value passed at construction time.
        return self._initial_legacy_api_key

    def _allow_legacy_now(self) -> bool:
        """Resolve the current ``ALLOW_LEGACY_API_KEY`` flag per request.

        The flag is cached at construction time by default for perf, but
        tests (and any future runtime config reload) need the live value.
        Resolution order matches ``_legacy_api_key_now``.
        """
        if self._settings_provider is not None:
            try:
                return bool(self._settings_provider().ALLOW_LEGACY_API_KEY)
            except Exception:
                pass
        try:
            import app.main as _main_mod
            return bool(
                getattr(getattr(_main_mod, "settings", None), "ALLOW_LEGACY_API_KEY", False)
            )
        except Exception:
            pass
        return self._allow_legacy_api_key

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path

        # 1. Health/docs bypass.
        if path in _OPEN_PATHS or any(
            path.startswith(p) for p in _AUTH_OPEN_PREFIXES
        ):
            return await call_next(request)

        # 2. Dev-mode bypass — if RECON_API_KEY is unset AND no JWT
        # keys are configured, allow the request through (matches the
        # pre-sec-auth-jwt behavior so single-user local installs
        # continue to work without any setup). Production deployments
        # MUST set RECON_API_KEY (or a JWT keypair) — see spec section 7.
        current_legacy = self._legacy_api_key_now()
        if not current_legacy and not self._jwt_keys_configured:
            request.state.user_id = "local"
            request.state.username = "local"
            request.state.jwt_jti = None
            request.state.scopes = []
            request.state.role = "admin"
            request.state.auth_method = "dev"
            return await call_next(request)

        # 3. Pull the Authorization header (case-insensitive).
        auth = (
            request.headers.get("authorization")
            or request.headers.get("Authorization")
            or ""
        ).strip()

        if not auth.startswith("Bearer "):
            return _unauth("missing or malformed Authorization header")

        token = auth[len("Bearer "):].strip()
        if not token:
            return _unauth("empty bearer token")

        # 3. Try JWT first.
        try:
            jwt_keys = self._jwt_keys_factory(request)
            decoded = jwt_keys.verify(
                token,
                ttl_seconds=_access_ttl_seconds(),
            )
            user_id = decoded.get("sub")
            if not isinstance(user_id, str) or not user_id:
                return _unauth("JWT missing sub claim")
            request.state.user_id = user_id
            request.state.username = decoded.get("username") or ""
            request.state.jwt_jti = decoded.get("jti")
            request.state.scopes = decoded.get("scopes") or []
            request.state.role = decoded.get("role") or "operator"
            request.state.auth_method = "jwt"
            logger.info("auth.jwt path=user_id=%s", user_id[:8])
            return await call_next(request)
        except Exception:
            # JWT path failed — fall through to legacy check.
            pass

        # 4. Legacy fallback (if enabled and a key is configured).
        current_legacy = self._legacy_api_key_now()
        allow_legacy_now = self._allow_legacy_now()
        if (
            allow_legacy_now
            and current_legacy
            and token == current_legacy
        ):
            # We don't have a real ``user_id`` for the legacy caller —
            # use a deterministic synthetic value so the audit_log row
            # carries a stable marker.
            request.state.user_id = "local"
            request.state.username = "legacy"
            request.state.jwt_jti = None
            request.state.scopes = []
            request.state.role = "admin"  # legacy caller had admin posture
            request.state.auth_method = "legacy"
            logger.info("auth.legacy path=token legacy_api_key matched")
            return await call_next(request)

        # 5. Both paths failed.
        if not allow_legacy_now or not current_legacy:
            return _unauth("invalid bearer token (legacy disabled)")
        return _unauth("invalid bearer token")


def _unauth(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": "unauthorized", "message": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _access_ttl_seconds() -> int:
    """Read the JWT TTL from Settings without forcing an import at module load."""
    from app.config import get_settings

    return int(get_settings().JWT_ACCESS_TTL_SECONDS)


__all__ = ["DualAuthMiddleware"]
