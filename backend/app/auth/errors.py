"""Auth error types and HTTP mapping (sec-auth-jwt, PR-J3.2).

Spec coverage (engram #1371):

- section 5 — every error body has a stable shape and never leaks
  password / pepper / plaintext token.

The exceptions are framework-agnostic; the ``to_http_response`` helper
maps each one to a (status, body) tuple the router layer can splat
into FastAPI's ``HTTPException``. We intentionally do NOT use
``HTTPException`` directly here — that would couple this module to
FastAPI and complicates unit-testing the mapping table.

Error taxonomy
--------------
Each ``AuthError`` subclass carries:

- ``status_code`` — HTTP status to return.
- ``code`` — machine-readable label (e.g. ``"invalid_credentials"``).
- ``message`` — human-readable message, NEVER includes any password
  / pepper / plaintext.
- ``headers`` — HTTP headers (e.g. ``WWW-Authenticate`` on 401,
  ``Retry-After`` on 423).
- ``flags`` — optional dict of extra JSON body keys (e.g.
  ``family_revoked: true`` on reuse-detected 401).

The router layer (PR-J3.5) catches ``AuthError`` and converts via
``to_http_response``. We never propagate the raw exception class as
the response body.
"""

from __future__ import annotations

from typing import Any


class AuthError(Exception):
    """Base class for every auth flow error.

    Concrete subclasses set ``status_code``, ``code``, ``message``,
    ``headers``, and ``flags`` as class attributes. ``to_http_response``
    builds the dict body from those attrs at conversion time.
    """

    status_code: int = 400
    code: str = "auth_error"
    message: str = "Authentication error"
    headers: dict[str, str] = {}
    flags: dict[str, Any] = {}

    def __init__(self, message: str | None = None, **flags: Any) -> None:
        super().__init__(message or self.message)
        if message:
            self.message = message
        # Per-instance override of flags (e.g. custom ``family_id``).
        self._instance_flags = dict(flags)

    @property
    def body(self) -> dict[str, Any]:
        """JSON body for the HTTP response."""
        out: dict[str, Any] = {"error": self.code, "message": self.message}
        out.update(self.flags)
        out.update(self._instance_flags)
        return out

    def to_http_response(self) -> tuple[int, dict[str, str], dict[str, Any]]:
        """Return ``(status_code, headers, body)`` for FastAPI's HTTPException."""
        return self.status_code, dict(self.headers), self.body


class InvalidCredentialsError(AuthError):
    """401 — email/password wrong or unknown (anti-enumeration).

    Per spec section 4 INV-6: identical wording whether the user exists,
    the password is wrong, or both. The router NEVER distinguishes
    between "no such user" and "wrong password" in the response.
    """

    status_code = 401
    code = "invalid_credentials"
    message = "Invalid email or password"
    headers = {"WWW-Authenticate": "Bearer"}


class TokenExpiredError(AuthError):
    """401 — JWT past ``exp``.

    Surfaces ``token_expired: true`` for client-side retry logic.
    """

    status_code = 401
    code = "token_expired"
    message = "Access token has expired"
    headers = {"WWW-Authenticate": "Bearer"}
    flags = {"token_expired": True}


class TokenRevokedError(AuthError):
    """401 — refresh token already used (family revoked per spec section 4 INV-2).

    Surfaces ``family_revoked: true`` so the client knows to fully
    re-authenticate (the legitimate t1 was used, but the whole
    family including the current tN just got nuked).
    """

    status_code = 401
    code = "token_revoked"
    message = "Refresh token has been revoked"
    headers = {"WWW-Authenticate": "Bearer"}
    flags = {"family_revoked": True}


class TokenInvalidError(AuthError):
    """401 — malformed, missing, or otherwise unverifiable token.

    Generic catch-all. The router layer should prefer the more-specific
    subclasses above (``TokenExpiredError``, ``TokenRevokedError``)
    when the cause is known.
    """

    status_code = 401
    code = "token_invalid"
    message = "Token is invalid"
    headers = {"WWW-Authenticate": "Bearer"}


class InsufficientScopeError(AuthError):
    """403 — token is valid but lacks the required scope for the endpoint.

    Surfaces ``required_scope`` so the client can request it via
    an OAuth-style re-consent flow.
    """

    status_code = 403
    code = "insufficient_scope"
    message = "Token lacks required scope"

    def __init__(self, required_scope: str, message: str | None = None) -> None:
        super().__init__(
            message=message or f"Token missing required scope: {required_scope}",
            required_scope=required_scope,
        )


class AdminForbiddenError(AuthError):
    """403 — authenticated but ``request.state.role`` is not ``"admin"``.

    PR-J3.7 (REQ-LEG-002). Mirrors ``InsufficientScopeError``'s shape
    so the router layer can render a single ``403 forbidden`` error
    body for both scope-mismatch and role-mismatch — the body always
    carries the missing privilege (``required_scope`` /
    ``required_role``) so the client knows which one to request.
    """

    status_code = 403
    code = "forbidden"
    message = "Admin role required"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message=message or self.message,
            required_role="admin",
        )


class SinceTooOldError(AuthError):
    """400 — ``?since`` precedes the hard lookback cap (365 d by default).

    PR-J3.7 (REQ-LEG-004). The cap prevents operator DoS via
    unbounded scans over a multi-million-row audit_log; surfaces
    ``max_lookback_days`` so the client can clamp its own date
    picker to the same window.
    """

    status_code = 400
    code = "since_too_old"
    message = "since exceeds max lookback"

    def __init__(
        self,
        max_lookback_days: int,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message=message or self.message,
            max_lookback_days=max_lookback_days,
        )


class InvalidSinceError(AuthError):
    """400 — ``?since`` is not a valid ISO 8601 datetime.

    PR-J3.7 (REQ-LEG-004). The Pydantic ``detail`` is surfaced
    verbatim so the client can show the operator exactly which
    character was malformed.
    """

    status_code = 400
    code = "invalid_since"
    message = "since is not a valid ISO 8601 datetime"

    def __init__(self, detail: str, message: str | None = None) -> None:
        super().__init__(
            message=message or self.message,
            detail=detail,
        )


class AccountLockedError(AuthError):
    """423 — too many failures; account temporarily locked.

    Surfaces ``locked_until`` as an ISO-8601 timestamp and a
    ``Retry-After`` header in seconds (rounded up).
    """

    status_code = 423
    code = "account_locked"
    message = "Account is temporarily locked"

    def __init__(
        self,
        locked_until_iso: str,
        retry_after_seconds: int,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message=message or "Too many failed attempts; account locked",
            locked_until=locked_until_iso,
        )
        # Override class-level headers with the dynamic Retry-After.
        self.headers = {
            "Retry-After": str(int(retry_after_seconds)),
            "WWW-Authenticate": "Bearer",
        }


class FamilyRevokedPublicError(AuthError):
    """401 — public view of TokenRevokedError after family revoke.

    Used by the router when ``RefreshService.rotate`` raises the
    internal ``FamilyRevokedError`` (which carries a ``family_id`` and
    ``revoked_count``). We translate it to a stable public-shape error
    so the body never includes ``family_id`` (a security signal we do
    not want to leak).
    """

    status_code = 401
    code = "token_revoked"
    message = "Refresh token has been revoked"
    headers = {"WWW-Authenticate": "Bearer"}
    flags = {"family_revoked": True}


# ---------------------------------------------------------------------------
# Public mapping table — used by the router / middleware
# ---------------------------------------------------------------------------


def to_http_response(err: AuthError) -> tuple[int, dict[str, str], dict[str, Any]]:
    """Convert any ``AuthError`` to a (status, headers, body) tuple.

    FastAPI's ``HTTPException`` expects ``(status, detail)``; we
    additionally expose headers so the router can wire them in
    via a custom exception handler (PR-J3.5).
    """
    return err.to_http_response()


__all__ = [
    "AccountLockedError",
    "AdminForbiddenError",
    "AuthError",
    "FamilyRevokedPublicError",
    "InsufficientScopeError",
    "InvalidCredentialsError",
    "InvalidSinceError",
    "SinceTooOldError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenRevokedError",
    "to_http_response",
]
