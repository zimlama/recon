"""Pydantic request/response schemas for the /api/v1/auth/* endpoints.

Spec coverage (engram #1371):
- section 1 "Auth lifecycle endpoints" — exact body/response shapes.
- section 4 INV-12 — error bodies never leak password / pepper / plaintext.

These schemas are intentionally small and purpose-built for the auth
endpoints. They are NOT shared with the rest of the app — broader
schemas live in ``app.schemas`` for ``/jobs``, ``/modules``, etc.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.auth.password import MIN_PASSWORD_LENGTH

# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """POST /api/v1/auth/login body.

    ``email`` must be a syntactically valid email (Pydantic EmailStr —
    lowercase + IDN-2008 compatible). ``password`` enforces the spec'd
    minimum length here AND at the password-hash layer (defense-in-depth).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=4096)


class RefreshRequest(BaseModel):
    """POST /api/v1/auth/refresh body.

    Refresh tokens are 43 base64url chars plus a ``rt_`` prefix — the
    ``min_length`` enforces only the prefix and a sane floor.
    """

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=4, max_length=4096)


class LogoutRequest(BaseModel):
    """POST /api/v1/auth/logout body — refresh token to revoke.

    Optional — when omitted, the server attempts a "best-effort revoke
    of all known families for this user" via the bearer auth (PR-J3.4
    expands this — see plan). For now we require the token so the
    contract is explicit.
    """

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=4, max_length=4096)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


class UserResponse(BaseModel):
    """Shape of the user sub-object in TokenPairResponse and /auth/me.

    Never includes ``password_hash`` (enforced at the model layer in
    ``app.auth.models.auth_user_to_dict``). Scopes are returned as a
    JSON array, not a JSON-encoded string.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    email: EmailStr
    role: str
    scopes: list[str] = Field(default_factory=list)
    created_at: datetime | None
    last_login_at: datetime | None
    disabled_at: datetime | None


class TokenPairResponse(BaseModel):
    """POST /auth/login and POST /auth/refresh success body."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # seconds (matches JWT_ACCESS_TTL_SECONDS)
    user: UserResponse


class LogoutResponse(BaseModel):
    """POST /auth/logout success body.

    ``family_revoked_count`` is the number of refresh-token rows that
    got their ``revoked_at`` set in this call. Exposed for client
    diagnostics; PR-J3.4 may add an ``audit_ticket_id``.
    """

    model_config = ConfigDict(extra="forbid")

    status: str = "ok"
    family_revoked_count: int = Field(ge=0)


# ---------------------------------------------------------------------------
# PR-J3.7 — legacy RECON_API_KEY usage-stats response (REQ-LEG-005)
# ---------------------------------------------------------------------------


class LegacyUsageStatsRow(BaseModel):
    """One row of the legacy-usage-stats aggregation.

    Each row corresponds to ONE client ``ip`` seen by the legacy
    ``RECON_API_KEY`` Bearer path over the requested window (filter
    from ``details.ip`` written by ``AuditLogMiddleware`` — see
    REQ-013 mod). ``sample_paths`` is bounded to the top-5 distinct
    paths the IP hit, ordered by per-IP frequency DESC
    (REQ-LEG-010).
    """

    model_config = ConfigDict(extra="forbid")

    ip: str
    request_count: int = Field(ge=0)
    first_used_at: datetime
    last_used_at: datetime
    first_user_agent: str
    last_user_agent: str
    sample_paths: list[str] = Field(max_length=5)


class LegacyUsageStatsResponse(BaseModel):
    """GET /api/v1/auth/legacy-usage-stats response body.

    The deprecation-window operator dashboard. Carries the
    lookback window (``since`` → ``as_of``, ``window_days``), the
    aggregated totals (``total_legacy_requests`` /
    ``unique_ips``), and the per-IP rows ordered
    ``request_count DESC`` (REQ-LEG-003). Rows from
    ``username='legacy'`` only — JWT-authenticated and dev-bypass
    rows are excluded because they wouldn't be served by the
    legacy static API key.

    The admin gate is JWT-verified (PR-J4 / REQ-ADM-001).
    """

    model_config = ConfigDict(extra="forbid")

    since: datetime
    as_of: datetime
    window_days: int = Field(ge=0, le=366)
    total_legacy_requests: int = Field(ge=0)
    unique_ips: int = Field(ge=0)
    rows: list[LegacyUsageStatsRow]


__all__ = [
    "LegacyUsageStatsResponse",
    "LegacyUsageStatsRow",
    "LoginRequest",
    "LogoutRequest",
    "LogoutResponse",
    "RefreshRequest",
    "TokenPairResponse",
    "UserResponse",
]
