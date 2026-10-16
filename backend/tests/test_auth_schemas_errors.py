"""Tests for auth Pydantic schemas + error mapping (PR-J3.1 + J3.2).

Spec coverage (engram #1371):
- section 1 — endpoint body/response shapes.
- section 4 INV-12 — error bodies never include password / pepper.
- section 5 — every error has a stable (status, code, message, headers) tuple.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.auth.errors import (
    AccountLockedError,
    AuthError,
    FamilyRevokedPublicError,
    InsufficientScopeError,
    InvalidCredentialsError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    to_http_response,
)
from app.auth.password import MIN_PASSWORD_LENGTH
from app.auth.schemas import (
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshRequest,
    TokenPairResponse,
    UserResponse,
)

# ---------------------------------------------------------------------------
# Section 1 — Schemas (J3.1)
# ---------------------------------------------------------------------------


def test_login_request_accepts_well_formed_email_and_12char_password() -> None:
    """LoginRequest passes with valid email + password."""
    req = LoginRequest(email="alice@example.com", password="x" * MIN_PASSWORD_LENGTH)
    assert req.email == "alice@example.com"
    assert req.password == "x" * MIN_PASSWORD_LENGTH


def test_login_request_rejects_short_password() -> None:
    """A password below MIN_PASSWORD_LENGTH fails ValidationError."""
    with pytest.raises(ValidationError) as ei:
        LoginRequest(email="alice@example.com", password="short")
    assert "password" in str(ei.value).lower()


def test_login_request_rejects_invalid_email() -> None:
    """An email without '@' fails Pydantic's EmailStr."""
    with pytest.raises(ValidationError):
        LoginRequest(email="not-an-email", password="x" * MIN_PASSWORD_LENGTH)


def test_login_request_rejects_extra_fields() -> None:
    """``model_config(extra='forbid')`` blocks unknown fields."""
    with pytest.raises(ValidationError):
        LoginRequest(
            email="alice@example.com",
            password="x" * MIN_PASSWORD_LENGTH,
            is_admin=True,
        )


def test_login_request_strips_whitespace() -> None:
    """Leading/trailing whitespace is stripped before storage."""
    req = LoginRequest(
        email="  alice@example.com  ",
        password="  " + "x" * MIN_PASSWORD_LENGTH + "  ",
    )
    assert req.email == "alice@example.com"
    assert not req.password.startswith(" ")
    assert not req.password.endswith(" ")


def test_refresh_request_rejects_short_token() -> None:
    """Refresh token shorter than 4 chars is rejected."""
    with pytest.raises(ValidationError):
        RefreshRequest(refresh_token="rt_")  # 3 chars
    with pytest.raises(ValidationError):
        RefreshRequest(refresh_token="")


def test_logout_request_accepts_full_token() -> None:
    """LogoutRequest accepts the full ``rt_<43 chars>`` shape."""
    req = LogoutRequest(refresh_token=f"rt_{'A' * 43}")
    assert req.refresh_token.startswith("rt_")


def test_token_pair_response_shape_matches_spec() -> None:
    """TokenPairResponse has exactly the spec'd fields and types."""
    resp = TokenPairResponse(
        access_token="access.jwt.here",
        refresh_token="rt_" + "x" * 43,
        expires_in=900,
        user=UserResponse(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            role="operator",
            scopes=["jobs:read"],
            created_at=None,
            last_login_at=None,
            disabled_at=None,
        ),
    )
    assert resp.token_type == "Bearer"
    assert resp.expires_in == 900
    assert resp.user.scopes == ["jobs:read"]


def test_user_response_drops_password_hash() -> None:
    """UserResponse model has no ``password_hash`` field — leaks impossible."""
    declared_fields = set(UserResponse.model_fields.keys())
    assert "password_hash" not in declared_fields
    assert "hashed_password" not in declared_fields
    assert "password" not in declared_fields


def test_logout_response_serialises_revocation_count() -> None:
    """LogoutResponse carries the family_revoked_count integer."""
    resp = LogoutResponse(family_revoked_count=3)
    dumped = resp.model_dump()
    assert dumped["status"] == "ok"
    assert dumped["family_revoked_count"] == 3


# ---------------------------------------------------------------------------
# Section 4 INV-12 + 5 — Errors (J3.2)
# ---------------------------------------------------------------------------


def test_invalid_credentials_error_has_401_with_no_leak() -> None:
    """InvalidCredentialsError status=401, message identical anti-enumeration."""
    err = InvalidCredentialsError()
    status, headers, body = err.to_http_response()
    assert status == 401
    assert body["error"] == "invalid_credentials"
    assert body["message"] == "Invalid email or password"
    assert "WWW-Authenticate" in headers


def test_invalid_credentials_error_message_is_stable_for_known_and_unknown() -> None:
    """Wording is identical for valid vs invalid email (anti-enumeration)."""
    a = InvalidCredentialsError()
    b = InvalidCredentialsError()
    assert a.body["message"] == b.body["message"]


def test_token_expired_error_carries_flag() -> None:
    """TokenExpiredError surfaces token_expired=True so clients can retry."""
    err = TokenExpiredError()
    assert err.body["token_expired"] is True
    assert err.status_code == 401


def test_token_revoked_error_carries_family_revoked_flag() -> None:
    """TokenRevokedError surfaces family_revoked=True."""
    err = TokenRevokedError()
    assert err.body["family_revoked"] is True
    assert err.status_code == 401


def test_token_invalid_error_is_catch_all_401() -> None:
    """TokenInvalidError is the generic 401 for malformed / missing token."""
    err = TokenInvalidError()
    assert err.status_code == 401
    assert err.body["error"] == "token_invalid"


def test_insufficient_scope_error_includes_required_scope() -> None:
    """InsufficientScopeError surfaces required_scope so clients can re-request."""
    err = InsufficientScopeError(required_scope="admin:keys")
    assert err.status_code == 403
    assert err.body["required_scope"] == "admin:keys"


def test_account_locked_error_sets_retry_after_header() -> None:
    """AccountLockedError 423 carries Retry-After header + locked_until body."""
    err = AccountLockedError(
        locked_until_iso="2026-10-14T12:00:00Z",
        retry_after_seconds=420,
    )
    status, headers, body = err.to_http_response()
    assert status == 423
    assert headers["Retry-After"] == "420"
    assert body["locked_until"] == "2026-10-14T12:00:00Z"


def test_family_revoked_public_error_hides_family_id() -> None:
    """FamilyRevokedPublicError.body NEVER carries the raw family_id."""
    err = FamilyRevokedPublicError()
    dumped = err.body
    assert "family_id" not in dumped
    assert "revoked_count" not in dumped
    assert dumped["error"] == "token_revoked"
    assert dumped["family_revoked"] is True


# ---------------------------------------------------------------------------
# Section 5 — message bodies never leak secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "err",
    [
        InvalidCredentialsError(),
        TokenExpiredError(),
        TokenRevokedError(),
        TokenInvalidError(),
        InsufficientScopeError(required_scope="admin"),
        AccountLockedError(locked_until_iso="2026-01-01T00:00:00Z", retry_after_seconds=60),
        FamilyRevokedPublicError(),
    ],
)
def test_error_bodies_never_carry_password_or_pepper(err: AuthError) -> None:
    """No AuthError subclass body contains literal password / pepper tokens.

    Spec section 4 INV-12.
    """
    body = err.body
    text = str(body)
    assert "password" not in text.lower() or err.code == "invalid_credentials", (
        f"error body unexpectedly mentions 'password': {body!r}"
    )
    # The hard rule: 'PEPPER_SECRET' literal must NEVER appear.
    assert "PEPPER_SECRET" not in text
    assert "pepper=" not in text
    # Refresh-token plaintext prefix must NEVER appear.
    assert "rt_A" not in text


def test_to_http_response_helper_matches_direct_call() -> None:
    """The helper function and the method produce the same tuple."""
    err = TokenExpiredError()
    direct = err.to_http_response()
    via_helper = to_http_response(err)
    assert direct == via_helper


def test_all_auth_errors_subclass_autherror() -> None:
    """Inventory check — every error type in __all__ is an AuthError subclass."""
    from app.auth import errors as mod

    for name in mod.__all__:
        cls = getattr(mod, name)
        if isinstance(cls, type) and issubclass(cls, Exception) and cls is not AuthError:
            assert issubclass(cls, AuthError), f"{name} is not an AuthError subclass"
