"""AuthService — login / refresh / logout / me (PR-J3.3 + J3.4).

This is the facade layer that the router (PR-J3.5) calls. It composes:

- ``PasswordService`` (PR-J1) for argon2id + pepper verification.
- ``JwtKeyManager`` (PR-J1) for access-token sign / verify / rotate.
- ``RefreshService`` (PR-J2) for opaque refresh-token issue / rotate.

Public surface
--------------
All methods are synchronous; the router wraps them in
``asyncio.to_thread`` (PR-J3.5) so the FastAPI event-loop stays free
during the ~80-150 ms argon2 verify.

Errors
------
All operations raise ``AuthError`` subclasses from ``app.auth.errors``
— they never leak ``password_hash``, ``PEPPER_SECRET``, or refresh-token
plaintext into exception messages.

Concurrency
-----------
``login`` is a single-threaded DB write per call. ``refresh`` invokes
``RefreshService.rotate`` which uses an atomic UPDATE so concurrent
``refresh`` calls on the same token yield exactly one winner.

Audit
-----
PR-J3.7 extends ``AuditLogMiddleware`` to read ``request.state``; this
service does NOT write audit rows directly — that responsibility lives
in the middleware so log shape stays uniform across endpoints.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.errors import (
    AccountLockedError,
    FamilyRevokedPublicError,
    InvalidCredentialsError,
    TokenExpiredError,
    TokenInvalidError,
)
from app.auth.jwt import JwtKeyManager
from app.auth.models import (
    AuthUser,
    auth_user_to_dict,
    encode_scopes,
)


# Spec-defined defaults for failed-login lockout (section 4 INV-5).
# Lockout was deferred to the controller layer in PR-J1; the constants
# live here so this service is self-contained.
MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION_SECONDS = 900
from app.auth.password import PasswordService, WeakPasswordError
from app.auth.refresh import (
    FamilyRevokedError,
    RefreshService,
    TokenInvalidError as RefreshTokenInvalidError,
)
from app.auth.schemas import UserResponse


# ---------------------------------------------------------------------------
# Public return types — keep them lean (router shapes them into Pydantic)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IssuedPair:
    """A (access_token, refresh_plaintext, expires_in, user_response) bundle."""

    access_token: str
    refresh_plaintext: str
    expires_in: int
    user: UserResponse


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


class AuthService:
    """High-level auth facade.

    Construction is explicit (no DI magic): pass in the per-request
    session, the JwtKeyManager, and the RefreshService. Keeps ``deps.py``
    (PR-J3.5) declarative without spooky-action-at-a-distance.

    The service owns no thread-unsafe state — every helper opens its own
    short-lived session when needed.
    """

    def __init__(
        self,
        db_session: Session,
        jwt_keys: JwtKeyManager,
        refresh: RefreshService,
        *,
        max_failed_logins: int = MAX_FAILED_LOGINS,
        lockout_duration_seconds: int = LOCKOUT_DURATION_SECONDS,
    ) -> None:
        self._db = db_session
        self._jwt = jwt_keys
        self._refresh = refresh
        self._max_failed_logins = int(max_failed_logins)
        self._lockout_seconds = int(lockout_duration_seconds)

    # ---- Login (J3.3) --------------------------------------------------------

    def login(
        self,
        email: str,
        password: str,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedPair:
        """Authenticate by email + password; mint an access + refresh pair.

        Anti-enumeration: ``InvalidCredentialsError`` wording is identical
        whether the user is unknown or the password is wrong. Lockout
        is per-user and configurable via the constructor.

        Raises:
            WeakPasswordError: input password is below MIN_PASSWORD_LENGTH.
                (Caught by the router and surfaced as a 422.)
            InvalidCredentialsError: wrong email or password.
            AccountLockedError: too many failed attempts.

        Side effects:
            - Updates ``last_login_at`` on success.
            - Resets ``failed_login_count`` on success.
            - Increments ``failed_login_count`` on failure.
            - Sets ``locked_until`` when threshold reached.
            - Inserts a refresh_tokens row (via RefreshService.issue).
        """
        # Lower-case the email so login is case-insensitive at the
        # application layer (the DB UNIQUE constraint is on raw value
        # but we always store/lookup lower-case via this service).
        email_norm = email.strip().lower()

        user = self._db.execute(
            select(AuthUser).where(AuthUser.email == email_norm)
        ).scalar_one_or_none()

        # Anti-enumeration: even when the user doesn't exist, we still
        # run argon2 against a dummy hash so the response time matches
        # a real wrong-password case. Spec section 4 INV-6.
        if user is None:
            PasswordService.verify(password, _DUMMY_HASH)
            raise InvalidCredentialsError()

        if user.disabled_at is not None:
            # Disabled user — same wording as wrong credentials.
            raise InvalidCredentialsError()

        if user.is_locked():
            # Compute Retry-After from locked_until.
            assert user.locked_until is not None  # for type checker
            from datetime import UTC, datetime

            now_naive = datetime.now(UTC).replace(tzinfo=None)
            retry_after = max(
                1,
                int((user.locked_until - now_naive).total_seconds()),
            )
            raise AccountLockedError(
                locked_until_iso=user.locked_until.isoformat(),
                retry_after_seconds=retry_after,
            )

        if not PasswordService.verify(password, user.password_hash):
            # Increment failure counter; lock if threshold crossed.
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= self._max_failed_logins:
                from datetime import UTC, datetime, timedelta

                user.locked_until = (
                    datetime.now(UTC).replace(tzinfo=None)
                    + timedelta(seconds=self._lockout_seconds)
                )
            self._db.commit()
            raise InvalidCredentialsError()

        # SUCCESS. Reset failure counter and stamp last_login_at.
        from datetime import UTC, datetime

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = datetime.now(UTC).replace(tzinfo=None)
        self._db.commit()

        return self._mint_pair(
            user,
            ip=ip,
            user_agent=user_agent,
        )

    # ---- Refresh (J3.4) -------------------------------------------------------

    def refresh(
        self,
        refresh_plaintext: str,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedPair:
        """Rotate a refresh token. Maps service-level errors to AuthError.

        Spec section 1: POST /auth/refresh — rotation. On success mints
        a new access + refresh pair. On family revocation (reuse
        detection) raises ``FamilyRevokedPublicError`` so the router
        returns 401 + family_revoked=True.
        """
        try:
            rotated = self._refresh.rotate(refresh_plaintext)
        except FamilyRevokedError:
            raise FamilyRevokedPublicError() from None
        except RefreshTokenInvalidError as exc:
            # Map internal reason to a public AuthError.
            reason = getattr(exc, "reason", "unknown")
            if reason == "expired":
                raise TokenExpiredError() from None
            if reason == "malformed":
                raise TokenInvalidError() from None
            raise TokenInvalidError() from None
        except ValueError:
            # Malformed token (no rt_ prefix)
            raise TokenInvalidError() from None

        # Look up the user (the rotated row carries it).
        user = self._db.execute(
            select(AuthUser).where(AuthUser.id == self._user_id_for_rotated(rotated))
        ).scalar_one_or_none()
        if user is None:
            # Defensive: user was deleted mid-rotation. Treat as invalid.
            raise TokenInvalidError()

        return self._mint_pair(
            user,
            refresh_plaintext_already=rotated.plaintext,
            ip=ip,
            user_agent=user_agent,
        )

    # ---- Logout (J3.4) --------------------------------------------------------

    def logout(self, refresh_plaintext: str) -> int:
        """Revoke the entire family for the presented refresh token.

        Returns the number of rows that transitioned from active to
        revoked in this call (0 if the token is unknown / already
        revoked). The router uses this for the response body.

        Idempotent — calling logout twice in a row is a no-op on the
        second call.
        """
        try:
            revoked = self._refresh.revoke_family(
                self._family_id_for_refresh(refresh_plaintext),
            )
        except ValueError:
            return 0
        return revoked

    # ---- Me (J3.4) ------------------------------------------------------------

    def me(self, user_id: str) -> UserResponse:
        """Return the UserResponse for ``user_id``, or raise TokenInvalidError."""
        user = self._db.execute(
            select(AuthUser).where(AuthUser.id == user_id)
        ).scalar_one_or_none()
        if user is None or user.disabled_at is not None:
            raise TokenInvalidError()
        d = auth_user_to_dict(user)
        return UserResponse(**d)

    # ---- Internal helpers -----------------------------------------------------

    def _mint_pair(
        self,
        user: AuthUser,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        refresh_plaintext_already: str | None = None,
    ) -> IssuedPair:
        """Mint a fresh JWT + refresh token pair for ``user``."""
        # 1. Refresh token — either re-use a freshly-rotated plaintext,
        #    or issue a brand-new one.
        if refresh_plaintext_already is not None:
            refresh_plain = refresh_plaintext_already
        else:
            issued = self._refresh.issue(
                user.id,
                ip=ip,
                user_agent=user_agent,
            )
            refresh_plain = issued.plaintext

        # 2. Access token — JWT signed by the active keypair.
        jti = str(uuid.uuid4())
        claims = {
            "sub": user.id,
            "role": user.role,
            "scopes": parse_scopes_helper(user.scopes),
            "jti": jti,
        }
        from app.config import get_settings

        settings = get_settings()
        access_token = self._jwt.sign(claims, ttl_seconds=settings.JWT_ACCESS_TTL_SECONDS)

        return IssuedPair(
            access_token=access_token,
            refresh_plaintext=refresh_plain,
            expires_in=settings.JWT_ACCESS_TTL_SECONDS,
            user=UserResponse(**auth_user_to_dict(user)),
        )

    def _family_id_for_refresh(self, plaintext: str) -> str:
        """Look up the family_id for ``plaintext`` (refresh service helper)."""
        row = self._refresh.lookup(plaintext)
        if row is None:
            raise ValueError("unknown refresh token")
        return row.family_id

    def _user_id_for_rotated(self, rotated) -> str:  # type: ignore[no-untyped-def]
        """The rotation mints a row with the SAME user_id; look it up."""
        row = self._refresh.lookup(rotated.plaintext)
        if row is None:
            raise TokenInvalidError()
        return row.user_id


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


# A static dummy hash used to match timing on user-not-found. Generated
# once at import time so every login-with-unknown-user takes the same
# ~80-150 ms argon2 path.
_DUMMY_HASH = PasswordService.hash("__dummy__password_for_timing__", pepper="")


def parse_scopes_helper(scopes_json: str) -> list[str]:
    """Re-export of models.parse_scopes — kept here so this module
    has zero cross-imports from app.auth.models at the top level.
    """
    from app.auth.models import parse_scopes

    return parse_scopes(scopes_json)


__all__ = ["AuthService", "IssuedPair", "WeakPasswordError"]
