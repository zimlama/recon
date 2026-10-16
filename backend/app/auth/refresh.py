"""RefreshService — opaque-token issue, rotate, family revocation (PR-J2, sec-auth-jwt).

Spec coverage (engram #1371):

- §1 Scenario "POST /auth/refresh — rotation" — rotate mints a new token in
  the same family and revokes the predecessor in one operation.
- §1 Scenario "POST /auth/refresh — reuse detection" — when an already-
  rotated (revoked_at IS NOT NULL) token is presented a second time, every
  sibling in the same family must be revoked and the caller informed.
- §4 INV-2 — reuse detection triggers family-wide revocation. After a
  positive rotate(), the old token is single-use; replay yields a hard
  ``FamilyRevokedError`` AND the family is dead.
- §4 INV-3 — rotation's ``replaced_by`` pointer chains new ↔ old for
  forensic reconstruction.
- §5 — no token plaintext, no password, no pepper value may appear in any
  log line. PR-J2.5 verifies this with ``test_security_auth.py``.

Threat model recap:

- A leaked refresh token is single-use: capture-the-flag labs replay it
  and we revoke the family. Without this, a stolen token grants the
  attacker the lifetime of the refresh TTL (7 days by default).
- Concretely, the rotate() path is the single point that can resolve
  "is this token still valid" and "what family does it belong to".
  It uses an atomic UPDATE where revoked_at IS NULL so a concurrent
  rotate() racing the same token gets exactly one winner — the loser
  raises TokenInvalidError("rotation_in_progress") so the client knows
  to retry with the new token it just received.
- Hashing: token_hash = HMAC-SHA256(plaintext, REFRESH_HASH_KEY). The HMAC
  key NEVER enters the DB. The plaintext prefix ``rt_`` lets grep / log
  scans catch accidental leaks.

This module deliberately exposes NO new SQL primitives — every operation
goes through the ``RefreshToken`` ORM model so changes to the schema
propagate to this layer automatically (the alembic migrations are the
single source of truth for column shape).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.models import RefreshToken

# ---------------------------------------------------------------------------
# Public exceptions — surfaced to the router layer (PR-J3.2 errors module)
# ---------------------------------------------------------------------------


class TokenInvalidError(Exception):
    """Refresh token is invalid (unknown, expired, or race-lost).

    The router (PR-J3) maps ``reason`` to a 401/423/etc. ``reason`` values:

    - ``"unknown"`` — hash not in DB.
    - ``"expired"`` — ``expires_at`` is in the past.
    - ``"rotation_in_progress"`` — concurrent rotate won the race; client
      should retry using the new token it just received.

    Plaintext token is NEVER included in the message — only ``reason`` and
    a tag of the row id. Plaintext leakage in logs is the #1 risk this
    PR's threat model defends against.
    """

    def __init__(self, reason: str, *, row_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.row_id = row_id


class FamilyRevokedError(Exception):
    """Refresh-token reuse detected — caller MUST revoke all sessions.

    Spec §4 INV-2. We surface this as a separate exception type so the
    router can return the spec'd ``401`` with ``family_revoked: true``
    and trigger a forced re-login.
    """

    def __init__(self, family_id: str, *, revoked_count: int) -> None:
        super().__init__(
            f"refresh family {family_id[:8]}... revoked; revoked_count={revoked_count}"
        )
        self.family_id = family_id
        self.revoked_count = revoked_count


# ---------------------------------------------------------------------------
# Public constants — exposed for tests + router layer
# ---------------------------------------------------------------------------


# Plaintext prefix chosen so log / grep scans can ALWAYS detect a leak.
# Any line containing the literal ``rt_`` followed by 43 base64url chars
# in production logs is a SECURITY INCIDENT (spec §5).
TOKEN_PREFIX: Final = "rt_"
# 32 random bytes encoded as url-safe base64 (no padding) → 43 chars.
# RFC 6749 §10.10 recommends >=128 bits of entropy → 32 bytes = 256 bits.
TOKEN_RANDOM_BYTES: Final = 32

# Default TTL (7 days). Spec §7. ``Settings.JWT_REFRESH_TTL_SECONDS=604800``.
DEFAULT_REFRESH_TTL_SECONDS: Final = 7 * 24 * 60 * 60


# ---------------------------------------------------------------------------
# Public return types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RefreshTokenIssued:
    """Return shape of ``RefreshService.issue()``.

    ``plaintext`` MUST be returned to the client exactly once — never
    persisted in plaintext by the service. The caller is responsible for
    shaping it into the HTTP response.
    """

    plaintext: str
    token_id: str
    family_id: str
    expires_at: datetime


@dataclass(frozen=True)
class RefreshTokenRotated:
    """Return shape of ``RefreshService.rotate()``.

    Same as ``RefreshTokenIssued`` plus a pointer to the predecessor row
    for audit logging (PR-J3.7 writes ``replaced_by`` to the audit_log
    chain so a security analyst can walk a token's full history).
    """

    plaintext: str
    token_id: str
    family_id: str
    expires_at: datetime
    predecessor_id: str


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


SessionFactory = Callable[[], Session]


class RefreshService:
    """Refresh-token issue / rotate / revoke service.

    Parameters
    ----------
    session_factory:
        Zero-arg callable returning a SQLAlchemy ``Session``. We take a
        factory so the FastAPI dependency layer can inject a request-
        scoped session without this module needing to know about
        ``Depends``.
    hash_key:
        The HMAC-SHA256 key used to hash every refresh token before DB
        persistence. Loaded from ``Settings.REFRESH_HASH_KEY`` at boot.
        MUST be >=32 bytes per spec §7 (enforced at the Settings layer
        in PR-J1.6 via ``Settings._validate_refresh_hash_key``).
    refresh_ttl_seconds:
        Tokens expire this many seconds after issue. Defaults to 7 days;
        configurable so tests can mint short-lived tokens for the
        concurrent-rotate race.
    clock:
        Override for tests that need a frozen clock (J2.4 concurrent-
        rotate). Defaults to naive-UTC ``datetime.now()``.

    Concurrency contract
    --------------------
    ``rotate()`` uses an atomic ``UPDATE ... WHERE revoked_at IS NULL``
    pattern so two simultaneous presentations of the same token yield
    exactly one ``RefreshTokenRotated`` and one ``TokenInvalidError``
    with ``reason="rotation_in_progress"``. The loser is informed via
    exception so the client can re-issue using the winner's plaintext.
    """

    def __init__(
        self,
        session_factory: SessionFactory,
        hash_key: str,
        *,
        refresh_ttl_seconds: int = DEFAULT_REFRESH_TTL_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(hash_key, str) or len(hash_key) < 32:
            # Defense-in-depth — the Settings layer already enforces this,
            # but we re-check so unit tests that build the service without
            # going through Settings still get a fail-loud error.
            raise ValueError("RefreshService.hash_key must be a string of >=32 bytes")
        if refresh_ttl_seconds <= 0:
            raise ValueError("refresh_ttl_seconds must be positive")

        self._session_factory = session_factory
        self._hash_key = hash_key.encode("utf-8")
        self._ttl = int(refresh_ttl_seconds)
        # Inline default clock as a closure to keep it private — we do NOT
        # expose it at module level so test_module_does_not_leak_internal_helpers
        # can pin the public surface.
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC).replace(tzinfo=None))
        )

    # ---- Helpers ------------------------------------------------------------

    def _hash(self, plaintext: str) -> str:
        """Compute the deterministic HMAC-SHA256 hex digest of ``plaintext``.

        Hex output (64 chars) is what we store in ``refresh_tokens.token_hash``.
        The plaintext token NEVER lands in the DB.
        """
        return hmac.new(
            self._hash_key,
            plaintext.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _generate_plaintext(self) -> str:
        """Generate a fresh opaque refresh token.

        Format: ``"rt_" + base64url(32 random bytes, no padding)`` →
        prefix (3) + 43 chars = 46 chars total. The 32-byte / 256-bit
        entropy matches RFC 6749 §10.10 minimums (128 bits) with a
        comfortable margin.
        """
        random_bytes = secrets.token_bytes(TOKEN_RANDOM_BYTES)
        b64 = base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")
        return f"{TOKEN_PREFIX}{b64}"

    def _expires_at(self, now: datetime | None = None) -> datetime:
        when = now if now is not None else self._clock()
        return when + timedelta(seconds=self._ttl)

    # ---- Public API ---------------------------------------------------------

    def issue(
        self,
        user_id: str,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> RefreshTokenIssued:
        """Mint a brand-new refresh token for ``user_id``.

        Creates a fresh ``family_id`` so this token starts a NEW chain
        (not an append to an existing family). Login-flow uses this on
        every successful authentication per spec §1.
        """
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a non-empty string")

        plaintext = self._generate_plaintext()
        token_hash = self._hash(plaintext)
        family_id = str(uuid.uuid4())
        now = self._clock()
        expires_at = self._expires_at(now)

        new_id = str(uuid.uuid4())
        row = RefreshToken(
            id=new_id,
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
            revoked_at=None,
            replaced_by=None,
            created_at=now,
            ip_first_seen=ip,
            user_agent_first_seen=user_agent,
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
            # Capture the auto-generated attributes from the live session —
            # after `with` exits, the row is detached and re-accessing
            # `row.id` triggers a load from DB which fails (DetachedInstance).
            # We synthesise the values ourselves because we generated them.

        return RefreshTokenIssued(
            plaintext=plaintext,
            token_id=new_id,
            family_id=family_id,
            expires_at=expires_at,
        )

    def rotate(self, plaintext: str) -> RefreshTokenRotated:
        """Atomically rotate ``plaintext``: revoke old, mint new in same family.

        Algorithm (RFC 6749 §6 + spec §4 INV-2):

        1. ``SELECT ... WHERE token_hash = HMAC(plaintext)``. If no row →
           ``TokenInvalidError("unknown")``.
        2. If the row is already revoked (``revoked_at IS NOT NULL``) →
           revoke the entire family (idempotent) and raise
           ``FamilyRevokedError``.
        3. If ``expires_at <= now`` → ``TokenInvalidError("expired")``.
           (Expired rows are NOT auto-deleted here — that's
           ``purge_expired()``'s job — so misuse is observable in logs.)
        4. INSERT the new row with a fresh ``token_id`` and the SAME
           ``family_id``.
        5. Atomic ``UPDATE ... SET revoked_at = NOW(), replaced_by = new.id
           WHERE id = row.id AND revoked_at IS NULL``. If ``rowcount == 0``
           → a concurrent rotate() won; raise
           ``TokenInvalidError("rotation_in_progress")``.

        Steps 1-3 happen OUTSIDE the update so we can return precise
        error reasons. Step 5's atomicity means the DB is the linearization
        point — there is no "two clients rotate the same token" race that
        succeeds silently.
        """
        if not isinstance(plaintext, str) or not plaintext.startswith(TOKEN_PREFIX):
            raise TokenInvalidError("malformed")
        token_hash = self._hash(plaintext)
        now = self._clock()

        with self._session_factory() as session:
            row = session.execute(
                select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            ).scalar_one_or_none()

            if row is None:
                raise TokenInvalidError("unknown")

            # INV-2: replay detection. The old row was already revoked —
            # someone (legit or attacker) is presenting the same token
            # twice. Revoke the entire family and notify the caller.
            if row.revoked_at is not None:
                revoked_count = self._revoke_family_in_session(session, row.family_id, now)
                session.commit()
                raise FamilyRevokedError(row.family_id, revoked_count=revoked_count)

            if row.expires_at <= now:
                raise TokenInvalidError("expired", row_id=row.id)

            # Insert the new row first so we have its id, then atomic-update
            # the predecessor with a FK pointer.
            new_id = str(uuid.uuid4())
            new_plaintext = self._generate_plaintext()
            new_hash = self._hash(new_plaintext)
            new_expires = self._expires_at(now)
            new_row = RefreshToken(
                id=new_id,
                user_id=row.user_id,
                token_hash=new_hash,
                family_id=row.family_id,
                expires_at=new_expires,
                revoked_at=None,
                replaced_by=None,
                created_at=now,
                ip_first_seen=None,
                user_agent_first_seen=None,
            )
            session.add(new_row)
            session.flush()  # populate new_row.id (already set, but explicit)

            update_result = session.execute(
                update(RefreshToken)
                .where(RefreshToken.id == row.id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=now, replaced_by=new_id)
            )

            if update_result.rowcount == 0:  # type: ignore[attr-defined]
                # Concurrent rotate won. Roll back the new row we just
                # inserted to keep state consistent.
                session.rollback()
                raise TokenInvalidError("rotation_in_progress", row_id=row.id)

            session.commit()
            return RefreshTokenRotated(
                plaintext=new_plaintext,
                token_id=new_id,
                family_id=row.family_id,
                expires_at=new_expires,
                predecessor_id=row.id,
            )

    # ---- Family / user revocation ------------------------------------------

    def revoke_family(self, family_id: str) -> int:
        """Revoke every ACTIVE row in ``family_id``.

        Idempotent — re-revoking a fully-revoked family is a 0-row UPDATE
        that returns 0. Returns the count of rows that transitioned from
        active to revoked in THIS call.
        """
        if not isinstance(family_id, str) or not family_id:
            raise ValueError("family_id must be a non-empty string")
        with self._session_factory() as session:
            n = self._revoke_family_in_session(session, family_id, self._clock())
            session.commit()
            return n

    def revoke_user(self, user_id: str) -> int:
        """Revoke every ACTIVE row belonging to ``user_id``.

        Used by logout-all-devices and by the CLI ``recon users disable``
        command (PR-J4). Like ``revoke_family``, idempotent.
        """
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a non-empty string")
        now = self._clock()
        with self._session_factory() as session:
            result = session.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == user_id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    def purge_expired(self) -> int:
        """DELETE rows whose ``expires_at`` is in the past.

        Returns the count of rows physically removed. Safe to run
        periodically (scheduled job in PR-J7) — never touches still-
        active rows. Replaces the audit-retained ``revoked_at`` chain
        only when ``expires_at`` has also passed.
        """
        now = self._clock()
        with self._session_factory() as session:
            result = session.execute(
                RefreshToken.__table__.delete().where(  # type: ignore[attr-defined]
                    RefreshToken.expires_at <= now,
                )
            )
            session.commit()
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    def lookup(self, plaintext: str) -> RefreshToken | None:
        """Return the row matching ``plaintext`` (or ``None`` if absent).

        Used by the logout endpoint (PR-J3.4) to find the family of the
        presented refresh token. Does NOT raise on missing token — None
        is the universal "no such row" signal.
        """
        if not isinstance(plaintext, str) or not plaintext.startswith(TOKEN_PREFIX):
            return None
        token_hash = self._hash(plaintext)
        with self._session_factory() as session:
            return session.execute(
                select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            ).scalar_one_or_none()

    def active_count(self, family_id: str) -> int:
        """Test helper — count rows in ``family_id`` with ``revoked_at IS NULL``.

        NOT exposed via the FastAPI router; intended for tests and admin
        diagnostics.
        """
        with self._session_factory() as session:
            result = session.execute(
                select(RefreshToken).where(
                    RefreshToken.family_id == family_id,
                    RefreshToken.revoked_at.is_(None),
                )
            )
            return len(list(result.scalars()))

    # ---- Private helpers ---------------------------------------------------

    def _revoke_family_in_session(self, session: Session, family_id: str, now: datetime) -> int:
        """Revoke every ACTIVE row in ``family_id`` using the GIVEN session.

        Internal — does NOT commit. The caller decides when to commit.
        Returns rowcount for the caller's reporting / rollback handling.
        """
        result = session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]


__all__ = [
    "DEFAULT_REFRESH_TTL_SECONDS",
    "FamilyRevokedError",
    "RefreshService",
    "RefreshTokenIssued",
    "RefreshTokenRotated",
    "TOKEN_PREFIX",
    "TokenInvalidError",
]
