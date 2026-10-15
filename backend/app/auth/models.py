"""ORM models for the sec-auth-jwt feature (Issue #29, PR-J1).

These mirror the alembic revisions in
``backend/alembic/versions/2026101400000{1,2}_*.py``. The schema is the
single source of truth — do NOT edit these models without writing a matching
alembic migration that is reversible in tests.

Two tables in this module:

- ``AuthUser`` — per-user credentials, role, scopes, lockout state.
- ``RefreshToken`` — opaque DB-backed refresh tokens with HMAC-SHA256
  hashes, family revocation, and rotation-on-use.

Note on PKs: ``AuthUser.id`` and ``RefreshToken.id`` are CHAR(36) UUIDs,
matching the convention used by ``Job``, ``ModuleRun``, etc. in
``app.models``. This keeps ``request.state.user_id`` directly comparable
to other entity IDs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    """UUID v4 string (matches convention used elsewhere in app.models)."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Naive UTC now (SQLite does not preserve tzinfo)."""
    return datetime.now(UTC).replace(tzinfo=None)


class AuthUser(Base):
    """A user that can log in via /api/v1/auth/login.

    ``password_hash`` is the argon2id PHC string returned by
    ``PasswordService.hash``. ``scopes`` is JSON-encoded on SQLite (the
    spec calls for JSONB on PostgreSQL; switching is a one-line change
    at the alembic level if/when we move).
    """

    __tablename__ = "auth_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        UniqueConstraint("email", name="uq_auth_users_email"),
        CheckConstraint("role IN ('admin', 'operator', 'service')", name="ck_auth_users_role"),
        Index("ix_auth_users_role", "role"),
        Index("ix_auth_users_disabled_at", "disabled_at"),
    )

    def is_locked(self, at: datetime | None = None) -> bool:
        """True iff ``locked_until`` is in the future (or set permanently).

        Used by the login flow (PR-J3.3) to short-circuit verify before
        even hitting argon2 — saves ~100 ms of CPU on a flood.
        """
        if self.locked_until is None:
            return False
        when = at if at is not None else _now()
        return when < self.locked_until

    def __repr__(self) -> str:
        return f"<AuthUser id={self.id} email={self.email} role={self.role}>"


class RefreshToken(Base):
    """A single refresh token row.

    Lifecycle:

    1. ``issue()`` (PR-J2): INSERT row with ``revoked_at=None`` and a fresh
       ``family_id``.
    2. ``rotate()`` (PR-J2): UPDATE this row with ``revoked_at=NOW()`` +
       ``replaced_by=<new id>``; INSERT new row sharing the same
       ``family_id``.
    3. On reuse of an already-revoked token: every row with the same
       ``family_id`` and ``revoked_at IS NULL`` gets ``revoked_at=NOW()``
       (RFC 6749 §6).

    ``replaced_by`` is a self-FK with ``ON DELETE SET NULL`` so deleting
    a row in the middle of a chain does not cascade-delete the head.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    family_id: Mapped[str] = mapped_column(String(36), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    replaced_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    ip_first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent_first_seen: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user: Mapped[AuthUser] = relationship(back_populates="refresh_tokens")

    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_revoked_at", "revoked_at"),
        Index("ix_refresh_tokens_user_expires", "user_id", "expires_at"),
    )

    def is_active(self, at: datetime | None = None) -> bool:
        """True iff the row is non-revoked AND not expired."""
        when = at if at is not None else _now()
        if self.revoked_at is not None:
            return False
        return self.expires_at > when

    def __repr__(self) -> str:
        state = "active" if self.revoked_at is None else "revoked"
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"family={self.family_id[:8]}... {state}>"
        )


# ---------------------------------------------------------------------------
# Type helpers used by other auth modules
# ---------------------------------------------------------------------------


def parse_scopes(scopes_json: str) -> list[str]:
    """Decode the JSON-encoded ``scopes`` column.

    Returned list is a copy — callers may mutate freely.
    """
    import json

    try:
        decoded = json.loads(scopes_json)
    except (TypeError, ValueError):
        return []
    if not isinstance(decoded, list):
        return []
    return [s for s in decoded if isinstance(s, str)]


def encode_scopes(scopes: list[str]) -> str:
    """Encode a list of scope strings for the ``scopes`` column.

    The reverse of ``parse_scopes``. We use JSON (not a delimiter char)
    so scope values may themselves contain commas / colons / spaces.
    """
    import json

    return json.dumps(sorted({s for s in scopes if isinstance(s, str)}))


def auth_user_to_dict(user: AuthUser) -> dict[str, Any]:
    """Serialise an ``AuthUser`` for the ``/auth/me`` response shape.

    Deliberately does NOT include ``password_hash``. The serialiser lives
    here, not in ``service.py``, so every caller cannot accidentally leak
    the hash by forgetting to drop a column.
    """
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "scopes": parse_scopes(user.scopes),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": (user.last_login_at.isoformat() if user.last_login_at else None),
        "disabled_at": user.disabled_at.isoformat() if user.disabled_at else None,
    }
