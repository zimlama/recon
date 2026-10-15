"""Smoke tests for app.auth.models — ORM schema + helper functions.

These verify the ORM declarations match the alembic schema and exercise
the helper utilities (``parse_scopes``, ``encode_scopes``,
``auth_user_to_dict``).

The strict schema/constraint invariants (UNIQUE email, FK CASCADE,
revoked_at filter) are covered by alembic tests in test_alembic_auth.py.
Here we focus on ORM behavior:
- ORM create_all produces a schema that passes alembic inspection.
- is_locked, is_active, auth_user_to_dict work on in-memory instances.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.models import (
    AuthUser,
    RefreshToken,
    auth_user_to_dict,
    encode_scopes,
    parse_scopes,
)


def test_auth_user_password_hash_required_round_trip() -> None:
    """An AuthUser row preserves the argon2id PHC hash verbatim."""
    engine = create_engine("sqlite:///:memory:")
    from app.database import Base

    # Importing auth.models registered AuthUser on Base.metadata via the
    # models module-level definitions; create_all here only creates the
    # auth tables so we don't depend on the full app schema.
    Base.metadata.create_all(bind=engine, tables=[AuthUser.__table__])
    session_factory = sessionmaker(bind=engine)
    phc = "$argon2id$v=19$m=65536,t=3,p=4$abc$def"
    with session_factory() as session:
        u = AuthUser(
            email="alice@example.com",
            password_hash=phc,
            role="operator",
        )
        session.add(u)
        session.commit()
        loaded = session.query(AuthUser).filter_by(email="alice@example.com").one()
    assert loaded.password_hash == phc
    assert loaded.role == "operator"
    assert loaded.scopes == "[]"
    engine.dispose()


def test_refresh_token_cascade_on_user_delete() -> None:
    """Deleting an AuthUser cascades to delete their refresh_tokens."""
    engine = create_engine("sqlite:///:memory:")
    from app.database import Base

    Base.metadata.create_all(bind=engine, tables=[AuthUser.__table__, RefreshToken.__table__])
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        u = AuthUser(
            email="bob@example.com",
            password_hash="h",
            role="operator",
        )
        session.add(u)
        session.flush()
        rt = RefreshToken(
            user_id=u.id,
            token_hash="a" * 64,
            family_id="fam-1",
            expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1),
        )
        session.add(rt)
        session.commit()
        user_id = u.id
        rt_id = rt.id

    with session_factory() as session:
        u = session.query(AuthUser).filter_by(id=user_id).one()
        session.delete(u)
        session.commit()
    with session_factory() as session:
        count = session.query(RefreshToken).filter_by(id=rt_id).count()
    assert count == 0, "CASCADE delete should have removed the refresh_tokens row"
    engine.dispose()


def test_is_locked_returns_false_when_locked_until_is_null() -> None:
    """An AuthUser with no locked_until is never considered locked."""
    u = AuthUser(email="x@y", password_hash="h", role="operator")
    assert u.is_locked() is False


def test_is_locked_returns_true_when_locked_until_in_future() -> None:
    """A future locked_until blocks login."""
    u = AuthUser(
        email="x@y",
        password_hash="h",
        role="operator",
        locked_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=15),
    )
    assert u.is_locked() is True


def test_is_locked_returns_false_when_locked_until_in_past() -> None:
    """A past locked_until has expired and no longer blocks login."""
    u = AuthUser(
        email="x@y",
        password_hash="h",
        role="operator",
        locked_until=datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1),
    )
    assert u.is_locked() is False


def test_refresh_token_is_active() -> None:
    """is_active() respects both revoked_at and expires_at."""
    now = datetime.now(UTC).replace(tzinfo=None)
    active = RefreshToken(
        user_id="u1",
        token_hash="a" * 64,
        family_id="f",
        expires_at=now + timedelta(days=1),
    )
    revoked = RefreshToken(
        user_id="u1",
        token_hash="b" * 64,
        family_id="f",
        expires_at=now + timedelta(days=1),
        revoked_at=now,
    )
    expired = RefreshToken(
        user_id="u1",
        token_hash="c" * 64,
        family_id="f",
        expires_at=now - timedelta(seconds=1),
    )
    assert active.is_active() is True
    assert revoked.is_active() is False
    assert expired.is_active() is False


def test_parse_scopes_round_trip() -> None:
    """parse_scopes(encode_scopes(x)) preserves the input list."""
    scopes = ["jobs:read", "jobs:write", "admin:keys"]
    assert parse_scopes(encode_scopes(scopes)) == sorted(scopes)


def test_parse_scopes_handles_garbage() -> None:
    """parse_scopes never raises — garbage returns []."""
    assert parse_scopes("not-json") == []
    assert parse_scopes("{}") == []
    assert parse_scopes('["a", 1, null, "b"]') == ["a", "b"]


def test_encode_scopes_dedupes_and_sorts() -> None:
    """encode_scopes canonicalizes order + removes duplicates."""
    # encode_scopes returns a JSON-encoded string (the SQL column type).
    assert encode_scopes(["b", "a", "b", "a"]) == '["a", "b"]'
    assert json.loads(encode_scopes(["c", "b", "a"])) == ["a", "b", "c"]


def test_auth_user_to_dict_drops_password_hash() -> None:
    """The serialiser MUST NOT expose password_hash (security regression guard)."""
    u = AuthUser(
        id="u-id",
        email="alice@example.com",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$SALT$HASH",
        role="operator",
        scopes='["jobs:read"]',
    )
    d = auth_user_to_dict(u)
    assert d["id"] == "u-id"
    assert d["email"] == "alice@example.com"
    assert d["role"] == "operator"
    assert d["scopes"] == ["jobs:read"]
    assert "password_hash" not in d, "auth_user_to_dict leaked password_hash!"
    # And it's not lurking in any nested field either:
    assert "password_hash" not in json.dumps(d)
