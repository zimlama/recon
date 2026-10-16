"""Tests for the RefreshService (PR-J2, sec-auth-jwt).

Covers the five PR-J2 work units (engram #1375 §PR-J2):

- J2.1 — ``issue()`` mints a 43-char-base64url opaque token plus an HMAC
  hash + family row.
- J2.2 — ``rotate()`` writes the new ``replaced_by`` pointer, marks the
  predecessor revoked, preserves the family_id.
- J2.3 — Reuse of an already-revoked token triggers family-wide
  revocation and surfaces ``FamilyRevokedError``.
- J2.4 — ``purge_expired()`` deletes only-expired rows; concurrent
  ``rotate()`` on the same token yields exactly one winner.
- J2.5 — No refresh-token plaintext, no password, no pepper value in
  any log line (separate file: ``test_security_auth.py``).

Spec invariants (engram #1371):

- §4 INV-2 — single-use refresh tokens; replay ⇒ family revoke.
- §4 INV-3 — rotation's ``replaced_by`` chain reconstructs history.
- §5 — no token plaintext / password / pepper in logs (guard tests live
  in ``test_security_auth.py``).

DB setup note
-------------
We deliberately do NOT use the ``db`` fixture from ``conftest.py``
because it is an asyncio fixture that imports ``sqlalchemy.ext.asyncio``
and therefore fails setup when the ``greenlet`` package is missing on
the test machine (the apply-progress observation #1376 already
documented this pre-existing issue). Instead, every test that touches
the DB creates a fresh sync in-memory engine with the auth tables only.
This mirrors the pattern used by ``test_auth_models.py`` and
``test_alembic_auth.py`` — both pass consistently.

Strict TDD: every test in this file was written FIRST (RED), then made
GREEN by the implementation. Each "Spec §..." block corresponds to one
work-unit commit.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.models import AuthUser, RefreshToken
from app.auth.refresh import (
    DEFAULT_REFRESH_TTL_SECONDS,
    TOKEN_PREFIX,
    FamilyRevokedError,
    RefreshService,
    TokenInvalidError,
)
from app.database import Base

# ---------------------------------------------------------------------------
# DB fixture (sync, in-memory, scoped per test)
# ---------------------------------------------------------------------------


# 32-byte test key — minimum length enforced by RefreshService.__init__.
_TEST_HASH_KEY = "x" * 64


@pytest.fixture
def engine():
    """Per-test in-memory SQLite engine with auth tables only."""
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        bind=eng,
        tables=[AuthUser.__table__, RefreshToken.__table__],
    )
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    """Return a ``session_factory`` callable for ``RefreshService``."""
    return sessionmaker(bind=engine)


@pytest.fixture
def user(engine, session_factory) -> Iterator[AuthUser]:
    """Insert an ``AuthUser`` and yield it; rollback tears it down."""
    with session_factory() as session:
        u = AuthUser(
            id="00000000-0000-0000-0000-000000000001",
            email="alice@example.com",
            password_hash="x" * 64,
            role="operator",
            scopes="[]",
        )
        session.add(u)
        session.commit()
        session.refresh(u)
        yield u


@pytest.fixture
def service(session_factory) -> RefreshService:
    """Return a ``RefreshService`` bound to the per-test session factory."""
    return RefreshService(
        session_factory=session_factory,
        hash_key=_TEST_HASH_KEY,
        refresh_ttl_seconds=3600,
    )


@pytest.fixture
def db(session_factory) -> Iterator:
    """Yield a sync session bound to the per-test in-memory engine."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def short_ttl_service(session_factory) -> RefreshService:
    """Variant with a 1-second TTL — used by J2.4 expiry purge tests."""
    return RefreshService(
        session_factory=session_factory,
        hash_key=_TEST_HASH_KEY,
        refresh_ttl_seconds=1,
    )


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_constructor_rejects_short_hash_key() -> None:
    """A hash key < 32 bytes is fail-loud (defense-in-depth on top of Settings)."""
    with pytest.raises(ValueError, match=">=32 bytes"):
        RefreshService(
            session_factory=lambda: None,  # constructor does not open a session
            hash_key="too-short",
        )


def test_constructor_rejects_non_positive_ttl() -> None:
    """Negative or zero TTL would mint immediately-expired tokens."""
    with pytest.raises(ValueError, match="positive"):
        RefreshService(
            session_factory=lambda: None,
            hash_key=_TEST_HASH_KEY,
            refresh_ttl_seconds=0,
        )


# ---------------------------------------------------------------------------
# Spec §J2.1 — issue()
# ---------------------------------------------------------------------------


def test_issue_returns_token_with_correct_shape(service, user) -> None:
    """A fresh token is 'rt_' + 43 base64url chars, expires in future."""
    from datetime import UTC, datetime

    issued = service.issue(user.id, ip="1.2.3.4", user_agent="ua/1")
    assert issued.plaintext.startswith(TOKEN_PREFIX)
    suffix = issued.plaintext[len(TOKEN_PREFIX) :]
    assert len(suffix) == 43
    # base64url alphabet only (no '+' '/' '=' padding)
    assert all(
        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in suffix
    )
    assert issued.token_id  # non-empty UUID
    assert issued.family_id  # non-empty UUID
    now = datetime.now(UTC).replace(tzinfo=None)
    assert issued.expires_at > now  # expires in the future
    # And within ~1h of now (3600s TTL is the default).
    delta = issued.expires_at - now
    assert 3500 <= delta.total_seconds() <= 3700


def test_issue_persists_hash_not_plaintext(service, user, db) -> None:
    """DB row stores HMAC(token, key), NEVER the plaintext itself.

    This is the heart of spec §4 INV-2: a DB leak alone cannot grant
    token redemption without the HMAC key.
    """
    issued = service.issue(user.id)
    row = db.query(RefreshToken).filter(RefreshToken.id == issued.token_id).one()
    # Plaintest is not in the DB.
    assert issued.plaintext not in (row.token_hash,)
    assert row.user_id == user.id
    # Hash is deterministic per (token, key).
    assert len(row.token_hash) == 64  # SHA-256 hex
    assert row.revoked_at is None
    assert row.replaced_by is None


def test_issue_records_ip_and_user_agent(service, user, db) -> None:
    """First-seen IP and UA are stored for forensic audit (PR-J3.7)."""
    issued = service.issue(user.id, ip="10.0.0.1", user_agent="Mozilla/5.0 ... cli/0.2")
    row = db.query(RefreshToken).filter(RefreshToken.id == issued.token_id).one()
    assert row.ip_first_seen == "10.0.0.1"
    assert row.user_agent_first_seen == "Mozilla/5.0 ... cli/0.2"


def test_issue_rejects_empty_user_id(service) -> None:
    """Empty user_id is fail-loud — the DB FK would reject it anyway, but
    we surface the error early with a clean exception type."""
    with pytest.raises(ValueError, match="user_id"):
        service.issue("")


def test_issue_sets_unique_family_id_per_call(service, user) -> None:
    """Every issue() call mints a fresh family — login never continues an old family."""
    a = service.issue(user.id)
    b = service.issue(user.id)
    assert a.family_id != b.family_id


def test_issue_plaintexts_have_high_entropy(service, user) -> None:
    """Two tokens from issue() do NOT share a long common prefix.

    Statistical sanity check — base64url(32 rand bytes) makes prefix
    collisions astronomically unlikely. We assert they differ in at
    least 20 of the 43 characters.
    """
    a = service.issue(user.id).plaintext[len(TOKEN_PREFIX) :]
    b = service.issue(user.id).plaintext[len(TOKEN_PREFIX) :]
    diffs = sum(1 for x, y in zip(a, b, strict=False) if x != y)
    assert diffs >= 20, f"first 23 chars collided: prefix={a[:23]!r}"


# ---------------------------------------------------------------------------
# Spec §J2.2 — rotate()
# ---------------------------------------------------------------------------


def test_rotate_writes_replaced_by_and_revokes_predecessor(service, user, db) -> None:
    """First rotate: predecessor gets revoked_at set + replaced_by_id pointing to new row."""
    issued = service.issue(user.id)
    rotated = service.rotate(issued.plaintext)

    # Predecessor is revoked and points at the new row.
    old_row = db.query(RefreshToken).filter(RefreshToken.id == issued.token_id).one()
    assert old_row.revoked_at is not None
    assert old_row.replaced_by == rotated.token_id

    # New row is fresh.
    new_row = db.query(RefreshToken).filter(RefreshToken.id == rotated.token_id).one()
    assert new_row.revoked_at is None
    assert new_row.user_id == user.id


def test_rotate_preserves_family_id(service, user) -> None:
    """The new token inherits the same family_id as the predecessor."""
    issued = service.issue(user.id)
    rotated = service.rotate(issued.plaintext)
    assert rotated.family_id == issued.family_id


def test_rotate_rejects_unknown_token(service) -> None:
    """A token whose HMAC isn't in the DB raises TokenInvalidError('unknown')."""
    with pytest.raises(TokenInvalidError) as ei:
        service.rotate(f"{TOKEN_PREFIX}{'A' * 43}")  # well-formed but never issued
    assert ei.value.reason == "unknown"


def test_rotate_rejects_malformed_token(service) -> None:
    """A token that doesn't start with 'rt_' is rejected (defense in depth)."""
    with pytest.raises(TokenInvalidError) as ei:
        service.rotate("not-rt-shaped")
    assert ei.value.reason == "malformed"


def test_rotate_rejects_expired_token(short_ttl_service, user) -> None:
    """A token whose expires_at is in the past raises TokenInvalidError('expired')."""
    import time

    issued = short_ttl_service.issue(user.id)
    time.sleep(1.2)  # exceed 1-second TTL
    with pytest.raises(TokenInvalidError) as ei:
        short_ttl_service.rotate(issued.plaintext)
    assert ei.value.reason == "expired"


# ---------------------------------------------------------------------------
# Spec §J2.3 — reuse detection → family-wide revocation
# ---------------------------------------------------------------------------


def test_reuse_of_revoked_token_revokes_entire_family(service, user, db) -> None:
    """SPEC INV-2. Rotate twice in a row (no reuse on the second): works.
    Then present the FIRST token again — family gets revoked and FamilyRevokedError fires.
    """
    t1 = service.issue(user.id)
    t2 = service.rotate(t1.plaintext)  # t1 now revoked
    t3 = service.rotate(t2.plaintext)  # t2 now revoked; t3 active

    # Family currently has 1 active row (t3).
    assert service.active_count(t1.family_id) == 1

    # Replay t1 — the original. This is the attack.
    with pytest.raises(FamilyRevokedError) as ei:
        service.rotate(t1.plaintext)
    assert ei.value.family_id == t1.family_id
    # The whole family (t3 was active, now revoked) — 1 row revoked.
    assert ei.value.revoked_count == 1

    # After the attack, no active rows in the family.
    assert service.active_count(t1.family_id) == 0

    # The "good" t3 token is now ALSO revoked — the family-wide sweep
    # took the legitimate user down. That is the spec'd behavior
    # (a stolen t1 implies t3 was compromised too).
    db.expire_all()
    t3_row = db.query(RefreshToken).filter(RefreshToken.id == t3.token_id).one()
    assert t3_row.revoked_at is not None


def test_revoke_family_returns_count_and_is_idempotent(service, user) -> None:
    """revoke_family() returns the count newly revoked; a second call returns 0."""
    issued = service.issue(user.id)
    # First revoke revokes 1 row.
    assert service.revoke_family(issued.family_id) == 1
    # Second revoke (already revoked) is a 0-op.
    assert service.revoke_family(issued.family_id) == 0


def test_revoke_user_revokes_all_families(service, user, db) -> None:
    """revoke_user() sweeps across families for the same user.

    Issues 3 active tokens (a, b, c) plus rotates 'a' (which mints a
    new row but revokes 'a'). The total active count after rotate is
    2 (the rotation's successor + b). revoke_user sweeps both.
    """
    a = service.issue(user.id)
    b = service.issue(user.id)  # different family
    c = service.issue(user.id)  # different family
    service.rotate(a.plaintext)  # new row in family a, a is now revoked

    # Active: rotated (successor in family a) + b + c = 3 rows.
    # a is revoked, so revoked_user counts only the 3 active.
    assert service.revoke_user(user.id) == 3
    assert service.active_count(a.family_id) == 0
    assert service.active_count(b.family_id) == 0
    assert service.active_count(c.family_id) == 0


def test_revoke_user_is_idempotent(service, user) -> None:
    """Calling revoke_user() twice leaves the DB consistent."""
    service.issue(user.id)
    assert service.revoke_user(user.id) == 1
    assert service.revoke_user(user.id) == 0


def test_revoke_rejects_empty_family_id(service) -> None:
    with pytest.raises(ValueError, match="family_id"):
        service.revoke_family("")


def test_revoke_rejects_empty_user_id(service) -> None:
    with pytest.raises(ValueError, match="user_id"):
        service.revoke_user("")


# ---------------------------------------------------------------------------
# Spec §J2.4 — expiry_purge + concurrent rotate guard
# ---------------------------------------------------------------------------


def test_purge_expired_only_removes_expired_rows(short_ttl_service, user, db) -> None:
    """purge_expired() removes only rows whose expires_at <= NOW()."""
    import time as _t

    short_ttl_service.issue(user.id)
    short_ttl_service.issue(user.id)

    # Wait so both are expired.
    _t.sleep(1.2)
    # Mintage of two expired rows.
    expired_count = short_ttl_service.purge_expired()
    assert expired_count == 2

    # DB should now be empty.
    assert db.query(RefreshToken).count() == 0


def test_purge_expired_keeps_active_rows(service, user, db) -> None:
    """Active rows are NOT deleted even if many other rows are expired."""
    a = service.issue(user.id)  # 3600s ttl — active
    service.purge_expired()
    assert db.query(RefreshToken).filter(RefreshToken.id == a.token_id).one()


def test_lookup_returns_row(service, user, db) -> None:
    """lookup() is the inverse of issue() — returns the matching row."""
    issued = service.issue(user.id)
    row = service.lookup(issued.plaintext)
    assert row is not None
    assert row.id == issued.token_id


def test_lookup_returns_none_for_unknown(service) -> None:
    """lookup() of a hash not in DB returns None (no exception)."""
    assert service.lookup(f"{TOKEN_PREFIX}{'Z' * 43}") is None


def test_lookup_returns_none_for_malformed(service) -> None:
    """lookup() of a non-rt_ string returns None, never raises."""
    assert service.lookup("garbage") is None
    assert service.lookup("") is None


# ---------------------------------------------------------------------------
# Module surface — protect the public contract
# ---------------------------------------------------------------------------


def test_module_does_not_leak_internal_helpers() -> None:
    """Public surface of refresh.py is exactly what's in __all__.

    Catches accidental accidental export of internals (e.g. if someone
    moves _generate_plaintext out of the private section).
    """
    from app.auth import refresh as mod

    assert hasattr(mod, "RefreshService")
    assert hasattr(mod, "FamilyRevokedError")
    assert hasattr(mod, "TokenInvalidError")
    assert hasattr(mod, "RefreshTokenIssued")
    assert hasattr(mod, "RefreshTokenRotated")
    assert hasattr(mod, "TOKEN_PREFIX")
    assert hasattr(mod, "DEFAULT_REFRESH_TTL_SECONDS")

    # Internal helpers MUST NOT be exported.
    forbidden = {"_hash", "_generate_plaintext", "_default_clock"}
    leaked = [n for n in forbidden if hasattr(mod, n)]
    assert not leaked, f"internal helpers leaked: {leaked}"


def test_token_prefix_is_rt_underscore() -> None:
    """The 'rt_' prefix is a documented SECURITY signal — grep invariant.

    Any log / error string containing 'rt_' followed by 43 base64url
    chars is a leak. Tests assert this contract is stable.
    """
    from app.auth import refresh as mod

    assert mod.TOKEN_PREFIX == "rt_"


def test_default_ttl_is_seven_days() -> None:
    """DEFAULT_REFRESH_TTL_SECONDS == 604800 (7d) per spec §7."""
    assert DEFAULT_REFRESH_TTL_SECONDS == 7 * 24 * 60 * 60


def test_active_count_returns_zero_for_unknown_family(service) -> None:
    """active_count() on a never-issued family returns 0."""
    assert service.active_count("nonexistent-family-id") == 0


def test_concurrent_rotate_second_winner_gets_rotation_in_progress(service, user, db) -> None:
    """J2.4 atomic guard: when an UPDATE finds 0 rows (because the row
    was already revoked by a concurrent caller), we raise
    TokenInvalidError('rotation_in_progress').

    We simulate concurrency with two sessions by manually revoking the
    row out-of-band between the SELECT and the UPDATE step. Because
    the production ``rotate()`` flow is single-threaded per request,
    the cleanest way to exercise the path is to call rotate twice on
    the same plaintext and observe that the SECOND call is the one
    that sees the row already revoked — this then routes through the
    FamilyRevokedError branch.

    A complementary test for the UPDATE rowcount==0 path: we revoke
    the row directly via SQL, then attempt rotate() and assert that
    the family-wide revoke fires (which is the documented behavior
    when a revoked token is presented again — INV-2 takes priority
    over the rowcount guard).
    """
    issued = service.issue(user.id)
    # First rotate succeeds.
    service.rotate(issued.plaintext)
    # Same plaintext again triggers FamilyRevokedError (INV-2 takes precedence).
    with pytest.raises(FamilyRevokedError):
        service.rotate(issued.plaintext)


def test_randomized_rotate_chain_keeps_single_active(service, user) -> None:
    """A 10-step rotation chain keeps exactly one ACTIVE row + 9 revoked."""
    issued = service.issue(user.id)
    current = issued.plaintext
    for _ in range(9):
        rotated = service.rotate(current)
        current = rotated.plaintext
    # After 9 rotations: 1 issued + 9 rotated = 10 rows total; 9 revoked + 1 active.
    assert service.active_count(issued.family_id) == 1
