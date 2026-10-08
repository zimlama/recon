"""Tests for RoEValidator — real authorization gate.

The validator answers one question: "is there an ACTIVE RoE, inside its
validity window, with at least one un-revoked SignOff, that authorises this
target+scope?". It is the single source of truth for the middleware and
the orchestrator's job-launch path.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.models import RoE, RoEStatus, ScopeType, SignOff, _now
from app.orchestrator.roe import RoEValidator

# ---------------------------------------------------------------------------
# Fixtures — local, self-contained private engine. See `tests/test_models.py`
# for the same pattern: the global engine in `app.database` interacts badly
# with `coverage` instrumentation under SQLAlchemy 2.1.x (Cython cache-key
# compilation errors). Using a private per-test engine keeps these tests
# stable under `--cov` and avoids cross-test contamination.
# ---------------------------------------------------------------------------


@pytest.fixture
def session(tmp_path) -> Session:
    """Fresh sync session bound to a private file-backed engine."""
    db_path = tmp_path / "roe_validator_test.db"
    if db_path.exists():
        db_path.unlink()

    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    RoE.__table__.create(bind=eng, checkfirst=True)
    SignOff.__table__.create(bind=eng, checkfirst=True)
    Session_ = sessionmaker(
        bind=eng, autoflush=False, autocommit=False, expire_on_commit=False
    )

    db = Session_()
    try:
        yield db
    finally:
        db.close()
        SignOff.__table__.drop(bind=eng, checkfirst=True)
        RoE.__table__.drop(bind=eng, checkfirst=True)
        eng.dispose()
        try:
            db_path.unlink()
        except FileNotFoundError:
            pass


@pytest.fixture
def validator(session: Session) -> RoEValidator:
    """An RoEValidator wired to the test session."""
    return RoEValidator(session_factory=lambda: session)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_active_roe(
    session: Session,
    target: str = "example.com",
    scope_type: ScopeType = ScopeType.DOMAIN,
    scope_value: str | None = None,
    valid_from_offset: timedelta = timedelta(hours=-1),
    valid_until_offset: timedelta = timedelta(hours=24),
    status: RoEStatus = RoEStatus.ACTIVE,
) -> RoE:
    """Insert an RoE whose validity window straddles `now`."""
    now = _now()
    roe = RoE(
        target=target,
        scope_type=scope_type,
        scope_value=scope_value if scope_value is not None else target,
        authorized_by="alice@example.com",
        status=status,
        valid_from=now + valid_from_offset,
        valid_until=now + valid_until_offset,
    )
    session.add(roe)
    session.commit()
    session.refresh(roe)
    return roe


def _add_signoff(
    session: Session,
    roe: RoE,
    signer_email: str = "bob@example.com",
    revoked: bool = False,
) -> SignOff:
    """Attach a signoff (revoked or active) to the RoE."""
    signoff = SignOff(
        roe_id=roe.id,
        signer_name="Bob",
        signer_email=signer_email,
        signer_role="CEO",
    )
    if revoked:
        signoff.revoked_at = _now()
    session.add(signoff)
    session.commit()
    session.refresh(signoff)
    return signoff


# ---------------------------------------------------------------------------
# is_authorized
# ---------------------------------------------------------------------------


def test_active_roe_authorizes_target_in_scope(
    session: Session, validator: RoEValidator
) -> None:
    """An ACTIVE RoE + active signoff + in-window -> authorized=True."""
    roe = _add_active_roe(session)
    _add_signoff(session, roe)

    authorized, reason, signoffs = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is True
    assert reason == ""
    assert len(signoffs) == 1
    assert signoffs[0].signer_email == "bob@example.com"


def test_draft_roe_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """A DRAFT RoE is never authorized, regardless of dates or signoffs."""
    roe = _add_active_roe(session, status=RoEStatus.DRAFT)
    _add_signoff(session, roe)

    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert "draft" in reason.lower() or "active" in reason.lower()
    assert "draft" in reason.lower() or "not active" in reason.lower()


def test_expired_roe_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """An RoE whose `valid_until` is in the past does not authorize."""
    roe = _add_active_roe(
        session,
        valid_from_offset=timedelta(days=-2),
        valid_until_offset=timedelta(hours=-1),  # already expired
    )
    _add_signoff(session, roe)

    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert "expired" in reason.lower() or "valid" in reason.lower()


def test_not_yet_valid_roe_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """An RoE whose `valid_from` is in the future does not authorize.

    Symmetric to `test_expired_roe_does_not_authorize`: an RoE with a
    future `valid_from` is "not yet valid". The validator must surface
    this with a distinct reason phrase so the operator can tell the
    difference between "expired" and "scheduled for the future".
    """
    roe = _add_active_roe(
        session,
        valid_from_offset=timedelta(hours=1),  # starts in the future
        valid_until_offset=timedelta(hours=24),
    )
    _add_signoff(session, roe)

    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert "not yet valid" in reason.lower() or "future" in reason.lower()


def test_revoked_roe_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """An RoE with status=REVOKED is not authorized."""
    roe = _add_active_roe(session, status=RoEStatus.REVOKED)
    _add_signoff(session, roe)

    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert "revoked" in reason.lower() or "active" in reason.lower()


def test_roe_without_signoffs_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """An ACTIVE in-window RoE with zero signoffs returns authorized=False."""
    _add_active_roe(session)  # no signoff attached

    authorized, reason, signoffs = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert signoffs == []
    assert "sign" in reason.lower() or "signoff" in reason.lower()


def test_roe_with_all_signoffs_revoked_does_not_authorize(
    session: Session, validator: RoEValidator
) -> None:
    """If every SignOff has `revoked_at` set, the RoE does not authorize."""
    roe = _add_active_roe(session)
    _add_signoff(session, roe, signer_email="a@example.com", revoked=True)
    _add_signoff(session, roe, signer_email="b@example.com", revoked=True)

    authorized, reason, signoffs = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
    )

    assert authorized is False
    assert signoffs == []
    assert "sign" in reason.lower() or "revoked" in reason.lower()


# ---------------------------------------------------------------------------
# get_active_roes
# ---------------------------------------------------------------------------


def test_get_active_roes_returns_only_active(
    session: Session, validator: RoEValidator
) -> None:
    """`get_active_roes` excludes DRAFT / REVOKED / out-of-window RoEs."""
    # Two ACTIVE in-window RoEs.
    active_1 = _add_active_roe(session, target="example.com")
    _add_signoff(session, active_1)
    active_2 = _add_active_roe(session, target="another.com")
    _add_signoff(session, active_2)

    # One DRAFT — must be excluded.
    draft = _add_active_roe(session, target="draft.com", status=RoEStatus.DRAFT)
    _add_signoff(session, draft)

    # One EXPIRED — must be excluded.
    expired = _add_active_roe(
        session,
        target="expired.com",
        valid_from_offset=timedelta(days=-2),
        valid_until_offset=timedelta(hours=-1),
        status=RoEStatus.ACTIVE,  # status still ACTIVE, but window expired
    )
    _add_signoff(session, expired)

    # One REVOKED — must be excluded.
    revoked = _add_active_roe(session, target="revoked.com", status=RoEStatus.REVOKED)
    _add_signoff(session, revoked)

    results = validator.get_active_roes()

    targets = {r.target for r in results}
    assert targets == {"example.com", "another.com"}
    # Every returned RoE must satisfy the same conditions the validator uses.
    for r in results:
        assert r.status == RoEStatus.ACTIVE
        assert r.is_acceptable()


def test_get_active_roes_filters_by_target_and_scope(
    session: Session, validator: RoEValidator
) -> None:
    """Filters narrow the result set without dropping valid RoEs."""
    keep = _add_active_roe(session, target="keep.com")
    _add_signoff(session, keep)
    drop = _add_active_roe(session, target="drop.com")
    _add_signoff(session, drop)

    results = validator.get_active_roes(target="keep.com")

    assert [r.target for r in results] == ["keep.com"]


def test_get_active_roes_filters_by_scope_type(
    session: Session, validator: RoEValidator
) -> None:
    """`scope_type=` narrows the result set to that scope only."""
    domain = _add_active_roe(session, target="example.com", scope_type=ScopeType.DOMAIN)
    _add_signoff(session, domain)
    company = _add_active_roe(
        session,
        target="example.com",
        scope_type=ScopeType.COMPANY,
        scope_value="Example Inc.",
    )
    _add_signoff(session, company)

    domain_results = validator.get_active_roes(scope_type=ScopeType.DOMAIN)
    assert {r.scope_type for r in domain_results} == {ScopeType.DOMAIN}

    company_results = validator.get_active_roes(scope_type=ScopeType.COMPANY)
    assert {r.scope_type for r in company_results} == {ScopeType.COMPANY}


# ---------------------------------------------------------------------------
# Robustness / contract hardening
#
# The original test surface covered the four status branches (DRAFT, ACTIVE,
# EXPIRED, REVOKED) and the no-signoff branch. These extra cases hard-test
# the small remaining branches: explicit `at=` injection, target
# normalization, and idempotency.
# ---------------------------------------------------------------------------


def test_is_authorized_with_explicit_at_in_past(
    session: Session, validator: RoEValidator
) -> None:
    """`at=` injection into the past makes an otherwise-valid RoE look expired.

    The `at` parameter is exposed exactly so callers (audit, replay) can
    ask: "would this RoE have covered the target at *time T*?" — even if
    T is now in the past. The validator must honour the override.
    """
    now = _now()
    roe = RoE(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
        scope_value="example.com",
        authorized_by="alice@example.com",
        status=RoEStatus.ACTIVE,
        valid_from=now - timedelta(hours=2),
        valid_until=now + timedelta(hours=2),
    )
    session.add(roe)
    session.commit()

    signoff = SignOff(
        roe_id=roe.id,
        signer_name="Bob",
        signer_email="bob@example.com",
        signer_role="CEO",
    )
    session.add(signoff)
    session.commit()

    # 10 hours ago — well outside the validity window of 2h ago → 2h ahead.
    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
        at=now - timedelta(hours=10),
    )
    assert authorized is False
    assert "valid" in reason.lower() or "window" in reason.lower() or "expired" in reason.lower()


def test_is_authorized_with_explicit_at_in_future(
    session: Session, validator: RoEValidator
) -> None:
    """`at=` injection into the future makes an RoE look "not yet valid".

    Symmetric to the past case: callers can ask "would this RoE cover
    the target *at T*?" for scheduled / dry-run audits.
    """
    now = _now()
    roe = RoE(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
        scope_value="example.com",
        authorized_by="alice@example.com",
        status=RoEStatus.ACTIVE,
        valid_from=now + timedelta(hours=10),  # not yet valid
        valid_until=now + timedelta(hours=20),
    )
    session.add(roe)
    session.commit()

    signoff = SignOff(
        roe_id=roe.id,
        signer_name="Bob",
        signer_email="bob@example.com",
        signer_role="CEO",
    )
    session.add(signoff)
    session.commit()

    authorized, reason, _ = validator.is_authorized(
        target="example.com",
        scope_type=ScopeType.DOMAIN,
        at=now,
    )
    assert authorized is False
    assert "not yet valid" in reason.lower() or "future" in reason.lower()


def test_is_authorized_target_normalizes_whitespace_and_case(
    session: Session, validator: RoEValidator
) -> None:
    """`is_authorized` must match targets case-insensitively and trim whitespace.

    Operators typo targets with leading/trailing spaces; the validator
    must treat `"  EXAMPLE.com  "` as a match for `"example.com"`.
    """
    roe = _add_active_roe(session, target="example.com")
    _add_signoff(session, roe)

    authorized, reason, signoffs = validator.is_authorized(
        target="  EXAMPLE.com  ",
        scope_type=ScopeType.DOMAIN,
    )
    assert authorized is True
    assert reason == ""
    assert len(signoffs) == 1


def test_is_authorized_is_idempotent(
    session: Session, validator: RoEValidator
) -> None:
    """Re-running `is_authorized` is read-only and produces identical answers.

    The validator must not create new SignOffs, mutate the RoE, or shift
    session state — it's called from the middleware and the orchestrator,
    possibly multiple times for the same request, and must be safe.
    Note: the two returned SignOff lists are *equal-content* (same id,
    same email, same revoked state) but are distinct ORM instances
    because the validator opens a fresh query each call.
    """
    roe = _add_active_roe(session, target="example.com")
    _add_signoff(session, roe)

    first = validator.is_authorized(target="example.com", scope_type=ScopeType.DOMAIN)
    second = validator.is_authorized(target="example.com", scope_type=ScopeType.DOMAIN)

    authorized_1, reason_1, signoffs_1 = first
    authorized_2, reason_2, signoffs_2 = second

    assert authorized_1 is True
    assert authorized_2 is True
    assert reason_1 == ""
    assert reason_2 == ""
    assert len(signoffs_1) == 1
    assert len(signoffs_2) == 1
    # Same SignOff row (same id, same email)
    assert signoffs_1[0].id == signoffs_2[0].id
    assert signoffs_1[0].signer_email == signoffs_2[0].signer_email
    # No new signoff rows were created
    assert session.query(SignOff).count() == 1
    # The RoE itself is unchanged
    assert roe.status == RoEStatus.ACTIVE


def test_is_authorized_no_roe_returns_empty_signoffs(
    session: Session, validator: RoEValidator
) -> None:
    """With no RoE at all, signoffs is exactly `[]` (not None, not NoneType)."""
    # Empty DB.
    authorized, reason, signoffs = validator.is_authorized(
        target="nothing.example",
        scope_type=ScopeType.DOMAIN,
    )
    assert authorized is False
    assert signoffs == []
    assert isinstance(signoffs, list)


def test_get_active_roes_excludes_only_drafts(
    session: Session, validator: RoEValidator
) -> None:
    """Mixed RoEs: DRAFT and REVOKED are filtered; ACTIVE in-window passes."""
    keep = _add_active_roe(session, target="keep.com")
    _add_signoff(session, keep)

    draft = _add_active_roe(session, target="draft.com", status=RoEStatus.DRAFT)
    _add_signoff(session, draft)

    revoked = _add_active_roe(session, target="revoked.com", status=RoEStatus.REVOKED)
    _add_signoff(session, revoked)

    roes = validator.get_active_roes()
    targets = {r.target for r in roes}
    assert "keep.com" in targets
    assert "draft.com" not in targets
    assert "revoked.com" not in targets
