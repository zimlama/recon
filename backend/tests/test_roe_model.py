"""Tests for RoE (Rules of Engagement) and SignOff ORM models.

Covers PR 1 of v0.1.1 plan: persistent RoE storage with sign-off support.

Models live in `app.models`:
  - `RoEStatus` / `ScopeType` enums
  - `RoE` — engagement envelope (target, scope, validity window, status)
  - `SignOff` — human authorization record; cascades with its RoE
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import RoE, RoEStatus, ScopeType, SignOff, _now


# ---------------------------------------------------------------------------
# Fixtures — reuse the global engine + session so FK PRAGMA (set up in
# `app.database`) is in force. The drop/recreate here is scoped to the RoE
# + SignOff tables only, so we don't disturb tables owned by other tests.
# ---------------------------------------------------------------------------


@pytest.fixture
def roe_db():
    """Per-test sync session with ONLY the RoE + SignOff tables created.

    Reuses the global engine from `app.database`, which has
    `PRAGMA foreign_keys=ON` wired up via an event listener. Without that
    PRAGMA SQLite would silently ignore our `ON DELETE CASCADE` clause and
    the cascade-delete test would fail.
    """
    from app.database import SessionLocal, engine

    RoE.__table__.drop(bind=engine, checkfirst=True)
    SignOff.__table__.drop(bind=engine, checkfirst=True)
    RoE.__table__.create(bind=engine, checkfirst=True)
    SignOff.__table__.create(bind=engine, checkfirst=True)

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        SignOff.__table__.drop(bind=engine, checkfirst=True)
        RoE.__table__.drop(bind=engine, checkfirst=True)


def _make_roe(**overrides) -> RoE:
    """Helper: build an RoE with sensible defaults for the test's window."""
    now = _now()
    defaults = {
        "target": "example.com",
        "scope_type": ScopeType.DOMAIN,
        "scope_value": "example.com",
        "authorized_by": "alice@example.com",
        "valid_from": now - timedelta(hours=1),
        "valid_until": now + timedelta(hours=24),
    }
    defaults.update(overrides)
    return RoE(**defaults)


# ---------------------------------------------------------------------------
# Default status
# ---------------------------------------------------------------------------


def test_roe_defaults_to_draft_status(roe_db) -> None:
    """A newly constructed RoE has status=DRAFT until explicitly activated.

    DRAFT is the safe default — only an operator who has reviewed the scope
    and recorded sign-offs should flip it to ACTIVE. See also
    `RoEValidator.is_authorized`, which rejects anything that is not ACTIVE.
    """
    roe = _make_roe()
    roe_db.add(roe)
    roe_db.commit()
    roe_db.refresh(roe)
    assert roe.status == RoEStatus.DRAFT


# ---------------------------------------------------------------------------
# Date window — `is_acceptable`
# ---------------------------------------------------------------------------


def test_roe_with_valid_dates_is_acceptable(roe_db) -> None:
    """An RoE whose window covers `at` returns True from `is_acceptable`.

    We test against the same instant we used to construct the window so the
    test is deterministic regardless of wall-clock drift during execution.
    """
    at = datetime(2026, 6, 1, 12, 0, 0)
    roe = _make_roe(
        valid_from=at - timedelta(hours=1),
        valid_until=at + timedelta(hours=1),
    )
    assert roe.is_acceptable(at=at) is True


def test_roe_with_expired_dates_is_not_acceptable(roe_db) -> None:
    """An RoE whose `valid_until` is in the past is NOT acceptable.

    `valid_until` is the authoritative expiry — once it has passed, the
    engagement is closed regardless of `status`. We verify the predicate at
    a point strictly after `valid_until`.
    """
    at = datetime(2026, 6, 2, 12, 0, 0)
    roe = _make_roe(
        valid_from=at - timedelta(days=2),
        valid_until=at - timedelta(hours=1),  # window ended before `at`
    )
    assert roe.is_acceptable(at=at) is False


# ---------------------------------------------------------------------------
# SignOff — revoke + cascade
# ---------------------------------------------------------------------------


def test_signoff_can_be_revoked(roe_db) -> None:
    """Setting `revoked_at` on a SignOff records the revocation timestamp.

    We do not delete the row because audit history matters — revocation is
    the canonical "we authorized this, then changed our minds" event.
    """
    roe = _make_roe()
    roe_db.add(roe)
    roe_db.commit()
    roe_db.refresh(roe)

    signoff = SignOff(
        roe_id=roe.id,
        signer_name="Alice",
        signer_email="alice@example.com",
        signer_role="CISO",
    )
    roe_db.add(signoff)
    roe_db.commit()
    roe_db.refresh(signoff)

    assert signoff.revoked_at is None

    signoff.revoked_at = _now()
    roe_db.commit()
    roe_db.refresh(signoff)
    assert signoff.revoked_at is not None


def test_signoff_cascade_deletes_with_roe(roe_db) -> None:
    """Deleting an RoE removes its SignOffs via FK ON DELETE CASCADE.

    Without cascade, stale signoffs would dangle — and the validator would
    keep counting them as authorizations, defeating the whole point of the
    revocation mechanism.
    """
    roe = _make_roe()
    roe_db.add(roe)
    roe_db.commit()
    roe_db.refresh(roe)

    signoff = SignOff(
        roe_id=roe.id,
        signer_name="Bob",
        signer_email="bob@example.com",
        signer_role="CEO",
    )
    roe_db.add(signoff)
    roe_db.commit()
    signoff_id = signoff.id

    # Confirm signoff exists before delete.
    assert roe_db.get(SignOff, signoff_id) is not None

    # Delete the parent — cascade should remove the child too.
    roe_db.delete(roe)
    roe_db.commit()
    roe_db.expire_all()  # clear identity-map cache so .get hits the DB

    assert roe_db.get(SignOff, signoff_id) is None