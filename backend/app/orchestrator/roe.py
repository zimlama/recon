"""Rules-of-Engagement validator.

Real authorization gate for recon jobs. The validator answers one question:

    "Is there an ACTIVE RoE, inside its validity window, with at least one
     un-revoked SignOff, that authorises this target+scope?"

The middleware (see `app.middleware.roe`) and the orchestrator's job-launch
path BOTH call this before doing recon activity. There is exactly one
implementation of the rule — keep the logic in one place so the API gate
and the in-process gate cannot drift apart.

Design choices:

- The matching predicate is intentionally simple: case-insensitive exact
  match on `(scope_type, scope_value OR target)`. We do NOT try to evaluate
  CIDR blocks or wildcards here — those belong in a future scope-resolver
  module (PR 2+). For PR 1 we want a correct, auditable, easy-to-reason
  about rule.

- "Active" means BOTH `status == ACTIVE` AND `valid_from <= at <= valid_until`.
  Either alone is not enough: a DRAFT RoE must never authorize even if its
  window covers now, and an ACTIVE RoE whose window has passed must also
  not authorize (the operator may not yet have flipped the status to
  EXPIRED).

- Revoked signoffs are filtered out of the returned list. Auditors still see
  them via the SignOff table — we don't delete.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import RoE, RoEStatus, ScopeType, SignOff, _now


class RoEValidator:
    """Validates that a recon request is covered by an active RoE.

    Args:
        session_factory: Zero-arg callable returning a SQLAlchemy `Session`.
            We accept a factory rather than a session directly so the same
            validator can be reused across requests (the middleware needs
            this — it cannot share a session across concurrent async tasks).
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_authorized(
        self,
        target: str,
        scope_type: ScopeType,
        at: datetime | None = None,
    ) -> tuple[bool, str, list[SignOff]]:
        """Check whether `target` is covered by an active RoE for `scope_type`.

        Returns:
            (authorized, reason, signoffs):
              - authorized: True iff a matching active RoE with at least
                one un-revoked SignOff exists.
              - reason: Human-readable explanation; empty string when
                authorized; otherwise a short phrase suitable for an HTTP
                403 detail (e.g. "RoE is in draft; not active").
              - signoffs: List of un-revoked SignOff objects attached to
                the matching RoE (empty when not authorized).
        """
        when = at if at is not None else _now()
        target_norm = target.strip().lower()

        session = self._session_factory()
        try:
            roe = self._find_candidate(session, target_norm, scope_type)
            if roe is None:
                return False, "no RoE matches target+scope", []

            if roe.status != RoEStatus.ACTIVE:
                return (
                    False,
                    f"RoE status is {roe.status.value}; not active",
                    [],
                )

            if not roe.is_acceptable(at=when):
                if when < roe.valid_from:
                    return (
                        False,
                        "RoE is not yet valid (valid_from is in the future)",
                        [],
                    )
                return (
                    False,
                    "RoE has expired (valid_until is in the past)",
                    [],
                )

            active_signoffs = [s for s in roe.sign_offs if s.revoked_at is None]
            if not active_signoffs:
                return (
                    False,
                    "RoE has no active (un-revoked) sign-offs",
                    [],
                )

            return True, "", active_signoffs
        finally:
            session.close()

    def get_active_roes(
        self,
        target: str | None = None,
        scope_type: ScopeType | None = None,
    ) -> list[RoE]:
        """List RoEs that are ACTIVE AND inside their validity window.

        Optional filters narrow the result set without dropping valid RoEs.
        A returned RoE is guaranteed to satisfy:
            - status == RoEStatus.ACTIVE
            - valid_from <= now <= valid_until

        SignOffs are not loaded — call `is_authorized` (or fetch the RoE
        directly) when you need them. This keeps list endpoints cheap.
        """
        session = self._session_factory()
        try:
            when = _now()
            stmt = select(RoE).where(RoE.status == RoEStatus.ACTIVE)
            if target is not None:
                stmt = stmt.where(RoE.target == target.strip().lower())
            if scope_type is not None:
                stmt = stmt.where(RoE.scope_type == scope_type)
            roes: list[RoE] = list(session.execute(stmt).scalars().all())
            return [r for r in roes if r.is_acceptable(at=when)]
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _find_candidate(
        self,
        session: Session,
        target_norm: str,
        scope_type: ScopeType,
    ) -> RoE | None:
        """Return the most-specific candidate RoE for (target, scope_type).

        We match on `scope_type` AND either `target` or `scope_value`
        (case-insensitive exact match). When several RoEs match we keep
        the most recently created — the operator's latest intent is the
        safest assumption. We eager-load sign_offs so the caller doesn't
        trigger an extra query per RoE.
        """
        stmt = (
            select(RoE)
            .where(RoE.scope_type == scope_type)
            .where(
                (RoE.target == target_norm) | (RoE.scope_value == target_norm)
            )
            .order_by(RoE.created_at.desc())
            .options(selectinload(RoE.sign_offs))
        )
        result: RoE | None = session.execute(stmt).scalars().first()
        return result


__all__ = ["RoEValidator"]
