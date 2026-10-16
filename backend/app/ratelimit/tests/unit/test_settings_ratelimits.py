# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Strict-TDD tests for the PR-J3.6 settings fields.

Covers spec REQ-INB-006 (the 7-default ``RATE_LIMITS`` table) and
REQ-INB-010 (``ALLOW_DEV_BYPASS`` must force-disable in production;
``RATE_LIMIT_BYPASS_TOKEN`` required when bypass enabled).

Each test asserts ONE behavior. A pass means the corresponding impl
piece is correct end-to-end through the pydantic-settings machinery.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_seven_default_rate_limits_present() -> None:
    """Spec REQ-INB-006: 7 defaults, exact templates, exact tuples.

    RED before impl: missing fields. GREEN after the three settings
    fields land in ``Settings`` with the post-gate-corrected defaults.

    PR-J3.6.5 (Issue #60) extends this to 10 defaults — the three
    handoff entries live in a sibling test
    (``test_handoff_endpoints_added_to_rate_limits``) so the diff to
    this assertion stays minimal and traceable.
    """
    s = Settings()
    expected = {
        "/api/v1/auth/login": (10, 60),
        "/api/v1/auth/refresh": (60, 60),
        "/api/v1/jobs": (10, 60),
        "/api/v1/jobs/{job_id}/cancel": (30, 60),
        "/api/v1/ai/jobs/{job_id}/validate": (10, 60),
        "/api/v1/ai/jobs/{job_id}/modules/{module_name}/validate": (10, 60),
        "/api/v1/jobs/{job_id}/report": (5, 60),
    }
    # PR-J3.6.5 (Issue #60): the handoff endpoints are added by a
    # separate test below; assert the 7 PR-J3.6 defaults here and the
    # 3 handoff additions in the sibling test. ``>=`` keeps this test
    # forward-compatible with future additions to the policy table.
    assert all(s.RATE_LIMITS.get(k) == v for k, v in expected.items()), (
        f"Expected the 7 spec defaults as-is, got {s.RATE_LIMITS!r}"
    )


def test_handoff_endpoints_added_to_rate_limits() -> None:
    """PR-J36.5 (Issue #60): 3 handoff endpoints with per-user caps.

    Threat-driven defaults (proposal §Threat model):
    - T1 (corpus exfiltration via paginate + walk): ``/api/v1/handoffs`` → (60, 60)
    - T2 (worker starvation via /handoff/download, ~MB JSON FileResponse):
      ``/api/v1/jobs/{job_id}/handoff/download`` → (10, 60) tightest cap
    - T3 (re-export amplification via missing file_path): bounded by the
      packet endpoint cap ``/api/v1/jobs/{job_id}/handoff`` → (120, 60)

    The middleware fans each entry out to ``("ip", endpoint)`` and
    ``("user", endpoint)`` keys via ``_scope_policies``; handoffs are
    auth-gated so the per-user limit is the binding constraint (per-IP
    is redundant on already-authenticated traffic).
    """
    s = Settings()
    handoff_entries = {
        "/api/v1/handoffs": (60, 60),
        "/api/v1/jobs/{job_id}/handoff": (120, 60),
        "/api/v1/jobs/{job_id}/handoff/download": (10, 60),
    }
    for template, expected_policy in handoff_entries.items():
        actual = s.RATE_LIMITS.get(template)
        assert actual == expected_policy, (
            f"handoff policy {template!r} expected {expected_policy!r}, "
            f"got {actual!r}; full table: {s.RATE_LIMITS!r}"
        )


def test_rate_limits_count_is_ten_after_handoff_additions() -> None:
    """PR-J3.6.5: PR-J3.6 had 7 entries; the 3 handoff additions bring it to 10.

    Pinned as a separate test so a future addition to the policy
    table is a deliberate move (the previous sibling test
    ``test_seven_default_rate_limits_present`` no longer asserts a
    hard count — see its updated docstring).
    """
    s = Settings()
    assert len(s.RATE_LIMITS) == 10, (
        f"Expected 10 entries (7 PR-J3.6 + 3 PR-J3.6.5 handoff), "
        f"got {len(s.RATE_LIMITS)}: {sorted(s.RATE_LIMITS)!r}"
    )


def test_allow_dev_bypass_defaults_to_false() -> None:
    """REQ-INB-010 baseline: bypass is OFF out of the box.

    Kept separate from the prod-disable test so a future change to
    the default is a deliberate move.
    """
    s = Settings()
    assert s.ALLOW_DEV_BYPASS is False


def test_allow_dev_bypass_force_disabled_in_production() -> None:
    """REQ-INB-010: ``APP_ENV='production'`` forces ``ALLOW_DEV_BYPASS=False``.

    Even when the operator sets ``ALLOW_DEV_BYPASS=True`` (env or kw),
    production sees the resolved value as ``False`` — same dev-only
    pattern the PR #56 B2 admin bypass fix used.

    The Settings class also requires strong secrets in production
    (PEPPER_SECRET, REFRESH_HASH_KEY, PERSON_DOSSIER_ENCRYPTION_KEY);
    satisfy those with 32-byte dummy strings so the validator under
    test (``ALLOW_DEV_BYPASS``) is the one we exercise.
    """
    s = Settings(
        APP_ENV="production",
        ALLOW_DEV_BYPASS=True,
        PEPPER_SECRET="p" * 64,
        REFRESH_HASH_KEY="r" * 64,
        PERSON_DOSSIER_ENCRYPTION_KEY="k" * 44,
    )
    assert s.ALLOW_DEV_BYPASS is False, (
        f"Production must force-disable bypass; got {s.ALLOW_DEV_BYPASS}"
    )


def test_allow_dev_bypass_honored_in_development() -> None:
    """REQ-INB-010: ``APP_ENV='development'`` honors ``ALLOW_DEV_BYPASS=True``.

    Counterweight to the prod test. A regression that always disables
    bypass would silently break the load-test escape hatch.
    """
    s = Settings(APP_ENV="development", ALLOW_DEV_BYPASS=True, RATE_LIMIT_BYPASS_TOKEN="secret")
    assert s.ALLOW_DEV_BYPASS is True


def test_negative_request_limit_rejected() -> None:
    """REQ-INB-006: malformed ``RATE_LIMITS`` (negative req) raises.

    Pydantic's ``ValidationError`` is the contract: the operator sees
    the misconfig at boot, not at request time.
    """
    with pytest.raises(ValidationError) as exc:
        Settings(RATE_LIMITS={"/x": (-1, 60)})
    assert "requests_limit" in str(exc.value), str(exc.value)


def test_non_int_request_limit_rejected() -> None:
    """REQ-INB-006: non-int ``RATE_LIMITS`` values raise.

    Catches ``settings.RATE_LIMITS={"/x": ("a", 60)}``-shaped config
    mistakes — a string slipped in via JSON env load.
    """
    with pytest.raises(ValidationError) as exc:
        Settings(RATE_LIMITS={"/x": ("a", 60)})
    assert "int" in str(exc.value).lower() or "value" in str(exc.value).lower()


def test_oversize_request_limit_rejected() -> None:
    """REQ-INB-006: ``requests_limit > 1_000_000`` is rejected.

    Hard upper bound on the policy table — a one-character typo (extra
    zero) should not silently quadruple the limit.
    """
    with pytest.raises(ValidationError) as exc:
        Settings(RATE_LIMITS={"/x": (1_000_001, 60)})
    assert "1_000_000" in str(exc.value)


def test_empty_token_rejected_when_bypass_enabled() -> None:
    """REQ-INB-010: ``ALLOW_DEV_BYPASS=True`` requires a non-empty token.

    Operator-visible misconfig: a bypass flag with no shared secret is
    as good as not running the middleware at all.
    """
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="development",
            ALLOW_DEV_BYPASS=True,
            RATE_LIMIT_BYPASS_TOKEN="",
        )
    assert "RATE_LIMIT_BYPASS_TOKEN" in str(exc.value)


def test_zero_window_rejected() -> None:
    """REQ-INB-006: ``window_seconds`` must be a positive int.

    A zero window would mean every request is over the limit at the
    first occurrence — operator-visible misconfig.
    """
    with pytest.raises(ValidationError) as exc:
        Settings(RATE_LIMITS={"/x": (10, 0)})
    assert "window_seconds" in str(exc.value)


def test_tuple_or_list_values_accepted() -> None:
    """JSON-driven env loads use lists, not tuples. Both MUST work."""
    s = Settings(RATE_LIMITS={"/x": [5, 30]})  # type: ignore[list-item]
    assert s.RATE_LIMITS["/x"] == (5, 30)


__all__: list[str] = []
