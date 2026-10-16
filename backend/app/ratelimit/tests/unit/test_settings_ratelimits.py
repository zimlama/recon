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
    assert dict(s.RATE_LIMITS) == expected, (
        f"Expected the 7 spec defaults, got {s.RATE_LIMITS!r}"
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
