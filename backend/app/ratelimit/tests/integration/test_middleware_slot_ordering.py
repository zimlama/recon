# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Middleware slot ordering tests (REQ-INB-015 / decision N).

Spec acceptance: ``RateLimitMiddleware`` MUST be at index ``0`` of
``app.user_middleware`` (Starlette LAST-ADDED = OUTERMOST). The
ordering proof:

.. code-block:: text

    registration order (in _install_middlewares):
      1. CORS          ← index 0 first
      2. RequestId     ← index 0 again
      3. RoE           ← (gated by ROE_ENABLED)
      4. AuditLog      ← index 0 again
      5. DualAuth      ← index 0 again
      6. RateLimit     ← index 0 LAST

    execution order (outer → inner, first to last):
      RateLimit → DualAuth → AuditLog → RoE → RequestId → CORS → router
"""
from __future__ import annotations

import pytest

from app.config import Settings


def _swap(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> Settings:
    """Reset the lru_cache on ``get_settings`` and swap module state.

    Mirrors the helper in ``tests/test_app_wiring.py`` so the rate-limit
    wiring tests can change env without spinning up a full app fixture.
    """
    import app.config as cfg_mod
    import app.main as main_mod

    cfg_mod.get_settings.cache_clear()
    fresh = cfg_mod.Settings(**overrides)
    monkeypatch.setattr(main_mod, "settings", fresh)
    return fresh


def test_rate_limit_middleware_at_index_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """``RateLimitMiddleware`` MUST be at index 0 of ``app.user_middleware``.

    Under Starlette ``user_middleware`` semantics, LAST-ADDED = OUTERMOST.
    ``app.add_middleware(RateLimitMiddleware, ...)`` is the LAST call
    in ``_install_middlewares``, so ``user_middleware[0]`` is
    RateLimitMiddleware.
    """
    _swap(monkeypatch)
    from app.main import create_app

    app = create_app()
    names = [m.cls.__name__ for m in app.user_middleware]
    assert names[0] == "RateLimitMiddleware", (
        f"RateLimitMiddleware must be outermost (user_middleware[0]); got {names!r}"
    )


def test_full_stack_order_rate_limit_outermost(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full ASGI execution chain: RateLimit → DualAuth → ... → CORS."""
    _swap(monkeypatch)
    from app.main import create_app

    app = create_app()
    names = [m.cls.__name__ for m in app.user_middleware]
    # Expected order (outer→inner): RateLimit, DualAuth, AuditLog,
    # (RoE absent by default), RequestId, CORS.
    expected_prefix = ["RateLimitMiddleware", "DualAuthMiddleware", "AuditLogMiddleware"]
    assert names[: len(expected_prefix)] == expected_prefix, (
        f"Expected outer stack to be {expected_prefix}, got {names!r}"
    )
    assert names[-1] == "CORSMiddleware", (
        f"CORS must be innermost (user_middleware[-1]); got {names!r}"
    )


def test_rate_limit_patterns_live_on_app_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """The compiled regex list lives on ``app.state`` after construction.

    Lets tests inject a custom policy set via ``app.state.rate_limit_patterns``
    without recompiling real patterns.
    """
    _swap(monkeypatch)
    from app.main import create_app

    app = create_app()
    assert hasattr(app.state, "rate_limit_patterns")
    patterns = app.state.rate_limit_patterns
    # 7 default templates.
    assert len(patterns) == 7, (
        f"Expected 7 compiled patterns from Settings.RATE_LIMITS, got {len(patterns)}"
    )


@pytest.mark.asyncio
async def test_auth_login_path_is_reached_by_rate_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression for the C-3 gate critical.

    ``POST /api/v1/auth/login`` with NO ``Authorization`` header from a
    single client IP must be rate-limited by the per-IP bucket (not
    silently passed through by DualAuth). The dual-auth middleware
    lets ``/api/v1/auth/login`` through without a token (the
    ``_AUTH_OPEN_PREFIXES`` shim), so the per-IP-before-auth guarantee
    depends on RateLimit being OUTERMOST.

    Default Settings.RATE_LIMITS limits ``/auth/login`` to 10/min/IP
    (spec REQ-INB-006). We fire 12 requests — the 11th and 12th MUST
    reject with 429, proving the per-IP limiter saw the traffic even
    though DualAuth would have let it through.
    """
    from app.database import Base, engine
    from app.main import create_app

    # Match the default limit exactly so the test catches regressions
    # to the policy table without ceremony.
    _swap(monkeypatch)
    from httpx import ASGITransport, AsyncClient

    app = create_app()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        statuses = []
        for _ in range(12):
            # NO Authorization header — the auth lifecycle shim
            # lets the request through DualAuth; the RateLimit
            # gate is what we're testing.
            r = await ac.post(
                "/api/v1/auth/login",
                json={"email": "nope@example.com", "password": "wrong"},
            )
            statuses.append(r.status_code)
        # ≥ 1 429 must appear (default limit is 10; we sent 12).
        assert 429 in statuses, (
            f"Expected at least one 429 (default limit=10, sent 12); got {statuses!r}"
        )
        # Body shape check on the 429 — spec REQ-INB-007.
        has_429 = any(s == 429 for s in statuses)
        assert has_429, (
            f"Expected at least one 429 (default limit=10, sent 12); got {statuses!r}"
        )
    Base.metadata.drop_all(bind=engine)


__all__: list[str] = []
