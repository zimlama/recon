# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Adversarial harness (REQ-INB-012 — the rate-limit acceptance test).

Spec acceptance REQ-INB-012:

> The system SHALL ship a pytest integration test
> (``@pytest.mark.integration``) that boots a FastAPI app via
> ``TestClient`` with default ``Settings.RATE_LIMITS``, hammers
> ``POST /api/v1/auth/login`` with **100 distinct fake credentials**
> (``distinct_credentials=True``) from **1 simulated client IP**,
> asserts at least one response in the burst has status ``429``,
> the total elapsed wall-clock time is **< 60 seconds**, and every
> ``429`` carries a ``Retry-After`` header with integer ≥ 1.

This test must run in the CI ``integration`` job and is excluded from
the coverage gate.
"""
from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import Base, engine


@pytest.mark.integration
@pytest.mark.asyncio
async def test_adversarial_100_login_attempts_emits_429(monkeypatch: pytest.MonkeyPatch) -> None:
    """``POST /api/v1/auth/login`` 100 times -> at least 1 x 429 in < 60 s."""
    # Swap settings to the project defaults — no test-side mutation.
    import app.config as cfg_mod
    import app.main as main_mod

    cfg_mod.get_settings.cache_clear()
    main_mod.settings = cfg_mod.Settings()
    from app.main import create_app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app = create_app()
    transport = ASGITransport(app=app)

    start = time.monotonic()
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        statuses: list[int] = []
        retry_afters: list[int] = []
        for i in range(100):
            r = await ac.post(
                "/api/v1/auth/login",
                json={"email": f"victim_{i}@example.com", "password": "wrongcreds"},
            )
            statuses.append(r.status_code)
            if r.status_code == 429:
                retry_afters.append(int(r.headers.get("Retry-After", "0")))
    elapsed = time.monotonic() - start
    Base.metadata.drop_all(bind=engine)

    # 1. At least one 429 in the burst.
    assert 429 in statuses, (
        f"Expected at least 1 429 across 100 attempts; got {sorted(set(statuses))!r}"
    )
    # 2. Wall-clock budget < 60 s.
    assert elapsed < 60.0, f"Adversarial harness took {elapsed:.2f}s (budget 60 s)"
    # 3. Every 429 carries Retry-After ≥ 1.
    assert all(r >= 1 for r in retry_afters), (
        f"All 429 Retry-After values must be ≥ 1; got {retry_afters!r}"
    )


__all__: list[str] = []
