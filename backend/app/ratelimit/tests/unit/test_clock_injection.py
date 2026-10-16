# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Clock-injection tests (REQ-INB-014 / decision L).

The injector contract is small but load-bearing:

1. ``RateLimiter(clock=...)`` accepts an optional callable.
2. The default is ``time.monotonic`` (NOT ``time.time`` — wall clock
   jumps would break the sliding window).
3. All time comparisons inside ``is_allowed`` go through ``self._clock``.
4. No ``freezegun`` / ``time-machine`` dependency in ``pyproject.toml``.
"""
from __future__ import annotations

import time
import tomllib
from pathlib import Path

from app.ratelimit import RateLimiter


def test_clock_ctor_arg_is_optional_and_defaults_to_monotonic() -> None:
    """Without an explicit clock, ``RateLimiter`` defaults to ``time.monotonic``.

    Verified by comparing ``RateLimiter()._clock`` against the
    ``time.monotonic`` builtin — they MUST be the SAME reference so
    production behavior is exactly the wall monotonic, not a wrapper.
    """
    rl = RateLimiter()
    assert rl._clock is time.monotonic, (
        f"Default clock must be time.monotonic, got {rl._clock!r}"
    )


def test_injected_clock_drives_window_decisions() -> None:
    """``RateLimiter(clock=frozen)`` MUST use the injected clock.

    The whole point: the limiter cannot read ``time.monotonic`` if a
    clock was injected. Pass a lambda that returns a constant and
    prove the limiter honors it (no auto-advance).
    """
    _const = 1_000.0
    frozen = lambda: _const  # noqa: E731
    rl = RateLimiter(clock=frozen, policies={("ip", "/x"): (1, 60)})
    # First request at frozen=1000 fills the limit.
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    # A second request at the SAME frozen timestamp STILL rejects —
    # proves the clock didn't auto-advance.
    allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False, (
        "Frozen clock must NOT advance; same-timestamp request must reject"
    )


def test_clock_used_for_retry_after_calculation() -> None:
    """``retry_after_seconds`` is computed via the injected clock.

    Set up a frozen clock where the buckets contain t=0 entries and
    the clock returns t=30. Window is 60. Expected retry is
    ``max(1, ceil(0+60-30)) = 30``.
    """
    clock = [0.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (1, 60)},
    )
    assert rl.is_allowed("ip", "1.2.3.4", "/x")[0] is True
    clock[0] = 30.0
    allowed, retry = rl.is_allowed("ip", "1.2.3.4", "/x")
    assert allowed is False
    assert retry == 30, f"retry should be 30 (now=30, oldest=0, window=60), got {retry}"


def test_now_kwarg_overrides_clock() -> None:
    """The ``now`` kwarg on ``is_allowed`` lets tests bypass the clock.

    Useful for fine-grained sub-second boundary tests without a
    mutable clock wrapper.
    """
    clock = [100.0]
    rl = RateLimiter(
        clock=lambda: clock[0],
        policies={("ip", "/x"): (1, 60)},
    )
    assert rl.is_allowed("ip", "1.2.3.4", "/x", now=100.0)[0] is True
    # Pass ``now=200`` directly — well past the 60-second window so
    # the prior 100-stamp must be evicted regardless of the clock.
    allowed, _ = rl.is_allowed("ip", "1.2.3.4", "/x", now=200.0)
    assert allowed is True


def test_no_freezegun_or_time_machine_in_pyproject() -> None:
    """NFR-INB-003: ``pyproject.toml`` MUST NOT depend on time-mocking libs.

    Read the file at import time (tomllib in py3.11+) and assert
    neither ``freezegun`` nor ``time-machine`` appears in deps or
    optional deps.
    """
    pyproject = Path(__file__).resolve().parents[4] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    deps = data.get("project", {}).get("dependencies", [])
    dev = data.get("project", {}).get("optional-dependencies", {}).get("dev", [])
    for name in ("freezegun", "time-machine"):
        assert not any(name in d.lower() for d in deps + dev), (
            f"{name!r} found in pyproject.toml dependencies — spec NFR-INB-003"
        )


__all__: list[str] = []
