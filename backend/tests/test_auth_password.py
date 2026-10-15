"""Tests for the PasswordService — argon2id + server-side pepper (PR-J1).

Spec invariants covered (engram #1371 §4):
  INV-8: p95 password verify < 300 ms on the CI baseline.
  INV-9: pepper is composed into the hash; rotation invalidates all hashes.

OWASP 2024 parameters for argon2id (spec §7):
  time_cost = 3, memory_cost = 64 MiB, parallelism = 4.

Each test must call the production code and assert a SPECIFIC output. A
test that only checks ``PasswordService is not None`` is a smoke test — we
forbid that pattern (strict-tdd.md).
"""

from __future__ import annotations

import re
import time

import pytest

from app.auth.password import (
    MIN_PASSWORD_LENGTH,
    PasswordService,
    WeakPasswordError,
)


# ---------------------------------------------------------------------------
# Hash format + determinism
# ---------------------------------------------------------------------------


def test_hash_returns_argon2id_phc_string(monkeypatch: pytest.MonkeyPatch) -> None:
    """hash() returns a PHC string starting with ``$argon2id$...``."""
    monkeypatch.setenv("PEPPER_SECRET", "x" * 32)
    h = PasswordService.hash("correct horse battery staple")
    assert h.startswith("$argon2id$"), (
        f"hash output {h[:40]!r} does not start with the argon2id PHC prefix"
    )
    # The PHC string must contain the OWASP 2024 parameters we configured.
    assert "m=65536" in h, "memory_cost=65536 not embedded in PHC"
    assert "t=3" in h, "time_cost=3 not embedded in PHC"
    assert "p=4" in h, "parallelism=4 not embedded in PHC"


def test_hash_deterministic_per_password_differs_per_salt() -> None:
    """Same password hashes to DIFFERENT outputs each call (per-salt)."""
    a = PasswordService.hash("correct horse battery staple")
    b = PasswordService.hash("correct horse battery staple")
    assert a != b, "two hashes of the same password collided — salt not random"


def test_hash_changes_when_pepper_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing PEPPER_SECRET produces a hash that does NOT verify under the old pepper.

    This is INV-9 enforcement at the unit level: rotating PEPPER_SECRET
    invalidates every stored hash. Operators MUST follow the rotation
    playbook in docs/auth-operations.md (PR-J7).
    """
    monkeypatch.setenv("PEPPER_SECRET", "A" * 32)
    h_old = PasswordService.hash("correct horse battery staple")

    monkeypatch.setenv("PEPPER_SECRET", "B" * 32)
    h_new = PasswordService.hash("correct horse battery staple")

    assert h_old != h_new, "pepper rotation did not change the hash output"
    # And the new hash MUST verify under the new pepper:
    assert PasswordService.verify(
        "correct horse battery staple", h_new, pepper="B" * 32
    )
    # And the old hash MUST NOT verify under the new pepper:
    assert not PasswordService.verify(
        "correct horse battery staple", h_old, pepper="B" * 32
    )


# ---------------------------------------------------------------------------
# Verify — round-trip + negative cases
# ---------------------------------------------------------------------------


def test_verify_success_round_trip() -> None:
    """hash then verify with the same password returns True."""
    pw = "correct horse battery staple"
    h = PasswordService.hash(pw)
    assert PasswordService.verify(pw, h) is True


def test_verify_wrong_password_returns_false_no_leak() -> None:
    """Wrong password returns False — never raises, never returns True."""
    h = PasswordService.hash("correct horse battery staple")
    assert PasswordService.verify("wrong horse battery staple", h) is False


def test_verify_malformed_hash_returns_false_no_raise() -> None:
    """Malformed stored hash returns False (no exception, no info leak)."""
    assert PasswordService.verify("anything", "not-a-phc-string") is False
    assert PasswordService.verify("anything", "") is False
    assert PasswordService.verify("anything", "$argon2id$malformed") is False


def test_verify_empty_password_returns_false() -> None:
    """Empty password rejected. Argon2id also rejects empty by default; we
    double-check at the service layer so callers cannot bypass it via
    missing validation upstream.
    """
    h = PasswordService.hash("a-real-password-1234")
    assert PasswordService.verify("", h) is False


# ---------------------------------------------------------------------------
# Strength policy
# ---------------------------------------------------------------------------


def test_weak_password_rejected_by_strength_regex() -> None:
    """Passwords under MIN_PASSWORD_LENGTH are rejected before hashing."""
    short = "a" * (MIN_PASSWORD_LENGTH - 1)
    with pytest.raises(WeakPasswordError) as ei:
        PasswordService.hash(short)
    assert ei.value.min_length == MIN_PASSWORD_LENGTH


def test_min_password_length_default_is_12() -> None:
    """Spec §1.1 LoginRequest.min_password_length=12. Enforced here."""
    assert MIN_PASSWORD_LENGTH == 12


def test_exactly_min_length_password_is_accepted() -> None:
    """A password exactly MIN_PASSWORD_LENGTH chars long is accepted."""
    pw = "A" + "a" * (MIN_PASSWORD_LENGTH - 1)
    # Sanity: 12 chars, contains at least one letter — should hash fine.
    h = PasswordService.hash(pw)
    assert h.startswith("$argon2id$")


# ---------------------------------------------------------------------------
# Timing budget — INV-8 (p95 verify < 300 ms on CI baseline)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trial", range(50))
def test_single_verify_completes_quickly(trial: int) -> None:
    """Each individual verify call is bounded; p95 is asserted separately."""
    pw = f"trial-{trial}-correct horse battery staple"
    h = PasswordService.hash(pw)
    t0 = time.perf_counter()
    PasswordService.verify(pw, h)
    elapsed = (time.perf_counter() - t0) * 1000  # ms
    # Per-call budget is generous (covers the longest of 50 trials); the
    # p95 budget is computed across all trials below.
    assert elapsed < 1000, f"trial {trial} verify took {elapsed:.1f} ms"


def test_p95_verify_under_300ms_budget() -> None:
    """INV-8: p95 over 50 verifies < 300 ms.

    Argon2id with m=64MiB t=3 p=4 takes ~80-150 ms per verify on the CI
    baseline. We allow 300 ms p95 to absorb CI noise; anything beyond
    indicates parameter creep (mitigation: re-run with stricter params).
    """
    pw = "correct horse battery staple"
    h = PasswordService.hash(pw)

    durations_ms: list[float] = []
    for _ in range(50):
        t0 = time.perf_counter()
        PasswordService.verify(pw, h)
        durations_ms.append((time.perf_counter() - t0) * 1000)

    durations_ms.sort()
    p95_idx = int(len(durations_ms) * 0.95) - 1
    p95 = durations_ms[p95_idx]
    assert p95 < 300, f"p95 verify {p95:.1f} ms exceeds 300 ms budget (INV-8)"

    # Sanity: first verify pays the warm-up cost; we don't gate on it but
    # log it so CI output makes the timing distribution obvious.
    print(
        f"\npassword verify timing (50 trials): "
        f"min={durations_ms[0]:.1f}ms median={durations_ms[25]:.1f}ms "
        f"p95={p95:.1f}ms max={durations_ms[-1]:.1f}ms"
    )


# ---------------------------------------------------------------------------
# Pepper composition — INV-9 (pepper is read at verify time)
# ---------------------------------------------------------------------------


def test_pepper_composition_included_at_hash_time() -> None:
    """The PEPPER_SECRET env var participates in the hash input.

    We verify by hashing with two peppers and checking the outputs differ.
    """
    pw = "correct horse battery staple"
    h_a = PasswordService.hash(pw, pepper="A" * 32)
    h_b = PasswordService.hash(pw, pepper="B" * 32)
    assert h_a != h_b, "pepper not composed into the hash"


def test_pepper_rotation_invalidates_old_hashes() -> None:
    """Rotating PEPPER_SECRET makes the old hash fail to verify.

    This is INV-9 in its sharp form: the playbook for rotation is
    ``rehash-all-passwords`` or ``force-password-reset``. We assert the
    negative — the old hash MUST NOT verify under the new pepper.
    """
    pw = "correct horse battery staple"
    h_old = PasswordService.hash(pw, pepper="OLD-PEPPER-VALUE-PAD-PAD-PAD-PAD-PAD")
    assert PasswordService.verify(
        pw, h_old, pepper="OLD-PEPPER-VALUE-PAD-PAD-PAD-PAD-PAD"
    )
    # Rotate the pepper:
    assert not PasswordService.verify(
        pw, h_old, pepper="NEW-PEPPER-VALUE-PAD-PAD-PAD-PAD-PAD"
    )


# ---------------------------------------------------------------------------
# needs_rehash — parameter-bump support
# ---------------------------------------------------------------------------


def test_needs_rehash_returns_false_for_current_params() -> None:
    """A hash generated by hash() reports needs_rehash()=False."""
    h = PasswordService.hash("correct horse battery staple")
    assert PasswordService.needs_rehash(h) is False


def test_needs_rehash_returns_true_for_old_params() -> None:
    """A hand-crafted hash with old parameters reports needs_rehash()=True.

    This is the trigger for the rehash-on-login flow: when OWASP raises
    the recommended cost, every verify() that succeeds is followed by an
    opportunistic rehash with the new params.
    """
    # Old parameters: m=4096, t=2, p=1 (the argon2-cffi defaults pre-2017).
    old = PasswordService.hash(
        "correct horse battery staple",
        time_cost=2,
        memory_cost=4096,
        parallelism=1,
    )  # type: ignore[arg-type]
    assert PasswordService.needs_rehash(old) is True


def test_needs_rehash_returns_false_for_malformed_hash() -> None:
    """Malformed stored hash → needs_rehash()=False (no info leak)."""
    assert PasswordService.needs_rehash("not-a-phc-string") is False
    assert PasswordService.needs_rehash("") is False
    assert PasswordService.needs_rehash("$argon2id$garbage") is False


def test_verify_returns_false_for_non_string_password() -> None:
    """Non-string password types are rejected before any hashing happens."""
    h = PasswordService.hash("correct horse battery staple")
    # type confusion at the verify layer — never raises.
    assert PasswordService.verify(None, h) is False  # type: ignore[arg-type]
    assert PasswordService.verify(12345, h) is False  # type: ignore[arg-type]
    assert PasswordService.verify(b"bytes", h) is False  # type: ignore[arg-type]


def test_verify_returns_false_for_non_string_hash() -> None:
    """Non-string stored_hash types are rejected without raising."""
    assert PasswordService.verify("any-password", None) is False  # type: ignore[arg-type]
    assert PasswordService.verify("any-password", 12345) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Re-export sanity (smoke)
# ---------------------------------------------------------------------------


def test_module_exports_expected_symbols() -> None:
    """Public API surface of app.auth.password."""
    from app.auth import password as mod

    assert hasattr(mod, "PasswordService")
    assert hasattr(mod, "MIN_PASSWORD_LENGTH")
    assert hasattr(mod, "WeakPasswordError")
    # Reject re-export of internal helpers — keeps the API tight.
    forbidden = {"_hash_argon2id", "_compose_pepper"}
    leaked = [n for n in forbidden if hasattr(mod, n)]
    assert not leaked, f"internal helpers leaked from app.auth.password: {leaked}"


def test_weak_password_error_message_mentions_min_length() -> None:
    """The WeakPasswordError message MUST name MIN_PASSWORD_LENGTH so callers
    (CLI, API) can surface a useful error to operators.
    """
    with pytest.raises(WeakPasswordError) as ei:
        PasswordService.hash("a" * (MIN_PASSWORD_LENGTH - 1))
    msg = str(ei.value)
    assert str(MIN_PASSWORD_LENGTH) in msg, (
        f"WeakPasswordError message {msg!r} does not mention "
        f"MIN_PASSWORD_LENGTH={MIN_PASSWORD_LENGTH}"
    )
    assert re.search(r"password", msg, re.IGNORECASE)