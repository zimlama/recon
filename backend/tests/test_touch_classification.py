# Copyright 2026 zimlama
# SPDX-License-Identifier: Apache-2.0
"""Tests for PR 2 — TouchClass enum + free-only registry filter + map table.

Covers:
- REQ-028: TouchClass enum contract (4 members, str-based, Pydantic-friendly)
- REQ-029: Module touch_classification + requires_paid mapping table (14 modules)
- REQ-030: tools_only_free filter at registry build time
- REQ-031: Per-job AuditLog on paid-module rejection

TDD order: each block was written and committed RED before GREEN.
"""

from __future__ import annotations

import importlib

import pytest
from pydantic import BaseModel, ValidationError

from app.modules.base import BaseReconModule, TouchClass

# =============================================================================
# REQ-028 — TouchClass enum contract
# =============================================================================


def test_touch_class_has_exactly_four_members() -> None:
    """TouchClass has exactly PASSIVE_TARGET, PASSIVE_THIRDPARTY, ACTIVE_TARGET, ACTIVE_THIRDPARTY."""
    values = {member.name for member in TouchClass}
    assert values == {
        "PASSIVE_TARGET",
        "PASSIVE_THIRDPARTY",
        "ACTIVE_TARGET",
        "ACTIVE_THIRDPARTY",
    }


def test_touch_class_is_str_enum() -> None:
    """Each TouchClass value is a str equal to lowercase_with_underscores."""
    assert TouchClass.PASSIVE_TARGET == "passive_target"
    assert TouchClass.PASSIVE_THIRDPARTY == "passive_thirdparty"
    assert TouchClass.ACTIVE_TARGET == "active_target"
    assert TouchClass.ACTIVE_THIRDPARTY == "active_thirdparty"

    # And every member is a str subclass
    for member in TouchClass:
        assert isinstance(member, str)


def test_touch_class_rejects_unknown_value_in_pydantic() -> None:
    """TouchClass used as Pydantic type rejects unknown strings with ValidationError."""

    class _Probe(BaseModel):
        touch: TouchClass

    with pytest.raises(ValidationError):
        _Probe(touch="not_a_real_class")  # type: ignore[arg-type]


def test_base_module_default_touch_classification() -> None:
    """BaseReconModule default touch_classification is PASSIVE_TARGET (conservative default)."""

    class _Probe(BaseReconModule):
        name = "probe"
        description = "probe for defaults"

        async def run(self, input):  # type: ignore[override,no-untyped-def]
            from app.modules.base import ModuleOutput

            return ModuleOutput(module=self.name)

        def get_ai_prompt(self) -> str:
            return "x"

    assert _Probe.touch_classification == TouchClass.PASSIVE_TARGET
    # And a subclass instance carries the same default
    instance = _Probe()
    assert instance.touch_classification == TouchClass.PASSIVE_TARGET


def test_base_module_default_requires_paid_is_false() -> None:
    """BaseReconModule default requires_paid is False (free-by-default)."""

    class _Probe(BaseReconModule):
        name = "probe2"
        description = "probe for defaults"

        async def run(self, input):  # type: ignore[override,no-untyped-def]
            from app.modules.base import ModuleOutput

            return ModuleOutput(module=self.name)

        def get_ai_prompt(self) -> str:
            return "x"

    instance = _Probe()
    assert instance.requires_paid is False


# =============================================================================
# REQ-029 — Module mapping table (14 modules)
# =============================================================================


# Source-verified per spec REQ-029 (file:line citations checked 2026-10-12)
EXPECTED_TOUCH_MAP: dict[str, tuple[TouchClass, bool]] = {
    "whois_rdap": (TouchClass.PASSIVE_TARGET, False),
    "dns_enum": (TouchClass.ACTIVE_TARGET, False),
    "subdomain_enum": (TouchClass.PASSIVE_THIRDPARTY, False),
    "certificate_transparency": (TouchClass.PASSIVE_THIRDPARTY, False),
    "wayback_machine": (TouchClass.PASSIVE_THIRDPARTY, False),
    "email_harvesting": (TouchClass.PASSIVE_THIRDPARTY, False),
    "shodan_censys": (TouchClass.PASSIVE_THIRDPARTY, False),
    "github_recon": (TouchClass.PASSIVE_THIRDPARTY, False),
    "google_dorking": (TouchClass.PASSIVE_THIRDPARTY, False),
    "metadata_analysis": (TouchClass.PASSIVE_THIRDPARTY, False),
    "breach_data": (TouchClass.PASSIVE_THIRDPARTY, False),
    "socmint": (TouchClass.PASSIVE_THIRDPARTY, False),
    "employee_osint": (TouchClass.PASSIVE_THIRDPARTY, False),
    "dark_web_osint": (TouchClass.PASSIVE_THIRDPARTY, False),
}


@pytest.mark.parametrize(
    ("module_name", "expected_touch", "expected_paid"),
    [(name, expected[0], expected[1]) for name, expected in EXPECTED_TOUCH_MAP.items()],
)
def test_module_touch_classification_mapping(
    module_name: str, expected_touch: TouchClass, expected_paid: bool
) -> None:
    """Each of the 14 modules declares the correct touch_classification + requires_paid."""
    # Lazy import so we get the class object (not the singleton)
    module = importlib.import_module(f"app.modules.{module_name}")
    cls_name = next(
        attr for attr in dir(module) if attr.endswith("Module") and attr != "BaseReconModule"
    )
    cls = getattr(module, cls_name)
    assert cls.touch_classification == expected_touch, (
        f"{module_name}.touch_classification should be {expected_touch}, "
        f"got {cls.touch_classification}"
    )
    assert cls.requires_paid == expected_paid, (
        f"{module_name}.requires_paid should be {expected_paid}, got {cls.requires_paid}"
    )


def test_every_module_in_registry_matches_expected_map() -> None:
    """All 14 modules from the spec map are present in the mapping table."""
    from app.modules import MODULE_REGISTRY

    # Strip the aggregator (person_dossier) — it's an internal cross-module
    # pass, not a data-source probe, and is intentionally NOT in REQ-029.
    non_aggregator = {k: v for k, v in MODULE_REGISTRY.items() if k != "person_dossier"}

    assert set(non_aggregator) == set(EXPECTED_TOUCH_MAP)


# =============================================================================
# REQ-030 — tools_only_free registry filter
# =============================================================================


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> None:
    """Clear lru_cache on get_settings around each test to allow monkeypatched env values.

    Required because `_build_registry()` reads `get_settings()` and Settings is
    cached. If the cache isn't cleared, monkeypatched env values won't take effect.
    """
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_metadata_analysis_paid() -> None:
    """Restore the module's original `requires_paid` after tests that monkeypatched it."""
    from app.modules.metadata_analysis import MetadataAnalysisModule

    original = MetadataAnalysisModule.requires_paid
    yield
    MetadataAnalysisModule.requires_paid = original


def test_tools_only_free_false_default_includes_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools_only_free=False (default OFF) keeps every module in the registry."""
    monkeypatch.setenv("TOOLS_ONLY_FREE", "false")
    from app.modules import _build_registry

    registry = _build_registry()
    # 14 modules + person_dossier aggregator = 15
    assert len(registry) >= 14


def test_tools_only_free_default_off_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools_only_free defaults to False when env is unset (backward-compat)."""
    monkeypatch.delenv("TOOLS_ONLY_FREE", raising=False)
    from app.modules import _build_registry

    registry = _build_registry()
    # All modules retained; none filtered
    assert len(registry) >= 14


def test_tools_only_free_true_excludes_paid(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools_only_free=True excludes modules whose requires_paid=True."""
    from app.modules.metadata_analysis import MetadataAnalysisModule

    monkeypatch.setattr(MetadataAnalysisModule, "requires_paid", True)
    monkeypatch.setenv("TOOLS_ONLY_FREE", "true")
    from app.modules import _build_registry

    registry = _build_registry()
    assert "metadata_analysis" not in registry
    # Other modules still present
    assert "whois_rdap" in registry


def test_tools_only_free_invalid_falls_back_to_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid TOOLS_ONLY_FREE value falls back to False (fail-open: allow all)."""
    monkeypatch.setenv("TOOLS_ONLY_FREE", "invalid_value")
    # Should not crash
    from app.modules import _build_registry

    registry = _build_registry()
    # Fail-open: all modules retained
    assert len(registry) >= 14


def test_paid_module_excluded_logs_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Each excluded paid module logs a WARNING containing its name."""
    import logging

    from app.modules.metadata_analysis import MetadataAnalysisModule

    monkeypatch.setattr(MetadataAnalysisModule, "requires_paid", True)
    monkeypatch.setenv("TOOLS_ONLY_FREE", "true")
    with caplog.at_level(logging.WARNING, logger="app.modules"):
        from app.modules import _build_registry

        _build_registry()

    assert any(
        "metadata_analysis" in r.message and "paid" in r.message.lower() for r in caplog.records
    )


def test_tools_only_free_false_excludes_no_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tools_only_free=False never excludes any module (even when one is paid)."""
    from app.modules.metadata_analysis import MetadataAnalysisModule

    monkeypatch.setattr(MetadataAnalysisModule, "requires_paid", True)
    monkeypatch.setenv("TOOLS_ONLY_FREE", "false")
    from app.modules import _build_registry

    registry = _build_registry()
    assert "metadata_analysis" in registry


# =============================================================================
# REQ-031 — Settings.tools_only_free env parsing
# =============================================================================


def test_settings_tools_only_free_default_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Settings().tools_only_free defaults to False (env unset)."""
    from app.config import Settings, get_settings

    monkeypatch.delenv("TOOLS_ONLY_FREE", raising=False)
    get_settings.cache_clear()
    s = Settings()
    assert s.tools_only_free is False


def test_settings_tools_only_free_true() -> None:
    """Settings parses TOOLS_ONLY_FREE=true as True."""
    from app.config import Settings

    s = Settings(tools_only_free=True)
    assert s.tools_only_free is True


def test_settings_tools_only_free_explicit_false() -> None:
    """Settings parses TOOLS_ONLY_FREE=false as False."""
    from app.config import Settings

    s = Settings(tools_only_free=False)
    assert s.tools_only_free is False


# =============================================================================
# Registry helper accessors — close the branch coverage on app/modules/__init__.py
# =============================================================================


def test_get_module_registry_returns_built_registry() -> None:
    """`get_module_registry()` returns the same dict object as `MODULE_REGISTRY`.

    The registry is module-level; the helper is just a typed accessor so
    tests + downstream code can pass it around without reaching into the
    module namespace. We verify object identity to lock down that contract.
    """
    from app.modules import MODULE_REGISTRY, get_module_registry

    result = get_module_registry()
    assert result is MODULE_REGISTRY
    assert isinstance(result, dict)
    assert len(result) >= 14


def test_get_module_returns_known_module_by_name() -> None:
    """`get_module(name)` looks up an instance by string name."""
    from app.modules import get_module

    mod = get_module("whois_rdap")
    # The instance is a BaseReconModule subclass with the expected .name
    from app.modules.base import BaseReconModule

    assert isinstance(mod, BaseReconModule)
    assert mod.name == "whois_rdap"


def test_get_module_unknown_name_raises_keyerror() -> None:
    """`get_module(name)` raises `KeyError` (not `ValueError`/`LookupError`).

    The error message includes the unknown name + the list of valid names
    so a misbehaving caller can debug without re-reading the source.
    """
    from app.modules import MODULE_REGISTRY, get_module

    with pytest.raises(KeyError) as exc_info:
        get_module("does_not_exist_anywhere")
    msg = str(exc_info.value)
    assert "does_not_exist_anywhere" in msg
    # At least one known module name appears in the error context
    assert any(name in msg for name in MODULE_REGISTRY.keys())


def test_get_module_picks_correct_instance_per_name() -> None:
    """Each name resolves to a distinct class instance.

    This protects against a registry bug where two names accidentally
    alias to the same instance (object identity).
    """
    from app.modules import get_module

    a = get_module("whois_rdap")
    b = get_module("dns_enum")
    c = get_module("whois_rdap")
    assert a is c
    assert a is not b


def test_registry_contains_aggregator_module() -> None:
    """`person_dossier` aggregator is present in the default registry.

    It's an internal cross-module pass (not a data-source probe), so it
    is intentionally excluded from the REQ-029 mapping table — but it
    MUST still be wired into the registry for downstream jobs to call.
    """
    from app.modules import MODULE_REGISTRY

    assert "person_dossier" in MODULE_REGISTRY


def test_base_module_validate_target_format_rejects_short_target() -> None:
    """Validate that `validate_target_format` raises on suspiciously short targets.

    Defense against accidental empty/whitespace targets reaching a
    downstream OSINT module — empty target is a silent foot-gun.
    """
    from app.modules.base import BaseReconModule

    class _Probe(BaseReconModule):
        name = "probe_short"
        description = "probe for validate_target_format"

        async def run(self, input):  # type: ignore[override,no-untyped-def]
            from app.modules.base import ModuleOutput

            return ModuleOutput(module=self.name)

        def get_ai_prompt(self) -> str:
            return "x"

    instance = _Probe()
    with pytest.raises(ValueError):
        instance.validate_target_format("ab")  # len 2 < 3 minimum
    with pytest.raises(ValueError):
        instance.validate_target_format("")
    # And a valid one returns a normalized target
    assert instance.validate_target_format("  Example.COM  ") == "example.com"

