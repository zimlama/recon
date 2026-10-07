"""Tests that all 14 module stubs are importable and ABC-conformant."""

from __future__ import annotations

import pytest

from app.modules import MODULE_REGISTRY
from app.modules.base import BaseReconModule
from app.models import ModuleTier

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


def test_all_14_modules_registered() -> None:
    """Exactly 14 modules in the registry."""
    assert len(MODULE_REGISTRY) == 14


def test_all_modules_have_required_metadata() -> None:
    """Every module has name, description, phase, tier, mitre_techniques."""
    for name, module in MODULE_REGISTRY.items():
        assert module.name, f"{name} has no name"
        assert module.description, f"{name} has no description"
        assert module.phase, f"{name} has no phase"
        assert isinstance(module.tier, ModuleTier), f"{name} tier is not ModuleTier"
        assert isinstance(module.mitre_techniques, list), f"{name} mitre_techniques is not a list"
        assert len(module.mitre_techniques) > 0, f"{name} has no MITRE techniques"


def test_tier1_modules() -> None:
    """Exactly 6 Tier 1 modules."""
    tier1 = [m for m in MODULE_REGISTRY.values() if m.tier == ModuleTier.TIER_1]
    assert len(tier1) == 6
    names = {m.name for m in tier1}
    assert names == {
        "whois_rdap",
        "dns_enum",
        "subdomain_enum",
        "certificate_transparency",
        "wayback_machine",
        "email_harvesting",
    }


def test_tier2_modules() -> None:
    """Exactly 4 Tier 2 modules."""
    tier2 = [m for m in MODULE_REGISTRY.values() if m.tier == ModuleTier.TIER_2]
    assert len(tier2) == 4
    names = {m.name for m in tier2}
    assert names == {
        "shodan_censys",
        "github_recon",
        "metadata_analysis",
        "google_dorking",
    }


def test_tier3_modules_require_consent() -> None:
    """All Tier 3 modules require explicit consent."""
    tier3 = [m for m in MODULE_REGISTRY.values() if m.tier == ModuleTier.TIER_3]
    assert len(tier3) == 4
    for m in tier3:
        assert m.requires_consent is True, f"{m.name} (Tier 3) must require consent"


def test_tier3_modules() -> None:
    """Exactly 4 Tier 3 modules."""
    tier3 = [m for m in MODULE_REGISTRY.values() if m.tier == ModuleTier.TIER_3]
    names = {m.name for m in tier3}
    assert names == {
        "breach_data",
        "socmint",
        "employee_osint",
        "dark_web_osint",
    }


def test_all_modules_are_basereconmodule_subclasses() -> None:
    """Every registered module extends BaseReconModule."""
    for module in MODULE_REGISTRY.values():
        assert isinstance(module, BaseReconModule)


def test_get_module_works() -> None:
    """get_module() returns the correct module."""
    from app.modules import get_module
    m = get_module("subdomain_enum")
    assert m.name == "subdomain_enum"


def test_get_module_unknown_raises() -> None:
    """get_module() raises KeyError for unknown modules."""
    from app.modules import get_module
    with pytest.raises(KeyError):
        get_module("nonexistent")


# ---- run() stub tests ----

@pytest.mark.asyncio
async def test_all_modules_run_returns_module_output() -> None:
    """Every module's run() returns a ModuleOutput (even if it's a stub)."""
    from app.modules.base import ModuleInput
    from app.modules.base import ModuleOutput
    for name, module in MODULE_REGISTRY.items():
        result = await module.run(ModuleInput(target="example.com"))
        assert isinstance(result, ModuleOutput), f"{name} run() did not return ModuleOutput"
        assert result.module == name, f"{name} returned wrong module name in output"


@pytest.mark.asyncio
async def test_stub_modules_have_not_implemented_error() -> None:
    """Stub modules (Day 1 placeholders) report 'Not implemented' in errors."""
    from app.modules.base import ModuleInput
    # Modules that are still stubs (not yet implemented beyond Day 1)
    stubs_at_day2 = {
        "breach_data",
        "socmint",
        "employee_osint",
        "dark_web_osint",
        "shodan_censys",
        "github_recon",
        "metadata_analysis",
        "google_dorking",
        "email_harvesting",
        "wayback_machine",
        "certificate_transparency",
    }
    for name in stubs_at_day2:
        if name in MODULE_REGISTRY:
            module = MODULE_REGISTRY[name]
            result = await module.run(ModuleInput(target="example.com"))
            # Stub returns either a placeholder error or empty findings + errors
            assert len(result.findings) == 0, f"{name} stub produced findings"
            assert len(result.errors) >= 1, f"{name} stub should report at least one error"
            assert "Not implemented" in result.errors[0], f"{name} stub error should say 'Not implemented'"


def test_all_modules_have_non_empty_ai_prompts() -> None:
    """Every module has a non-empty AI prompt (used for validation)."""
    for name, module in MODULE_REGISTRY.items():
        prompt = module.get_ai_prompt()
        assert isinstance(prompt, str), f"{name} prompt is not a string"
        assert len(prompt) > 50, f"{name} prompt is too short ({len(prompt)} chars)"
        # Prompt should mention verdict categories
        assert "CONFIRMED" in prompt, f"{name} prompt missing CONFIRMED"
        assert "FALSE_POSITIVE" in prompt, f"{name} prompt missing FALSE_POSITIVE"


def test_tier1_modules_have_all_passive_metadata() -> None:
    """Tier 1 modules: no API keys (except optional), always-on, mostly no consent."""
    # email_harvesting DOES require consent (PII handling)
    pure_tier1_no_consent = {"whois_rdap", "dns_enum", "subdomain_enum",
                              "certificate_transparency", "wayback_machine"}
    for name in pure_tier1_no_consent:
        m = MODULE_REGISTRY[name]
        assert m.requires_api_keys == [], f"{name} should not require API keys"
        assert m.requires_consent is False, f"{name} should not require consent"
        assert m.enabled_by_default is True, f"{name} should be enabled by default"

    # email_harvesting is Tier 1 but requires consent (PII)
    email_mod = MODULE_REGISTRY["email_harvesting"]
    assert email_mod.requires_consent is True, "email_harvesting requires consent (PII)"


def test_tier3_modules_all_require_consent() -> None:
    """All Tier 3 modules require explicit consent."""
    tier3_names = {"breach_data", "socmint", "employee_osint", "dark_web_osint"}
    for name in tier3_names:
        m = MODULE_REGISTRY[name]
        assert m.requires_consent is True, f"{name} (Tier 3) must require consent"
