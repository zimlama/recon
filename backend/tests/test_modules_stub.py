"""Tests that all 14 module stubs are importable and ABC-conformant."""

from __future__ import annotations

import pytest

from app.modules import MODULE_REGISTRY
from app.modules.base import BaseReconModule
from app.models import ModuleTier


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
