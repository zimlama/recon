"""Tests for BaseReconModule ABC contract."""

from __future__ import annotations

import pytest

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, ModuleInput, ModuleOutput
from app.modules.whois_rdap import WhoisRDAPModule


class ConcreteTestModule(BaseReconModule):
    name = "concrete_test"
    description = "A test module"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.002"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 5

    async def run(self, input: ModuleInput) -> ModuleOutput:
        return ModuleOutput(
            module=self.name,
            findings=[Finding(type="ip_address", value="1.2.3.4", source="test")],
        )

    def get_ai_prompt(self) -> str:
        return "Test prompt"


class _AbstractAttempt(BaseReconModule):
    """Intentionally missing run() and get_ai_prompt() to test ABC."""
    name = "abstract"
    description = "Should not be instantiable"


def test_abstract_cannot_instantiate() -> None:
    """BaseReconModule cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseReconModule()  # type: ignore[abstract]


def test_abstract_subclass_cannot_instantiate() -> None:
    """Subclass missing abstract methods cannot be instantiated."""
    with pytest.raises(TypeError):
        _AbstractAttempt()


def test_concrete_module_instantiable() -> None:
    """Subclass with all methods can be instantiated."""
    m = ConcreteTestModule()
    assert m.name == "concrete_test"
    assert m.tier == ModuleTier.TIER_1


def test_module_without_name_raises() -> None:
    """Modules must set `name` class attribute."""

    class NamelessModule(BaseReconModule):
        description = "no name"
        tier = ModuleTier.TIER_1

        async def run(self, input: ModuleInput) -> ModuleOutput:
            return ModuleOutput(module="x")

        def get_ai_prompt(self) -> str:
            return "x"

    with pytest.raises(ValueError, match="must set `name`"):
        NamelessModule()


def test_module_without_description_raises() -> None:
    """Modules must set `description` class attribute."""

    class DescriptionlessModule(BaseReconModule):
        name = "x"
        tier = ModuleTier.TIER_1

        async def run(self, input: ModuleInput) -> ModuleOutput:
            return ModuleOutput(module="x")

        def get_ai_prompt(self) -> str:
            return "x"

    with pytest.raises(ValueError, match="must set `description`"):
        DescriptionlessModule()


def test_whois_rdap_module_is_concrete() -> None:
    """WhoisRDAPModule is properly implemented."""
    m = WhoisRDAPModule()
    assert m.name == "whois_rdap"
    assert m.tier == ModuleTier.TIER_1
    assert "T1596.002" in m.mitre_techniques
    assert m.enabled_by_default is True


def test_target_format_validation() -> None:
    """target validation strips and lowercases."""
    m = WhoisRDAPModule()
    assert m.validate_target_format("EXAMPLE.COM") == "example.com"
    with pytest.raises(ValueError):
        m.validate_target_format("")


def test_module_repr() -> None:
    """Module __repr__ is informative."""
    m = WhoisRDAPModule()
    r = repr(m)
    assert "WhoisRDAPModule" in r
    assert "whois_rdap" in r
    assert "tier_1" in r
