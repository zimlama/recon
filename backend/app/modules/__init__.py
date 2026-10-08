"""Recon module registry + loader.

Single source of truth for which modules are available. Adding a new module:
1. Create `app/modules/<name>.py` extending BaseReconModule
2. Import it here
3. Add to __all__ and MODULE_REGISTRY
"""

from __future__ import annotations

from app.modules.base import BaseReconModule
from app.modules.breach_data import BreachDataModule
from app.modules.certificate_transparency import CertificateTransparencyModule
from app.modules.dark_web_osint import DarkWebOSINTModule
from app.modules.dns_enum import DNSEnumModule
from app.modules.email_harvesting import EmailHarvestingModule
from app.modules.employee_osint import EmployeeOSINTModule
from app.modules.github_recon import GitHubReconModule
from app.modules.google_dorking import GoogleDorkingModule
from app.modules.metadata_analysis import MetadataAnalysisModule
from app.modules.person_dossier import PersonDossierModule
from app.modules.shodan_censys import ShodanCensysModule
from app.modules.socmint import SOCMINTModule
from app.modules.subdomain_enum import SubdomainEnumModule
from app.modules.wayback_machine import WaybackMachineModule
from app.modules.whois_rdap import WhoisRDAPModule

__all__ = [
    "BaseReconModule",
    "MODULE_REGISTRY",
    "get_module_registry",
    "get_module",
]


def _build_registry() -> dict[str, BaseReconModule]:
    """Build the module registry. Lazy — called once at startup."""
    return {
        # Tier 1 — always-on, fully passive
        "whois_rdap": WhoisRDAPModule(),
        "dns_enum": DNSEnumModule(),
        "subdomain_enum": SubdomainEnumModule(),
        "certificate_transparency": CertificateTransparencyModule(),
        "wayback_machine": WaybackMachineModule(),
        "email_harvesting": EmailHarvestingModule(),
        # Tier 2 — free-tier APIs
        "shodan_censys": ShodanCensysModule(),
        "github_recon": GitHubReconModule(),
        "metadata_analysis": MetadataAnalysisModule(),
        "google_dorking": GoogleDorkingModule(),
        # Tier 3 — white-hat gated
        "breach_data": BreachDataModule(),
        "socmint": SOCMINTModule(),
        "employee_osint": EmployeeOSINTModule(),
        "dark_web_osint": DarkWebOSINTModule(),
        # PR 4 — Tier 3 aggregator (cross-module, depends on the others)
        "person_dossier": PersonDossierModule(),
    }


MODULE_REGISTRY: dict[str, BaseReconModule] = _build_registry()


def get_module_registry() -> dict[str, BaseReconModule]:
    """Return the module registry (read-only)."""
    return MODULE_REGISTRY


def get_module(name: str) -> BaseReconModule:
    """Look up a module by name. Raises KeyError if not found."""
    if name not in MODULE_REGISTRY:
        raise KeyError(f"Unknown module: {name}. Available: {list(MODULE_REGISTRY)}")
    return MODULE_REGISTRY[name]
