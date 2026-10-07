"""Certificate Transparency module — Tier 1 (passive).

Queries public CT logs for certificates issued to the target. Fully passive
(no contact with target infrastructure).

MITRE ATT&CK: T1596.003
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class CertificateTransparencyModule(BaseReconModule):
    """Certificate Transparency log query."""

    name = "certificate_transparency"
    description = "Certificate Transparency log mining (crt.sh, Censys cert search)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1596.003"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 30
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query CT logs for certificates.

        TODO(Day 2): Implement:
        - crt.sh API: https://crt.sh/?q={target}&output=json
        - Extract SAN (Subject Alternative Names) → list of subdomains
        - Note issuance dates, CAs, validity periods
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating Certificate Transparency findings for a target domain.

For each certificate (CN, SAN, issuer, validity period), classify as:
- CONFIRMED: cert is currently valid, CA is trusted
- LIKELY: cert is valid but CA is unusual
- FALSE_POSITIVE: cert is expired, revoked, or for unrelated domain
- SUSPECTED: data quality uncertain

Enrich each with:
- subdomain_priority: HIGH (newly issued admin/vpn/dev), MEDIUM (production), LOW (test/staging)
- risk_signals: e.g., self-signed, expired recently, unusual CA
- reasoning: 1 sentence

Watch for:
- Internal hostnames in SANs (leaked internal naming)
- Typosquatted look-alikes
- Recently expired certs (might be replaced)
- Free CAs (Let's Encrypt) vs paid (more legitimate)

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["CertificateTransparencyModule"]
