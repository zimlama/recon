"""DNS enumeration module — Tier 1 (passive).

Queries A, AAAA, NS, MX, TXT, CNAME, SOA, SRV records. Attempts AXFR.

MITRE ATT&CK: T1590.002, T1596.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class DNSEnumModule(BaseReconModule):
    """DNS record enumeration."""

    name = "dns_enum"
    description = "DNS record enumeration (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV, AXFR)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1590.002", "T1596.001"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 15
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run DNS enumeration against the target.

        TODO(Day 2): Implement using `dig` via subprocess or `dnspython` library.
        Example: `dig {target} ANY +noall +answer`
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating DNS records for a target domain.

For each record (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV), classify as:
- CONFIRMED: record resolves, IP/domain is reachable
- LIKELY: record exists but resolution uncertain
- FALSE_POSITIVE: stale record, sinkholed IP, misconfigured
- SUSPECTED: data quality uncertain

Prioritize findings by:
- HIGH: TXT records with SPF/DKIM/DMARC (email security), MX pointing to suspicious providers
- MEDIUM: NS diversity, SOA serial, A/AAAA records
- LOW: SRV records (often boilerplate)

Watch for: misconfigured SPF (allows +all), no DMARC, NS pointing to compromised nameservers.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["DNSEnumModule"]
