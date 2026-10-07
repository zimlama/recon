"""Wayback Machine module — Tier 1 (passive).

Mines archive.org snapshots for removed/old content.

MITRE ATT&CK: T1593
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class WaybackMachineModule(BaseReconModule):
    """Web archive recon (Wayback Machine + gau + waybackurls)."""

    name = "wayback_machine"
    description = "Historical URL extraction from Wayback Machine, gau, waybackurls, CDX API"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1593"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 60
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query Wayback Machine for historical URLs.

        TODO(Day 2): Implement:
        - gau {target} (Get All URLs)
        - waybackurls {target}
        - CDX API: https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json
        - Filter for interesting paths (admin, login, api, dev, etc.)
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 2"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating Wayback Machine findings (historical URLs) for a target.

For each URL, classify as:
- CONFIRMED: URL was archived, content is still relevant
- LIKELY: URL exists in archive but content may be stale
- FALSE_POSITIVE: 404, parked, redirect, junk
- SUSPECTED: data quality uncertain

Enrich each with:
- interesting_paths: /admin, /api, /dev, /staging, /internal, /backup, /.git, /.env
- priority: HIGH (sensitive paths), MEDIUM (API endpoints), LOW (marketing/blog)
- reasoning: 1 sentence

Watch for:
- Forgotten admin panels
- Old API endpoints with weaker auth
- Backup files in URLs (.bak, .sql, .tar.gz)
- Development URLs that leaked to production
- Removed-but-still-referenced pages

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["WaybackMachineModule"]
