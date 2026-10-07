"""Metadata analysis module — Tier 2 (passive).

Extracts EXIF, author, software versions from public documents (PDF, DOCX, XLSX, images).

MITRE ATT&CK: T1593
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class MetadataAnalysisModule(BaseReconModule):
    """Document/image metadata extraction."""

    name = "metadata_analysis"
    description = "EXIF, document metadata (author, software, paths, GPS) from public files"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593"]
    requires_api_keys: list[str] = []
    estimated_duration_seconds = 30
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Extract metadata from public documents.

        TODO(Day 3): Implement:
        - Discover public PDFs/DOCX/XLSX/images via the target's web presence
        - Download each (or use Wayback URLs)
        - Run exiftool on each
        - Extract: author, software, paths, GPS (if image)
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 3"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating document metadata findings for a target organization.

For each metadata field (author, software, path, GPS), classify as:
- CONFIRMED: real, current, useful for the engagement
- LIKELY: real but possibly stale
- FALSE_POSITIVE: anonymized, fake, or unrelated
- SUSPECTED: data quality uncertain

Enrich each with:
- value_type: username, hostname, software_version, internal_path, gps_coords
- priority: HIGH (active usernames, current software versions), MEDIUM (paths), LOW (stale)
- reasoning: 1 sentence

Watch for:
- Internal usernames (username reuse → password spray targets)
- Software versions (CVE matching)
- Internal paths (network topology hints)
- GPS coordinates (physical location)
- Printer names (network recon)

PII HANDLING: GPS coordinates are sensitive. Only note country/region unless
explicitly authorized to geolocate.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["MetadataAnalysisModule"]
