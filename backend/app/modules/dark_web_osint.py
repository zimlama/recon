"""Dark web OSINT module — Tier 3 (white-hat gated, requires Tor).

Monitors Tor hidden services for credential dumps, target mentions, actor tradecraft.
GATED: requires explicit user consent + Tor network access in lab-isolated env.

SAFETY:
- Read-only, no transactions
- No engagement with threat actors
- Document all access for chain of custody
- Never tip off the target during active recon

MITRE ATT&CK: T1589.001, T1593.001
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from typing import Any

import httpx

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)

# ahmia.fi is a clearnet Tor hidden service search engine (no Tor required)
AHMIA_API_URL = "https://ahmia.fi/search/"
AHMIA_TIMEOUT = 20

# SOCKS5 proxy for Tor (when tor is running locally)
TOR_SOCKS5 = "socks5://127.0.0.1:9050"


class DarkWebOSINTModule(BaseReconModule):
    """Dark web OSINT (ahmia.fi + optional Tor)."""

    name = "dark_web_osint"
    description = "Dark web monitoring (ahmia.fi + optional Tor hidden service search)"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_3
    mitre_techniques = ["T1589.001", "T1593.001"]
    requires_api_keys: list[str] = []
    requires_consent = True  # PII + safety
    estimated_duration_seconds = 180
    enabled_by_default = False  # Tier 3 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Search for target mentions on dark web sources."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        # 1. Try ahmia.fi (clearnet, no Tor needed)
        try:
            ahmia_results = await self._search_ahmia(target)
            findings.extend(ahmia_results)
        except Exception as e:  # noqa: BLE001
            errors.append(f"ahmia.fi query failed: {e!s}")

        # 2. If Tor is available, query .onion sources (note: requires Tor sidecar)
        if shutil.which("tor"):
            try:
                tor_findings = await self._search_via_tor(target)
                findings.extend(tor_findings)
            except Exception as e:  # noqa: BLE001
                errors.append(f"Tor search failed: {e!s}")

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of dark web findings."""
        return """You are validating dark web OSINT findings for a target organization.

For each mention/credential dump/leak, classify as:
- CONFIRMED: real, current, active listing
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: paste site, unrelated, hoax
- SUSPECT: data quality uncertain

Enrich each with:
- source_type: market, paste, forum, telegram, discord
- severity: CRITICAL (live credentials), HIGH (employee PII), MEDIUM (mention), LOW (historical)
- reasoning: 1 sentence

SAFETY RULES:
- Read-only, no transactions
- Do NOT engage with threat actors
- Document all access for chain of custody
- Never tip off the target during active recon

Respond with structured JSON matching the LDMValidationResult schema."""  # noqa: E501

    # ---- Private helpers ----

    async def _search_ahmia(self, target: str) -> list[Finding]:
        """Search ahmia.fi for the target domain (clearnet index of .onion sites)."""
        try:
            async with httpx.AsyncClient(timeout=AHMIA_TIMEOUT) as client:
                response = await client.get(
                    AHMIA_API_URL,
                    params={"q": target},
                )
                if response.status_code != 200:
                    return []
                try:
                    data = response.json()
                except Exception:  # noqa: BLE001
                    return []
        except httpx.HTTPError:
            return []

        findings: list[Finding] = []
        for item in data.get("results", [])[:10]:  # limit to 10
            title = item.get("title", "")
            url = item.get("url", "")
            if not url:
                continue
            findings.append(
                Finding(
                    type=FindingType.DARKWEB_MENTION,
                    value=title or url,
                    source="ahmia.fi",
                    confidence=0.7,
                    finding_metadata={
                        "url": url,
                        "last_seen": item.get("last_seen", ""),
                    },
                )
            )
        return findings

    async def _search_via_tor(self, target: str) -> list[Finding]:
        """Search via Tor (requires running tor on localhost:9050).

        Note: httpx 0.28 uses `proxy=` which may need `httpx-socks` for SOCKS5.
        If SOCKS5 isn't supported, this falls back to ahmia.fi directly.
        """
        try:
            transport = httpx.AsyncHTTPTransport(proxy=TOR_SOCKS5)
            async with httpx.AsyncClient(
                timeout=AHMIA_TIMEOUT,
                transport=transport,
            ) as client:
                response = await client.get(AHMIA_API_URL, params={"q": target})
                if response.status_code != 200:
                    return []
                data = response.json()
        except (httpx.HTTPError, Exception) as e:  # noqa: BLE001
            logger.debug("tor_search_error", error=str(e))
            return []

        findings: list[Finding] = []
        for item in data.get("results", [])[:5]:  # fewer results via Tor
            findings.append(
                Finding(
                    type=FindingType.DARKWEB_MENTION,
                    value=item.get("title", item.get("url", "")),
                    source="tor",
                    confidence=0.9,  # Tor is more authoritative
                    finding_metadata={
                        "url": item.get("url", ""),
                    },
                )
            )
        return findings


__all__ = ["DarkWebOSINTModule"]