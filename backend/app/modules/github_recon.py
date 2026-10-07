"""GitHub recon module — Tier 2 (free tier, semi-passive).

Mines public GitHub for leaked secrets, internal hostnames, credentials.

MITRE ATT&CK: T1593.003, T1552.001
"""

from __future__ import annotations

from app.models import ModuleTier
from app.modules.base import BaseReconModule, ModuleInput, ModuleOutput


class GitHubReconModule(BaseReconModule):
    """GitHub OSINT — leaked secrets, internal hostnames, commit metadata."""

    name = "github_recon"
    description = "GitHub OSINT: orgs, users, gists, commit history, leaked secrets"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_2
    mitre_techniques = ["T1593.003", "T1552.001"]
    requires_api_keys: list[str] = []  # GITHUB_TOKEN optional (raises rate limit)
    estimated_duration_seconds = 60
    enabled_by_default = False  # Tier 2 — opt-in

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Query GitHub for leaked info.

        TODO(Day 3): Implement:
        - GitHub Code Search API: https://api.github.com/search/code?q={target}
        - GitHub Commits API: org:target commits
        - gitleaks on discovered repos
        - GitHub Dorks: GHDB GitHub-specific queries
        """
        return ModuleOutput(
            module=self.name,
            findings=[],
            duration_seconds=0.0,
            errors=["Not implemented — scheduled for Day 3"],
        )

    def get_ai_prompt(self) -> str:
        return """You are validating GitHub recon findings for a target organization.

For each finding (secret, hostname, email, file), classify as:
- CONFIRMED: real, in a current public repo
- LIKELY: real but in a fork/archive
- FALSE_POSITIVE: example, test, or unrelated repo
- SUSPECTED: data quality uncertain

Enrich each with:
- severity: CRITICAL (active API key, credentials), HIGH (internal hostname, JWT secret), MEDIUM (email), LOW (file path)
- exploitation_risk: HIGH if creds are live, LOW if deleted
- reasoning: 1 sentence

Watch for:
- Hardcoded API keys (AWS, Stripe, Slack, etc.)
- Internal IP addresses / hostnames in code
- .env files committed
- SSH private keys
- Database connection strings with creds
- Tokens that are still active vs revoked

SECRET HANDLING: NEVER transmit, log, or share actual secrets. Truncate to
first 4 + last 4 chars. Flag the secret TYPE only.

Output JSON: {"verdicts": [...], "summary": "...", "recommended_action": "...", "recommended_next_module_chain": [...]}"""


__all__ = ["GitHubReconModule"]
