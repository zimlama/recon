"""Handoff packet schema — vendor-neutral public contract for Phase 2 consumers.

This is the canonical JSON document that a future `zimlama/recon-phase2`
(or any other scanning tool) consumes to start active enumeration.

Schema versioning: semver. Breaking changes require a major version bump.
Additive changes (new optional fields) are backwards-compatible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Current schema version
SCHEMA_VERSION = "1.0.0"


# ---- Sub-models ----

class HandoffSource(BaseModel):
    """Identifies the producer of the handoff."""

    model_config = ConfigDict(extra="forbid")

    repo: Literal["zimlama/recon"] = "zimlama/recon"
    version: str = Field(..., description="Semantic version of the producer, e.g. '0.1.0'")
    job_id: str
    phase: Literal["01-recon-osint"] = "01-recon-osint"
    completed_at: datetime


class HandoffTarget(BaseModel):
    """The target of the original recon."""

    model_config = ConfigDict(extra="forbid")

    primary_domain: str
    authorization_scope: str = Field(
        ..., description="Human-readable scope (e.g., 'domain *.example.com')"
    )
    active_scan_authorized: bool = False  # Must be re-confirmed for Phase 2


class HandoffShodanExposure(BaseModel):
    """Shodan InternetDB / Censys data for a single host."""

    model_config = ConfigDict(extra="forbid")

    open_ports: list[int] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    cves_observed: list[str] = Field(default_factory=list)


class HandoffConfirmedTarget(BaseModel):
    """A target (subdomain or IP) confirmed by AI validation."""

    model_config = ConfigDict(extra="forbid")

    subdomain: str
    ips: list[str] = Field(default_factory=list)
    asn: str | None = None
    country: str | None = None
    tech_stack_hint: dict[str, str] = Field(default_factory=dict)
    shodan_exposure: HandoffShodanExposure | None = None
    priority_for_next_phase: Literal["HIGH", "MEDIUM", "LOW"]
    ai_reasoning: str
    ai_verdict: Literal["CONFIRMED", "LIKELY", "SUSPECTED"]
    ai_confidence: float = Field(..., ge=0.0, le=1.0)


class HandoffTechStack(BaseModel):
    """Summary of detected tech stack."""

    model_config = ConfigDict(extra="forbid")

    web_servers: dict[str, list[str]] = Field(default_factory=dict)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    databases: dict[str, list[str]] = Field(default_factory=dict)
    cloud_providers: dict[str, list[str]] = Field(default_factory=dict)


class HandoffCredentialsExposure(BaseModel):
    """Summary of credential exposure (PII-handled)."""

    model_config = ConfigDict(extra="forbid")

    emails_found: int = 0
    breach_count: int = 0
    # Note: never include actual emails or credentials in the handoff


class HandoffRecommendedModule(BaseModel):
    """A module recommended for Phase 2 (or next iteration)."""

    model_config = ConfigDict(extra="forbid")

    module: str
    priority: Literal["HIGH", "MEDIUM", "LOW"]
    rationale: str


class HandoffCertificate(BaseModel):
    """A certificate observed in CT logs."""

    model_config = ConfigDict(extra="forbid")

    cn: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    san: list[str] = Field(default_factory=list)


class HandoffConsentFlags(BaseModel):
    """Track which modules ran and what consent was given."""

    model_config = ConfigDict(extra="forbid")

    tier_3_modules_run: list[str] = Field(default_factory=list)
    white_hat_only: bool = True


# ---- Top-level packet ----

class HandoffPacket(BaseModel):
    """The complete handoff packet (public contract).

    Versioned via `schema_version` (semver). Consumers MUST validate this
    schema version before consuming.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Semantic version of the handoff schema",
    )
    schema_url: str = Field(
        default="https://github.com/zimlama/recon/blob/main/docs/HANDOFF.md",
        description="URL to the schema documentation",
    )

    source: HandoffSource
    target: HandoffTarget
    confirmed_targets: list[HandoffConfirmedTarget] = Field(default_factory=list)
    tech_stack_summary: HandoffTechStack = Field(default_factory=HandoffTechStack)
    credentials_exposure_summary: HandoffCredentialsExposure = Field(
        default_factory=HandoffCredentialsExposure
    )
    certificates: list[HandoffCertificate] = Field(default_factory=list)
    recommended_modules: list[HandoffRecommendedModule] = Field(default_factory=list)

    do_not_scan: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "0.0.0.0/8",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "::1/128",
            "fc00::/7",
        ]
    )

    consent_flags: HandoffConsentFlags = Field(default_factory=HandoffConsentFlags)


__all__ = [
    "SCHEMA_VERSION",
    "HandoffPacket",
    "HandoffSource",
    "HandoffTarget",
    "HandoffShodanExposure",
    "HandoffConfirmedTarget",
    "HandoffTechStack",
    "HandoffCredentialsExposure",
    "HandoffRecommendedModule",
    "HandoffCertificate",
    "HandoffConsentFlags",
]
