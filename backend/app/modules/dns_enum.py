"""DNS enumeration module — Tier 1 (passive + light active).

Queries A, AAAA, NS, MX, TXT, CNAME, SOA, SRV records via dnspython.
Attempts AXFR (zone transfer) — usually refused, but informative when successful.

MITRE ATT&CK: T1590.002, T1596.001
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.zone

import httpx

from app.models import ModuleTier
from app.modules.base import BaseReconModule, Finding, FindingType, ModuleInput, ModuleOutput

logger = logging.getLogger(__name__)


# Public DNS resolvers (fallback chain)
DEFAULT_RESOLVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
]

# Record types to query (label, dnspython rdatatype, FindingType)
RECORD_TYPES: list[tuple[str, int, FindingType]] = [
    ("A", dns.rdatatype.A, FindingType.IP_ADDRESS),
    ("AAAA", dns.rdatatype.AAAA, FindingType.IP_ADDRESS),
    ("NS", dns.rdatatype.NS, FindingType.OTHER),
    ("MX", dns.rdatatype.MX, FindingType.OTHER),
    ("TXT", dns.rdatatype.TXT, FindingType.OTHER),
    ("CNAME", dns.rdatatype.CNAME, FindingType.OTHER),
    ("SOA", dns.rdatatype.SOA, FindingType.OTHER),
    ("SRV", dns.rdatatype.SRV, FindingType.OTHER),
]

# Per-resolver timeout (seconds)
RESOLVER_TIMEOUT = 3
RESOLVER_LIFETIME = 8


class DNSEnumModule(BaseReconModule):
    """DNS record enumeration across multiple record types.

    Public DNS only. Does NOT perform active brute force (that's subdomain_enum).
    Tries multiple public resolvers for reliability.
    """

    name = "dns_enum"
    description = "DNS record enumeration (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV) + AXFR attempt"
    phase = "01-recon-osint"
    tier = ModuleTier.TIER_1
    mitre_techniques = ["T1590.002", "T1596.001"]
    requires_api_keys: list[str] = []
    requires_consent = False
    estimated_duration_seconds = 15
    enabled_by_default = True

    async def run(self, input: ModuleInput) -> ModuleOutput:
        """Run DNS enumeration against the target."""
        target = self.validate_target_format(input.target)
        findings: list[Finding] = []
        errors: list[str] = []
        start = time.time()

        resolver = self._build_resolver()

        # Query each record type
        for label, rdatatype, finding_type in RECORD_TYPES:
            try:
                records = await self._query_records(resolver, target, rdatatype)
                for value, metadata in records:
                    findings.append(
                        Finding(
                            type=finding_type,
                            value=value,
                            source=f"dns_{label.lower()}",
                            confidence=0.95,
                            finding_metadata=metadata,
                        )
                    )
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist — stop early
                errors.append(f"NXDOMAIN for {target}")
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                # If the resolver chain is dead or one query hangs, every
                # remaining record type will fail the same way — stop now
                # to avoid piling up work in the executor queue.
                errors.append(f"DNS query failed at {label}: {e!s}")
                break
            except Exception as e:  # noqa: BLE001
                errors.append(f"{label} query failed: {e!s}")

        # Attempt AXFR (zone transfer)
        try:
            axfr_findings = await self._attempt_axfr(resolver, target)
            findings.extend(axfr_findings)
        except Exception as e:  # noqa: BLE001
            errors.append(f"AXFR attempt failed: {e!s}")

        return ModuleOutput(
            module=self.name,
            findings=findings,
            duration_seconds=time.time() - start,
            errors=errors,
        )

    def get_ai_prompt(self) -> str:
        """System prompt for AI validation of DNS findings."""
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

Watch for:
- SPF that allows +all (email spoofing risk)
- Missing DMARC (no email authentication policy)
- NS pointing to known compromised nameservers
- Sinkholed IPs in A/AAAA records
- Unusually low or high TTL values

Respond with structured JSON matching the LDMValidationResult schema."""

    # ---- Private helpers ----

    def _build_resolver(self) -> dns.resolver.Resolver:
        """Build a dnspython resolver with public fallback chain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = DEFAULT_RESOLVERS
        resolver.timeout = RESOLVER_TIMEOUT
        resolver.lifetime = RESOLVER_LIFETIME
        return resolver

    async def _query_records(
        self,
        resolver: dns.resolver.Resolver,
        domain: str,
        rdatatype: int,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Query one record type. Returns list of (value, metadata) tuples.

        Runs the synchronous dnspython query in a thread executor to avoid
        blocking the event loop.
        """
        loop = asyncio.get_event_loop()

        def _do_query() -> list[tuple[str, dict[str, Any]]]:
            results: list[tuple[str, dict[str, Any]]] = []
            try:
                answers = resolver.resolve(domain, rdatatype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                raise  # propagate to caller
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                logger.debug(
                    "dns_query_terminated", rdatatype=rdatatype, error=str(e)
                )
                raise  # propagate so run() can break early

            for rdata in answers:
                metadata: dict[str, Any] = {}
                value = self._format_rdata(rdata, rdatatype, metadata)
                if value:
                    results.append((value, metadata))
            return results

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _do_query),
                timeout=RESOLVER_LIFETIME + 2,
            )
        except (TimeoutError, dns.exception.Timeout):
            raise

    def _format_rdata(
        self,
        rdata: dns.rdata.Rdata,
        rdatatype: int,
        metadata: dict[str, Any],
    ) -> str | None:
        """Format an rdata object as a string + extract metadata."""
        try:
            if rdatatype == dns.rdatatype.A:
                return str(rdata.address)
            if rdatatype == dns.rdatatype.AAAA:
                return str(rdata.address)
            if rdatatype == dns.rdatatype.NS:
                return str(rdata.target).rstrip(".")
            if rdatatype == dns.rdatatype.MX:
                metadata["preference"] = rdata.preference
                return f"{rdata.preference} {rdata.exchange}".strip()
            if rdatatype == dns.rdatatype.TXT:
                # Concatenate TXT strings (DKIM, SPF, DMARC, verification tokens)
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                # Capture well-known TXT record types for metadata
                txt_lower = txt.lower()
                if txt_lower.startswith("v=spf1"):
                    metadata["type"] = "spf"
                elif txt_lower.startswith("v=dkim1"):
                    metadata["type"] = "dkim"
                elif txt_lower.startswith("v=dmarc1"):
                    metadata["type"] = "dmarc"
                elif "-" in txt and len(txt) > 20:
                    metadata["type"] = "verification"
                return txt
            if rdatatype == dns.rdatatype.CNAME:
                return str(rdata.target).rstrip(".")
            if rdatatype == dns.rdatatype.SOA:
                metadata["mname"] = str(rdata.mname).rstrip(".")
                metadata["rname"] = str(rdata.rname).rstrip(".")
                metadata["serial"] = rdata.serial
                metadata["refresh"] = rdata.refresh
                metadata["retry"] = rdata.retry
                metadata["expire"] = rdata.expire
                metadata["minimum"] = rdata.minimum
                return str(rdata.mname).rstrip(".")
            if rdatatype == dns.rdatatype.SRV:
                metadata["port"] = rdata.port
                metadata["priority"] = rdata.priority
                metadata["weight"] = rdata.weight
                return f"{rdata.target}".rstrip(".")
            # Fallback
            return rdata.to_text()
        except Exception as e:  # noqa: BLE001
            logger.debug("rdata_format_error", error=str(e), rdatatype=rdatatype)
            return None

    async def _attempt_axfr(
        self,
        resolver: dns.resolver.Resolver,
        domain: str,
    ) -> list[Finding]:
        """Attempt a zone transfer (AXFR). Usually refused, but a successful
        AXFR is a significant finding.
        """
        findings: list[Finding] = []
        # Get the authoritative nameserver first
        try:
            loop = asyncio.get_event_loop()
            ns_answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(domain, dns.rdatatype.NS)
            )
        except Exception:
            return findings

        # Try AXFR against each nameserver
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata.target).rstrip(".")
            try:
                loop = asyncio.get_event_loop()

                def _do_axfr() -> dns.zone.Zone | None:
                    try:
                        return dns.zone.from_xfr(
                            dns.query.xfr(
                                ns_host,
                                domain,
                                timeout=RESOLVER_LIFETIME,
                            )
                        )
                    except Exception:
                        return None

                zone = await asyncio.wait_for(
                    loop.run_in_executor(None, _do_axfr),
                    timeout=RESOLVER_LIFETIME + 2,
                )
                if zone is not None:
                    # SUCCESSFUL AXFR — significant finding
                    node_count = sum(1 for _ in zone.nodes)
                    findings.append(
                        Finding(
                            type=FindingType.OTHER,
                            value=domain,
                            source="dns_axfr",
                            confidence=1.0,
                            finding_metadata={
                                "event": "axfr_succeeded",
                                "nameserver": ns_host,
                                "records": node_count,
                                "severity": "HIGH",
                            },
                        )
                    )
            except TimeoutError:
                # AXFR timed out — common with slow nameservers
                logger.debug("axfr_timeout", nameserver=ns_host)
            except dns.exception.FormError:
                # AXFR refused — expected on most servers
                logger.debug("axfr_refused", nameserver=ns_host)

        return findings


__all__ = ["DNSEnumModule"]
