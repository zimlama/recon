# Multi-Repo Architecture

> **Repos**: `zimlama/recon` (this, Phase 1) + `zimlama/recon-phase2` (Phase 2, future)
> **Integration boundary**: the HandoffPacket JSON contract — see [HANDOFF.md](HANDOFF.md)
> **Status**: Phase 2 not yet built (target: v0.4.0 of Phase 1 roadmap). The contract has been stable since v0.1.0.

This document explains why `zimlama/recon` is split across two repos, what each one owns, and how Phase 2 will consume what Phase 1 produces.

---

## 1. Why split?

Phase 1 (**passive recon**) and Phase 2 (**active scanning**) have fundamentally different risk profiles, audiences, and operational constraints. Forcing them into a single repo leads to a monolith that does neither well.

| Concern | Phase 1 (passive) | Phase 2 (active) |
|---------|--------------------|------------------|
| Network traffic | Outbound only to public sources (crt.sh, RDAP, theHarvester) | Inbound probes against the target (port scans, vuln probes) |
| Authorization model | Single operator, scope = "I have a target and tell it to recon itself" | Two-party RoE: written scope, explicit ack, audit trail per request |
| Reversibility | Reading a public page is not a "side effect" — fully reversible | Sending a non-idempotent probe to a server is an audit-grade event |
| Threat model | False positives, false negatives, PII handling | Authorized-but-risky: misfired probes, accidental DoS, scope drift |
| Latency budget | Batch job, 5-60 minutes is fine | Tighter SLOs; some probes are time-bounded (e.g. *Nuclei* templates on thousands of endpoints) |
| LLM role | Confirmation bias reducer (filter false positives, enrich) | Co-pilot (suggest next probe, summarize response) |
| Tooling footprint | Python + httpx + SQLite + Next.js | Same + port scanners (nmap/masscan), vuln frameworks (Nuclei), fuzzers, possibly C2 emulation |

A single repo would mix:

- "What if the AI mislabels a finding?" (Phase 1: embarrassment) with "What if a probe triggers a WAF that blocks a customer's API?" (Phase 2: incident).
- "Telemetry is zero — all data in `./data/`" with "Telemetry is mandatory — every probe is a SOC alert candidate".

Two repos share **only** the handoff JSON contract. Each owns its own auth, its own deployment story, its own compliance boundary. Phase 1 stays Apache-2.0 (as it is). Phase 2 will be Apache-2.0 too, but may add a stronger dual-control mechanism.

---

## 2. Phase 1 — `zimlama/recon` (this repo)

### What it does

Passive + semi-passive external reconnaissance on a target domain. Produces:

1. A database of findings + AI verdicts.
2. A PDF report.
3. A vendor-neutral handoff JSON.

### What it does NOT do

- Active port scans (Nmap, Masscan).
- Web app fuzzing (Nuclei, ffuf).
- Authenticated probing.
- Anything that needs `active_scan_authorized=true`.

### Modules it ships

15 modules as of v0.2.0 (see [MODULE_GUIDE.md](MODULE_GUIDE.md)):

| Tier | Count | Examples |
|------|-------|----------|
| 1 (always-on, passive) | 6 | whois_rdap, dns_enum, subdomain_enum, certificate_transparency, wayback_machine, email_harvesting |
| 2 (free-tier APIs, semi-passive) | 4 | shodan_censys, github_recon, metadata_analysis, google_dorking |
| 3 (gated) | 4 | breach_data, socmint, employee_osint, dark_web_osint |
| 3 aggregator | 1 | person_dossier (Tier 3, gated, cross-module correlator) |

### What Phase 1 outputs that Phase 2 consumes

The HandoffPacket (canonical schema: `1.0.0`, semver-stable). See [HANDOFF.md](HANDOFF.md) for the full spec.

Notable top-level fields Phase 2 will care about:

| Field | Phase 2 use |
|-------|-------------|
| `confirmed_targets[]` | List of `subdomain + ips + asn + country + tech_stack_hint + priority_for_next_phase + shodan_exposure`. These are the host candidates Phase 2 should scan. |
| `tech_stack_summary` | Tells Phase 2 which Nuclei templates and version-CVEs to load. |
| `do_not_scan` | Strict enforcement list — Phase 2 MUST refuse any target whose IP is in this set, regardless of how it was passed in. |
| `consent_flags.tier_3_modules_run` | Audit trail — Phase 2 surfaces what Phase 1 already touched. |
| `person_dossiers[]` *(v0.2.0+)* | One row per unique person identity (by `email_hash`), with `source_modules` indicating which Phase 1 modules saw them. Phase 2 uses this as input to "credential-stuffing watch-list" rules (without ever seeing plaintext). |

---

## 3. Phase 2 — `zimlama/recon-phase2` (future repo)

> **Repo URL**: TBD. Tracking issue: see roadmap in [PRD §Out-of-scope](../docs/PRD-recon-phase1.md#out-of-scope-deferred-to-v02).

### What it will do

Active scanning (Nmap masscan-style enumeration), vulnerability probing (Nuclei templates by tech stack), web-app testing (ffuf, sqlmap as opt-in modules), credential-stuffing watch-list derivation from handoff `person_dossiers[]`.

### What it will consume from Phase 1

The handoff JSON. Specifically:

```python
# pseudo-code for Phase 2 start
packet = load_handoff("./handoff.json")
assert packet.schema_version in {"1.0.0", "1.1.0", ...}
assert packet.target.active_scan_authorized is True   # re-confirmed at Phase 2 start
for target in packet.confirmed_targets:
    if target.subdomain in packet.do_not_scan: continue
    port_scan(target.subdomain, ports=derive_from_shodan(target.shodan_exposure))
    nuclei_scan(target.subdomain, templates=derive_from_tech_stack(packet.tech_stack_summary))
```

### What it will NOT do

Phase 2 also avoids re-doing Phase 1 work. There is **no** Phase 2 module that runs `crt.sh` queries against the same target — that's what the handoff `certificates[]` field is for. Phase 2 is "do less, but do it for real".

### Authorization model

Phase 2 introduces a stronger RoE enforcement than Phase 1's opt-in `ROE_ENABLED` middleware. Each Phase 2 job requires:

1. A `RoE` row covering the target + scope.
2. A fresh `active_scan_authorized=true` flag signed by the operator at job-start time (the handoff's `target.active_scan_authorized=false` is treated as informational — Phase 2 must confirm separately).
3. An audit row per probe request, sampled to a SIEM.

The Phase 1 `RoEMiddleware` is the prototype; Phase 2 hardens it (likely with a Postgres backend + signed RoE documents).

---

## 4. The handoff contract as integration boundary

Two constraints keep the boundary clean:

1. **Schema is the contract.** Phase 1 publishes a semver-versioned JSON schema ([HANDOFF.md](HANDOFF.md)). Phase 2 imports `app.handoff.schema` (or its mirror) — never reads Python internals.
2. **No bidirectional coupling.** Phase 1 has zero dependencies on Phase 2. Phase 2 imports `app.handoff` from Phase 1 *or* a published pypi package, but never the other way around.

The contract version policy (from [HANDOFF.md](HANDOFF.md#versioning-policy)):

- **Patch** (1.0.0 → 1.0.1): bug fixes, no schema change.
- **Minor** (1.0.0 → 1.1.0): additive (new optional fields). **Consumers are safe to upgrade without code changes.**
- **Major** (1.0.0 → 2.0.0): breaking (renamed fields, removed fields, type changes). Both repos coordinate the bump.

### v0.2.0 contract change (additive, non-breaking)

The handoff now includes `person_dossiers: list[HandoffPersonDossierSummary]` at the top level. Phase 2 consumers that don't recognize this field ignore it (Pydantic `extra="ignore"`). Consumers that do recognize it can use it for watch-list derivation.

```json
{
  "schema_version": "1.0.0",
  "source": { ... },
  "target": { ... },
  "confirmed_targets": [ ... ],
  "tech_stack_summary": { ... },
  "person_dossiers": [
    {
      "persona_id": "p-001",
      "email_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "source_modules": ["employee_osint", "socmint", "breach_data"],
      "role_relevance": "HIGH",
      "priority_for_next_phase": "MEDIUM",
      "confidence": 0.85,
      "coherence": "HIGH",
      "profiles_count": 3,
      "breach_exposures_count": 2
    }
  ],
  "do_not_scan": [ ... ],
  "consent_flags": { ... }
}
```

Schema field reference (full list in [HANDOFF.md](HANDOFF.md#field-reference)):

| Field | Type | Privacy notes |
|-------|------|---------------|
| `persona_id` | string | Fake-id assigned by `person_dossier` (e.g. `p-001`). Resets per job. |
| `email_hash` | string | SHA-256 of the lowercased email, hex-encoded. **Plaintext never appears in the handoff.** |
| `source_modules` | list[string] | The Tier 3 modules that corroborated this identity. Used by Phase 2 to prioritize. |
| `role_relevance` | enum | `HIGH` (exec, IT, security) / `MEDIUM` / `LOW` / default `LOW`. |
| `priority_for_next_phase` | enum | `HIGH` / `MEDIUM` / `LOW`. |
| `confidence` | float (0.0–1.0) | Aggregated (max +0.1 boost per multi-source corroboration, capped at 1.0). |
| `coherence` | enum | LLM-assessed (HIGH / MEDIUM / LOW / NONE). 1 call per dossier, 256 tokens max. |
| `profiles_count` / `breach_exposures_count` | int | How many distinct findings joined into this dossier. |

Phase 2 watches `source_modules` — e.g. a dossier with `["breach_data", "socmint", "employee_osint"]` is higher-confidence than one with only `["breach_data"]`.

---

## 5. How to start Phase 2

You'll need a fresh repo. Recommended scaffolding:

```
zimlama/recon-phase2/
├── pyproject.toml          # python 3.11+, fastapi, pydantic v2, sqlalchemy 2
├── app/
│   ├── main.py             # FastAPI app
│   ├── handoff/
│   │   ├── loader.py       # reads HandoffPacket from JSON, validates schema_version
│   │   └── consumer.py     # iterates confirmed_targets[]
│   ├── scope/
│   │   ├── roe.py          # hardened RoE (Postgres-backed, signed)
│   │   └── do_not_scan.py  # enforces packet.do_not_scan at every probe site
│   ├── modules/
│   │   ├── port_scanner.py # nmap or masscan wrapper
│   │   ├── nuclei.py       # nuclei template runner, tech-stack-aware
│   │   └── ...
│   ├── orchestrator/
│   └── tests/
└── README.md
```

The seam you'll import from Phase 1 (or its published equivalent):

```python
# Phase 2 imports — only the public contract surface
from app.handoff.schema import HandoffPacket

def load(handoff_path: Path) -> HandoffPacket:
    raw = json.loads(handoff_path.read_text())
    packet = HandoffPacket.model_validate(raw)
    if packet.target.active_scan_authorized is not True:
        raise ActiveScanNotAuthorized(
            f"Phase 2 requires fresh active_scan_authorized=true; "
            f"handoff says {packet.target.active_scan_authorized!r}. "
            f"Re-confirm authorization with the engagement owner."
        )
    return packet
```

### Why publish handoff schema as a pypi package?

The cleanest long-term move:

```
# pyproject.toml (Phase 2)
[project]
dependencies = [
    "zimlama-recon-handoff>=1.0,<2.0",  # semver-strict
]
```

This way Phase 1 and Phase 2 can diverge on internal architecture without breaking each other, and consumers of both (e.g. a future `zimlama/recon-aggregator`) can pin to whatever they need.

---

## 6. Multi-repo caveats

These are real trade-offs. Document them now so they don't surprise anyone later.

### 1. Schema drift is the cost

Every time Phase 1 adds a field that Phase 2 should know about, a Phase 1 maintainer has to coordinate with a Phase 2 maintainer. We mitigate this with:

- Additive-only minor versions (Phase 2 can delay upgrade by N minor versions safely).
- The `extra="forbid"` policy on `HandoffPacket` (Phase 1 can't accidentally publish unexpected top-level fields).
- `CHANGELOG.md` cross-references Phase 1 ↔ Phase 2 in the same release.

### 2. Two CI pipelines

Each repo has its own:

- Lint + type-check + test pipeline.
- Docker build + push.
- Release tagging.

Shared GitHub Actions workflows live in a third (private) repo or are duplicated. Duplication is fine — they're 200 lines each.

### 3. Two compliance boundaries

If a customer runs only Phase 1 (no active scanning authorized), they have no Phase 2 surface area at all. That's a feature, not a bug.

### 4. The "engagement" abstraction

Currently a Phase 1 job is its own engagement. For multi-job engagements (Phase 1 + Phase 2 on the same target), a third repo could spawn — `zimlama/recon-engagement` — that owns the umbrella. Not planned; deferred until there are real users.

---

## 7. Roadmap

| Version | Repo | What ships |
|---------|------|------------|
| v0.1.0 | Phase 1 | Initial 14 modules, AI validation, basic handoff (1.0.0) |
| v0.2.0 | Phase 1 | RoE middleware, touch_classification, person_dossier aggregator, handoff adds `person_dossiers[]` |
| v0.3.0 | Phase 1 | Multi-user (JWT), observability (Sentry + Prometheus), maybe Postgres backend |
| v0.4.0 | Phase 1 | Publish `zimlama-recon-handoff` pypi package + sync helper CLI |
| v0.1.0 | Phase 2 | Active scanning MVP (port_scan + nuclei); consumes handoff 1.x |

---

## 8. See also

- [HANDOFF.md](HANDOFF.md) — the contract v1.0.0 spec
- [ARCHITECTURE.md](ARCHITECTURE.md) — Phase 1 internal architecture
- [MODULE_GUIDE.md](MODULE_GUIDE.md) — what the 15 Phase 1 modules do
- [PRD §Out-of-scope](../docs/PRD-recon-phase1.md#out-of-scope-deferred-to-v02) — Phase 2 deferred items
- `wiki/decisions/2026-10-06-multi-repo.md` in the Folio mirror — the original decision rationale
