# HANDOFF — Public Contract for Phase 2 Consumers

> **Schema version**: 1.0.0
> **Status**: Stable
> **Last updated**: 2026-10-13 (v0.2.0 — additive `person_dossiers[]` only; no breaking changes)

**Version**: [v0.2.0](https://github.com/zimlama/recon/releases/tag/v0.2.0) — contract v1.0.0 (additive: new optional `person_dossiers[]` at top level; consumers that don't recognize the field ignore it).
**Previous version**: [v0.1.0](https://github.com/zimlama/recon/releases/tag/v0.1.0) — contract v1.0.0 (initial release).

## Consumers

- `zimlama/recon-phase2` — future Phase 2 (active scanning) consuming the handoff JSON.

(To add your project to this section, open a PR.)

## What is the handoff?

When a `zimlama/recon` job completes, the system generates a **handoff packet** — a vendor-neutral JSON document that describes the target's external attack surface. A future `zimlama/recon-phase2` (or any other scanning tool) can consume this packet to start active enumeration without re-doing passive recon.

## Schema v1.0.0

```json
{
  "schema_version": "1.0.0",
  "schema_url": "https://github.com/zimlama/recon/blob/main/docs/HANDOFF.md",
  "source": {
    "repo": "zimlama/recon",
    "version": "0.1.0",
    "job_id": "j-uuid",
    "phase": "01-recon-osint",
    "completed_at": "2026-10-06T14:23:00Z"
  },
  "target": {
    "primary_domain": "example.com",
    "authorization_scope": "domain *.example.com",
    "active_scan_authorized": false
  },
  "confirmed_targets": [
    {
      "subdomain": "api.example.com",
      "ips": ["1.2.3.4"],
      "asn": "AS12345",
      "country": "US",
      "tech_stack_hint": {"server": "nginx/1.21.0"},
      "shodan_exposure": {"open_ports": [80, 443], "products": ["nginx"], "cves_observed": []},
      "priority_for_next_phase": "HIGH",
      "ai_reasoning": "Public-facing API with known vulnerable nginx version",
      "ai_verdict": "CONFIRMED",
      "ai_confidence": 0.95
    }
  ],
  "tech_stack_summary": {
    "web_servers": {"nginx": ["1.21.0"]},
    "frameworks": {},
    "databases": {"PostgreSQL": ["15.0"]},
    "cloud_providers": {"AWS": ["us-east-1"]}
  },
  "credentials_exposure_summary": {
    "emails_found": 12,
    "breach_count": 3
  },
  "certificates": [
    {
      "cn": "api.example.com",
      "issuer": "Let's Encrypt",
      "valid_from": "2026-09-01T00:00:00Z",
      "valid_to": "2026-12-01T00:00:00Z",
      "san": ["api.example.com", "www.example.com"]
    }
  ],
  "recommended_modules": [
    {"module": "host_discovery", "priority": "HIGH", "rationale": "47 live hosts identified"},
    {"module": "port_scanning", "priority": "HIGH", "rationale": "Shodan shows 3 ports per host"},
    {"module": "web_fingerprinting", "priority": "MEDIUM", "rationale": "HTTP services running, identify WAF/CMS"}
  ],
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
  "do_not_scan": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7"],
  "consent_flags": {
    "tier_3_modules_run": [],
    "white_hat_only": true
  }
}
```

## Field reference

### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | ✅ | Semver version of the handoff schema |
| `schema_url` | string | ✅ | URL to the schema documentation |
| `source` | object | ✅ | Producer metadata (see below) |
| `target` | object | ✅ | Target metadata (see below) |
| `confirmed_targets` | array | ❌ | List of confirmed subdomain/IP targets (see below) |
| `tech_stack_summary` | object | ❌ | Aggregated tech stack (see below) |
| `credentials_exposure_summary` | object | ❌ | Email + breach exposure (PII-handled) |
| `certificates` | array | ❌ | Certificates observed in CT logs |
| `recommended_modules` | array | ❌ | Phase 2 module recommendations |
| `person_dossiers` | array | ❌ | Per-identity aggregation output from `person_dossier` (v0.2.0+, additive) |
| `do_not_scan` | array | ✅ | IP ranges to never scan (default: RFC 1918 + reserved) |
| `consent_flags` | object | ✅ | What consent was given (white-hat only) |

### `source`

| Field | Type | Description |
|-------|------|-------------|
| `repo` | string | Always `"zimlama/recon"` (this project) |
| `version` | string | Semver version of the producer (e.g., `"0.1.0"`) |
| `job_id` | string | UUID of the source job |
| `phase` | string | Always `"01-recon-osint"` for Phase 1 |
| `completed_at` | string | ISO 8601 timestamp of when the job completed |

### `target`

| Field | Type | Description |
|-------|------|-------------|
| `primary_domain` | string | The main domain (e.g., `"example.com"`) |
| `authorization_scope` | string | Human-readable scope (e.g., `"domain *.example.com"`) |
| `active_scan_authorized` | bool | `false` for Phase 1 (must be re-confirmed for Phase 2) |

### `confirmed_targets[]`

| Field | Type | Description |
|-------|------|-------------|
| `subdomain` | string | The subdomain (e.g., `"api.example.com"`) |
| `ips` | array of strings | IP addresses this subdomain resolves to |
| `asn` | string \| null | AS number (e.g., `"AS12345"`) |
| `country` | string \| null | ISO country code (e.g., `"US"`) |
| `tech_stack_hint` | object | Key-value: technology → version (e.g., `{"nginx": "1.21.0"}`) |
| `shodan_exposure` | object \| null | Shodan InternetDB data (open_ports, products, cves) |
| `priority_for_next_phase` | string | `HIGH` / `MEDIUM` / `LOW` (AI-assigned) |
| `ai_reasoning` | string | 1-2 sentence technical reasoning |
| `ai_verdict` | string | `CONFIRMED` / `LIKELY` / `SUSPECTED` (from AI validation) |
| `ai_confidence` | float | 0.0-1.0 (AI's confidence) |

### `tech_stack_summary`

| Field | Type | Description |
|-------|------|-------------|
| `web_servers` | object | Key-value: web server → versions |
| `frameworks` | object | Key-value: framework → versions |
| `databases` | object | Key-value: database → versions |
| `cloud_providers` | object | Key-value: provider → regions |

### `credentials_exposure_summary`

| Field | Type | Description |
|-------|------|-------------|
| `emails_found` | int | Total public emails found (NOT the emails themselves) |
| `breach_count` | int | Total breach exposures found |

**Privacy**: This object NEVER contains actual emails or credentials. Only counts.

### `certificates[]`

| Field | Type | Description |
|-------|------|-------------|
| `cn` | string | Common name |
| `issuer` | string | Issuing CA |
| `valid_from` | string | ISO 8601 |
| `valid_to` | string | ISO 8601 |
| `san` | array of strings | Subject Alternative Names |

### `recommended_modules[]`

| Field | Type | Description |
|-------|------|-------------|
| `module` | string | Module name (e.g., `"port_scanning"`) |
| `priority` | string | `HIGH` / `MEDIUM` / `LOW` |
| `rationale` | string | 1-sentence why this module is recommended |

### `person_dossiers[]` (v0.2.0+, additive)

Per-identity aggregation emitted by the `person_dossier` Tier 3 aggregator. Phase 2 consumers use this to derive a credential-stuffing watch-list — *without ever seeing plaintext email*.

| Field | Type | Description |
|-------|------|-------------|
| `persona_id` | string | Per-job fake ID assigned by `person_dossier` (e.g., `"p-001"`). Resets each `job_id`; not a stable cross-job identifier. |
| `email_hash` | string | SHA-256 of the lowercased email, hex-encoded. Plaintext email **never** appears in the handoff. |
| `source_modules` | array of strings | The Tier 3 modules that corroborated this identity (e.g., `["employee_osint", "socmint", "breach_data"]`). Phase 2 prioritizes by source diversity. |
| `role_relevance` | string | `HIGH` / `MEDIUM` / `LOW`. Inferred role importance (exec, IT/eng, support, etc.). |
| `priority_for_next_phase` | string | `HIGH` / `MEDIUM` / `LOW`. Aggregate priority for Phase 2 to attack. |
| `confidence` | float (0.0–1.0) | Aggregated (max + 0.1 boost per multi-source corroboration, capped at 1.0). |
| `coherence` | string | LLM-assessed coherence: `HIGH` / `MEDIUM` / `LOW` / `NONE`. Bounded call (256 tokens, 30s). |
| `profiles_count` | int | Number of distinct social/professional profiles joined into this dossier. |
| `breach_exposures_count` | int | Number of distinct breach rows contributing to this dossier. |

#### Privacy invariants (verified)

- **Schema**: `HandoffPersonDossierSummary.model_config = ConfigDict(extra="forbid")` — no plaintext `email` field can be added without breaking the schema.
- **In-transit**: The LLM (used for the coherence call) only receives `email_hash`. The Dossier prompt template never embeds plaintext.
- **At rest**: The `identity_map` table holds raw email **only as a Fernet ciphertext** (`IdentityMap.encrypted_email`), keyed by Fernet (`PERSON_DOSSIER_ENCRYPTION_KEY`). Plaintext is scoped to a single internal helper that routes directly into `encrypt_email()`.
- **Orphan breaches**: a breach row that doesn't correlate with `employee_osint` or `socmint` is recorded in `errors[]` rather than being folded into a low-confidence dossier, for transparent operator review.

Phase 2 consumers can derive a Phase 2 watch-list by sorting `person_dossiers[]` by `(confidence, coherence, role_relevance)` and treating the top N as the candidate set — but the actual operation (e.g. credential-stuffing watch vs. active probe) belongs to Phase 2's RoE model, not Phase 1.

### `consent_flags`

| Field | Type | Description |
|-------|------|-------------|
| `tier_3_modules_run` | array | List of Tier 3 modules that were run (e.g., `["breach_data"]`) |
| `white_hat_only` | bool | Always `true` (this is a recon tool, not an attack tool) |

## v0.2.0 changelog (additive only)

| Field added | Where | Notes |
|-------------|-------|-------|
| `person_dossiers[]` | `HandoffPacket` (top-level) | Optional; absent → empty list. Existing 1.0.0 consumers ignore it (Pydantic `extra="ignore"` on importer side, or simply skip unknown fields in JSON parsers). |
| `HandoffPersonDossierSummary` | new schema class | `extra="forbid"` — no plaintext email can be added. |

No fields removed, renamed, or retyped. No type changes. **Strictly additive** — minor-version semantics hold. See [`CHANGELOG.md`](../CHANGELOG.md) v0.2.0 entry for the producer side.

## How to consume

### Option 1: File

```bash
./scripts/export-handoff.sh <job_id> ./handoff.json
```

### Option 2: REST API

```bash
curl http://localhost:8000/api/v1/jobs/<job_id>/handoff/download -o handoff.json
```

### Option 3: MCP

```
get_handoff(job_id="<job_id>")
```

### Option 4: Python

```python
from app.handoff.importer import import_handoff
packet = import_handoff("./data/handoffs/h-2026-10-06-uuid.json")
print(packet.confirmed_targets)
```

## Versioning policy

- **Patch** (1.0.0 → 1.0.1): bug fixes, no schema change
- **Minor** (1.0.0 → 1.1.0): additive changes (new optional fields)
- **Major** (1.0.0 → 2.0.0): breaking changes (renamed fields, removed fields, type changes)

**Consumers** MUST validate `schema_version` before consuming.
**Producers** MUST support `schema_version` checking in their validators.

## Multi-repo architecture

Phase 1 (this repo, `zimlama/recon`) produces the handoff.
Phase 2 (future repo, `zimlama/recon-phase2`) consumes the handoff.

See [MULTI_REPO.md](MULTI_REPO.md) for the full architecture.

## Example handoffs

See `examples/sample-handoff.json` in the repo.

## License

The handoff schema is Apache-2.0 licensed. Consumers may use, modify, and distribute handoffs freely.
