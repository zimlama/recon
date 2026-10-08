# PRD: zimlama/recon — Phase 1 Ethical Hacking Reconnaissance Framework

> **Version**: 0.2.0 (released)
> **Date**: 2026-10-13
> **Owner**: zimlama
> **Status**: v0.2.0 shipped

## Status

✅ **v0.1.0 released** (2026-10-12) — initial 14 modules + AI validation + handoff v1.0.0. See [CHANGELOG.md](../CHANGELOG.md).
✅ **v0.2.0 released** (2026-10-13) — RoE middleware (PR 1), touch_classification + tools_only_free filter (PR 2), person_dossier aggregator + privacy primitives (PR 4), all audit findings closed. See [CHANGELOG.md](../CHANGELOG.md).

Active development is now focused on **v0.3.0** (multi-user + observability). See [Out of scope](#out-of-scope-deferred-to-v02) below for the deferred items.

## Problem statement

Pentesters and red team operators need a reconnaissance tool that is:

1. **Vendor-neutral** — not locked to Shodan, Censys, Burp, or any single ecosystem
2. **Self-hosted** — no SaaS dependency, no recurring costs, full data ownership
3. **AI-validated** — auto-filter hundreds of false positives that operators currently triage manually
4. **Privacy-first** — zero telemetry, no phone-home, all data local
5. **Professional** — produces reports that can be delivered to clients
6. **Open source** — Apache-2.0 licensed, auditable, community-contributable

Current options fail at least 2-3 of these:
- Shodan Monitor / Censys Search: SaaS-only, recurring costs
- Burp Suite: not recon-focused, paid
- recon-ng / SpiderFoot: no AI validation, basic reports
- Custom scripts: not integrated, no reports

## Target users

- **Pentesters** (primary) — running engagements for clients
- **Red team operators** — adversary simulation, continuous recon
- **Bug bounty hunters** — surface discovery for targets
- **Security researchers** — open-source methodology

## Goals (v0.1, achieved)

| Goal | Metric | Status |
|------|--------|--------|
| Self-hosted install in < 5 min | `time ./install.sh` | ✅ Achieved |
| 14 recon modules functional | Each module produces findings | ✅ Achieved (v0.1.0) |
| AI validation per module | Each module has LDMValidationResult | ✅ Achieved (v0.1.0) |
| Handoff JSON for Phase 2 | Schema v1.0.0, semver stable | ✅ Achieved (v0.1.0); additive only through v0.2.0 |
| 90% test coverage | `pytest --cov-fail-under=90` | ✅ Achieved; 91.4% module coverage in v0.2.0 |
| 0 references to third-party brands | `grep -r "DragonJar"` returns 0 | ✅ Verified every release |

## Goals (v0.2.0, achieved)

| Goal | Metric | Status |
|------|--------|--------|
| Rules-of-Engagement gate | RoEMiddleware + RoEValidator + RoE model | ✅ Achieved (PR 1) |
| Free-tier-only deployments | `tools_only_free` filter + 14-row mapping table | ✅ Achieved (PR 2) |
| Per-person aggregation | person_dossier Tier 3, privacy-by-design | ✅ Achieved (PR 4) |
| All audit findings closed | 24/24 (3 CRITICAL + 9 HIGH + 7 MEDIUM + 5 LOW) | ✅ Achieved |

## Goals (v0.3.0, target)

| Goal | Metric |
|------|--------|
| Multi-user (JWT) | `RECON_AUTH_MODE=jwt`, per-user job scoping |
| Postgres backend | `DATABASE_URL=postgresql://...` swap |
| Observability | Structured logs + Prometheus + healthcheck thresholds |
| Production hardening | TLS via Caddy / Cloudflare Tunnel, rate-limit per-user |

## Non-goals (v0.1)

- Active scanning (Phase 2 — separate repo)
- Multi-user auth
- Federation / multi-tenant
- Real-time WebSocket progress
- Custom LLM providers
- Web UI for AI prompt editing

## Success criteria

The product is successful if a pentester can:

1. `git clone https://github.com/zimlama/recon && cd recon && ./install.sh`
2. Open http://localhost:8080
3. Click "New Job" → enter `example.com` → accept disclaimer → run
4. See modules run in parallel with progress
5. Get a PDF report with cover page, findings, AI insights
6. Export handoff JSON for future Phase 2
7. Delete all data with `make purge TARGET=example.com`

All in under 30 minutes, with zero external service dependencies (except the configured LLM).

## User stories

### US-1: New job (pentester)

> As a pentester, I want to start a recon job for a target domain, see which modules run in real-time, and download a PDF report.

**Acceptance**:
- User can enter target domain in form
- User can select which Tier 1 modules to run (default = all 6)
- User must accept disclaimer + type target to confirm
- User sees progress for each module
- User can download PDF + MD report
- User can download handoff JSON

### US-2: AI validation (pentester)

> As a pentester, I want AI to filter false positives from my recon results and tell me which assets are worth investigating further.

**Acceptance**:
- Each module's findings are validated by MiniMax M3
- Each finding has a verdict (CONFIRMED, LIKELY, SUSPECTED, FALSE_POSITIVE)
- Each finding has a priority (HIGH, MEDIUM, LOW)
- AI suggests next modules to run
- User can re-trigger AI validation manually

### US-3: Handoff (tool author)

> As the author of a future Phase 2 tool, I want to consume the handoff JSON from Phase 1 to start active enumeration without re-doing passive recon.

**Acceptance**:
- Handoff JSON is in a stable, documented schema (v1.0.0)
- Schema is vendor-neutral (no zimlama-specific fields)
- Schema is accessible via file, REST, MCP, CLI
- Schema is extensible (additive changes only)

### US-4: Privacy (security lead)

> As a security lead, I want to ensure no recon data leaves our infrastructure, and we can delete all data when an engagement ends.

**Acceptance**:
- Zero telemetry
- All data in `./data/` (local filesystem)
- `make purge TARGET=example.com` deletes ALL data for that target
- Audit log of all actions
- No phone-home except configured LLM

## Functional requirements

See [docs/HANDOFF.md](HANDOFF.md) for the complete spec.

## Constraints

- **LATAM-aware**: disclaimer covers CO + BR + MX + AR + CL + PE + US + EU
- **No DragonJar references**: brand is zimlama (sanitized per user)
- **90% coverage gate**: strict, both backend + frontend
- **Apache-2.0 license**: permissive + patent grant
- **Conventional commits**: no AI attribution
- **English primary**: docs in English, Spanish for LATAM context only

## Out of scope (deferred to v0.3+)

| Feature | When |
|---------|------|
| Active scanning (Phase 2) | separate repo, post-v0.4.0 |
| Multi-user auth (JWT) | v0.3 |
| Federation | v0.4 |
| WebSocket real-time | v0.3 |
| Custom LLM providers | v0.3 |
| Nuclei integration | Phase 2 (separate repo) |
| Burp Suite extension | v0.4 |
| Mobile app | v0.5+ |

Already shipped in v0.2.0 (was originally on this list): RoE enforcement, `person_dossier` aggregator, audit-finding closures.

## Open questions

See `wiki/open-questions.md` in the Folio mirror.
