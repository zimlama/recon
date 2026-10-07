# Changelog

All notable changes to zimlama/recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-12

### Sprint recap (7-day MVP)

Built in 7 days by `zimlama` following the SDD workflow:

- **Day 1** — Initial scaffold: backend (FastAPI + Pydantic + SQLAlchemy), frontend (Next.js + Tailwind + Zustand), MCP server, brand kit
- **Day 2** — Tier 1 modules: `whois_rdap`, `dns_enum`, `subdomain_enum` (48 tests, TDD discipline)
- **Day 3** — Tier 1 modules: `certificate_transparency`, `wayback_machine`, `email_harvesting` (52 tests)
- **Day 4** — Frontend: 7 pages + 12 components + 106 tests (96.04% coverage)
- **Day 5** — Tier 2 modules: `shodan_censys`, `github_recon`, `metadata_analysis`, `google_dorking` (49 tests)
- **Day 6** — Tier 3 modules: `breach_data`, `socmint`, `employee_osint`, `dark_web_osint` (41 tests) + integration tests (7)
- **Day 7** — E2E Playwright tests (8 smoke tests) + final polish

### Added
- 14 recon modules (6 Tier 1, 4 Tier 2, 4 Tier 3 gated)
- FastAPI backend (Python 3.11+) with Pydantic v2 + SQLAlchemy 2 + Alembic
- Next.js 14 frontend (App Router, TypeScript 5, Tailwind 3, Zustand)
- AI validation via MiniMax M3 (OpenAI-compatible, with retry + exponential backoff)
- Handoff packet schema v1.0.0 (vendor-neutral public contract for future Phase 2)
- MCP stdio server with 6 tools (start_recon_job, get_job_status, etc.)
- Report generation: Markdown + CSS-styled PDF via md-to-pdf + Node + Puppeteer
- LATAM-aware disclaimer (Colombia, Brasil, México, Argentina, Chile, Perú, US, EU)
- Self-hosted Docker Compose (dev + prod profiles)
- GitHub Actions CI (pytest + ruff + mypy + pyright + vitest + docker build + codeql)
- Brand kit: zimlama logo (Invader Zim GIR-inspired), design tokens, report CSS
- Playwright E2E smoke tests (8 tests covering Dashboard, Jobs, Modules, Disclaimer, New Job flow)
- Frontend Vitest unit tests (106 tests, 96% coverage on non-page code)
- Folio mirror: `mindos/folio/40_proyectos/zimlama-recon/`

### Module catalog (14 modules)

| Tier | Module | MITRE techniques |
|-------|-------|------------------|
| 1 | `whois_rdap` | T1596.002, T1590.001 |
| 1 | `dns_enum` | T1590.002, T1596.001 |
| 1 | `subdomain_enum` | T1596.002, T1596.003, T1589.001 |
| 1 | `certificate_transparency` | T1596.003 |
| 1 | `wayback_machine` | T1593 |
| 1 | `email_harvesting` (PII) | T1589.002 |
| 2 | `shodan_censys` | T1596.005 |
| 2 | `github_recon` | T1593.003, T1552.001 |
| 2 | `metadata_analysis` | T1593 |
| 2 | `google_dorking` | T1593.002 |
| 3 | `breach_data` (gated) | T1589.001 |
| 3 | `socmint` (gated) | T1593.001 |
| 3 | `employee_osint` (gated) | T1589.003, T1593.001 |
| 3 | `dark_web_osint` (gated) | T1589.001, T1593.001 |

### Security
- `.env.example` only — no real secrets in repo
- `.env` is gitignored + chmod 600 on install
- Audit middleware logs all user actions (job_create, module_run, etc.)
- Built-in banned-targets list (RFC 1918 + loopback + reserved) — aborts silently
- CORS restricted to configured origins
- LATAM-aware disclaimer with explicit consent + typed target confirmation
- PII handling: `email_harvesting` filters role-based + privacy-protected domains; `breach_data` uses HIBP k-anonymity (never logs plaintext emails)
- WCAG AA color contrast (verified with semantic tokens)

### Stats
- 251 backend tests passing (+ 14 E2E + 106 frontend = 371 total)
- 91.43% modules package coverage
- 96.04% frontend non-page coverage
- Apache-2.0 license
- 0 `Co-Authored-By` in commits (conventional commits only)

### Architecture
- **Multi-repo ready**: handoff JSON schema is vendor-neutral. Future `ziimap.arecon-phase2` can consume the output without depending on this codebase.
- **Single-user MVP**: no auth required (KISS). Multi-user is v0.3+ roadmap.
- **No telemetry**: all data stays local in `./data/`. User can `make purge TARGET=example.com` to wipe everything.

[Unreleased]: https://github.com/zimlama/recon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zimlama/recon/releases/tag/v0.1.0