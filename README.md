# zimlama recon — Phase 1

> **Self-hosted reconnaissance framework for web applications. Open source. AI-validated. Privacy-first.**

[![Release](https://img.shields.io/github/v/release/zimlama/recon)](https://github.com/zimlama/recon/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)

`zimlama/recon` is a modular web application that runs **Phase 1 reconnaissance** on a target domain, validates each finding with AI, and produces a professional PDF report. Designed for pentesters and red team operators who want a clean, self-hosted, vendor-neutral recon tool.

> **Disclaimer**: This tool sends real network requests to your target. Use only on systems you have **written authorization** to test. See [SECURITY.md](SECURITY.md) for the full responsibility statement.

---

## Features

- **15 recon modules** across 3 tiers (6 passive + 4 semi-passive + 5 white-hat gated) — includes the `person_dossier` cross-module aggregator (v0.2.0)
- **AI-validated findings** via MiniMax-M3 (or any OpenAI-compatible provider)
- **Modular architecture** — every module is a standalone Pydantic class, repairable in isolation
- **Self-hosted** — single `install.sh` command, no SaaS dependency, no telemetry
- **Handoff contract** — public JSON schema (v1.0.0, additive through v0.2.0) for future Phase 2 (scanning) consumers
- **Rules-of-Engagement gating** — `RoEMiddleware` opt-in (env `ROE_ENABLED=true`) for engagements that need RoE enforcement on POST `/jobs`
- **Free-tier-only deployments** — `tools_only_free=true` filters the module registry to modules that don't require paid API keys
- **Privacy-by-design** — `person_dossier` SHA-256 hashes emails at the module boundary; raw addresses stored at rest only as Fernet ciphertext
- **MCP server** — stdio interface for opencode/Claude integration
- **Professional reports** — Markdown + CSS-styled PDF with cover page and severity badges
- **LATAM-aware** — disclaimer covers Colombia, Brasil, México, Argentina, Chile, Perú
- **Bilingual docs** — English + Spanish where relevant

---

## Quickstart (one command)

```bash
git clone https://github.com/zimlama/recon.git
cd recon
./install.sh  # Docker auto-installs on Linux/macOS
```

Open http://localhost:8080 in your browser.

---

## Quickstart

### Prerequisites

- macOS (Intel or Apple Silicon) or Linux (x86_64 / aarch64)
- Docker Engine 24+ with Compose v2
- Internet connection (for tool installation + AI validation)
- MiniMax M3 API key (get one at [api.minimaxi.com](https://api.minimaxi.com/))

### Install

```bash
git clone https://github.com/zimlama/recon.git
cd recon
chmod +x install.sh
./install.sh
```

The installer will:
1. Detect your OS (mac / linux / wsl)
2. Verify Docker + Compose v2
3. Create `.env` from `.env.example`
4. Ask for your `MINIMAX_API_KEY` (input is masked)
5. Build + start the containers
6. Open the UI at http://localhost:5173

### First recon

1. Open http://localhost:5173
2. Click **"New Job"**
3. Enter a target domain (e.g., `example.com`)
4. Accept the pentester responsibility modal
5. Type the target domain to confirm
6. Watch the modules run in parallel
7. Review findings + AI validation badges
8. Download the PDF report

---

## Architecture

```
zimlama/recon/
├── backend/        FastAPI + Pydantic + SQLAlchemy 2 + Alembic + mypy/ruff/pytest
├── frontend/       Next.js 14 (App Router) + React 18 + TypeScript 5 + Tailwind 3
├── templates/      Reusable brand kit (zimlama Invader-Zim style)
├── docs/           PRD, RFCs, architecture, module guide, handoff contract
├── scripts/        Install, report generation, handoff export
├── openspec/       SDD workflow artifacts (gentle-ai)
└── .github/        CI/CD workflows
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full mermaid diagram and design rationale.

---

## Modules (15 total)

### Tier 1 — Always-on, fully passive

| Module | Sub-phase | Tools |
|---|---|---|
| `whois_rdap` | Domain registration intel | RDAP, WHOIS |
| `dns_enum` | DNS record walk | dig, host |
| `subdomain_enum` | Subdomain discovery (passive) | subfinder, crt.sh, amass |
| `certificate_transparency` | TLS cert history | crt.sh, Censys cert search |
| `wayback_machine` | Historical URL archive | gau, waybackurls, CDX API |
| `email_harvesting` | Public email discovery | theHarvester, Hunter.io, HIBP |

### Tier 2 — Free-tier APIs (work without keys)

| Module | Sub-phase | Tools |
|---|---|---|
| `shodan_censys` | Internet-wide asset search | Shodan InternetDB (no key), Censys (free tier) |
| `github_recon` | Code-host OSINT | gh CLI, GitHub API, gitleaks |
| `metadata_analysis` | Document EXIF | exiftool, metagoofil |
| `google_dorking` | Search-engine recon | GHDB, SerpAPI (optional) |

### Tier 3 — White-hat gated (explicit consent required)

| Module | Sub-phase | Tools |
|---|---|---|
| `breach_data` | Credential exposure | HIBP k-anonymity |
| `socmint` | Social-media intelligence | recon-ng, SpiderFoot (passive) |
| `employee_osint` | Personnel enumeration | linkedin2username, sherlock |
| `dark_web_osint` | Tor hidden services | ahmia, Whonix (lab-isolated) |
| `person_dossier` (v0.2.0) | Cross-module per-identity aggregation (no external IO — reads sibling findings) | SHA-256 + Fernet |

See [docs/MODULE_GUIDE.md](docs/MODULE_GUIDE.md) for what each module does, what it returns, and what it does NOT do.

---

## Handoff to Phase 2

When a recon job completes, `zimlama/recon` automatically generates a **handoff packet** — a vendor-neutral JSON document that describes the target's external attack surface. A future `zimlama/recon-phase2` (or any other scanning tool) can consume this packet to start active enumeration.

The handoff is exposed via:
- File: `./data/handoffs/h-<id>.json` (canonical, shareable)
- REST: `GET /api/v1/handoffs/{id}`
- MCP: `get_handoff(handoff_id)`
- CLI: `python -m recon.handoff.export <job_id>`

See [docs/HANDOFF.md](docs/HANDOFF.md) for the schema and [docs/MULTI_REPO.md](docs/MULTI_REPO.md) for the multi-repo architecture.

---

## AI Validation

Every module's findings are validated by **MiniMax M3** (or any OpenAI-compatible LLM). The validator:
- Filters false positives (typosquats, parked domains, sinkholes)
- Enriches findings with context (tech hints, priority for next phase)
- Suggests what to do next (which modules to run, what to investigate)
- Generates a confidence score per finding

Configure via `.env`:
- `MINIMAX_API_KEY` (required)
- `MINIMAX_BASE_URL` (default: `https://api.minimaxi.com/v1`)
- `MINIMAX_MODEL` (default: `MiniMax-M3`)

See [docs/AI_VALIDATION.md](docs/AI_VALIDATION.md) for the per-module prompts and validation schema.

---

## Reports

Each recon job produces two artifacts:

1. **Markdown** — human-readable, source of truth (`./data/reports/<job_id>.md`)
2. **PDF** — professional report with cover page, table of contents, severity badges, AI summary (`./data/reports/<job_id>.pdf`)

The PDF is generated via `md-to-pdf` (Node.js + Puppeteer) using the `templates/brand-kit/report.css` stylesheet.

See [docs/REPORT_TEMPLATES.md](docs/REPORT_TEMPLATES.md) for the report structure and customization options.

---

## Development

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov=app --cov-fail-under=90
ruff check .
mypy app/
```

### Frontend

```bash
cd frontend
pnpm install
pnpm dev
pnpm test
pnpm test:e2e
```

### Coverage gates

- Backend: `pytest --cov=app --cov-fail-under=90` (90% required)
- Frontend: `vitest run --coverage --coverage.thresholds.lines=90`

---

## MCP Server

`zimlama/recon` exposes a **stdio MCP server** for opencode/Claude integration.

```bash
python -m recon.mcp.server
```

Available tools:
- `start_recon_job(target, modules)` — create a new recon job
- `get_job_status(job_id)` — check progress
- `get_findings(job_id, verdict?)` — fetch findings (optionally filtered)
- `get_handoff(handoff_id)` — export handoff packet
- `get_report_path(job_id)` — get report file path
- `list_modules()` — enumerate available modules

See [`backend/app/mcp/server.py`](backend/app/mcp/server.py) for the full tool schema.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, code style, and PR process.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Legal

This tool is for **authorized security testing only**. By using it you accept full responsibility for your actions. Unauthorized access to computer systems is a crime under local laws (see [SECURITY.md](SECURITY.md) for the full LATAM + US/EU list).
