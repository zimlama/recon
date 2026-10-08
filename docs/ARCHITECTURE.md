# Architecture

> **v0.2.0**: The diagram and directory layout below now include the 15 modules (PR 4 `person_dossier` shipped), the `RoEMiddleware` (PR 1), and the `tools_only_free` filter (PR 2). See CHANGELOG.md for the full release notes.

## High-level diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Browser (User)                            │
│                  http://localhost:8080                       │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              nginx (Frontend container)                     │
│              + Next.js standalone build                     │
└──────────────────────┬──────────────────────────────────────┘
                       │ /api/* proxy
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Backend (FastAPI :8000)                              │
│   ┌────────────────────────────────────────────────┐        │
│   │  Middleware stack (outer → inner)               │        │
│   │  ├─ AuditMiddleware (sees everything, including │        │
│   │  │   403s from RoEMiddleware)                   │        │
│   │  ├─ RoEMiddleware (gates POSTs, only if         │        │
│   │  │   ROE_ENABLED=true, else pass-through)       │        │
│   │  └─ CORSMiddleware (handles preflight, last)    │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Routes (FastAPI routers)                       │        │
│   │  ├─ /api/v1/jobs (CRUD, RoE-gated POST)        │        │
│   │  ├─ /api/v1/modules (catalog, 14+1 entries)    │        │
│   │  ├─ /api/v1/findings                           │        │
│   │  ├─ /api/v1/reports                            │        │
│   │  ├─ /api/v1/handoff (public contract)          │        │
│   │  ├─ /api/v1/ai (validation)                    │        │
│   │  └─ /api/v1/roes (v0.2.0+, RoE CRUD)           │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Orchestrator (asyncio)                        │        │
│   │  ├─ JobRunner: asyncio.gather per module       │        │
│   │  │   sweep_stuck_jobs() on startup              │        │
│   │  ├─ AIValidator: MiniMax M3 per module         │        │
│   │  ├─ RateLimiter: token bucket per (target,mod) │        │
│   │  └─ RoEValidator: is_authorized(target, scope) │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Modules (15) — BaseReconModule ABC            │        │
│   │  Tier 1 (6): whois, dns, subdomain, ct,        │        │
│   │              wayback, email                    │        │
│   │  Tier 2 (4): shodan, github, metadata, dorking │        │
│   │  Tier 3 (5): breach, socmint, employee,        │        │
│   │              darkweb, person_dossier           │        │
│   │  (person_dossier is an aggregator — no net IO, │        │
│   │   reads sibling ModuleRun rows)                 │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Handoff subsystem (vendor-neutral contract)  │        │
│   │  ├─ HandoffPacket v1.0.0 (Pydantic)            │        │
│   │  ├─ Schema: extra="forbid" — no surprise fields│        │
│   │  ├─ person_dossiers[] (v0.2.0 additive)        │        │
│   │  ├─ Exporter: job → JSON file (atomic write)   │        │
│   │  └─ Importer: JSON → DB row                    │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Privacy primitives (v0.2.0)                    │        │
│   │  ├─ hash_email() → SHA-256 (deterministic)     │        │
│   │  ├─ encrypt_email() → Fernet ciphertext        │        │
│   │  ├─ EncryptionKeyMissingError                  │        │
│   │  └─ IdentityMap table (encrypted raw email)    │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  Report subsystem                              │        │
│   │  ├─ MarkdownReportGenerator: job → MD           │        │
│   │  ├─ load_css: brand-kit                        │        │
│   │  └─ PDFGenerator: MD → PDF via npx md-to-pdf   │        │
│   │     (process-group cleanup, 120s timeout)      │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  MCP server (stdio)                             │        │
│   │  └─ 6 tools (start_recon_job, get_status, etc.) │        │
│   └────────────────────────────────────────────────┘        │
│   ┌────────────────────────────────────────────────┐        │
│   │  LLM Client (httpx async, OpenAI-compat)       │        │
│   │  ├─ Stub mode when key is placeholder          │        │
│   │  ├─ Retry w/ 2**attempt + Retry-After + jitter │        │
│   │  ├─ Malformed-response marker (no silent drop)  │        │
│   │  └─ Auth errors raise immediately, no retry    │        │
│   └────────────────────────────────────────────────┘        │
└────────────┬──────────────────────────┬─────────────────────┘
             │                          │
             ▼                          ▼
    ┌──────────────────┐      ┌────────────────────────┐
    │  SQLite DB        │      │  MiniMax M3 API         │
    │  ./data/recon.db  │      │  (OpenAI-compat)       │
    │  (WAL mode)       │      │                        │
    └──────────────────┘      └────────────────────────┘
```

## What's new in v0.2.0

Three PRs landed on top of v0.1.0. The diagram and the directory tree below already include all of them.

### PR 1 — Rules-of-Engagement (RoE) middleware

- **`backend/app/middleware/roe.py`** — `RoEMiddleware` (Starlette/FastAPI middleware).
- **`backend/app/orchestrator/roe.py`** — `RoEValidator.is_authorized(target, scope)` and `get_active_roes()`.
- **`backend/app/models.py`** — `RoE` and `SignOff` tables (Alembic migration `20261007224728_add_roe_tables.py`).
- **`backend/app/main.py`** — wired between CORS (innermost) and Audit (outermost), only when `ROE_ENABLED=true`.
- **`.env.example`** — `ROE_ENABLED=false` (opt-in for backward compat).
- **`.env` settings** — `ROE_ENABLED`, `ROE_SESSION_FACTORY` (forward-compat slot).

Order rationale (per the design): **Audit (outermost) → RoE → CORS (innermost)**. Audit sees 403s as they bubble out; CORS handles OPTIONS preflight before RoE sees it.

### PR 2 — Touch classification + free-only filter

- **`backend/app/modules/base.py`** — `TouchClass(StrEnum)` with four members (`PASSIVE_TARGET`, `PASSIVE_THIRDPARTY`, `ACTIVE_TARGET`, `ACTIVE_THIRDPARTY`) plus class attributes `touch_classification` and `requires_paid: bool`.
- **All 14 modules** — classified per a 14-row mapping table; defaults `requires_paid=False` (safe).
- **`backend/app/config.py`** — `tools_only_free: bool` (default `False`) + `before` validator (fail-open on bad env value).
- **`backend/app/modules/__init__.py`** — `_build_registry()` filters out paid modules when `tools_only_free=true`, logs a WARNING per excluded module.

### PR 4 — person_dossier aggregator (Tier 3, gated)

- **`backend/app/modules/person_dossier.py`** — `PersonDossierModule`. Cross-module aggregator — no external IO. Reads completed findings from `employee_osint`, `socmint`, `breach_data`, optionally `email_harvesting`, groups by `email_hash`, emits one `Finding(type=DOSSIER)` per unique identity. Includes a per-dossier LLM coherence call (256 tokens, 30s timeout).
- **`backend/app/utils/encryption.py`** — `hash_email()` (SHA-256 hex), `encrypt_email()` + `decrypt_email()` (Fernet), and `EncryptionKeyMissingError`.
- **`backend/app/models.py`** — `IdentityMap` SQLAlchemy table for encrypted raw-email storage at rest + `FindingType.DOSSIER` enum value (now 16 types).
- **`backend/app/handoff/schema.py`** — `HandoffPacket.person_dossiers: list[HandoffPersonDossierSummary]` (additive, non-breaking; existing 1.0.0 consumers ignore it).
- **`backend/app/config.py`** — `PERSON_DOSSIER_ENCRYPTION_KEY: str | None` (Fernet key).
- **`backend/app/modules/__init__.py`** — 15th entry in `MODULE_REGISTRY`.

Privacy invariants verified at three layers (schema `extra="forbid"`, code-path isolation, storage ciphertext-only). Plaintext emails never reach logs, the handoff, or the LLM.

## Directory structure

```
zimlama-recon/
├── backend/                    # FastAPI Python app
│   ├── app/
│   │   ├── main.py             # FastAPI app factory
│   │   ├── config.py           # pydantic-settings
│   │   ├── database.py         # SQLAlchemy 2 setup
│   │   ├── models.py           # ORM: Job, ModuleRun, Finding, ...
│   │   ├── schemas.py          # Pydantic API models
│   │   ├── cli.py              # Typer CLI
│   │   ├── audit/              # Audit middleware
│   │   ├── orchestrator/       # Job runner, AI validator, rate limiter
│   │   ├── modules/            # 15 recon modules (14 + person_dossier aggregator)
│   │   ├── llm/                # MiniMax M3 client + prompts
│   │   ├── handoff/            # Public handoff contract
│   │   ├── routes/             # FastAPI routers
│   │   ├── report/             # MD + PDF generation
│   │   └── mcp/                # MCP stdio server
│   ├── alembic/                # DB migrations
│   ├── tests/                  # pytest
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                   # Next.js 14
│   ├── src/
│   │   ├── app/                # App Router pages
│   │   ├── components/         # React components
│   │   ├── lib/                # API client, utils, types
│   │   └── stores/             # Zustand stores
│   ├── public/
│   ├── package.json
│   ├── next.config.js
│   ├── tailwind.config.ts
│   └── Dockerfile
│
├── templates/
│   └── brand-kit/              # zimlama brand assets
│       ├── logo/               # SVG variants
│       ├── fonts/              # Google Fonts (Plus Jakarta, Montserrat, IBM Plex Mono)
│       ├── report.css          # PDF report stylesheet
│       ├── report-cover/       # Cover page template
│       ├── components/         # React components
│       ├── tokens.css          # Design tokens
│       ├── tokens.ts           # TS tokens
│       └── README.md
│
├── docs/                       # PRD, RFCs, architecture, handoff spec
│
├── scripts/                    # Helper scripts
│
├── openspec/                   # SDD workflow artifacts
│
├── examples/                   # Sample handoff, sample report
│
├── .github/
│   ├── workflows/              # CI/CD
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── .gitignore
├── .env.example                # Placeholders ONLY
├── LICENSE                     # Apache-2.0
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── Makefile
├── install.sh
└── docker-compose.yml
```

## Data flow: a typical recon job

```
1. User opens UI → Dashboard
2. Clicks "New Job" → form (target + modules + disclaimer modal)
3. POST /api/v1/jobs → creates Job row (status=pending)
4. Background task starts → JobRunner.run_job(job_id)
5. JobRunner updates Job.status = running
6. asyncio.gather(*[_run_single_module(...) for each selected module])
7. For each module:
   a. Create ModuleRun row (status=running)
   b. Acquire rate limit
   c. await module.run(ModuleInput(target, ...))
   d. Persist ModuleRun + Finding rows
8. JobRunner updates Job.status = validating
9. For each completed module:
   a. AIValidator.validate_module_findings(module, target, findings)
   b. Persist AIValidation row (verdict, confidence, recommended_next)
10. HandoffBridge.generate_handoff_for_job(job_id)
    a. Build HandoffPacket from Job + ModuleRuns + AIValidations
    b. Write JSON to ./data/handoffs/h-<date>-<id>.json
    c. Insert Handoff DB row
11. JobRunner updates Job.status = completed, completed_at, duration_seconds
12. UI polls /api/v1/jobs/{id} → shows status
13. User downloads report.pdf (POST /api/v1/jobs/{id}/report, then GET /download)
14. User downloads handoff.json (GET /api/v1/jobs/{id}/handoff/download)
15. User deletes all data (make purge TARGET=example.com)
```

## Data model

```
┌────────────┐
│    Job     │  UUID v4, target, status, selected_modules,
│            │  user_consent, typed_confirmation, dates, duration
└────┬───────┘
     │ 1:N
     ▼
┌────────────┐
│ ModuleRun  │  module_name, tier, status, dates, findings_count,
│            │  raw_output_path, errors
└────┬───────┘
     │ 1:N           1:1
     ▼               ▼
┌────────────┐   ┌──────────────┐
│  Finding   │   │ AIValidation │  decision, summary, confidence,
│            │   │              │  recommended_next_modules
└────────────┘   └──────────────┘

┌────────────┐
│  Handoff   │  1:1 with Job — schema_version, packet JSON, file_path
└────────────┘

┌────────────┐
│ AuditLog   │  timestamp, action, target, job_id, user_id, details
└────────────┘
```

## Concurrency model

- **Single-user** (v0.1): one user, one backend instance
- **Per-job**: one JobRunner instance, modules run in `asyncio.gather`
- **Per-module**: one ModuleRun record, one AI validation
- **DB**: SQLite with `check_same_thread=False` + connection pooling
- **Lifespan**: FastAPI `lifespan` context manager initializes DB + LLM client + orchestrator on startup, cleans up on shutdown

## Security model

### Secrets
- `.env` is gitignored, `chmod 600`
- `MINIMAX_API_KEY` is the only required secret
- All API keys passed via env vars

### Authorization
- Single-user, no auth (v0.1)
- User MUST accept disclaimer + type target to start
- All actions logged to `audit_log`

### Banned targets
Built-in list of RFC 1918 + loopback + link-local + reserved IP ranges. If a job's target resolves to a banned IP, the system aborts immediately.

### Privacy
- No telemetry, no analytics
- All data in `./data/` (local)
- User can purge all data with `make purge TARGET=example.com`

## Performance

- Subdomain enum (47 hosts): ~2-5 min
- Cert transparency: ~30s
- Wayback: ~1-2 min
- DNS enum: ~30s
- Email harvesting: ~1-3 min
- AI validation: ~5-15s per module
- Report generation: ~10s

Total: ~10-20 min for a typical recon (5-6 modules, AI on).

## Deployment

- **Local (single user)**: `./install.sh` (5-10 min on first run)
- **Production (multi-user)**: future work, not in v0.1

## See also

- [PRD-recon-phase1.md](PRD-recon-phase1.md) — Product Requirements
- [RFC-001-stack.md](RFC-001-stack.md) — Tech stack decisions
- [HANDOFF.md](HANDOFF.md) — Public handoff contract
- [MULTI_REPO.md](MULTI_REPO.md) — Multi-repo architecture
