# RFC-001: Tech Stack Selection

**Status**: Accepted
**Date**: 2026-10-06
**Author**: zimlama

## Context

`zimlama/recon` needs a full-stack web app that can:

- Run 14 recon modules (mix of Python subprocess, HTTP, MCP tools)
- Validate findings with an LLM (MiniMax M3, OpenAI-compatible)
- Serve a web UI for job management + reports
- Be self-hosted via Docker on macOS + Linux
- Provide a vendor-neutral handoff JSON for future Phase 2 tools

## Decision

| Layer | Technology | Version |
|-------|------------|---------|
| Backend framework | FastAPI | 0.110+ |
| Backend language | Python | 3.11+ |
| Validation | Pydantic | v2.5+ |
| ORM | SQLAlchemy | 2.0+ |
| Migrations | Alembic | 1.13+ |
| Type checker | mypy | 1.8+ (strict) + pyright |
| Linter | ruff | 0.4+ |
| Formatter | ruff format | 0.4+ |
| Test runner | pytest | 8.0+ + pytest-asyncio + pytest-cov |
| HTTP async | httpx + aiohttp | latest |
| Logging | structlog | 24+ |
| CLI | typer | 0.12+ |
| Frontend framework | Next.js | 14.2+ (App Router) |
| Frontend language | TypeScript | 5.5+ (strict) |
| Frontend UI | React | 18.3+ |
| Styling | Tailwind CSS | 3.4+ |
| Components | shadcn/ui | latest (copy-paste) |
| State | Zustand | 4.5+ |
| Form validation | Zod + react-hook-form | latest |
| Frontend tests | Vitest + Testing Library | latest |
| E2E tests | Playwright | latest |
| Frontend linter | ESLint | 8.57+ |
| Database | SQLite | 3 (built-in) |
| Container | Docker Compose | v2 |
| LLM | MiniMax M3 (OpenAI-compat) | MiniMax-M3 |
| Report MD → PDF | md-to-pdf (Node) | latest |
| MCP | stdio server (custom impl) | MCP 1.0+ |
| CI | GitHub Actions | latest |
| License | Apache-2.0 | — |

## Alternatives considered

### Backend

| Option | Why not |
|--------|---------|
| Django | Too heavy for a recon tool; ORM is good but admin UI is bloat |
| Flask | Lacks async, type hints, OpenAPI auto-gen |
| Express/Node | Mature MCP SDK in Python; subprocess management is better in Python |

### Frontend

| Option | Why not |
|--------|---------|
| Vue 3 + PrimeVue | Next.js has better TypeScript + RSC + standalone build |
| SvelteKit | Smaller community; less mature for enterprise |
| Pure React (no Next.js) | Loses SSR, RSC, file-based routing, API routes |

### Database

| Option | Why not |
|--------|---------|
| PostgreSQL | Single-user, no need for concurrency; adds setup complexity |
| MongoDB | Document DB is overkill; relationships matter for jobs/findings |
| MySQL | Same as Postgres; SQLite is simpler |

### AI

| Option | Why not |
|--------|---------|
| OpenAI GPT-4 | Recurring costs; user wanted vendor-neutral + cost-effective |
| Anthropic Claude | Same cost issue; user chose MiniMax M3 |
| Local Llama 3 (Ollama) | Requires GPU; user explicitly chose MiniMax M3 |
| Mixtral | Less mature SDK; OpenAI-compat was preferred |

### Report

| Option | Why not |
|--------|---------|
| Pandoc + LaTeX | Heavy, complex setup, xelatex required |
| WeasyPrint (Python) | Good but user explicitly chose md-to-pdf |
| wkhtmltopdf | Deprecated, old WebKit |
| Puppeteer direct | User asked for md-to-pdf which is a thin wrapper over Puppeteer |

## Consequences

### Positive

- FastAPI + Pydantic v2: type-safe, auto OpenAPI, async-native
- Next.js 14: modern React with SSR/RSC, standalone Docker build
- SQLite: zero setup, single-user, swap to Postgres = 1 line via DATABASE_URL
- MiniMax M3: OpenAI-compat = easy migration if provider changes
- md-to-pdf: matches user's explicit request

### Negative

- Two languages (Python + TypeScript) → two toolchains, two linters
- SQLite for production means no multi-writer concurrency (acceptable for single-user)
- MiniMax M3 is a newer provider; SDK is OpenAI-compat but quirks may appear
- md-to-pdf requires Node.js in the backend Docker image (slight bloat)

### Mitigations

- TDD discipline + 90% coverage gate catches integration issues
- SQLAlchemy 2 makes Postgres swap trivial (1 line)
- LLM client uses retry with exponential backoff + stub mode
- Node is a well-known runtime; 80MB image bloat is acceptable

## Migration path

If we outgrow any of these choices:

- **SQLite → Postgres**: change `DATABASE_URL`, no code change (SQLAlchemy abstracts it)
- **MiniMax M3 → OpenAI/Anthropic**: same OpenAI-compat API, just change `MINIMAX_BASE_URL` + `MINIMAX_API_KEY`
- **md-to-pdf → WeasyPrint**: same `MarkdownReportGenerator` output, just swap `PDFGenerator` impl
- **Vue/React switch**: would require rewriting frontend, but backend API contract is stable

## Approval

- [x] Approved by zimlama (project owner)
- [ ] Reviewed by community (TBD after v0.1.0 release)
