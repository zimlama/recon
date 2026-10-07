# Changelog

All notable changes to zimlama/recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-06

### Added
- Initial release of zimlama/recon Phase 1
- 14 recon modules (6 Tier 1, 4 Tier 2, 4 Tier 3 gated)
- FastAPI backend with Pydantic v2 + SQLAlchemy 2 + Alembic
- Next.js 14 frontend (App Router, TypeScript, Tailwind, Zustand)
- AI validation via MiniMax M3 (OpenAI-compatible)
- Handoff packet schema v1.0.0 (vendor-neutral public contract)
- MCP stdio server (6 tools)
- Report generation: Markdown + CSS-styled PDF via md-to-pdf
- LATAM-aware disclaimer (CO + BR + MX + AR + CL + PE + US + EU)
- Self-hosted Docker Compose (dev + prod profiles)
- GitHub Actions CI (lint + test + typecheck + Docker build)
- Brand kit: zimlama logo (Invader Zim GIR-inspired), design tokens, report CSS
- Apache-2.0 license

### Security
- `.env.example` only — no real secrets in repo
- Audit middleware logs all user actions
- Built-in banned-targets list (RFC 1918, loopback, etc.)
- CORS restricted to configured origins
- WCAG AA color contrast

[Unreleased]: https://github.com/zimlama/recon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zimlama/recon/releases/tag/v0.1.0
