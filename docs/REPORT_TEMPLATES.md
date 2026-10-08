# Report Templates

> **Layer**: Backend (Python Markdown generator) + Node (`md-to-pdf` + Puppeteer)
> **Output**: `<./data/reports/recon-<target>-<job-prefix>.{md,pdf}>`
> **Status**: Released in v0.1.0, report-cover template polished in v0.2.0.

This document describes the structure of `zimlama/recon` PDF reports, where they are written, how the Markdown → PDF pipeline works, and how to customize them.

---

## 1. Where reports live

Every completed job writes two files into `./data/reports/` (configurable via `REPORTS_DIR` in `.env`):

| File | Format | Source | Purpose |
|------|--------|--------|---------|
| `recon-<target>-<jobid8>.md` | Markdown | `MarkdownReportGenerator` | Source of truth — human-readable, greppable, diffable |
| `recon-<target>-<jobid8>.pdf` | PDF (A4) | `PDFGenerator` via `md-to-pdf` | Deliverable — sent to clients, printed, attached to engagement notes |

`<jobid8>` is the first 8 characters of the job's UUID v4. Example: `./data/reports/recon-example.com-a1b2c3d4.md`.

The paths are persisted on the `Job` row (`report_md_path`, `report_pdf_path`) and exposed via:

| Transport | Endpoint / command |
|-----------|--------------------|
| REST | `GET /api/v1/jobs/{job_id}/report` |
| Download | `GET /api/v1/jobs/{job_id}/report/download` |
| MCP | `get_report_path(job_id="<id>")` |

If the PDF generation step fails (Node not installed, Chromium crashes, 2-minute timeout), the Markdown file still exists — the PDF endpoint returns 502 with a clear error and the `Job.error_message` is populated. You can always download the MD and render it locally with `pandoc -o report.pdf report.md`.

---

## 2. Report structure

The Markdown source is built by [`backend/app/report/markdown_gen.py`](../backend/app/report/markdown_gen.py) (`MarkdownReportGenerator`). Sections, in order:

### 2.1 YAML frontmatter

```yaml
---
title: "Reconocimiento Pasivo — example.com"
target: "example.com"
date: "2026-10-13"
job_id: "a1b2c3d4-..."
phase: "01-recon-osint"
ai_validated: true
classification: "CONFIDENTIAL"
generator: "zimlama/recon v0.1.0"
---
```

Greppable for ops pipelines and engagement trackers.

### 2.2 Cover page

The first `#` heading becomes the title. The PDF renderer adds a full-bleed cover via `templates/brand-kit/report-cover/cover.html` — see [§4](#4-the-cover-page).

### 2.3 Executive summary

Module-level counts: total runs, successful runs, total findings, job duration. Empty if zero findings.

### 2.4 Methodology

Hardcoded reference to MITRE ATT&CK (T1589, T1590, T1591, T1592, T1593, T1595, T1596) and OWASP Testing Guide v4.2. Lists every Tier 1 source consulted. Notes that each finding was validated by MiniMax M3.

### 2.5 Findings by module

One `###` section per `ModuleRun` in the job:

```
### 1. subdomain_enum

- **Tier:** tier_1
- **Status:** completed
- **Hallazgos:** 47
- **Duración:** 134.2s

| Valor | Tipo | Fuente | Confianza |
|-------|------|--------|-----------|
| `api.example.com` | subdomain | crt.sh | 0.95 |
| `staging.example.com` | subdomain | subfinder | 0.80 |
...

**AI Summary:** Found 47 subdomains; 12 confirmed active, 5 likely, 30 false positive.
**AI Confidence:** 0.78
**Recommended Action:** CONTINUE
**Next Modules:** shodan_censys, dns_enum
```

A module with zero findings renders `_No se encontraron hallazgos._` instead of an empty table. Findings are truncated to the first 50 per module — the full set is in the database and accessible via `GET /api/v1/jobs/{id}/findings`.

### 2.6 AI insights

One blockquote per module that has an AI validation:

```
## AI Insights (MiniMax M3)

### subdomain_enum

> Found 47 subdomains; 12 confirmed active, 5 likely, 30 false positive.
```

### 2.7 Annexes

| Annex | Content |
|-------|---------|
| A. Comandos ejecutados | Pointer to `./data/audit/` (audit log + stderr of each module) |
| B. Artefactos crudos | Pointer to `./data/artifacts/` (subfinder JSON, crt.sh CSV, etc.) |
| C. Handoff packet | Inline reference to `GET /api/v1/jobs/{id}/handoff` |

### 2.8 Footer

```
_Reporte generado por zimlama/recon v0.1.0 — 2026-10-13T17:42:00Z_
```

---

## 3. Severity badges

The CSS at [`templates/brand-kit/report.css`](../templates/brand-kit/report.css) defines two badge taxonomies:

### 3.1 Severity badges (per-finding)

| Class | Color | Hex | Use |
|-------|-------|-----|-----|
| `.badge-critico` | deep red | `#890f0a` | Critical — exposed admin/config, live credentials |
| `.badge-alto` | orange | `#e55934` | High — admin panel, DB without auth, default creds |
| `.badge-medio` | amber | `#fbb03b` | Medium — login pages, error pages, internal paths |
| `.badge-bajo` | blue | `#3c8dbc` | Low — marketing pages, static assets |
| `.badge-info` | gray | `#6b7280` | Informational only |

### 3.2 AI verdict badges

| Class | Color | Hex | Use |
|-------|-------|-----|-----|
| `.badge-confirmed` | blue | `#3c8dbc` | CONFIRMED verdict |
| `.badge-likely` | amber | `#fbb03b` | LIKELY verdict |
| `.badge-suspected` | gray | `#6b7280` | SUSPECTED verdict |
| `.badge-false-positive` | light gray | `#cccccc` | FALSE_POSITIVE (filtered out) |

The MarkDown never embeds these by hand — it uses the prose form (`HIGH`, `LOW`, etc.). The PDF renderer's CSS graduates them based on the markdown source — see `templates/brand-kit/components/Badges.tsx` (rendered server-side via Puppeteer when `md-to-pdf` runs).

---

## 4. The cover page

The cover is rendered by a separate HTML template at [`templates/brand-kit/report-cover/cover.html`](../templates/brand-kit/report-cover/cover.html), not by the markdown itself. Puppeteer composes the HTML cover page first, then appends the rest of the markdown after a forced page break.

The cover carries:

- zimlama logo (Invader-Zim GIR-inspired) centered, scaled to ~150pt
- Title: `Reconocimiento Pasivo`
- Subtitle: `Fase 1`
- Target: `example.com` (monospace, red brand color)
- Meta block: job_id, phase, date (UTC), engagement name if set
- Classification banner: `CONFIDENTIAL` if `classification=CONFIDENTIAL` in frontmatter

To restyle:

1. Edit `cover.html` (HTML + inline CSS).
2. Re-run a job — `md-to-pdf` picks up the change on next render.

---

## 5. The CSS stylesheet

[`templates/brand-kit/report.css`](../templates/brand-kit/report.css) is read at PDF-generation time by [`backend/app/report/css_style.py`](../backend/app/report/css_style.py) (`load_css()`). It uses CSS variables for theming so swapping to a new brand is a matter of changing 5 hex values at the top:

```css
:root {
  --zimlama-negro: #0a0a0a;
  --zimlama-rojo: #c11b05;        /* brand accent */
  --zimlama-blanco: #faf8f6;
  --zimlama-gris: #4a4a4a;
  --zimlama-piel: #7ab23c;        /* GIR green */
  --zimlama-purple: #6b3fa0;

  /* severity scale (drives badges) */
  --sev-critico: #890f0a;
  --sev-alto: #e55934;
  --sev-medio: #fbb03b;
  --sev-bajo: #3c8dbc;
  --sev-info: #6b7280;
}
```

Fonts: Montserrat (body), Plus Jakarta Sans (headings), IBM Plex Mono (code) — all Google Fonts.

Page setup: A4, margins `25mm 20mm 30mm 20mm`. First page (cover) has `margin: 0` and the cover template brings its own padding. Print color-adjust is set to `exact` so screenshots/pantones render correctly.

---

## 6. The MD → PDF pipeline

[`backend/app/report/pdf_gen.py`](../backend/app/report/pdf_gen.py) (`PDFGenerator`) wraps `md-to-pdf` (npm) in a subprocess with strict process-group cleanup.

```
MarkdownReportGenerator  ──►  ./data/reports/recon-foo-a1b2.md
                                    │
                                    ▼
                             PDFGenerator.convert(md_path)
                                    │
                                    ▼
                          asyncio.create_subprocess_exec(
                              "npx", "--yes", "md-to-pdf",
                              md_path,
                              "--css", _report.css,
                              cwd=reports_dir,
                              start_new_session=True,   # own process group
                          )
                                    │
                                    ▼  (Puppeteer + Chromium inside md-to-pdf)
                          ./data/reports/recon-foo-a1b2.pdf
```

**Key behaviors**:

- **Timeout**: 120 seconds. On timeout, `os.killpg(SIGTERM)` cascades to all child processes (npx spawns node + chromium). A 5-second SIGKILL fallback prevents zombie Chromium workers.
- **Missing Node**: if `npx` is not on `$PATH`, the call logs `npx_not_found` and returns `None`. The MD is still produced.
- **Process-group cleanup**: v0.2.0 hardening (closes audit finding R4-1) — a SIGKILL on `npx` alone used to leak Chromium workers.
- **Atomic CSS staging**: the brand-kit CSS is copied to `reports_dir/_report.css` before subprocess runs, deleted in a `finally`. Avoids stale CSS contamination between concurrent jobs.

### Failure modes

| Symptom | Likely cause |
|---------|--------------|
| `.pdf` never created, `.md` exists | Node missing OR Chromium crashed inside 120s |
| `pdf_conversion_timeout` log | Job had very long tables (>5000 rows) — Chromium choked |
| `pdf_conversion_failed` with `stderr` snippet | Usually a font issue (Google Fonts blocked) — override fonts in `report.css` to system fonts |

---

## 7. How to customize

### 7.1 Add a custom section

Add a method to `MarkdownReportGenerator._build_markdown()`:

```python
# backend/app/report/markdown_gen.py
def _build_markdown(self, include_raw, include_ai, include_annex):
    sections: list[str] = []
    sections.append(self._frontmatter())
    sections.extend(self._cover())
    sections.extend(self._executive_summary())
    sections.extend(self._methodology())

    # New section — insert before "findings by module"
    if self.job.compliance_mode:
        sections.extend(self._compliance_attestation())

    sections.extend(self._findings_by_module(include_raw, include_ai))
    # ... rest unchanged
```

### 7.2 Add a new severity level

1. Add the color CSS variable in `report.css` (e.g. `--sev-emergency: #ff0044`).
2. Add a `.badge-emergency { background: var(--sev-emergency); color: white; }` rule.
3. Use the badge in your markdown by wrapping the text in `<span class="badge badge-emergency">EMERGENCY</span>`. (Markdown inside the report supports a small subset of HTML.)

### 7.3 Switch the rendering engine

The PDF generator is isolated in `pdf_gen.py`. To swap to WeasyPrint, Pandoc, or any other backend:

1. Replace `PDFGenerator.convert()` with your implementation.
2. Keep the same signature: `async def convert(self, md_path: Path) -> Path | None`.
3. No other code touches it.

### 7.4 Skip PDF generation entirely

Useful for headless servers without Node:

```python
# main.py lifespan:
PDFGenerator.__init__ = lambda self: setattr(self, "enabled", False)
```

Or just don't install Node — the MD is always produced, the PDF is best-effort.

### 7.5 Brand kit versioning

The CSS, cover HTML, and brand assets are versioned together. The CSS carries a comment header you can grep:

```css
/* ============================================================
   zimlama brand-kit — report.css
   Styles for markdown-to-PDF report rendering.
   Uses CSS variables for theming.
   ============================================================ */
```

When you change the brand, bump a version comment at the top so engagement-side diffs stay clean.

---

## 8. See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — where the report fits in the request flow
- [AI_VALIDATION.md](AI_VALIDATION.md) — what generates the per-finding verdicts that become badges
- [HANDOFF.md](HANDOFF.md) — `confirmed_targets[]` in the handoff uses the same priority/verdict contract
- [templates/brand-kit/report.css](../templates/brand-kit/report.css) — the stylesheet
- [templates/brand-kit/report-cover/cover.html](../templates/brand-kit/report-cover/cover.html) — the cover page template
