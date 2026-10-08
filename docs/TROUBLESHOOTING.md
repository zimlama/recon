# Troubleshooting

> **Audience**: Operators running `zimlama/recon` (self-hosted single-user mode).
> **Scope**: Common issues from production runs in `mindos/folio/40_proyectos/zimlama-recon/wiki/sesiones/`.

If something is broken and not covered here, open an issue with the output of:

```bash
./scripts/monitor.sh health
```

plus the relevant container log (`docker compose logs backend --tail 200`).

---

## 1. Install & first run

### "Docker daemon not running" / `docker info` fails

```
ERROR: Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Cause**: Docker Engine isn't started, or the user isn't in the `docker` group.

**Fix**:

```bash
# macOS
open -a Docker         # wait ~30s for whale icon to stabilize

# Linux
sudo systemctl start docker
sudo usermod -aG docker $USER
# log out and back in
```

Then re-run `./install.sh`.

### `./install.sh` aborts at "Docker Compose v2 not found"

```
ERROR: 'docker compose version' returned 1
```

**Cause**: Legacy `docker-compose` (Python) was installed but `docker compose` (plugin) wasn't.

**Fix**: Install the Compose plugin:

```bash
# macOS
brew install docker-compose-plugin

# Ubuntu / Debian
sudo apt-get update && sudo apt-get install docker-compose-plugin
```

### `MINIMAX_API_KEY` not configured → AI validation skipped

Every module's report section ends with the badge "AI validation skipped — MINIMAX_API_KEY not configured". This is **not a bug**, it's the stub mode in [AI_VALIDATION.md §2](AI_VALIDATION.md#2-three-operating-modes). The job still completes; the report still produces valid findings without verdicts.

**Fix when ready**: copy `.env.example` to `.env`, set a real `MINIMAX_API_KEY=sk-minimax-...`, then `docker compose restart backend`.

### `subfinder: command not found` (warning, not fatal)

`subfinder` is an optional accelerator for `subdomain_enum`. Without it the module falls back to crt.sh + Censys free search — slower but works.

**Fix (optional)**: install via Go (`go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`) or Homebrew (`brew install subfinder`). The installer does not install it by default.

---

## 2. Per-module failures

### `exiftool not found` → `metadata_analysis` is SKIPPED

`exiftool` is a Perl binary required by `metadata_analysis`. Without it, the module reports `SKIPPED` and the rest of the job continues.

**Fix**:

```bash
# Debian/Ubuntu
sudo apt-get install libimage-exiftool-perl

# macOS
brew install exiftool

# Alpine (Docker)
apk add --no-cache exiftool
```

### `ctypes not found` / `cryptography` import error

The `person_dossier` module (v0.2.0+) uses `cryptography` (Fernet) for email encryption. On stripped-down Linux images:

```
ImportError: No module named '_ctypes'
```

**Fix**: install `libffi-dev` (provides `_ctypes`).

```bash
# Debian/Ubuntu
sudo apt-get install libffi-dev python3-dev
pip install --upgrade cryptography

# Alpine
apk add --no-cache libffi-dev
```

Then `docker compose build --no-cache backend && docker compose up -d`.

### `Permission denied creating handoff file`

```
OSError: [Errno 13] Permission denied: './data/handoffs/h-...json'
```

**Cause**: `./data/` was created by a different UID (often root, on first run).

**Fix**:

```bash
sudo chown -R $USER:$USER ./data ./frontend/.next
chmod -R u+rwX ./data
```

The installer applies `chmod 600` to `.env` and `chmod 700` to `./data` automatically.

### `RateLimitedError after first call`

Logs show:

```
LLM rate limited, waiting 2.0s (Retry-After: default)
LLM rate limited, waiting 4.5s (Retry-After: default)
LLMError: LLM failed after 3 retries
```

**Cause**: MiniMax M3 free tier rate limit, or a shared API key used by too many jobs.

**Fix**:

- Wait — exponential backoff is automatic (1s, 2s, 4s with `Retry-After` + jitter, per [AI_VALIDATION.md §4](AI_VALIDATION.md#4-the-validator-aivalidator--llmclient)).
- Reduce parallel module count: `Settings.RATE_LIMIT_RECON_RPS=5` in `.env`.
- If running concurrent jobs from multiple terminals, use distinct API keys (MiniMax M3 supports this by `MINIMAX_API_KEY` per terminal).

### `MODULE_REGISTRY: module 'foo' not found` (test only)

If you're seeing this in production logs (not tests), check that all 14 module files in `backend/app/modules/` are importable:

```bash
cd backend
python -c "from app.modules import MODULE_REGISTRY; print(sorted(MODULE_REGISTRY))"
```

Should print exactly the 14 module names (15 in v0.2.0+ with `person_dossier`).

---

## 3. Test issues

### "Coverage below 90%"

```
FAIL Required test coverage of 90% not reached. Total coverage: 87.32%
```

**Cause**: New code added without tests, or pre-existing untested scaffolding.

**Fix**:

1. Add tests for your new code in `backend/tests/`.
2. If you hit uncovered wiring code (e.g. `app/main.py` lifespan handler), the project allows this — main.py coverage can stay low; but `app/modules/` must stay > 90%.
3. Pre-existing gaps are listed in `wiki/audits/2026-10-12-pre-release-audit.md`. Don't fix them in a feature PR; open a separate "baseline repair" PR.

### A specific test fails intermittently

Usually flaky timing or shared state:

```bash
# Run in isolation
pytest tests/test_X.py::test_y -x -v

# Run serially (no xdist)
pytest tests/test_X.py -p no:xdist

# Run with verbose logging
pytest tests/test_X.py --log-cli-level=DEBUG
```

If still flaky, check for shared `lru_cache` on `get_settings()` — env-var monkeypatching requires `_reset_settings_cache` (autouse fixture in `tests/conftest.py`).

### `ImportError: cannot import name 'EmployeeOSINTModule' from 'app.modules.employee_osint'`

Pre-existing typo if `origin/developer` is checked out: `app/modules/__init__.py` references `EmployeeOsintModule` but the class is `EmployeeOSINTModule`. Fixed in commit `b56b17a`.

---

## 4. Auth & network

### CORS error in the browser console

```
Access to fetch at 'http://localhost:8000/api/v1/jobs' from origin
'http://localhost:5173' has been blocked by CORS policy: ...
```

**Cause**: `CORS_ORIGINS` in `.env` doesn't include the frontend origin.

**Fix**:

```env
# .env (default — both nginx and Next.js dev)
CORS_ORIGINS=http://localhost:5173,http://localhost:8080,http://127.0.0.1:5173,http://127.0.0.1:8080
```

For a custom origin (e.g. `https://recon.example.com`), append it and restart the backend:

```bash
docker compose restart backend
```

Wildcard `*` is **rejected at startup** (closes audit finding C4); CORS with credentials is **never** allowed.

### "Frontend can't reach backend" but the API works on curl

Two common causes:

1. **Reverse proxy strips `/api`** — if you put nginx/Caddy in front, make sure it forwards `/api/*` to `backend:8000` and rewrites the path. The internal Docker Compose setup uses the frontend container's nginx for this.

2. **`NEXT_PUBLIC_API_URL` wrong** — set at build time:

   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8000
   ```

   Then rebuild the frontend: `docker compose build --no-cache frontend`.

### `401 Unauthorized` on every request

You enabled `RECON_API_KEY` in `.env` but the client isn't sending it.

Default config has `RECON_API_KEY` unset → dev mode bypasses auth. Setting it forces every request to send `Authorization: Bearer <key>`.

```bash
curl -H "Authorization: Bearer $RECON_API_KEY" http://localhost:8000/api/v1/jobs
```

The MCP server (`python -m recon.mcp.server`) and the frontend (when `NEXT_PUBLIC_API_KEY` is set) are pre-wired to send the header. Browser-based access needs the key in local storage by way of the UI's first-load modal.

---

## 5. RoE enforcement (v0.2.0+)

### `403 roe_not_authorized` on `POST /api/v1/jobs`

You enabled `ROE_ENABLED=true` but no `RoE` row exists in the DB.

**Fix**: either disable RoE (`ROE_ENABLED=false`) or create a RoE first:

```python
# via MCP
create_roe(
    target="example.com",
    scope_pattern="*.example.com",
    valid_until="2026-12-31T23:59:59Z",
    signoff_by="<operator name>",
)

# via REST
curl -X POST http://localhost:8000/api/v1/roes \
  -H "Authorization: Bearer $RECON_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scope_pattern": "*.example.com",
    "valid_until": "2026-12-31T23:59:59Z",
    "signoff_by": "Operator Name"
  }'
```

See [AI_VALIDATION.md §9](AI_VALIDATION.md#9-when-things-go-wrong) for status codes per failure mode.

### "RoE expired" even though `valid_until` is future

Check timezone: `valid_until` is stored UTC-naive in SQLite. If you sent `2026-10-13T23:59:59-05:00`, normalize to UTC: `2026-10-14T04:59:59Z`.

---

## 6. Reports & handoff

### PDF is blank or has only the cover

Cause: the Markdown source has no sections beyond the cover. Usually a "all modules failed" job (every module timed out).

**Fix**:

```bash
make logs TARGET=example.com   # check job logs
make purge TARGET=example.com  # reset and re-run
```

### Handoff JSON has `schema_version: "1.0.0"` but my Phase 2 consumer expects 1.1.0

Additive new fields don't bump the **minor** version — `schema_version` advances only on breaking changes per [HANDOFF.md versioning policy](HANDOFF.md#versioning-policy). Check the v0.2.0 release notes (`CHANGELOG.md`) for the new `person_dossiers[]` field at the top level; it's additive, so 1.0.0 consumers ignore it gracefully.

### `handoff_status: "failed"` on a completed job

The handoff export threw. The recon succeeded; only the vendor-neutral export failed.

```bash
docker compose logs backend | grep handoff_generation_failed
```

Common causes: `./data/handoffs/` not writable, stale `Job.error_message` cleared too early, or schema mismatch on a new field. The handoff can be regenerated manually:

```bash
python -m recon.handoff.export <job_id>
```

---

## 7. Performance

### A module hangs for >10 minutes

Per v0.2.0 resilience fix, every module has `asyncio.wait_for(timeout=600)`. If you see `asyncio.TimeoutError` in logs, the module is being terminated. Common culprits:

- `subdomain_enum` with huge wordlist on a slow resolver
- `wayback_machine` if the CDX API is rate-limiting
- `dns_enum._attempt_axfr` if the zone transfer times out

You can lower the per-module timeout with `Settings.RATE_LIMIT_RECON_RPS` (per-second cap) but the hard ceiling is 600s per module.

### Job gets stuck in `VALIDATING` forever

The pre-v0.2.0 disaster case. Fixed by `JobRunner.sweep_stuck_jobs(max_age_minutes=30)` called on `lifespan` startup. If you still see it on an unpatched install, restart the backend — the sweeper catches it.

---

## 8. Where to get more help

| Where | Use it for |
|-------|------------|
| `wiki/sesiones/` in the Folio mirror | Pre-release sessions, what changed and why |
| `wiki/audits/2026-10-12-pre-release-audit.md` | All known issues + resolutions through v0.2.0 |
| `make logs TARGET=example.com` | Per-target audit trail + stderr from every module |
| `docker compose logs backend --tail 200` | Last 200 lines of the backend |
| GitHub Issues | New bugs not yet documented |

When filing an issue, include:

```
- zimlama/recon version (git rev-parse HEAD)
- OS + Docker version (`docker version`)
- .env values minus secrets (paste REDACTED)
- Reproduction steps
- Full error traceback + 50 lines of surrounding logs
```
