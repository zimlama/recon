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

## 7. Install failures on small VMs behind firewalls (added v0.2.1)

These six failures each blocked `./install.sh` end-to-end on a 5 GB-class VM behind a MikroTik firewall. The v0.2.1 release fixes them in code (`backend/Dockerfile`, `install.sh`); this section exists so an operator hitting one of them knows what happened and what to do.

> **Walk-down order**: when an install fails with several stacked errors, fix them in this order: network → curl → disk → permissions → runtime. Each row below has the verbatim error message and the fix.

### `lookup proxy.golang.org: no such host` (in `go install` step)

Go 1.20+ uses a pure-Go resolver. It falls back to TCP when UDP DNS answers are too small. Some firewalls (notably MikroTik) accept UDP DNS queries but reject TCP DNS — the resolver then fails with `no such host` even though `nslookup proxy.golang.org` works from the host shell.

**Fix (one-time, on the VM host — requires `sudo`):**

```bash
sudo tee /etc/docker/daemon.json > /dev/null <<'JSON'
{ "dns": ["1.1.1.1", "8.8.8.8"] }
JSON
sudo systemctl restart docker
```

Verify:
```bash
docker run --rm alpine sh -c "nslookup proxy.golang.org 2>&1 | tail -4"
# Should return Cloudflare/Google IPs, not the local router's.
```

> **Why this lives on the host, not in the build**: `RUN echo nameserver ... > /etc/resolv.conf` in the Dockerfile fails (BuildKit marks `/etc/resolv.conf` read-only), and `docker buildx create --driver-opt dns=...` is rejected by the `docker-container` driver. The daemon-level `dns` directive is the only knob that propagates to every container.

### `curl: (28) Connection timed out after 300354 milliseconds` (downloading `go.dev/dl/go*.tar.gz`)

`curl`'s default `--connect-timeout` is **300 seconds**. Some CDN frontends (incl. `go.dev` on first SYN) take longer, especially through firewalls that inspect stateful connections. `wget` retries until `--timeout=600` and usually succeeds.

**Fix in v0.2.1**: `backend/Dockerfile:59` passes `--connect-timeout 600 --max-time 1800 --retry 5 --retry-all-errors` to the curl that pulls the Go toolchain.

**Workaround if you must modify the Dockerfile yourself**: same flags on any other `RUN curl -fsSL https://...` step. Cheap insurance against timeout variance.

### `./install.sh: line 54: NC: unbound variable`

Only triggered when running `install.sh` non-interactively (`nohup ./install.sh </dev/null &`, or in a CI runner without a PTY). `install.sh:47` non-TTY else-branch forgot to set `NC='\033[0m'`, but every log helper (`log`, `ok`, `warn`, `err`, `section`) uses `${NC}`. `set -u` then aborts.

**Fix in v0.2.1**: `514ad72` adds `NC=''` to the else-branch.

**To confirm you're hitting this, not a different issue**:

```bash
./install.sh </dev/null
# If this crashes immediately at "─── Prerequisites ───" or similar,
# it's the NC issue (or a sibling color var).
```

### `mkdir /home/recon/tmp/go-build*: no space left on device`

On hosts with ≤5 GB free disk, two parallel Docker image builds (`backend` + `frontend`) exhaust space before `go install subfinder` finishes. Both `GOCACHE` and `TMPDIR` were already moved out of `/tmp` (a336b27), but intermediate build artifacts still got committed to the layer if not cleaned in the same `RUN`.

**Fix in v0.2.1**: `6a4b64d` keeps `GOCACHE` / `TMPDIR` on real disk but adds `go clean -cache && go clean -modcache` at the end of the `go install` `RUN` so the committed layer state contains only `/home/recon/go/bin/{subfinder,httpx,waybackurls,katana}`.

**Workaround before running `install.sh`**:

```bash
docker system prune -af --volumes
docker builder prune -af
df -h /    # confirm at least 4 GB free
```

### `mkdir /home/recon/.cache/go-build: permission denied`

This was a regression introduced by an earlier attempt (`63ca603`) that used BuildKit `--mount=type=tmpfs` and `--mount=type=cache`. BuildKit's mounts are `root:root mode 0755` by default — running `USER recon` immediately afterwards fails on the first write.

**Fix in v0.2.1**: `6a4b64d` drops the `--mount` directives entirely. If you see this on a custom Dockerfile, drop the mounts and use `go clean` at end of `RUN`.

### `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file` (after install builds, container Restarting loop)

`docker-compose.yml` bind-mounts `./data:/app/data`. Bind mounts preserve *host* ownership. On a fresh VM, `./data` was created by an earlier failed run as `root:root mode 0755`. The container's `recon` user (UID 999) can't open `/app/data/recon.db` for writing.

**Fix in v0.2.1**: `bb82934` adds `chmod 777 ./data` in `install.sh:547` immediately before `docker compose up`.

**Workaround if you can't re-run install.sh**:

```bash
chmod 777 ./data    # or: sudo chown 999:999 ./data
docker compose --profile prod up -d
```

---

## 8. CI failures (maintainer / contributor)

### "Invalid workflow file: `.github/workflows/release.yml#L15` — workflow is not reusable as it is missing a `on.workflow_call` trigger"

The `release.yml` workflow calls `uses: ./.github/workflows/ci.yml` to re-run regression tests before publishing Docker images, but `ci.yml` was missing the required `on: workflow_call` trigger. Without it, every release run fails at parse time, contaminating the CI status UI on `main` and silently breaking the automated release pipeline (Docker image publish + GitHub Release notes for future tags).

**Fix** (one line in `.github/workflows/ci.yml`):

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_call:       # required for `uses: ./.github/workflows/ci.yml` from release.yml
```

Other triggers are unaffected; only enables `release.yml` to call `ci.yml` as a reusable workflow. See commit `0bc82bc` (PR #18).

**Verify after merge**:

```bash
gh run list --workflow release.yml --limit 5    # should show green runs after next tag push
gh pr view 18 --json statusCheckRollup          # on PR; CI jobs should pass
```

### "Failed to restore: Cache service responded with 400" / `pip install` exit code 1 in backend CI

GitHub Actions Cache Service intermittently returns HTTP 400 when restoring `pip` or `pnpm` cache. Backend pytest, ruff, and mypy all die in setup because `pip install -e ".[dev]"` can't run while the cache restore is failing. Backend tests fail in 7–9 seconds (before any actual test runs).

**Workaround A** — clear caches from the GitHub UI: `Actions → Caches → Delete all`, then re-trigger the workflow.

**Workaround B** — re-open the PR: `gh pr close <num> && gh pr reopen` resets the run state.

**Workaround C** (last resort) — make the cache optional by removing `cache: 'pip'` and `cache-dependency-path` from `actions/setup-python`. CI will run ~30 s slower per job but won't depend on the cache service.

This is a GitHub Actions infrastructure issue, not a code issue. v0.2.1 was shipped with manual image publish + manual release notes because of this combined with the missing `workflow_call` trigger above.

---

## 9. Where to get more help

For the **v0.2.1 install-failure series in detail** (timeline + commit messages + verbatim shell transcripts), see [postmortems/v0.2.1-release.md](postmortems/v0.2.1-release.md).

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
