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

## 10. Development lessons from Issue #24 baseline repair

> **Added in v0.3.0-pre** (Issue #24 baseline-repair: PR-A ruff, PR-B mypy, PR-C coverage, PR-D pnpm-lock).
> **Format**: each lesson follows the operator's opencode `lessons-doc rule` (mandatory 4-part format) — **Symptom → Diagnosis → Root cause → Fix**. Paste the verbatim Symptom into `grep` / `Ctrl+F` to find the fix again in 6 months.
> **Audience**: contributors working on `backend/app/`, the test suite, or the CI workflow files.

These six lessons cost real time during the Issue #24 baseline repair across four PRs. They are recorded here so the next contributor doesn't repeat the same archaeology.

### Lesson index

| # | Symptom (grep-able) | Trigger context |
|---|---|---|
| 1 | `No such command 'init-db'. Did you mean 'init-db-cmd'?` | Typer CLI test (`tests/test_cli.py`) |
| 2 | `AttributeError: <module 'app.cli'> does not have the attribute 'LLMClient'` | pytest mock on a CLI command |
| 3 | typer exits with code 2 → `assert result.exit_code == 0` fails | Calling `app.cli.main()` directly from tests |
| 4 | Test passes in isolation, fails in full suite: `assert 0 == 1` (file not at expected path) | `@lru_cache` `Settings` + monkeypatch in `tests/test_handoff_exporter.py` |
| 5 | `ruff check .` in CI fails with 397 errors on files NOT touched in the PR | ruff version mismatch between CI (0.4.0) and local (0.15.x) |
| 6 | `ERR_PNPM_NO_LOCKFILE  No lockfile found in /home/runner/work/recon/recon/frontend` | First run on `frontend/` after `pnpm install` locally without committing the lockfile |

---

### 1. Typer command name auto-derivation

```
No such command 'init-db'. Did you mean 'init-db-cmd'?
```

**Diagnosis** — confirm the Typer-derived command name:

```bash
python3 -c "from app.cli import cli; [print(c.name) for c in cli.registered_commands]"
```

You will see `init-db-cmd` (not `init-db`).

**Root cause**: Typer auto-derives the command name from the function name by replacing underscores with hyphens. `init_db_cmd` → `init-db-cmd`, NOT `init-db`. The `Did you mean` hint is Typer's edit-distance suggestion — the test is calling the *human-plausible* name, not the *Typer-derived* one.

**Fix** — either match the derived name in the test, or rename the function:

```python
# Option A: use the Typer-derived name
def test_init_db():
    result = runner.invoke(cli, ["init-db-cmd"])
    assert result.exit_code == 0

# Option B: rename the function so Typer derives the command you wanted
@app.command()
def init_db() -> None:     # underscore + cmd suffix dropped
    ...
    # runner.invoke(cli, ["init-db"]) now works
```

> [!info] Verify-by-grep pattern
> When a Typer test fails with a "No such command" line that contains `Did you mean`, the answer is one `python3 -c` away — list the registered commands.

---

### 2. Local function-level imports break naive patching

```python
AttributeError: <module 'app.cli'> does not have the attribute 'LLMClient'
```

**Diagnosis** — prove the import lives inside the function, not at the module top:

```bash
# Confirms the name is NOT in the module namespace:
python3 -c "import app.cli; print(hasattr(app.cli, 'LLMClient'))"    # → False

# Now open app/cli.py and grep for the import:
grep -n "from app.llm.client" app/cli.py
# Hits inside a `def ...():` block, not at column 0.
```

**Root cause**: when a command does `from app.llm.client import LLMClient` *inside* the function body (not at module top-level), the name is bound in the function's **local** namespace only, never in `app.cli`'s module namespace. `patch("app.cli.LLMClient", ...)` therefore fails with `AttributeError` — pytest's `mock.patch` resolves the dotted path against the **module's** globals, not the function's locals.

**Fix** — patch at the import source, not at the consumer:

```python
# ❌ Doesn't work — LLMClient was never bound on app.cli
with patch("app.cli.LLMClient") as mock_llm:
    ...

# ✅ Works — patch where the name actually lives
with patch("app.llm.client.LLMClient") as mock_llm:
    ...
```

> [!warning] Anti-pattern
> Reach for `from x import y` at module top-level when the imported symbol is also used by tests that `patch()` it. Function-local imports are fine for cold-path dependencies but invisible to mock-patchers.

---

### 3. `main()` reads `sys.argv` when called from tests

```
Usage: cli [OPTIONS] COMMAND [ARGS]...
Try 'cli --help' for help.

Error: No such command 'tests/test_cli.py'.
```

(Reported by pytest as `SystemExit: 2` → `assert result.exit_code == 0` fails.)

**Diagnosis** — narrow the failure to `argv` contamination:

```bash
# Outside pytest — works fine:
python3 -c "from app.cli import main; main()"                  # exit 0

# Inside pytest — fails with the "No such command 'tests/test_cli.py'" error:
pytest tests/test_cli.py::test_main_default -x

# Confirm the implementation reads argv indirectly:
grep -n "def main" app/cli.py
# Likely hits:  def main() -> None: cli()    # no args forwarded
```

**Root cause**: Click/Typer's `cli()` invocation without explicit args falls back to reading `sys.argv`. Pytest populates `sys.argv` with its own args (`['tests/test_cli.py', '-v', ...]`), which typer then interprets as command names. Outside pytest, `sys.argv` is `['']` and `cli()` is a no-op. Inside pytest it's the dotted test path.

**Fix** — patch the `cli` symbol that `main()` would call before invoking it:

```python
from unittest.mock import patch
from app.cli import main

def test_main_default():
    with patch("app.cli.cli") as mock_cli:      # prevents the real CLI from reading argv
        rc = main()
    assert rc == 0
    mock_cli.assert_called_once_with()
```

> [!tip] Cleaner alternative
> If you can change `main()`, give `cli` an explicit `args=None` so it falls back to `sys.argv[1:]` only when no args were passed. Tests can then pass a real `["init-db-cmd"]` list and avoid `sys.argv` mocking entirely.

---

### 4. `Settings` cached via `@lru_cache` needs module-level binding patch

```python
AssertionError: assert 0 == 1     # file not created where the test expected
```

**Diagnosis** — confirm two different `Settings` instances are in play:

```bash
# The exporter's cached binding:
python3 -c "from app.handoff.exporter import settings; print(id(settings))"

# The cached getter's instance (may differ if another test rebuilt Settings):
python3 -c "from app.config import get_settings; print(id(get_settings()))"

# If the two IDs differ → the bug. Also check:
grep -n "Settings(" app/handoff/exporter.py
grep -n "@lru_cache" app/config.py
```

**Root cause**: `get_settings()` is decorated with `@lru_cache`, and `app/handoff/exporter.py` does `from app.config import get_settings; settings = get_settings()` at **module load time**. If another test (running earlier in the suite) calls `Settings(...)` directly, that fresh instance is *not* the cached one — `monkeypatch.setattr(get_settings(), "HANDOFFS_DIR", str(tmp))` mutates a different object from the one `exporter.settings` already cached. Both instances have a `HANDOFFS_DIR` attribute, but pointing at different directories.

**Fix** — patch the **module-level binding** the consumer actually reads, not the getter's return value:

```python
# tests/test_handoff_exporter.py
from app.handoff import exporter as exporter_mod    # gives access to the cached binding

def test_handoff_export_writes_to_tmp(monkeypatch, tmp_path):
    target = tmp_path / "handoffs"
    monkeypatch.setattr(exporter_mod.settings, "HANDOFFS_DIR", str(target))
    # ... exporter will write to target, not to the cached Settings.HANDOFFS_DIR
```

> [!warning] Why `monkeypatch.setenv("HANDOFFS_DIR", ...)` is not enough
> The cached `Settings` instance was constructed at import time from the *initial* environment. `setenv` after import does not refresh the cached object — it would require calling `_reset_settings_cache()` (already exposed by the autouse fixture in `tests/conftest.py` if you need it; use it sparingly because it invalidates the cache for the rest of the suite).

---

### 5. CI ruff 0.4.0 vs local 0.15.x rule mismatch on pre-existing files

```
ruff check .
app/cli.py:1:1: I001 Import block is un-sorted or un-formatted
app/cli.py:3:1: F401 'os' imported but unused
...  (397 errors total, all on files NOT touched in the current PR)
```

**Diagnosis** — confirm the version delta between CI and local, and confirm the failing files pre-date the PR:

```bash
# In CI:
pip show ruff | grep Version                     # → 0.4.0

# Locally:
ruff --version                                  # → 0.15.x

# Confirm the failing files are not part of the current PR:
gh api repos/zimlama/recon/actions/runs/<id>/logs | grep '\.py:[0-9]+:' | awk -F: '{print $1}' | sort -u
git diff --name-only origin/developer HEAD      # current PR's touched files
# Intersection = 0 → failures are pre-existing, not regressions.
```

**Root cause**: CI pins `ruff==0.4.0` (older version with narrower rule coverage), but local development uses `ruff==0.15.x` (newer, stricter). The repo's `pyproject.toml` does not override every rule, so the version delta surfaces as new errors. These are **NOT regressions introduced by the PR** — they are pre-existing bugs that the newer ruff is now flagging.

**Fix** — pick one of the two paths and document the choice:

```bash
# Path A — match local to CI (cheap, may hide newer rules):
pip install "ruff==0.4.0"

# Path B — admin-merge per the documented #24 pattern:
# The only CI failures are pre-existing bugs, not regressions. Either:
#   (i) ship the PR with the older ruff temporarily, fix the ruff-cosmetic
#       warnings in a follow-up PR; OR
#  (ii) bump CI to ruff==0.15.x and absorb the 397 fixes in this PR.
```

> [!info] Pin decision
> The v0.3.0-pre plan is Path B(ii): bump CI's ruff pin to match local, and absorb the 397 fixes into PR-A. Don't take Path A — you'd be debugging two rule sets in your head for the lifetime of the project.

---

### 6. Missing `pnpm-lock.yaml` causes `--frozen-lockfile` CI failures

```
ERR_PNPM_NO_LOCKFILE  No lockfile found in /home/runner/work/recon/recon/frontend
```

**Diagnosis** — confirm the file is missing and CI expects it:

```bash
ls frontend/pnpm-lock.yaml                       # → "No such file or directory"
cat .github/workflows/ci.yml | grep -A 2 "pnpm install"
# Expect:  pnpm install --frozen-lockfile
```

**Root cause**: developers ran `pnpm install` locally to install dependencies but never committed the resulting `pnpm-lock.yaml`. CI's `--frozen-lockfile` mode then fails because no lockfile exists to freeze against. **Two side effects** beyond the failed build:

1. Every CI run regenerates the dependency tree from scratch — non-reproducible builds and ~30 s added latency per frontend job.
2. A class of supply-chain attacks: a transitive dep can swap between runs because there's no signed, version-pinned lockfile to gate against. `--frozen-lockfile` is the defense.

**Fix** — commit the lockfile that `pnpm install` already produced locally:

```bash
cd frontend && pnpm install                       # regenerates pnpm-lock.yaml if missing
git add pnpm-lock.yaml
git commit -m "chore(frontend): add pnpm-lock.yaml"
```

> [!warning] Don't re-generate the lockfile after fixing real bugs
> If you ever see "lockfile out of sync" errors after a real bug fix, **re-run** `pnpm install`, **inspect** `git diff pnpm-lock.yaml` for unexpected version bumps, **then commit**. A 1 000-line lockfile diff with mysterious bumps is a supply-chain indicator, not a routine update.

---

## 10. PR-G2 gate-flip lessons (Issue #30 Phase 1.5A2)

This section collects the cross-cutting lessons from flipping the `npm audit` and `trivy fs` gates from advisory (`|| true` / `exit-code: 0`) to **blocking** in `main`. The follow-up chain (PR #51 → PR #52 → PR #54) uncovered five distinct root causes; each is below in the standard 4-part format. The verbatim error strings are what to grep for in CI logs.

### 10.1 `pnpm overrides` in `package.json` is silently ignored by pnpm ≥ 11

**Symptom** — `pnpm install` does not apply the `overrides` field declared at the root of `frontend/package.json`; the lockfile shows the old (vulnerable) version. pnpm prints no warning.

```
"overrides": {
  "postcss-selector-parser": "^7.1.0"  // declared in package.json
}
// pnpm-lock.yaml still pins postcss-selector-parser@6.1.4 — no error
```

**Diagnosis** —
```bash
grep "postcss-selector-parser@" frontend/pnpm-lock.yaml   # → 6.1.4
pnpm --version                                            # → 12.11.2
```

The `overrides` field is documented in `pnpm` docs as a **legacy** location. Since pnpm v11 it is no longer read; pnpm reads overrides only from `pnpm-workspace.yaml` (and the deprecated `"pnpm": { "overrides": ... }` in `package.json`).

**Root cause** — the v0.2.0 release was set up with pnpm 9 and the legacy `overrides` field worked. We then upgraded pnpm locally to 12, but nobody re-read the docs. The lockfile kept the old (vulnerable) resolutions because the override was effectively a no-op.

**Fix** — move the field to `frontend/pnpm-workspace.yaml`:
```yaml
# /frontend/pnpm-workspace.yaml
packages:
  - '.'

overrides:
  postcss-selector-parser: ^7.1.0
  glob: '>=10.5.0'
  postcss: '>=8.5.18'
```

After `pnpm install`, the lockfile pins `postcss-selector-parser@7.1.6`, `glob@13.0.6`, `postcss@8.5.30` (verified by `pnpm why <pkg>` and `grep`).

### 10.2 pnpm 9 vs pnpm 12 lockfile format incompatibility

**Symptom** — CI's `Frontend install` job fails with:
```
ERROR  packages field missing or empty
##[error]Process completed with exit code 1.
```
even though `pnpm install --frozen-lockfile` works fine locally.

**Diagnosis** —
```bash
# CI:
gh api .../jobs/<id>/logs | grep -A 1 "Setup Pnpm"
# → pnpm 9.15.4 (via pnpm/action-setup@<sha> with version: 9)
# Local:
which pnpm   # → 12.11.2
```

**Root cause** — the lockfile was generated locally with pnpm 12 which writes a v9-format lockfile that pnpm 9's reader rejects. The lockfile IS valid v9 (it has `lockfileVersion: '9.0'` and a `packages:` block), but pnpm 9's stricter reader complains "packages field missing or empty" when the workspace file lacks an explicit `packages:` declaration.

**Fix** —
1. Add `packages: - '.'` to `frontend/pnpm-workspace.yaml` (declares the single-package workspace, pnpm 9's reader now happy).
2. Regenerate `frontend/pnpm-lock.yaml` with the same pnpm version CI uses:
   ```bash
   # Local-only, NOT in package.json:
   /Users/leonardomejia/Library/pnpm/pnpm install --no-frozen-lockfile
   ```

Long-term: pin pnpm in `package.json#packageManager` so local and CI always agree.

### 10.3 `trivy-action` v0.36.0: use `trivyignores`, not `ignorefile`

**Symptom** — CI fails on the `trivy fs` step with:
```
Unexpected input(s) 'ignorefile', valid inputs are
['scan-type', 'image-ref', 'input', 'scan-ref', 'exit-code', ...]
```

**Diagnosis** —
```bash
gh api .../jobs/<id>/logs | grep -i "ignorefile"
# → "Unexpected input(s) 'ignorefile'..."
# But locally:
trivy fs --ignorefile .trivyignore --exit-code 1 .   # → exit 0 (CLI works)
```

**Root cause** — the `aquasecurity/trivy-action` Action wraps the `trivy` CLI but uses its own input vocabulary. The CLI's `--ignorefile` flag is exposed in the Action as **`trivyignores`** (plural, comma-separated). Plain `ignorefile` is not a valid Action input, even though it sounds like the CLI flag.

**Fix** — rename in the workflow `with:` block:
```yaml
- name: Run trivy filesystem scan
  uses: aquasecurity/trivy-action@v0.36.0
  with:
    scan-type: "fs"
    scan-ref: "."
    trivyignores: ".trivyignore"   # ← correct input name
    exit-code: "1"
```

### 10.4 SARIF mode in `trivy-action` silently unsets the severity filter

**Symptom** — `trivy fs` exits 1 in CI after `.trivyignore` is in place, even though the same command exits 0 locally. CI duration: 161 ms (way too short for an actual scan — the action returned 1 without doing a real scan).

```
Found ignorefile '.trivyignore':   ← file IS being read
# ... file contents echoed ...
Building SARIF report with all severities
Running Trivy with options: trivy fs .
##[error]Process completed with exit code 1.
```

**Diagnosis** — read the `entrypoint.sh` of `trivy-action` v0.36.0 (the wrapper script that runs the action):
```bash
if [ "${TRIVY_FORMAT:-}" = "sarif" ]; then
  if [ "${INPUT_LIMIT_SEVERITIES_FOR_SARIF:-false,,}" != "true" ]; then
    echo "Building SARIF report with all severities"
    unset TRIVY_SEVERITY            # ← HERE
  fi
fi
```

**Root cause** — the SARIF spec wants all severities in the report, so the Action **unsets** `TRIVY_SEVERITY` before invoking `trivy` when `format=sarif` and `limit-severities-for-sarif != true`. Combined with `exit-code: "1"`, ANY non-ignored CVE of ANY severity (including moderate/low) blocks the build. The `.trivyignore` covers CRITICAL+HIGH, but the next 14.x advisories also include 11 MODERATE + 2 LOW that aren't allowlisted.

**Fix** — set the explicit severity-cap in the Action:
```yaml
- name: Run trivy filesystem scan
  uses: aquasecurity/trivy-action@v0.36.0
  with:
    scan-type: "fs"
    scan-ref: "."
    format: "sarif"
    severity: "HIGH,CRITICAL"
    limit-severities-for-sarif: "true"   # ← preserve the filter
    trivyignores: ".trivyignore"
    exit-code: "1"
```

`limit-severities-for-sarif: "true"` keeps `TRIVY_SEVERITY=HIGH,CRITICAL` in the env, so the SARIF report only contains HIGH+CRITICAL findings, and `exit-code: 1` only blocks on those.

### 10.5 `pnpm dlx` in `security.yml` needs `corepack enable`

**Symptom** — the `npm audit` job in `security.yml` fails immediately:
```
/usr/bin/bash: line 1: pnpm: command not found
##[error]Process completed with exit code 127.
```

**Diagnosis** —
```bash
gh api .../jobs/<id>/logs | grep -B 1 "pnpm dlx"
# → "pnpm: command not found" before any pnpm command runs
# Compare with the frontend CI workflow (ci.yml) which has:
#   - uses: pnpm/action-setup@v4
#   - run: pnpm install --frozen-lockfile
# The security workflow only had actions/setup-node@v4 — installs node + npm, NOT pnpm.
```

**Root cause** — `actions/setup-node` installs node + npm but not pnpm. The original `npm audit ... || true` didn't need pnpm, so the security workflow was written without it. Switching to `pnpm dlx audit-ci@^7` requires pnpm on `PATH`.

**Fix** — add `corepack enable` after `Setup Node`:
```yaml
- name: Setup Node
  uses: actions/setup-node@v4
  with:
    node-version: "20"

- name: Enable corepack (pnpm shim)
  run: corepack enable
```

`corepack` (bundled with node ≥ 16.9) shims `pnpm` (and `yarn`) to the version declared in `package.json#packageManager`. If that's not set, install pnpm via `pnpm/action-setup` like the frontend CI workflow does.

### 10.6 Audit-ci vs npm audit: per-advisory allowlist

**Symptom** — `npm audit --audit-level=high` blocks merges on the 13 next 14.x HIGH advisories (all of which require a MAJOR bump to next 15.5+, deferred to v0.3.0). We want the gate blocking, but we cannot bump next today.

**Diagnosis** — `npm-audit` has no per-advisory allowlist. `--audit-level` only filters by severity. The only way to keep the gate blocking while tolerating known-deferred CVEs is to either:
- Bump the deps (deferred, see #38)
- Use a different tool that supports per-advisory allowlist

**Root cause** — `npm audit` is a strict tool. Audit-ci (`IBM/audit-ci`, `pnpm dlx audit-ci@^7`) is a thin wrapper around `npm`/`pnpm`/`yarn` audit that adds per-advisory allowlist, JSON output, and better CI integration. It's the right tool for "block on new CVEs, allow known-deferred ones".

**Fix** — install audit-ci via `pnpm dlx`, declare the allowlist in a JSONC file:
```jsonc
// frontend/audit-ci.jsonc
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "critical": true,            // ← only block on CRITICAL
  "package-manager": "pnpm",
  "report-type": "full",
  "output-format": "json",
  "allowlist": [
    // 2 next.js 14.x CRITICAL — fix in next 15.5.24+ (MAJOR, #38)
    "GHSA-p293-qw3h-jr36",
    "GHSA-2xp9-vwfh-vxw4",
    // 1 vitest 1.6.1 CRITICAL — fix in vitest 3.2.6+ (MAJOR, #38)
    "GHSA-5xrq-8626-4rwp",
    // 2 tinypool 0.8.4 FALSE POSITIVES — vitest 1.x requires tinypool@^0.8.3
    "GHSA-5gmw-xhrv-c9v3",
    "GHSA-85c8-ppgw-ccpr"
  ]
}
```

```yaml
# .github/workflows/security.yml (npm-audit step)
- name: npm audit (blocking — gate flipped in PR-G2 via audit-ci)
  working-directory: frontend
  run: |
    mkdir -p ../reports
    pnpm dlx audit-ci@^7 --config ./audit-ci.jsonc --output-format json \
      > ../reports/npm-audit.json
```

> [!info] Why a JSONC file and not `.npmrc` or `package.json`?
> audit-ci is config-format-agnostic and the JSONC schema is editor-friendly (hover-completion, validation, inline comments with rationale). Each allowlist entry has a comment explaining *why* it's allowlisted, with a `Refs #<issue>` pointing at the deferred-bump issue. New engineers reviewing the file can see the plan without leaving the editor.

### 10.7 Tinypool / vite / next false-positive triage pattern

**Symptom** — pnpm audit reports `tinypool@0.8.4` as vulnerable to `GHSA-5gmw-xhrv-c9v3` (Prototype Pollution → RCE in 2.x), and `vite@5.4.21` as vulnerable to GHSAs that apply to vite ≤ 6.4.2.

**Diagnosis** —
```bash
# tinypool:
pnpm why tinypool
# → tinypool@0.8.4 └─┬ vitest@1.6.1 (transitive)
#    vitest 1.x's package.json: "tinypool": "^0.8.3"
#    Tinypool 0.x and 2.x are DIFFERENT APIs. The 2.x RCE code path
#    doesn't exist in 0.x.
# But the advisory's vulnerable_versions is "<=2.1.0", which technically
# includes 0.8.4 (semver-wise 0.8.4 < 2.1.0).

# vite:
pnpm why vite
# → vite@5.4.21
#    vite 5.4.21 is < the vuln range floor 6.4.x. The advisory
#    doesn't actually apply to vite 5.x.
```

**Root cause** — pnpm-audit (like npm-audit) flags any package whose name matches, even when the installed version is older than the vulnerable code path. For tinypool, the vuln was introduced in 2.x; for vite, the vuln is in 6.4.0–6.4.2. Both advisories are over-broad.

**Fix** — add to the audit-ci allowlist (see 10.6) with comments explaining "vitest 1.x requires tinypool@^0.8.3; bumping tinypool to 2.x would BREAK vitest (different API)". Then add a CI-side assertion that the vitest 1.x constraint is still in effect:
```bash
# local sanity:
grep '"tinypool":' frontend/node_modules/vitest/package.json   # → "^0.8.3"
```

If vitest 3.x is ever adopted (deferred to #38), revisit the allowlist and remove the tinypool entries.

---

## 11. OpenCode harness crashes with `n.content.map` on long sessions (2026-10-16)

> **Full RCA + workaround + DRY write:** [`folio/wiki/concepts/OpenCode-V2-Session-Compaction-Bug.md`](../../mindos/folio/wiki/concepts/OpenCode-V2-Session-Compaction-Bug.md). This section is the operator-facing summary only.

**Symptom** — the opencode TUI shows every user message producing:

```
[session] Failed to drain Session
  cause: TypeError: undefined is not an object (evaluating 'n.content.map')
    at SessionCompaction.compact (/$bunfs/root/opencode:6997:2228)
```

Once the first crash lands, **every** subsequent user message re-crashes at the same site. The session is unrecoverable in place. Symptom observed on `ses_eba8f9e0fffegK8V3vBAJctqGs` (134 msgs, 5 crashes), `ses_ec2f6befdffeqx6iS2NzI64013` (1415 msgs, 3 crashes), and 3 other sessions.

**Diagnosis** — the v2.0.30 auto-compactor iterates over the message history and calls `n.content.map(...)` on every message, but `user` messages in opencode's wire format have `{text, files, agents}` — no `content` field. So `n.content` is `undefined` for every user message, and `.map()` throws. Trigger = session crosses the ~100-message compaction threshold, not the user input.

**Fix (workaround)** — the bug is in opencode's bundled Bun code (`/$bunfs/root/opencode:6763:4682`); there is no in-place fix. Recover by:

1. Verify the work is in git: `git -C /Users/leonardomejia/projects/zimlama-recon log --oneline -5 && git status -s`
2. Find the most-recently-updated session for context:
   ```bash
   sqlite3 ~/.local/share/opencode/opencode.db \
     "SELECT id, title, datetime(time_updated/1000,'unixepoch') FROM session_v2 WHERE parent_id IS NULL ORDER BY time_updated DESC LIMIT 5;"
   ```
3. Start a new session in the worktree with the same agent/model, paste the last 5–10 git log entries + `git status` + the last assistant message verbatim, then continue.
4. Archive the broken session (do NOT delete — keep the data for future RCA):
   ```bash
   sqlite3 ~/.local/share/opencode/opencode.db \
     "UPDATE session_v2 SET title = title || ' [CRASHED: n.content.map compaction bug]' WHERE id = '<broken-session-id>';"
   ```

**Mitigation** — keep new sessions < 100 messages (start a new session per PR, not per day); prefer the `plan` agent for design work; do not run the `gentle-orchestrator` for > 1 PR's worth of tool calls in a single session.

**Status** — bug confirmed, no upstream fix in v2.0.30. Workaround verified. Tracked in Engram observation (search `n.content.map compaction`).

---

## 12. PR #56 (sec-auth-jwt) BLOCKER fixes (2026-10-16)

The PR #56 4R review of 2026-10-16 flagged four BLOCKER findings against the
sec-auth-jwt feature branch. Each was fixed in its own atomic commit, with a
failing test written FIRST (strict TDD). Cross-references: commits
`15d7ea4` (B1), `f247ee3` (B2), `864a876` (B3), `abc9c96` (B4) on
`feature/sec-auth-jwt`.

The four lessons below are deliberately short and grep-able; the full
commits carry the Symptom / Diagnosis / Root cause / Fix blocks per the
opencode lessons-doc rule, and the engram observation #1376
(`sdd/sec-auth-jwt/apply-progress`) carries the cumulative TDD evidence
table across the four fix batches.

### Lesson index (section 12)

| # | Symptom (grep-able) | Blocker |
|---|---------------------|---------|
| 12.1 | `audit_log` row has `user_id='local'` after a JWT login | B1 |
| 12.2 | `role='admin'` every request in a misconfigured production deploy | B2 |
| 12.3 | Lifespan logs `jwt_keys_init_failed warning=...` then says `app_ready` | B3 |
| 12.4 | `ruff check backend/` reports `F811 redefined-while-unused` on `status` in `main.py` | B4 |

---

### 12.1 AuditLogMiddleware writes `user_id='local'` regardless of auth

**Symptom** — after a successful JWT login the audit_log row records the
request as anonymous:

```sql
SELECT user_id, username, request_jwt_jti
  FROM audit_log
 WHERE action LIKE '%/auth/login%'
 ORDER BY id DESC LIMIT 1;
-- user_id='local'   username='local'   request_jwt_jti=NULL
```

The principal who just authenticated as `alice@example.com` is logged
anonymously; replay / revocation analysis is impossible because every
row looks identical.

**Diagnosis** — two things must hold simultaneously for the row to
carry the JWT identity:

1. `backend/app/audit/middleware.py` must read from `request.state`:

   ```bash
   grep -n 'user_id' backend/app/audit/middleware.py
   # → line 41 (pre-fix):  user_id='local'        ← hardcoded literal
   ```

2. The SQLAlchemy `AuditLog` model must declare the columns that the
   Alembic migration adds in production:

   ```bash
   grep -nE 'username|request_jwt_jti' backend/app/models.py
   # → no column declarations (only an unrelated `USERNAME` enum value)
   ```

**Root cause** — PR-J3.7a (audit) landed BEFORE PR-J3.8 (dual-auth).
The audit middleware was merged with a hardcoded `user_id='local'` and
SQLAlchemy model columns that did not declare `username` /
`request_jwt_jti`. The Alembic migration
`20261014000002_extend_audit_log_with_user` correctly added the
columns in production, but `Base.metadata.create_all()` (used by
`tests/conftest.client`) only mirrors declared columns so the test DB
never saw them. The dual-auth middleware populated
`request.state.{user_id, username, jwt_jti}` correctly but nothing
downstream read them.

**Fix** — two coupled changes:

1. Add the columns to the SQLAlchemy `AuditLog` model so test DB mirrors
   production shape:

   ```python
   # backend/app/models.py — AuditLog class additions
   username:        Mapped[str|None] = mapped_column(String(64), nullable=True)
   request_jwt_jti: Mapped[str|None] = mapped_column(String(36), nullable=True)
   ```

2. `AuditLogMiddleware` reads `request.state` with `getattr(...)` defaults:

   ```python
   # backend/app/audit/middleware.py (post-call_next)
   user_id  = getattr(request.state, "user_id",   "local")
   username = getattr(request.state, "username", "local")
   jwt_jti  = getattr(request.state, "jwt_jti",  None)
   ...
   AuditLog(...,
            user_id=user_id,
            username=username,
            request_jwt_jti=jwt_jti,
            ...,
   )
   ```

The `getattr` defaults preserve the pre-B1 fallback for endpoints that
bypass auth (`/health`, `/docs`, `/api/v1/auth/*`).

New pinning test: `backend/tests/test_audit_middleware_jwt.py` —
four tests covering JWT vs legacy vs unauthenticated rows.

---

### 12.2 Dev-mode admin bypass authenticates as `admin` in production

**Symptom** — with `.env` missing both `RECON_API_KEY` and the JWT key
files, a production deploy serves every route to anonymous callers
with `role='admin'`:

```bash
APP_ENV=production RECON_API_KEY= \
    uvicorn app.main:app --port 8000 &
curl -sS -o /dev/null -w '%{http_code}\n' \
    http://prod-host/api/v1/modules
# → 200     (should be 401 or 503)

curl -X POST -d '{"target":"competitor.example",
                  "selected_modules":["subdomain_enum"]}' \
    -H 'Content-Type: application/json' \
    http://prod-host/api/v1/jobs
# → 200 / job created   (red-team drives the API anonymously)
```

**Diagnosis** — confirm the bypass is reachable and that `APP_ENV` is
not consulted:

```bash
grep -n 'role = "admin"' backend/app/auth/middleware.py
# → line 170 (pre-fix): unconditional hardcode

grep -n 'APP_ENV\|is_production' backend/app/auth/middleware.py | head -5
# → 0 hits in the bypass block — no gate, anywhere
```

**Root cause** — `DualAuthMiddleware` dev-bypass (lines 159-172) was
written before sec-auth-jwt to preserve single-user local-install
behavior with zero env vars. After PR-J1 added pydantic-level
PRODUCTION-aware validators (`PEPPER_SECRET`, `REFRESH_HASH_KEY`,
`PERSON_DOSSIER_ENCRYPTION_KEY`), the middleware-level and
lifespan-level checks were never added. A half-configured production
boot silently serves admin-wide.

**Fix** — gate the bypass on `APP_ENV != "production"` and refuse with
HTTP 503 (Retry-After: 5) when in production AND both secrets are
missing. The new helper resolves `APP_ENV` per request through the
settings provider so tests can monkey-patch between requests:

```python
# backend/app/auth/middleware.py
def _is_production_now(settings_provider) -> bool:
    if settings_provider is None:
        return False
    try:
        return bool(settings_provider().APP_ENV == "production")
    except Exception:
        return False

# Inside dispatch(), at the bypass branch:
if not current_legacy and not self._jwt_keys_configured:
    if _is_production_now(self._settings_provider):
        logger.error(
            "auth_subsystem_not_configured "
            "RECON_API_KEY=unset JWT_PRIVATE_KEY_PATH=unset "
            "APP_ENV=production - refusing anonymous admin bypass"
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "auth_subsystem_not_configured",
                "message": (
                    "Authentication is not configured for "
                    "APP_ENV=production. Set RECON_API_KEY or "
                    "JWT_PRIVATE_KEY_PATH + JWT_PUBLIC_KEY_PATH "
                    "before serving requests. See spec section 7."
                ),
            },
            headers={"Retry-After": "5"},
        )
    # dev/staging/test: keep the pre-existing bypass
    request.state.user_id = "local"
    ...
    request.state.role = "admin"
```

New pinning test: `backend/tests/test_auth_middleware_admin_bypass.py`
— three tests covering production-503 / dev-200 / production+secret-200.

---

### 12.3 Lifespan silently swallows JWT/RefreshService init failures

**Symptom** — production deploy with `JWT_PRIVATE_KEY_PATH` unset (or
pointing at a typo'd file) boots happily and only fails at the first
`/auth/login`:

```bash
APP_ENV=production JWT_PRIVATE_KEY_PATH=/nonexistent/priv.pem \
    uvicorn app.main:app --port 8000 2>&1 | grep -E 'app_ready|init_failed'
# INFO  app_starting    env=production version=0.2.1
# INFO  db_initialized
# WARN  jwt_keys_init_failed error=private key not found: /nonexistent/priv.pem
# INFO  app_ready                                          ← misleading!
#
curl -X POST http://prod-host/api/v1/auth/login -d '{...}'
# 500 Internal Server Error: 'NoneType' object has no attribute 'verify'
```

A scanner that doesn't probe `/api/v1/auth/login` thinks the service is
healthy.

**Diagnosis** — confirm the swallowing code and that `APP_ENV` is not
consulted:

```bash
grep -n 'except Exception.*# noqa.*log + continue\|logger.warning.*init_failed' \
    backend/app/main.py
# → lines 84-85 (JwtKeyManager) and 100-101 (RefreshService) in pre-fix

grep -n 'APP_ENV\|is_production' backend/app/main.py | head -5
# → 0 hits in the except branch (pre-fix)
```

**Root cause** — asymmetry with the PR-J1 pydantic validators. Those
raise at `Settings()` construction in production, so operators see the
failure immediately. JWT keys live on disk (RSA PEM files); their
absence is checked at runtime when `JwtKeyManager` opens the file —
and that path was wrapped in `try/except (Exception): logger.warning(...)`,
swallowing the failure in EVERY environment, including production.
Net effect: PR-J1 fail-loud contract violated at the runtime boundary
even though it was satisfied at construction.

**Fix** — branch the except on `APP_ENV` and re-raise as
`RuntimeError` in production:

```python
# backend/app/main.py lifespan (now extracted to _init_jwt_subsystem)
is_production = s.APP_ENV == "production"
try:
    app.state.jwt_keys = _JwtKeyManager(...)
except Exception as exc:
    msg = f"JwtKeyManager init failed: {exc}"
    if is_production:
        logger.error("jwt_keys_init_failed_fatal error=%s", exc)
        raise RuntimeError(
            msg + " - production deploys refuse to boot without a "
            "working JWT subsystem. Set JWT_PRIVATE_KEY_PATH and "
            "JWT_PUBLIC_KEY_PATH to readable RSA PEM files."
        ) from exc
    logger.warning("jwt_keys_init_failed error=%s", exc)
elif is_production:
    raise RuntimeError(
        "JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH must both be set "
        "in production. ..."
    )
```

Same fail-loud branch for `RefreshService` and a belt-and-suspenders
guard for the short-`REFRESH_HASH_KEY` path (`elif is_production: raise`).

New pinning tests in `backend/tests/test_main.py` — four tests covering
production-missing-keys / production-bad-paths / dev-missing-keys /
healthy-config regression.

---

### 12.4 `ruff F811 redefined-while-unused` on `status` (PR-introduced lint)

**Symptom** — PR-J3.8 introduced (and B3 amplified) three PR-introduced
ruff items in `backend/app/main.py`:

```bash
$ ruff check backend/app/main.py --select F811,C901
F811 Redefinition of unused status from line 12
  --> backend/app/main.py:298:9
C901 create_app is too complex (11 > 10)
  --> backend/app/main.py:201:5
C901 lifespan   is too complex (12 > 10)
  --> backend/app/main.py:57:11
```

Plus two cosmetic items in `alembic/versions/` (excluded from ruff but
listed in the spec for hygiene): W292 trailing-newline + RUF003 en-dash.

**Diagnosis** — three independent smells bundled together:

```bash
# 1) The F811 collision
grep -n "^from fastapi import\|status, headers, body" backend/app/main.py
# → import line at 12 + closure tuple-unpacking

# 2) The C901 complexity (McCabe threshold = 10)
# create_app accumulated middleware, exception-handler, router and
# health-endpoint wiring since PR-J1.
# lifespan picked up +2 branches from B3 (the is_production gate +
# the new RuntimeError raise).
```

**Root cause** — three coupled issues:

1. The `_auth_error_handler` closure unpacks `(status, headers, body)`
   from `to_http_response()` and reuses the bare name `status`,
   shadowing the unused `from fastapi import status` (which is also
   F401 noise in the baseline).

2. `create_app` accumulated middleware, exception handler, router and
   health-endpoint wiring since PR-J1. Each additive change pushed
   branch count up by 1-2 paths until McCabe crossed 10.

3. PR-J3.8's B3 fail-loud work added two new branches inside both the
   JWT-init and RefreshService-init ifs (the `is_production` gate and
   the new `RuntimeError` raise), pushing lifespan complexity from
   10 to 12.

**Fix** — three coupled changes in `backend/app/main.py`:

```python
# 1) F811 — rename the local var
@app.exception_handler(_AuthError)
async def _auth_error_handler(request, exc) -> JSONResponse:
    http_status, headers, body = _auth_to_http(exc)
    return JSONResponse(status_code=http_status, content=body, headers=headers)

# 2) C901 create_app — extract helpers (create_app shrinks to C(5))
def _resolve_settings(): ...                  # Settings per call
def _install_middlewares(app, s): ...         # CORS + RequestId +
                                             # RoE + Audit + DualAuth
def _register_exception_handlers(app): ...    # AuthError handler
def _mount_routers(app): ...                 # 7 routers
def _register_health_endpoints(app): ...     # /health + /health/ready

# 3) C901 lifespan — extract helpers (lifespan shrinks to C(4))
def _init_jwt_subsystem(app, s): ...
def _init_refresh_subsystem(app, s): ...
async def _drain_and_close(app): ...
```

The alembic items are fixed as named in the spec — trailing newlines
added to both rev files, en-dash `~10–15` → ASCII hyphen `~10-15`.

Verification target per the spec:

```bash
$ cd backend && pytest -q
870 passed, 1 xfailed, 22 warnings in 69.21s
   # 859 baseline + 4 (B1) + 3 (B2) + 4 (B3) = 870; no regressions

$ ruff check backend/ --statistics
Found 110 errors.   # baseline 114 -> 110 (-4 PR-introduced items +
                    #  -1 incidental F401 from lifespan helper extraction)
```

Cross-references: commit `abc9c96` (B4) on `feature/sec-auth-jwt`;
engram obs #1376 (`sdd/sec-auth-jwt/apply-progress`); 4R review
2026-10-16 R4 Resilience.

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
