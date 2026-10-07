# Design: PR 2 — Touch Classification + Free-Only Registry Filter

## Context

`ModuleTier.TIER_1/2/3` does not distinguish *what kind of contact* a module makes nor whether it requires paid APIs. PR 2 adds a `TouchClass` enum and a `requires_paid` flag that filters the registry at load time. Reference: `wiki/sesiones/2026-10-07-plan-mejoras-person-osint.md` (PR 2); specs REQ-028 → REQ-030 in `sdd-spec`.

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| `TouchClass` location | `app/modules/base.py` | `ModuleTier` persisted (`models.py:182-184`); `TouchClass` metadata-only. Co-locate with `BaseReconModule`. |
| `requires_paid` default | `False` on all 14 | API audit: RDAP, crt.sh, Wayback CDX, PGP, Shodan InternetDB keyless, GitHub keyless, SerpAPI free, HIBP k-anon, Sherlock, ahmia.fi — all free. Forward-compat. |
| `tools_only_free` evaluation | At registry build, frozen `dict` | L4 (anti-block) demands deterministic, no-I/O filtering. Same target → same module set always. |
| Paid-request rejection | HTTP 400 at `routes/jobs.py:38` + `AuditLog(action="module_paid_rejected")` | Fail fast with clear UX. `AuditLog.action` accepts arbitrary strings (`models.py:321`). |

## `TouchClass` Enum (`backend/app/modules/base.py`)

| Value | Definition | Example |
|---|---|---|
| `PASSIVE_TARGET` | Reads public registries owned by target; never modifies or probes. | RDAP/WHOIS of target's own domain |
| `PASSIVE_THIRDPARTY` | Reads public data indexed by third parties; target never contacted. | crt.sh, Wayback CDX, HIBP, GitHub |
| `ACTIVE_TARGET` | Actively probes target infra (queries target can observe). | DNS AXFR against target NS |
| `ACTIVE_THIRDPARTY` | Actively probes third-party infra on target's behalf. | Reserved (no current module) |

## `BaseReconModule` Changes

Add next to `backend/app/modules/base.py:71-80`:

```python
touch_classification: TouchClass = TouchClass.PASSIVE_TARGET
requires_paid: bool = False
```

No `__init__` validation — defaults are conservative and backward-compatible.

## Module Mapping Table

Verified per file:line. Citations = data-source code.

| Module | Source | TouchClass | requires_paid |
|---|---|---|---|
| `whois_rdap` | `whois_rdap.py:124-163` | PASSIVE_TARGET | False |
| `dns_enum` | `dns_enum.py:60-120, 256-313` | ACTIVE_TARGET | False |
| `subdomain_enum` | `subdomain_enum.py:111-209` | PASSIVE_THIRDPARTY | False |
| `cert_transparency` | `certificate_transparency.py:153-178` | PASSIVE_THIRDPARTY | False |
| `wayback_machine` | `wayback_machine.py:174-262` | PASSIVE_THIRDPARTY | False |
| `email_harvesting` | `email_harvesting.py:208-303` | PASSIVE_THIRDPARTY | False |
| `shodan_censys` | `shodan_censys.py:159-190` | PASSIVE_THIRDPARTY | False |
| `github_recon` | `github_recon.py:148-307` | PASSIVE_THIRDPARTY | False |
| `google_dorking` | `google_dorking.py:188-245` | PASSIVE_THIRDPARTY | False |
| `metadata_analysis` | `metadata_analysis.py:131-305` | PASSIVE_THIRDPARTY | False |
| `breach_data` | `breach_data.py:138-176` | PASSIVE_THIRDPARTY | False |
| `employee_osint` | `employee_osint.py:89-145` | PASSIVE_THIRDPARTY | False |
| `socmint` | `socmint.py:120-150` | PASSIVE_THIRDPARTY | False |
| `dark_web_osint` | `dark_web_osint.py:105-179` | PASSIVE_THIRDPARTY* | False |

**Corrections vs. plan** (L1): plan labeled 5 modules `PASSIVE_TARGET`; source shows all 5 read third-party data → `PASSIVE_THIRDPARTY`. `shodan_censys`/`github_recon`/`google_dorking` were dual-labeled; collapsed to `PASSIVE_THIRDPARTY`. `sdd-spec` codifies as parameterized test in `backend/tests/test_touch_classification.py` (RED before any module update).

## `MODULE_REGISTRY` Filter

```python
# backend/app/modules/__init__.py
def _build_registry() -> dict[str, BaseReconModule]:
    settings = get_settings()  # lru_cache-wrapped, config.py:123-130
    modules: dict[str, BaseReconModule] = {
        "whois_rdap": WhoisRDAPModule(),
        # ... existing 14 entries (ordering, comments unchanged)
    }
    if settings.tools_only_free:
        if excluded := sum(1 for v in modules.values() if v.requires_paid):
            modules = {k: v for k, v in modules.items() if not v.requires_paid}
            logger.info("paid_modules_filtered", count=excluded)
    return modules
```

`get_module_registry()` signature unchanged.

## Failure Modes

| Scenario | Behavior |
|---|---|
| `tools_only_free=true`, current modules | OK — 14 in registry, no exclusions |
| `tools_only_free=true`, paid module added later | Excluded at build; `logger.info("paid_modules_filtered", count=N)` |
| User requests paid module + `tools_only_free=true` | HTTP 400 + `AuditLog(action="module_paid_rejected")` |
| `requires_paid=True` but provider key unset | Existing config check raises — unchanged |
| Module omits `touch_classification` | Default `PASSIVE_TARGET`; no error |

## Audit Log

`AuditLog(action="module_paid_rejected", details={"module": m, "reason": "tools_only_free=true"})` row at `routes/jobs.py` alongside the HTTP 400. Schema unchanged (`models.py:321`).

## Migration Impact

Existing tests pass (defaults backward-compatible). `routes/jobs.py` gains one validation branch. `mcp/server.py:205` and `cli.py:52` unchanged. Frontend `ModuleCard.tsx` may show a paid/free badge (optional). No Alembic migration. `pyproject.toml:163` enforces `fail_under = 90`; new tests must hold the line.

## File Changes

| File | Action |
|---|---|
| `backend/app/modules/base.py` | Add `TouchClass` enum + 2 class attrs on `BaseReconModule` |
| `backend/app/config.py` | Add `tools_only_free: bool = True` to `Settings` |
| `backend/app/modules/__init__.py` | `_build_registry()` reads filter and excludes paid |
| `backend/app/modules/*.py` (14 files) | Declare `touch_classification` + `requires_paid` per table |
| `backend/app/routes/jobs.py` | Paid-module rejection + `AuditLog` row |
| `backend/tests/test_touch_classification.py` | NEW — enum, parameterized mapping, filter, route |

## Open Questions

- **Q1**: `dark_web_osint._search_via_tor` (`dark_web_osint.py:146-179`) — `ACTIVE_THIRDPARTY`? Opt-in + `requires_consent=True`; currently folded into `PASSIVE_THIRDPARTY`. Defer to `sdd-spec`.
- **Q2**: Keep `ACTIVE_THIRDPARTY` enum value with zero current occupants (forward slot)? Drop if YAGNI.
- **Q3**: `AuditLog` on paid-module rejection — at build time (one per process) or per job attempt? Current: per-job.
- **Q4**: `dns_enum`'s AXFR is active but free — runtime notice when `tools_only_free=true`? Orthogonal to `requires_paid`; raise in PR 3 (harness).