# PR 2 — touch_classification — Specification (Delta)

> **Delta spec for change `2026-10-12-pr2-touch-classification`.**
> Source of truth (post-archive): `openspec/specs/modules/spec.md`.
> Mapping table below is the **corrected, source-verified** table from
> `design.md` (L1 anti-hallucination review, file:line citations re-checked
> against current source on 2026-10-12).
>
> **L1 — Anti-hallucination note**: Every mapping row is verified against
> the cited source. The 5 modules the original plan mis-labelled
> `PASSIVE_TARGET` (subdomain_enum, certificate_transparency,
> wayback_machine, email_harvesting, metadata_analysis) all read
> third-party data sources (crt.sh, web.archive.org, PGP keyservers) →
> `PASSIVE_THIRDPARTY`. `dns_enum` is the only `ACTIVE_TARGET` because
> `dns_enum._attempt_axfr` (lines 256-313) actively probes the target's
> authoritative nameservers.

---

## ADDED Requirements

### Requirement: TouchClass Enum

The system SHALL expose a `TouchClass` `str` enum in `backend/app/modules/base.py`
that classifies how a module interacts with the target and third parties.

The `TouchClass` enum SHALL contain exactly four members:

| Value | Definition |
|---|---|
| `PASSIVE_TARGET` | Reads public registries owned by target; never modifies or probes. |
| `PASSIVE_THIRDPARTY` | Reads public data indexed by third parties; target never contacted. |
| `ACTIVE_TARGET` | Actively probes target infra (queries target can observe). |
| `ACTIVE_THIRDPARTY` | Actively probes third-party infra on target's behalf. Reserved for future use (no current occupant). |

Each value SHALL be a `str` whose underlying string value is the lowercase,
underscore-separated form of the member name
(e.g., `TouchClass.PASSIVE_TARGET == "passive_target"`).

`TouchClass` SHALL be exported from `backend/app/modules/base.py` so
consumers (`backend/app/modules/__init__.py`,
`backend/tests/test_touch_classification.py`) can import it without
reaching into private names.

#### Scenario: TouchClass has 4 members

- GIVEN the module file `backend/app/modules/base.py` is imported
- WHEN a caller inspects `TouchClass`
- THEN it SHALL have members `PASSIVE_TARGET`, `PASSIVE_THIRDPARTY`,
  `ACTIVE_TARGET`, `ACTIVE_THIRDPARTY`
- AND it SHALL NOT contain any other members

#### Scenario: TouchClass is a str enum

- GIVEN `TouchClass` is imported
- WHEN the caller compares `TouchClass.PASSIVE_TARGET == "passive_target"`
- THEN the comparison SHALL be `True`
- AND `isinstance(TouchClass.PASSIVE_TARGET, str)` SHALL be `True`

#### Scenario: TouchClass rejects unknown values

- GIVEN `TouchClass` is used as a Pydantic field type
- WHEN an unknown string (e.g., `"invalid_class"`) is assigned
- THEN Pydantic SHALL raise `pydantic.ValidationError`

#### Scenario: TouchClass enum is I/O free at import

- GIVEN the application process is starting
- WHEN `backend/app/modules/base.py` is imported
- THEN no network calls SHALL be made
- AND `TouchClass` SHALL be fully populated before any module instance
  is constructed

---

### Requirement: Module Touch Classification and Free-Only Flag

`BaseReconModule` (`backend/app/modules/base.py`) SHALL declare two new
class attributes:

```python
touch_classification: TouchClass = TouchClass.PASSIVE_TARGET
requires_paid: bool = False
```

Every concrete subclass of `BaseReconModule` SHALL override
`touch_classification` with its actual classification (no subclass
SHALL rely on the default, except where `PASSIVE_TARGET` is genuinely
correct).

A concrete subclass SHALL set `requires_paid = True` if and only if the
module needs a paid API key to function. A module that works without a
key (free tier) SHALL keep `requires_paid = False` even if a paid tier
exists.

The default values are conservative and backward-compatible: existing
modules that do not set these attributes will compile and behave
correctly, but the build-time registry validation
(see REQ-MODULE-REGISTRY-FILTER) SHALL warn if any module falls back to
the default `PASSIVE_TARGET`.

#### Scenario: Module declares its actual touch_classification

- GIVEN a module file (e.g., `backend/app/modules/subdomain_enum.py`)
- WHEN the subclass is defined
- THEN it SHALL set `touch_classification = TouchClass.PASSIVE_THIRDPARTY`
- AND it SHALL NOT inherit the default `PASSIVE_TARGET`

#### Scenario: Module declares requires_paid

- GIVEN a module that uses HIBP free tier (e.g., `breach_data`)
- WHEN the subclass is defined
- THEN it SHALL set `requires_paid = False`
- AND if a paid tier exists, the module SHALL still function without
  the paid key

#### Scenario: mypy --strict accepts new attributes

- GIVEN `mypy --strict` is run against `backend/app/modules/`
- WHEN it type-checks each of the 14 module files
- THEN no errors SHALL be reported for the `touch_classification` or
  `requires_paid` class attributes
- AND all 14 modules SHALL compile cleanly

#### Scenario: Module that forgets to override falls back to default

- GIVEN a new module that forgets to set `touch_classification`
- WHEN the registry is built
- THEN the module SHALL compile (no error)
- AND a warning SHALL be logged indicating the default was used
- AND the module SHALL be classified as `PASSIVE_TARGET` until corrected

#### Scenario: Privacy — no PII in labels

- GIVEN the `TouchClass` enum and the `touch_classification` /
  `requires_paid` attributes
- WHEN they are persisted (e.g., in `ModuleRun.module_input`)
- THEN no PII SHALL be embedded
- AND only the enum value and boolean flag are stored

#### Scenario: Anti-block — deterministic classification

- GIVEN two clients start the application with identical environment
  variables
- WHEN `MODULE_REGISTRY` is built
- THEN both clients SHALL see the same `touch_classification` for each
  module
- AND the same `requires_paid` flag
- AND there SHALL be no race, random, or time-dependent behavior

---

### Requirement: Module Registry Filtering by tools_only_free

The `Settings` class in `backend/app/config.py` SHALL declare a
`tools_only_free: bool = True` field (env var `TOOLS_ONLY_FREE`).

`_build_registry()` in `backend/app/modules/__init__.py` SHALL, after
populating the 14-entry dict:

  1. Read `settings.tools_only_free`.
  2. If `True`, exclude every module whose `requires_paid == True`.
  3. For each excluded module, log an `INFO` record including the
     module name.
  4. If `False` (default), include all 14 modules.

The `get_module_registry()` signature SHALL NOT change; it returns
the filtered dict.

`get_settings()` is wrapped in `lru_cache(maxsize=1)` (see
`backend/app/config.py:123-130`) so the registry build-time call is
the only settings read.

#### Scenario: tools_only_free=true filters paid modules

- GIVEN `TOOLS_ONLY_FREE=true` in the environment
- AND exactly one module (hypothetically) sets `requires_paid = True`
- WHEN `_build_registry()` runs at import time
- THEN `MODULE_REGISTRY` SHALL exclude that paid module
- AND `len(MODULE_REGISTRY)` SHALL equal `13`
- AND an `INFO` log SHALL be emitted naming the excluded module

#### Scenario: tools_only_free=false (default) keeps all modules

- GIVEN `TOOLS_ONLY_FREE` is unset (default `True`)
  **OR** `TOOLS_ONLY_FREE=false` is set explicitly
- AND all 14 current modules set `requires_paid = False`
- WHEN `_build_registry()` runs
- THEN `MODULE_REGISTRY` SHALL contain exactly 14 entries
- AND `set(MODULE_REGISTRY.keys())` SHALL equal
  `{"whois_rdap", "dns_enum", "subdomain_enum",
    "certificate_transparency", "wayback_machine",
    "email_harvesting", "shodan_censys", "github_recon",
    "metadata_analysis", "google_dorking", "breach_data",
    "socmint", "employee_osint", "dark_web_osint"}`

#### Scenario: Adversarial — user requests paid module under tools_only_free

- GIVEN `TOOLS_ONLY_FREE=true`
- AND a paid module is excluded from `MODULE_REGISTRY`
- WHEN the user submits a job with that module in
  `payload.selected_modules`
- THEN `POST /jobs` SHALL return HTTP 400
- AND the error body SHALL clearly state which module was rejected
  and why (`tools_only_free=true`)
- AND an `AuditLog` row SHALL be inserted with
  `action="module_paid_rejected"` and
  `details={"module": m, "reason": "tools_only_free=true"}`

#### Scenario: Adversarial — invalid TOOLS_ONLY_FREE string falls back

- GIVEN `TOOLS_ONLY_FREE=maybe` in the environment
- WHEN `Settings()` parses the field
- THEN `tools_only_free` SHALL fall back to `True` (Pydantic strict
  coercion) **OR** Pydantic SHALL raise a validation error at startup
  (reject malformed config)
- AND the application SHALL NOT silently treat the bad value as
  `False` (avoiding silent unsafe behavior)

#### Scenario: Adversarial — module omits requires_paid attribute

- GIVEN a module that does not set `requires_paid`
- WHEN `_build_registry()` evaluates it
- THEN it SHALL default to `False`
- AND the module SHALL be included regardless of
  `tools_only_free` value
- AND no error SHALL be raised

#### Scenario: Anti-block — filter is O(n) and deterministic

- GIVEN the registry has at most 14 entries (current + planned)
- WHEN the filter executes
- THEN it SHALL complete in under 1 ms (O(n) dict comprehension)
- AND it SHALL NOT perform any network I/O
- AND it SHALL NOT read `time.time()` or any other non-stable source

#### Scenario: Privacy — filter emits no PII

- GIVEN the exclusion log message
- WHEN a paid module is excluded
- THEN only the module name (string identifier) SHALL appear in logs
- AND no PII, target domain, or job context SHALL be emitted

---

### Requirement: Mapping Table — Module Touch Classification (Source-Verified)

The system SHALL classify each of the 14 modules as follows. The
mapping is verified against the cited source on 2026-10-12 (L1
anti-hallucination review). Any future change to a module's data
sources SHALL be accompanied by an update to this mapping AND a
re-verification of the citation.

| Module | `touch_classification` | `requires_paid` | Source citation | Justification |
|---|---|---|---|---|
| `whois_rdap` | `PASSIVE_TARGET` | `False` | `whois_rdap.py:124-163` (`_query_rdap`, `_query_whois`); `RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"` (`whois_rdap.py:26`) | Reads the target's own domain registration via RDAP/WHOIS registries. |
| `dns_enum` | `ACTIVE_TARGET` | `False` | `dns_enum.py:60-120, 256-313` (`_query_records`, `_attempt_axfr`) | Standard record queries are passive; `AXFR` (`dns_enum.py:275-281`, `dns.query.xfr`) actively probes the target's authoritative NS. |
| `subdomain_enum` | `PASSIVE_THIRDPARTY` | `False` | `subdomain_enum.py:111-209` (`_run_subfinder`, `_query_crtsh`); `CRTSH_URL = "https://crt.sh/?q={domain}&output=json"` (`subdomain_enum.py:24`) | Aggregates from crt.sh (third-party CT logs) and subfinder (third-party passive aggregator). |
| `certificate_transparency` | `PASSIVE_THIRDPARTY` | `False` | `certificate_transparency.py:153-178` (`_query_crtsh`); `CRTSH_URL = "https://crt.sh/"` (`certificate_transparency.py:28`) | Mines crt.sh (third-party) CT logs. |
| `wayback_machine` | `PASSIVE_THIRDPARTY` | `False` | `wayback_machine.py:174-262` (`_run_tool`, `_query_cdx`); `CDX_API_URL = "https://web.archive.org/cdx/search/cdx"` (`wayback_machine.py:30`) | Reads Internet Archive (third-party). |
| `email_harvesting` | `PASSIVE_THIRDPARTY` | `False` | `email_harvesting.py:208-303` (`_query_pgp_servers`, `_query_single_pgp_server`, `_run_theharvester`); `PGP_KEYSERVERS = ["https://keys.openpgp.org", "https://pgp.mit.edu"]` (`email_harvesting.py:35-38`) | Queries PGP keyservers (third-party) + theHarvester subprocess. |
| `shodan_censys` | `PASSIVE_THIRDPARTY` | `False` | `shodan_censys.py:159-190` (`_query_shodan_internetdb`, `_query_censys`); `SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"` (`shodan_censys.py:27`), `CENSYS_SEARCH_URL = "https://search.censys.io/api/v1/hosts/{ip}"` (`shodan_censys.py:31`) | InternetDB is keyless free; Censys is free tier. Both are third-party. |
| `github_recon` | `PASSIVE_THIRDPARTY` | `False` | `github_recon.py:148-307` (`_search_code`); `GITHUB_API_URL = "https://api.github.com"` (`github_recon.py:34`) | Reads public GitHub (third-party) code/commit search. GITHUB_TOKEN optional. |
| `google_dorking` | `PASSIVE_THIRDPARTY` | `False` | `google_dorking.py:188-245` (`_search_serpapi`, `_serpapi_query`); `SERPAPI_URL = "https://serpapi.com/search"` (`google_dorking.py:24`) | SerpAPI (third-party) Google search; SERP_API_KEY optional. |
| `metadata_analysis` | `PASSIVE_THIRDPARTY` | `False` | `metadata_analysis.py:131-305` (`_find_documents_via_wayback`, `_extract_metadata`); `WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"` (`metadata_analysis.py:31`) | Discovers docs via Wayback CDX (third-party); EXIF extraction is local. |
| `breach_data` | `PASSIVE_THIRDPARTY` | `False` | `breach_data.py:138-176` (`_check_hibp`); `HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"` (`breach_data.py:27`) | HIBP k-anonymity API (third-party, free). HIBP_API_KEY optional (raises rate limits). |
| `socmint` | `PASSIVE_THIRDPARTY` | `False` | `socmint.py:120-150` (`_check_platform`); `SOCIAL_PLATFORMS` (`socmint.py:26-35`) — LinkedIn, GitHub, Twitter, Facebook, Instagram, YouTube, TikTok | All targets are third-party social platforms. |
| `employee_osint` | `PASSIVE_THIRDPARTY` | `False` | `employee_osint.py:89-145` (`_run_sherlock`, `_generate_username_patterns`) | Sherlock (open-source) checks third-party platforms; pattern inference is local. |
| `dark_web_osint` | `PASSIVE_THIRDPARTY` | `False` | `dark_web_osint.py:105-179` (`_search_ahmia`, `_search_via_tor`); `AHMIA_API_URL = "https://ahmia.fi/search/"` (`dark_web_osint.py:31`) | ahmia.fi (clearnet, third-party) is primary; Tor is opt-in (`shutil.which("tor")`, `dark_web_osint.py:66`). The act of fetching a Tor `.onion` page is read-only. |

#### Scenario: Mapping is enforced by parameterized test

- GIVEN `backend/tests/test_touch_classification.py` (new file)
- WHEN pytest is run with the parameterized test
  `test_module_touch_classification[module_name-expected_class]`
- THEN every (module, class) pair from the table above SHALL be
  asserted exactly as written
- AND the test SHALL fail (RED) if any module's
  `touch_classification` does not match the table

#### Scenario: Mapping is enforced by requires_paid test

- GIVEN the same test file
- WHEN `test_module_requires_paid[module_name-False]` runs for all 14
  modules
- THEN every assertion SHALL pass (all 14 are currently `False`)

#### Scenario: Adding a paid module updates both code and table

- GIVEN a new module is added with `requires_paid = True`
- WHEN the PR is opened
- THEN `design.md`, this spec, and `backend/tests/test_touch_classification.py`
  SHALL all be updated in the same commit
- AND the parameterized test SHALL include the new module

---

### Requirement: Audit Log on Paid-Module Rejection (Per-Job)

When `POST /jobs` rejects a request because a paid-only module is
requested while `tools_only_free=true`, the system SHALL write a
single `AuditLog` row per attempt (not per process boot).

The row SHALL contain:

- `action = "module_paid_rejected"` (a `String(50)` per
  `backend/app/models.py:321`, so any short string is valid)
- `details = {"module": "<module_name>", "reason": "tools_only_free=true"}`
- Standard `AuditLog` fields: timestamp, actor, target, etc.

#### Scenario: Per-job audit row exists

- GIVEN a job creation request that triggers paid-module rejection
- WHEN the HTTP 400 is returned
- THEN exactly one `AuditLog` row SHALL be inserted with
  `action="module_paid_rejected"` and the rejected module's name in
  `details`

#### Scenario: No boot-time audit row

- GIVEN the application starts with `tools_only_free=true`
- WHEN no job has been created yet
- THEN `AuditLog` SHALL contain zero `module_paid_rejected` rows
- AND the rejection SHALL NOT be logged at startup

#### Scenario: Adversarial — repeated rejections create one row each

- GIVEN the user submits 5 job requests that each trigger rejection
- WHEN all are processed
- THEN 5 `module_paid_rejected` rows SHALL exist
- AND there SHALL be no deduplication or rate-limiting on the audit
  log itself

---

## Open Questions — RESOLVED in this spec

| # | Question | Decision | Rationale |
|---|---|---|---|
| Q1 | Should `dark_web_osint._search_via_tor` (`dark_web_osint.py:146-179`) be classified as `ACTIVE_THIRDPARTY` because Tor fetching is "active"? | **`PASSIVE_THIRDPARTY`** (keep current mapping) | Tor is opt-in (`requires_consent=True`, `dark_web_osint.py:47`) and gated behind `shutil.which("tor")` (`dark_web_osint.py:66`). The act of fetching a Tor `.onion` page is read-only HTTP — the target's hidden service observes its own logs, no transfer/upload. Forward slot `ACTIVE_THIRDPARTY` is reserved for future modules that truly push data to third parties. |
| Q2 | Keep `ACTIVE_THIRDPARTY` enum value with zero current occupants (YAGNI)? | **Keep it** (reserved) | Forward-compat for PR 7+ (active third-party probes like controlled phishing-intelligence lookups). Costs nothing to keep. |
| Q3 | `AuditLog` on paid-module rejection — at build time (one per process) or per job attempt? | **Per-job attempt** | User may have multiple jobs in flight; per-job preserves the audit trail granularity needed for forensics. Build-time logging would lose per-user attribution. |
| Q4 | `dns_enum`'s AXFR is active but free — runtime notice when `tools_only_free=true`? | **Defer to PR 3** (harness layer) | Orthogonal to `requires_paid`. PR 3 owns the per-job "active probe warning" UX. This spec only governs the registry filter, not the per-module warnings surfaced to the user. |

---

## Non-Functional Requirements

- **NFR-1**: Test coverage for `TouchClass`, the 14-module mapping
  table, and the `_build_registry()` filter SHALL be ≥ 95% (enums and
  dicts are easy to cover).
- **NFR-2**: All 14 modules SHALL compile under `mypy --strict`
  after the new class attributes are added
  (`backend/pyproject.toml`).
- **NFR-3**: Global coverage SHALL stay ≥ 90%
  (`fail_under = 90` per `backend/pyproject.toml:163`); new tests
  SHALL hold the line.
- **NFR-4**: No PII SHALL be embedded in `TouchClass` enum values, the
  mapping table, or the exclusion log message — only labels and
  module-name identifiers.

---

## Files Affected

| File | Action |
|---|---|
| `backend/app/modules/base.py` | ADD `TouchClass` enum; ADD `touch_classification` + `requires_paid` class attrs on `BaseReconModule` |
| `backend/app/config.py` | ADD `tools_only_free: bool = True` field to `Settings` |
| `backend/app/modules/__init__.py` | MODIFY `_build_registry()` to read `settings.tools_only_free` and exclude paid modules |
| `backend/app/modules/*.py` (14 files) | DECLARE `touch_classification` + `requires_paid` per mapping table |
| `backend/app/routes/jobs.py` | ADD paid-module rejection branch (HTTP 400) + `AuditLog` row insertion |
| `backend/tests/test_touch_classification.py` | NEW — enum, parameterized mapping, filter, route rejection |

No Alembic migration required (no DB schema change).