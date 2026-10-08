# AI Validation

> **Layer**: Backend (FastAPI + Pydantic v2 + httpx async)
> **Provider**: MiniMax M3 (OpenAI-compatible). Any OpenAI-compat endpoint works by setting `MINIMAX_BASE_URL`.
> **Status**: Released in v0.1.0, hardened in v0.2.0.

This document explains how `zimlama/recon` uses an external LLM to filter, enrich, and prioritize the raw output of every recon module. It complements [ARCHITECTURE.md](ARCHITECTURE.md) (where the validator sits in the request flow) and [MODULE_GUIDE.md](MODULE_GUIDE.md) (what each module actually does before AI sees it).

---

## 1. Why AI validation?

A Tier 1 `subdomain_enum` module can return 200+ hostnames in 2 minutes. Most are noisy: parked domains, CDN aliases, marketing microsites that resolve but carry zero attack surface. Without filtering, an operator wastes hours triaging by hand.

The AI validator sits **after** every module and **before** the report. It does four things per finding:

1. **Classifies** each finding into `CONFIRMED | LIKELY | SUSPECTED | FALSE_POSITIVE`.
2. **Prioritizes** it `HIGH | MEDIUM | LOW` for the next phase.
3. **Enriches** with module-specific context (a subdomain gets a `tech_stack_hint`, a breach count gets `exposure_risk`).
4. **Suggests** the next module to run (e.g. "if you found internal hostnames in cert SANs, run `metadata_analysis` next").

The verdict is persisted as an `AIValidation` row attached to the `ModuleRun`. The report generator renders it as colored badges — see [REPORT_TEMPLATES.md](REPORT_TEMPLATES.md).

---

## 2. Three operating modes

The LLM is optional — `zimlama/recon` runs without a key in dev/test, never burns credits you don't have, and degrades gracefully on outage.

| Mode | Trigger | Behavior |
|------|---------|----------|
| **Stub** | `MINIMAX_API_KEY` unset or matches the placeholder `sk-minimax-replace-with-real-key` | Every `chat_completion` returns a stub `LDMValidationResult` with empty verdicts, summary `"AI validation skipped — MINIMAX_API_KEY not configured."`, and `recommended_action=CONTINUE`. The job completes normally; the report renders a "skipped" notice. |
| **Real** | A real key is set | `httpx.AsyncClient` is built lazily, JSON-mode requests are sent to `MINIMAX_BASE_URL/v1/chat/completions`, retries with exponential backoff + jitter on 429/5xx, auth errors (401/403) raise immediately. |
| **Error** | Provider returns a schema-mismatching body, or is unreachable | `LLMClient` returns `{"_malformed": true, "_raw": ..., "_error": ...}` for shape problems, raises `LLMError` for transport problems. `AIValidator` catches both and emits an `LDMValidationResult` with `recommended_action=REQUEST_USER_DECISION` so the operator sees a "review required" badge instead of the job crashing. |

The split between **LLM-down vs LLM-wrong** matters: the first is an infrastructure incident (retry harder, alert ops); the second is a model regression (re-prompt, re-fine-tune). They are logged as `ai_api_failure` and `ai_schema_mismatch` respectively.

---

## 3. The contract: `LDMValidationResult`

The full Pydantic schema is in [`backend/app/llm/schemas.py`](../backend/app/llm/schemas.py). The top-level shape:

```python
class LDMValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")   # no surprise fields

    verdicts: list[FindingVerdict]              # one per finding (empty is OK)
    summary: str = Field(..., min_length=20)    # 2-3 sentences at module level
    recommended_action: RecommendedAction       # CONTINUE | PRODUCE_REPORT | REQUEST_USER_DECISION
    recommended_next_module_chain: list[str]    # ordered module names
```

Every per-finding verdict is:

```python
class FindingVerdict(BaseModel):
    value: str                      # the finding value (e.g. "api.example.com")
    verdict: VerdictType            # CONFIRMED | LIKELY | SUSPECTED | FALSE_POSITIVE
    priority: Priority              # HIGH | MEDIUM | LOW
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=10)       # 1-2 sentence technical reasoning
    enrichment: dict[str, str] = {} # module-specific extra context
```

Helper properties on `LDMValidationResult`:

| Property | Returns |
|----------|---------|
| `confirmed_count` | Number of `CONFIRMED` verdicts |
| `likely_count` | Number of `LIKELY` verdicts |
| `false_positive_count` | Number of `FALSE_POSITIVE` verdicts |
| `suspected_count` | Number of `SUSPECTED` verdicts |
| `high_priority_count` | Number of `HIGH` priority verdicts |

These drive the report's headline summary ("3 confirmed, 12 likely, 27 false positive out of 200 findings") and the per-module badge colors.

---

## 4. The validator: `AIValidator` + `LLMClient`

Two classes, both in `backend/app/`.

### `LLMClient` ([`backend/app/llm/client.py`](../backend/app/llm/client.py))

Async httpx wrapper around the OpenAI-compatible `/chat/completions` endpoint.

```python
async def chat_completion(
    self,
    messages: list[dict[str, str]],
    response_format: dict[str, str] | None = None,  # {"type": "json_object"}
    temperature: float = 0.1,                       # low = deterministic
    max_tokens: int = 4096,
) -> dict[str, Any]: ...
```

**Retry behavior**:

| Status | Behavior |
|--------|----------|
| 200 OK + schema match | Returns parsed dict |
| 200 OK + schema mismatch | Returns `{"_malformed": true, "_raw": ..., "_error": ...}` (caller decides) |
| 401 / 403 | Raises `LLMError("Authentication failed: ...")` immediately, no retry |
| 429 | Reads `Retry-After` header if present, falls back to `2**attempt` seconds, adds `random.uniform(0, 0.5*wait)` jitter, retries up to `MINIMAX_MAX_RETRIES` times |
| 5xx / network error | Exponential backoff `2**attempt`, retries up to `MINIMAX_MAX_RETRIES` times, then raises `LLMError` |

The client is built lazily inside `_get_client()` and re-used across requests. Call `await client.close()` on shutdown to drain the connection pool.

### `AIValidator` ([`backend/app/orchestrator/ai_validator.py`](../backend/app/orchestrator/ai_validator.py))

Builds the per-module prompt + JSONL payload, calls `LLMClient`, parses the response into `LDMValidationResult`.

```python
async def validate_module_findings(
    self, module: BaseReconModule, target: str, findings: list[Finding]
) -> LDMValidationResult: ...
```

The user-message format is fixed:

```
Target: example.com
Module: subdomain_enum
Total findings: 47

Findings (JSONL):
{"value": "api.example.com", "type": "subdomain", "source": "crt.sh", "confidence": 0.95}
{"value": "staging.example.com", "type": "subdomain", "source": "subfinder", "confidence": 0.80}
...

Validate each finding and respond with structured JSON.
```

System prompt comes from [`backend/app/llm/prompts.py`](../backend/app/llm/prompts.py) via `get_prompt(module_name)`.

**Three failure modes are handled separately**:

```python
except (httpx.HTTPError, LLMError) as e:
    # LLM is down → operator reviews later
    return LDMValidationResult(verdicts=[], summary=f"AI service unavailable: {e!s}...",
                               recommended_action=REQUEST_USER_DECISION)

try:
    return LDMValidationResult.model_validate(response)
except ValidationError as e:
    # LLM returned wrong shape → schema mismatch (model regression)
    return LDMValidationResult(verdicts=[], summary=f"AI returned malformed response...",
                               recommended_action=REQUEST_USER_DECISION)

except Exception:
    # Unexpected — treat as API failure, never crash the job
    return LDMValidationResult(verdicts=[], summary=f"AI validation failed unexpectedly...",
                               recommended_action=REQUEST_USER_DECISION)
```

---

## 5. Per-module prompts

Each of the 14 modules has its own system prompt that defines how the LLM should evaluate that module's findings. Prompts live in [`backend/app/llm/prompts.py`](../backend/app/llm/prompts.py) and share a `COMMON_INSTRUCTIONS` suffix that enforces the strict JSON output format.

### Example 1 — `subdomain_enum`

```text
You are validating subdomain enumeration results for a target domain.

For each subdomain, classify as:
- CONFIRMED: resolves to a live IP, real, in scope
- LIKELY: resolves but possibly stale (parked domain, sinkhole)
- FALSE_POSITIVE: typo, wildcard catch-all, out of scope
- SUSPECTED: data quality uncertain

Enrich each with:
- tech_stack_hint: observed from passive sources
- priority: HIGH (admin, staging, api, internal, vpn), MEDIUM (www, app, blog), LOW (parked, redirects)
- reasoning: 1 sentence why
```

### Example 2 — `github_recon`

```text
You are validating GitHub recon findings for a target organization.

For each finding (secret, hostname, email, file), classify as:
- CONFIRMED: real, in a current public repo
- LIKELY: real but in a fork/archive
- FALSE_POSITIVE: example, test, or unrelated repo
- SUSPECTED: data quality uncertain

Enrich each with:
- severity: CRITICAL (active API key), HIGH (internal hostname, JWT secret), ...
- exploitation_risk: HIGH if creds are live, LOW if deleted
- reasoning: 1 sentence

SECRET HANDLING: NEVER transmit, log, or share actual secrets. Flag the TYPE only.
```

### Example 3 — `breach_data`

```text
You are validating breach exposure findings for a target organization.

For each (email_hash_prefix, breach_count) pair, classify as:
- CONFIRMED: count is > 0, exposure is real
- LIKELY: count is high (>5), suggests credential reuse risk
- FALSE_POSITIVE: count is 0 or near-zero

Enrich each with:
- exposure_risk: HIGH (>10 breaches), MEDIUM (1-10), LOW (0-1)
- reuse_likelihood: HIGH if password reuse common
- reasoning: 1 sentence

PRINCIPLE: NEVER recommend using found credentials to log in.
```

### Example 4 — `person_dossier` (v0.2.0+)

Person dossiers use a tighter prompt because the LLM only sees a SHA-256 hash, never plaintext:

```text
You are assessing the coherence of a person-identity dossier for a target organization.

You will receive:
- email_hash: SHA-256 of the candidate's email (plaintext never sent)
- source_modules: which Tier 3 modules corroborated the identity
- source_count: number of corroborating sources
- confidence: aggregated confidence

Classify the dossier as:
- HIGH: 3+ sources agree, sources diverse (e.g. breach + socmint + employee_osint)
- MEDIUM: 2 sources agree
- LOW: single source, or all sources are the same module
- NONE: contradictory signals across sources (different breach_name patterns, etc.)
```

All 14 prompts are registered in the `PROMPTS` dict at the bottom of `prompts.py`. Adding a 15th module is just one entry.

---

## 6. Privacy model

The LLM is the third party in the loop. We minimize what we send and persist:

| Sensitive data | Sent to LLM? | Persisted at rest? |
|----------------|--------------|---------------------|
| Raw emails (e.g. `john@acme.com`) | **No** — only SHA-256 `email_hash` | Encrypted with Fernet in `identity_map.encrypted_email`. Never logged. |
| Sealed secrets (AWS keys, JWT tokens) from `github_recon` | **No** — `gitleaks` redacts before findings are built; only the secret TYPE is sent | Redaction summary only |
| GPS coordinates from `metadata_analysis` | Only country/region unless the operator enables the per-module override | Per-finding `metadata_analysis` field |
| Breach counts | Yes — HIBP k-anonymity already guarantees the first 5 hex chars of the email hash are the only thing ever sent over the wire | Numeric counts only |

The `person_dossier` module (v0.2.0) is the strictest: it never lets plaintext email pass the module boundary. See `PersonDossierModule._resolve_plaintext_email()` — the only function that sees plaintext, and it routes directly into `encrypt_email()` (Fernet + AES-128-CBC + HMAC-SHA256). The LLM only ever sees the SHA-256 hash.

---

## 7. Configuration

All knobs are in [`backend/app/config.py`](../backend/app/config.py) (Pydantic `BaseSettings`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `MINIMAX_API_KEY` | `sk-minimax-not-configured` | Triggers **stub mode** if unset/placeholder |
| `MINIMAX_BASE_URL` | `https://api.minimaxi.com/v1` | Override to point at OpenAI, Anthropic via gateway, local Ollama, etc. |
| `MINIMAX_MODEL` | `MiniMax-M3` | Model name in the chat-completions payload |
| `MINIMAX_TIMEOUT_SECONDS` | `60` | Total request timeout (httpx) |
| `MINIMAX_MAX_RETRIES` | `3` | Retries on 429/5xx after the first attempt |
| `AI_VALIDATION_ENABLED` | `True` | Master toggle — disable for fully offline runs |

`.env.example` ships with placeholders. Copy to `.env` and edit:

```bash
cp .env.example .env
# Edit .env and set:
MINIMAX_API_KEY=sk-minimax-XXXXXXXXXXXXXXXXXXXXXX
```

The installer (`./install.sh`) prompts for the key and writes it with `chmod 600`.

---

## 8. Testing

The validator and LLM client are independently covered:

- [`backend/tests/test_llm_client.py`](../backend/tests/test_llm_client.py) — 7+ tests covering:
  - `test_stub_response_when_no_api_key` — placeholder key returns stub
  - `test_chat_completion_success` — round-trip with mocked httpx
  - `test_chat_completion_malformed_response_surfaces_marker` — `_malformed` contract
  - `test_chat_completion_auth_error_no_retry` — 401/403 raise immediately
  - `test_ldm_validation_result_helpers` — counter properties
- [`backend/tests/test_integration_day6.py`](../backend/tests/test_integration_day6.py) — full orchestrator + modules + handoff end-to-end with mock LLM (asserts all 14 modules run, validations persist, handoff generates).

Run locally:

```bash
cd backend
pytest tests/test_llm_client.py -v
pytest tests/test_integration_day6.py -v
```

Coverage on `app/llm/` and `app/orchestrator/ai_validator.py` is > 90% (the project gate is 90%).

---

## 9. When things go wrong

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Every report says "AI validation skipped" | `MINIMAX_API_KEY` placeholder | Set a real key in `.env` |
| `LLMError: Authentication failed: 401` | Bad or revoked key | Regenerate at `api.minimaxi.com`, update `.env` |
| `ai_api_failure` warnings with backoff | LLM provider is down | Wait or switch `MINIMAX_BASE_URL` to a backup provider |
| `ai_schema_mismatch` warnings | Model regression / prompt drift | Re-run validation; check `prompts.py` matches expected JSON schema |
| Job hangs in `VALIDATING` for > 30 min | Module crashed mid-validation | Restart — `JobRunner.sweep_stuck_jobs()` (added v0.2.0) marks them FAILED |

For full troubleshooting see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — overall request flow
- [MODULE_GUIDE.md](MODULE_GUIDE.md) — what each module does before AI sees it
- [HANDOFF.md](HANDOFF.md) — `confirmed_targets[].ai_verdict` fields come from this validator
- [REPORT_TEMPLATES.md](REPORT_TEMPLATES.md) — how verdicts render as badges
