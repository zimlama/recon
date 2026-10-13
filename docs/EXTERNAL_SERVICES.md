<!--
Copyright 2026 zimlama
SPDX-License-Identifier: Apache-2.0
-->

# External Services Setup

> **Audience**: operators deploying `zimlama/recon` for the first time.
> **Goal**: tell you exactly which external accounts and binaries you need, why, what they cost, how to obtain them, and what happens if you skip them.
> **Read time**: ~15 min. **Action time**: 15-60 min depending on which tier you pick.

`zimlama/recon` is self-hosted and ships with **graceful degradation** — every external dependency is optional except the LLM key. You can run a useful recon with **zero paid accounts** and only the free binaries. This document walks you through the three tiers:

- **[Tier 0 — Minimum viable](#tier-0--minimum-viable)**: zero paid accounts, only the binaries in the standard `$PATH` of a developer machine. Runs every module. Skips some enrichments.
- **[Tier 1 — Free enrichments](#tier-1--free-enrichments-recommended)**: add the three free API keys (Censys, GitHub, optional SerpAPI). ~15 min of account creation. Recommended.
- **[Tier 2 — Paid for higher rate limits](#tier-2--paid-optional)**: HIBP API key for breach_data without 429s. ~$4/month.

---

## TL;DR — the matrix

| Service          | Type             | Required?                   | Cost                | Where to get it                                                  | Env var(s)                                          |
| ---------------- | ---------------- | --------------------------- | ------------------- | ---------------------------------------------------------------- | --------------------------------------------------- |
| MiniMax M3 (LLM) | Cloud API        | **Yes** (for AI validation) | Pay-per-token       | [api.minimaxi.com](https://api.minimaxi.com/)                    | `MINIMAX_API_KEY`                                   |
| Censys Search    | Cloud API        | Optional                    | Free 250 queries/mo | [search.censys.io/register](https://search.censys.io/register)   | `CENSYS_API_ID`, `CENSYS_API_SECRET`                |
| GitHub           | Cloud API        | Optional (recommended)      | Free with account   | [github.com/settings/tokens](https://github.com/settings/tokens) | `GITHUB_TOKEN`                                      |
| SerpAPI          | Cloud API        | Optional                    | Free 100 queries/mo | [serpapi.com](https://serpapi.com/)                              | `SERP_API_KEY`                                      |
| HIBP             | Cloud API        | Optional (Tier 3)           | $3.50/mo            | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | `HIBP_API_KEY`                                      |
| Hunter.io        | Cloud API        | Not used yet                | Free 25/mo          | [hunter.io/api](https://hunter.io/api)                           | `HUNTER_API_KEY` (reserved)                         |
| Shodan           | Cloud API        | Not needed                  | —                   | —                                                                | `SHODAN_API_KEY` (reserved; module uses InternetDB) |
| 12 binaries      | Local subprocess | Recommended                 | Free                | See per-binary section                                           | (none — just install)                               |
| Free public APIs | —                | Always on                   | Free                | None                                                             | (none)                                              |

---

## 0. Before you start

You already have these from the main install (`./install.sh`):

- Docker Engine 24+ with Compose v2
- Python 3.11+ (for the local dev workflow)
- Node.js 20+ and pnpm (for the frontend dev workflow)
- `git`, `curl`, `jq`

If you don't have them yet, run `./install.sh` first. It will ask for `MINIMAX_API_KEY` only and create `.env` with placeholders for everything else.

---

## Tier 0 — Minimum viable

You can run **every module** without any paid API key. Here's what each module does at this tier and what it skips.

### Modules at Tier 0

| Module | Tier | Without any key | Source |
|--------|------|-----------------|--------|
| `whois_rdap` | 1 | Full functionality | RDAP bootstrap (no auth) |
| `dns_enum` | 1 | Full functionality | `dig` + `host` binaries |
| `subdomain_enum` | 1 | Full functionality | subfinder (if installed) + crt.sh (no auth) |
| `certificate_transparency` | 1 | Full functionality | crt.sh (no auth) |
| `wayback_machine` | 1 | Full functionality (Wayback CDX) | gau/waybackurls/CDX API |
| `email_harvesting` | 1 | PGP keyservers (no auth) + theHarvester (if installed) | Hunter.io / theHarvester skipped if no key |
| `shodan_censys` | 2 | Uses **Shodan InternetDB** (no key, IP lookup only) | `https://internetdb.shodan.io/{ip}` |
| `github_recon` | 2 | GitHub Code Search works without token, but **60 req/hr limit** | `https://api.github.com` |
| `metadata_analysis` | 2 | Full functionality | exiftool + python-docx/pypdf |
| `google_dorking` | 2 | Falls back to **curated GHDB templates** | ~50 dorks hardcoded |
| `breach_data` | 3 | HIBP **k-anonymity** works without key, but **strict rate limit** | `api.pwnedpasswords.com/range/{prefix}` |
| `socmint` | 3 | Skipped if no tools installed | recon-ng / SpiderFoot |
| `employee_osint` | 3 | Skipped if no tools installed | linkedin2username / sherlock |
| `dark_web_osint` | 3 | Ahmia.fi works without key (Tor required for `.onion` resolution) | `https://ahmia.fi/search/` |
| `person_dossier` | 3 | Full functionality (no external IO — reads sibling findings) | SHA-256 + Fernet |

**Bottom line**: Tier 0 gives you **15 modules running, 4 without enrichment** (shodan_censys, github_recon, google_dorking, breach_data all work but with less data or stricter rate limits). No payment required.

### Binaries to install (free, ~10 min)

Most of these are one Homebrew / apt / go install away. **Required** for full coverage, **optional** for minimum viable.

| Binary | Used by | Install (macOS) | Install (Linux) | Verify |
|--------|---------|-----------------|-----------------|--------|
| `dig` + `host` | dns_enum | built-in | `apt install dnsutils` | `dig +short google.com` |
| `subfinder` | subdomain_enum | `brew install subfinder` | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subfinder -version` |
| `exiftool` | metadata_analysis | `brew install exiftool` | `apt install libimage-exiftool-perl` | `exiftool -ver` |
| `theHarvester` | email_harvesting | `brew install theharvester` | `pipx install theHarvester` | `theHarvester -h` |
| `gh` | github_recon | `brew install gh` | See [cli.github.com](https://cli.github.com/) | `gh --version` |
| `gitleaks` | github_recon | `brew install gitleaks` | `go install github.com/zricethezav/gitleaks/v8@latest` | `gitleaks version` |
| `gau` | wayback_machine | `brew install gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` | `gau --version` |
| `waybackurls` | wayback_machine | `brew install waybackurls` | `go install github.com/tomnomnom/waybackurls@latest` | `waybackurls -version` |
| `recon-ng` | socmint | `pipx install recon-ng` | same | `recon-ng --help` |
| `linkedin2username` | employee_osint | `pipx install linkedin2username` | same | `linkedin2username -h` |
| `sherlock` | employee_osint | `brew install sherlock` or `pipx install sherlock-project` | same | `sherlock --version` |
| `amass` | subdomain_enum (optional) | `brew install amass` | See [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) | `amass -version` |

**To verify all at once** (run this after installing):

```bash
for bin in dig host subfinder exiftool theHarvester gh gitleaks gau waybackurls; do
  if command -v "$bin" &>/dev/null; then
    echo "  ✓ $bin: $(command -v $bin)"
  else
    echo "  ✗ $bin: MISSING"
  fi
done
```

**Missing binaries are fine** — the modules that need them will skip and log a warning. The job still completes.

---

## Tier 1 — Free enrichments (recommended)

Three accounts that take ~5 min each, give you much richer output, and cost nothing.

### 1.1 Censys (for `shodan_censys` enrichment)

**Why**: without it, `shodan_censys` only queries Shodan InternetDB (basic ports + tags). With it, you get Censys Search data (CVEs observed, products, geo).

**Free tier**: 250 queries/month, 1 query/second. Plenty for a single recon engagement.

**How to get it** (5 min):

1. Go to [search.censys.io/register](https://search.censys.io/register)
2. Sign up with email + password
3. Verify your email
4. Go to [search.censys.io/account/api](https://search.censys.io/account/api)
5. Copy your **API ID** and **Secret**

**Configure**:

```bash
# In backend/.env (or .env at repo root)
CENSYS_API_ID=your-api-id-here
CENSYS_API_SECRET=your-secret-here
```

**Verify**:

```bash
curl -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  "https://search.censys.io/api/v1/hosts/8.8.8.8" | jq '. | {ip, services: [.services[] | {port_name, service_name}]}'
```

You should see `8.8.8.8` with its DNS service. If you get 401, the credentials are wrong.

---

### 1.2 GitHub personal access token (for `github_recon`)

**Why**: without a token, GitHub API limits you to **60 requests/hour per IP** — you'll hit 429s within 2 minutes of any serious recon. With a token, you get 5,000 req/hour.

**Free tier**: 5,000 req/hour with any GitHub account.

**How to get it** (3 min):

1. Go to [github.com/settings/tokens?type=classic](https://github.com/settings/tokens?type=classic)
2. Click **"Generate new token"** → **"Generate new token (classic)"**
3. **Note**: `zimlama-recon-local`
4. **Expiration**: 90 days (or your preference; you'll just re-issue)
5. **Scopes**: only `public_repo` is required. Do NOT grant write/admin scopes.
6. Click **"Generate token"**
7. **Copy the token immediately** — you won't see it again

**Configure**:

```bash
# In backend/.env
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Verify**:

```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/rate_limit" | jq '.rate | {limit, remaining, reset}'
```

`limit` should be 5000. If it's 60, the token wasn't applied.

---

### 1.3 SerpAPI (for `google_dorking` real searches)

**Why**: without it, `google_dorking` returns curated GHDB templates (50 hand-picked dorks, no actual Google results). With it, you get real Google SERP results through SerpAPI.

**Free tier**: 100 searches/month, then $50/mo for 5,000.

**How to get it** (3 min):

1. Go to [serpapi.com](https://serpapi.com/)
2. Click **"Register"** → sign up with email
3. Verify email
4. Go to [serpapi.com/dashboard](https://serpapi.com/dashboard)
5. Copy your **Private API Key**

**Configure**:

```bash
# In backend/.env
SERP_API_KEY=your-serpapi-key
```

**Verify**:

```bash
curl "https://serpapi.com/search?q=test&api_key=$SERP_API_KEY" | jq '.search_metadata | {status, total_results_time}'
```

Should return status "Success" and a numeric time.

---

## Tier 2 — Paid (optional)

### 2.1 HIBP (for `breach_data` without 429s)

**Why**: without a key, HIBP enforces strict rate limits (~1 req/2 sec shared pool). Multi-email recon jobs will hit 429s. With a key, you get 10 req/sec dedicated.

**Cost**: $3.50 USD/month (Pwned 1 plan). [Pricing](https://haveibeenpwned.com/API/Key).

**How to get it** (5 min):

1. Go to [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
2. Click **"Subscribe"** under the Pwned 1 plan
3. Pay $3.50 with credit card (PayPal also)
4. Once subscribed, the API key is shown on your account page
5. Copy the key

**Configure**:

```bash
# In backend/.env
HIBP_API_KEY=your-hibp-key-here
```

**Verify**:

```bash
curl -H "hibp-api-key: $HIBP_API_KEY" \
  "https://api.haveibeenpwned.com/range/21DA1" | head -5
```

Should return a list of hash suffixes (40-char hex strings). If you get 401, the key is wrong or the subscription is not active.

---

## MiniMax M3 (mandatory for AI validation)

Without `MINIMAX_API_KEY` set, the project **runs** in **stub mode**: jobs execute, findings are produced, but the AI validator returns empty verdicts with `recommended_action=CONTINUE`. Reports still render but lack the "AI validation badges".

To get real AI validation, you need a MiniMax M3 API key.

**Cost**: pay-per-token. New accounts typically get free credits to start. See [api.minimaxi.com](https://api.minimaxi.com/) for current pricing.

**How to get it** (3 min):

1. Go to [api.minimaxi.com](https://api.minimaxi.com/)
2. Sign up with email
3. Verify email
4. Go to your dashboard / API keys section
5. Create a new API key
6. Copy the key (it starts with `eyJ...` or `sk-...` depending on the current format)

**Configure**:

```bash
# In backend/.env
MINIMAX_API_KEY=your-key-here
# Optional: override the endpoint if you proxy it
# MINIMAX_BASE_URL=https://api.minimaxi.com/v1
# Optional: override the model
# MINIMAX_MODEL=MiniMax-M3
```

**Verify**:

```bash
curl -X POST "$MINIMAX_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $MINIMAX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "'"${MINIMAX_MODEL:-MiniMax-M3}"'",
    "messages": [{"role": "user", "content": "Reply with the word OK"}],
    "max_tokens": 10
  }' | jq '.choices[0].message.content'
```

Should return `"OK"`. If you get 401, the key is wrong. If 402, out of credits.

---

## Free public APIs (no setup needed)

These work out of the box. They're called by modules with no auth. If any of these are down, the relevant module logs a warning and continues with other sources.

| API | URL | Used by | Auth |
|-----|-----|---------|------|
| crt.sh | `https://crt.sh` | certificate_transparency, subdomain_enum | None |
| Wayback CDX | `https://web.archive.org/cdx/search/cdx` | wayback_machine | None |
| RDAP bootstrap | `https://data.iana.org/rdap` | whois_rdap | None |
| Shodan InternetDB | `https://internetdb.shodan.io` | shodan_censys | None |
| HIBP k-anonymity | `https://api.pwnedpasswords.com/range/...` | breach_data | None (but rate-limited) |
| Ahmia.fi | `https://ahmia.fi/search/` | dark_web_osint | None |

**No setup. No accounts. No cost.** If your network blocks them, the modules just produce fewer findings.

---

## Encryption key (Fernet, for `person_dossier`)

This is **not** an external service — it's a local symmetric key. But it's mandatory in production (fail-loud at boot) so it's documented here.

**Why**: the `person_dossier` module encrypts raw emails at rest in the `identity_map` table (PR 4 privacy-by-design). Without this key, the table is skipped and a warning is logged per affected email hash.

**Cost**: free. **Risk**: if you lose this key, encrypted emails in `identity_map` become unreadable forever. **Back it up**.

**How to get it**:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

This prints a base64-encoded 32-byte key. **Copy it and store it somewhere safe** (1Password, Bitwarden, encrypted file). The project will not display it again.

**Configure**:

```bash
# In backend/.env
PERSON_DOSSIER_ENCRYPTION_KEY=the-base64-key-here
```

**Verify**:

```bash
python -c "
from cryptography.fernet import Fernet
import os
key = os.environ['PERSON_DOSSIER_ENCRYPTION_KEY'].encode()
f = Fernet(key)
print('OK' if f.decrypt(f.encrypt(b'test')) == b'test' else 'FAIL')
"
```

**Key rotation is not supported in v0.2.x.** If you need to rotate, you must decrypt all rows in `identity_map` with the old key, generate a new one, re-encrypt. Track for v0.3.0.

---

## The three setup profiles

Pick the profile that matches your budget and patience.

### Profile A — Minimum viable (10 min, $0)

```bash
# 1. Just MiniMax
MINIMAX_API_KEY=sk-...
# 2. Fernet key
PERSON_DOSSIER_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
# 3. Install 6 binaries (subfinder, exiftool, gh, gitleaks, gau, waybackurls)
# 4. Run ./install.sh
```

**What works**: all 15 modules, AI validation, handoff, reports. Shodan/Google/HIBP/GitHub use free tier / fallback sources. **No payment**.

### Profile B — Recommended free tier (20 min, $0)

```bash
# Same as A, plus:
CENSYS_API_ID=...
CENSYS_API_SECRET=...
GITHUB_TOKEN=ghp_...
# Optional: SERP_API_KEY=...
```

**What works**: A + Censys enrichment + 5,000 req/hr GitHub + real Google (if SerpAPI added). **Still no payment**.

### Profile C — Fully loaded (30 min, ~$4/mo)

```bash
# Same as B, plus:
HIBP_API_KEY=...
```

**What works**: B + 10 req/sec HIBP. **Pays $3.50/month** for HIBP.

---

## What `install.sh` actually does (v0.2.2+)

The installer is a full **interactive wizard** that handles every key in this document. The flow:

1. **Pre-flight checks** — OS detection (mac/linux/WSL), Docker + Compose v2, git, python3, cryptography module
2. **Bootstrap `.env`** from `.env.example` (idempotent — never overwrites existing)
3. **Required key** — prompts for `MINIMAX_API_KEY` (input masked, mandatory)
4. **Auto-generated local secrets** — `SECRET_KEY` and `PERSON_DOSSIER_ENCRYPTION_KEY` are generated via Python if blank. The Fernet key is mandatory in production.
5. **Optional API keys** — one prompt each for `CENSYS_API_ID`+`CENSYS_API_SECRET`, `GITHUB_TOKEN`, `SERP_API_KEY`, `HIBP_API_KEY`. Each one is skippable (Enter to skip). Pressing Enter keeps the current value.
6. **Operational** — `RECON_API_KEY` (Bearer auth) and `ROE_ENABLED` (y/N)
7. **External binaries report** — checks for `subfinder`, `exiftool`, `theHarvester`, `gh`, `gitleaks`, `gau`, `waybackurls`, `recon-ng`, `sherlock`. Missing ones are listed with a link back to this doc — the install does NOT fail.
8. **Build + start** — `docker compose build` then `--profile prod up -d`
9. **Health checks** — waits up to 60s for backend `/health` and frontend `:8080`
10. **Self-tests** — verifies every configured integration actually works:
    - Backend `/health` and `/health/ready`
    - Module registry returns ≥1 module
    - MiniMax API (if key set) — POST a tiny chat completion
    - GitHub API (if token set) — check `rate_limit` returns 5000
    - Censys API (if creds set) — fetch `8.8.8.8`
    - SerpAPI (if key set) — check `"Success"` status
    - HIBP API (if key set) — fetch a known range
    - Fernet key — round-trip encrypt/decrypt
    - Docker containers running
11. **Final report** — shows every key (masked) with ✓/○, lists missing binaries, and prints the next steps

Each self-test that fails shows the **exact remediation** in the output, e.g.:

```
  Backend /health/ready (DB + LLM)             FAIL
    ↳ Fix: Check docker compose logs backend | tail -50. If 'DB fail',
       verify DATABASE_URL. If 'LLM fail', verify MINIMAX_API_KEY.
```

**The installer is idempotent** — re-running it keeps everything that's already set and only prompts for what you type over. The self-tests run on every invocation, so you can re-run after editing `.env` to verify a fix.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Module skipped: requires_api_keys` | The module needs a key you didn't set | Either set the key or accept the skip (the module is opt-in) |
| `429 Too Many Requests` from HIBP | No API key, hitting shared rate limit | Add `HIBP_API_KEY` (Tier 2) |
| `401 Unauthorized` from MiniMax | Wrong key | Regenerate at [api.minimaxi.com](https://api.minimaxi.com/) |
| `60/hour rate limit` from GitHub | No token | Add `GITHUB_TOKEN` |
| `boot failed: PERSON_DOSSIER_ENCRYPTION_KEY must be set in production` | Prod env without Fernet key | Set the env var OR set `APP_ENV=development` (not recommended) |
| `binary not found: subfinder` | Didn't install it | Install via brew/go OR accept the module running with crt.sh only |

For deeper debugging see [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## What this document does NOT cover

- **Tor setup** for `dark_web_osint` — that needs a separate guide. The module uses Ahmia.fi (clearnet) by default; you only need Tor if you want to query `.onion` sites.
- **Self-hosted LLM** (e.g. running MiniMax-M3 behind a local proxy) — `MINIMAX_BASE_URL` accepts any OpenAI-compatible endpoint, so this works out of the box, but operational setup is out of scope.
- **Cloud deployment** (AWS/GCP secrets manager, etc.) — for production deployment, use your platform's secret store and inject as env vars.
- **Multi-user setup** — Tier 3 modules need `ROE_ENABLED=true` and a valid RoE for the target. See [docs/ARCHITECTURE.md](ARCHITECTURE.md) §RoE.

---

**See also**: [README.md](../README.md) · [docs/AI_VALIDATION.md](AI_VALIDATION.md) · [docs/MODULE_GUIDE.md](MODULE_GUIDE.md) · [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [.env.example](../backend/.env.example)
