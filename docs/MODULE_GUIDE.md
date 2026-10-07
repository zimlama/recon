# MODULE_GUIDE.md

> **Non-programmer readable.** What each of the 14 modules does, what it finds, what it does NOT do, and when to enable it. (Plus 1 aggregator — `person_dossier` on developer branch.)

## Quick reference

| Module | Tier | Always-on? | Time | API key | Consent |
|--------|------|------------|------|---------|---------|
| whois_rdap | 1 | ✅ | ~10s | — | — |
| dns_enum | 1 | ✅ | ~15s | — | — |
| subdomain_enum | 1 | ✅ | ~2-5min | — | — |
| certificate_transparency | 1 | ✅ | ~30s | — | — |
| wayback_machine | 1 | ✅ | ~1-2min | — | — |
| email_harvesting | 1 | ✅ | ~1-3min | — | PII handling |
| shodan_censys | 2 | ❌ (opt-in) | ~45s | Shodan (optional) | — |
| github_recon | 2 | ❌ (opt-in) | ~1min | GITHUB_TOKEN (optional) | — |
| metadata_analysis | 2 | ❌ (opt-in) | ~30s | — | — |
| google_dorking | 2 | ❌ (opt-in) | ~1min | SerpAPI (optional) | — |
| breach_data | 3 | ❌ (gated) | ~20s | HIBP (optional) | **explicit** |
| socmint | 3 | ❌ (gated) | ~2min | — | **explicit** |
| employee_osint | 3 | ❌ (gated) | ~1.5min | — | **explicit** |
| dark_web_osint | 3 | ❌ (gated) | ~3min | — | **explicit** + Tor |

## Tier 1 — Always-on, fully passive

### whois_rdap
**What**: Looks up domain registration info (registrar, dates, nameservers, registrant) via RDAP or WHOIS.
**Finds**: Domain registrar, creation date, expiration date, nameservers, status codes.
**Does NOT do**: No DNS queries, no subdomain discovery.
**Source**: RDAP (preferred) or WHOIS.
**MITRE**: T1596.002, T1590.001

### dns_enum
**What**: Queries DNS records (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV) for the target. Attempts AXFR.
**Finds**: IP addresses, mail servers, TXT records (SPF/DKIM/DMARC), name servers.
**Does NOT do**: No subdomain brute force (that's `subdomain_enum`).
**Source**: `dig` via subprocess.
**MITRE**: T1590.002, T1596.001

### subdomain_enum
**What**: Discovers subdomains via passive sources (crt.sh, subfinder, amass) + DNS validation.
**Finds**: Subdomains like `api.example.com`, `admin.example.com`, `staging.example.com`.
**Does NOT do**: No active DNS brute force (without explicit user opt-in).
**Source**: subfinder, crt.sh, amass.
**MITRE**: T1596.002, T1596.003, T1589.001

### certificate_transparency
**What**: Mines public Certificate Transparency logs for certificates issued to the target.
**Finds**: Subdomains (via SAN), issuing CAs, validity periods, internal hostnames leaked in certs.
**Does NOT do**: No direct connection to target.
**Source**: crt.sh, Censys cert search.
**MITRE**: T1596.003

### wayback_machine
**What**: Mines web.archive.org snapshots for removed/old content.
**Finds**: Historical URLs (admin panels, API endpoints, backup files, dev paths).
**Does NOT do**: No live crawling (that's separate).
**Source**: gau, waybackurls, CDX API.
**MITRE**: T1593

### email_harvesting
**What**: Collects public email addresses from web pages, PGP keys, search engines.
**Finds**: Email addresses of employees, IT, support.
**Does NOT do**: No login attempts, no unauthorized outreach.
**PII handling**: Only collects public emails. Never used for unauthorized purposes.
**Source**: theHarvester, Hunter.io, PGP, HIBP.
**MITRE**: T1589.002

## Tier 2 — Free-tier APIs (opt-in)

### shodan_censys
**What**: Internet-wide asset search using Shodan InternetDB (free, no key) + Censys (free tier).
**Finds**: Open ports, services, banners, CVEs.
**Does NOT do**: No active probing.
**Source**: internetdb.shodan.io, Censys Search API.
**API key**: Optional (Shodan raises limits; InternetDB is keyless).
**MITRE**: T1596.005

### github_recon
**What**: Mines public GitHub for leaked secrets, internal hostnames, commit history.
**Finds**: API keys, internal hostnames, .env files, SSH keys, email addresses.
**Does NOT do**: No login attempts, no private repo access.
**PII handling**: Truncate secrets to first 4 + last 4 chars. Flag the secret TYPE only.
**Source**: gh CLI, GitHub Search API, gitleaks.
**API key**: Optional (GITHUB_TOKEN raises rate limit from 60 to 5000 req/h).
**MITRE**: T1593.003, T1552.001

### metadata_analysis
**What**: Extracts EXIF, author, software versions from public documents.
**Finds**: Usernames (from author), software versions, internal paths, GPS coordinates.
**Does NOT do**: No document modification.
**PII handling**: GPS coordinates are sensitive. Only note country/region.
**Source**: exiftool, metagoofil.
**MITRE**: T1593

### google_dorking
**What**: Search-engine advanced operators to find exposed files, admin panels.
**Finds**: Exposed config files, backup files, admin panels, error pages.
**Does NOT do**: No active probing.
**Source**: SerpAPI (optional), GHDB seed.
**API key**: Optional (SERP_API_KEY).
**MITRE**: T1593.002

## Tier 3 — White-hat gated (require explicit consent)

### breach_data
**What**: Checks if target emails appear in known breaches via HIBP k-anonymity.
**Finds**: Breach exposure count per email (no plaintext ever).
**Does NOT do**: No login attempts with found credentials.
**PII handling**: k-anonymity only (send first 5 chars of hash, never full email).
**Source**: HIBP API.
**API key**: Optional (HIBP_API_KEY raises rate limit).
**MITRE**: T1589.001

### socmint
**What**: Social-media intelligence using passive techniques + authorized research personas.
**Finds**: Public social profiles, connections, post patterns.
**Does NOT do**: No active engagement (no following, no DM, no liking).
**Ethics**: Respect platform ToS. No doxxing.
**Source**: SpiderFoot, Maltego, recon-ng.
**MITRE**: T1593.001

### employee_osint
**What**: Identifies employees and infers username conventions.
**Finds**: Employee names, roles, username patterns.
**Does NOT do**: No unauthorized use of personal data.
**PII handling**: Username patterns are useful for authorized password spray only.
**Source**: LinkedIn, sherlock, recon-ng.
**MITRE**: T1589.003, T1593.001

### dark_web_osint
**What**: Monitors Tor hidden services for credential dumps, target mentions.
**Finds**: Live credential dumps, target mentions, actor tradecraft.
**Does NOT do**: No transactions, no engagement with threat actors.
**Safety**: Read-only, evidence-archived, lab-isolated. Container must have no internet except via Tor.
**Source**: ahmia.fi, Telegram/Discord channels.
**MITRE**: T1589.001, T1593.001

## How to enable modules

In the New Job form, modules are grouped by tier:

- **Tier 1**: Always checked by default. Uncheck to skip.
- **Tier 2**: Unchecked by default. Check to enable.
- **Tier 3**: Unchecked by default. Checking requires explicit consent.

You can also enable/disable modules per-job in the form.

## Cost & rate limits

| Module | API calls | Cost |
|--------|-----------|------|
| whois_rdap | 1-2 | Free |
| dns_enum | 10-20 | Free |
| subdomain_enum | 50-200 | Free |
| certificate_transparency | 10-50 | Free |
| wayback_machine | 50-200 | Free |
| email_harvesting | 10-50 | Free (theHarvester) / paid (Hunter.io) |
| shodan_censys | 10-50 | Free (InternetDB) / paid (Shodan) |
| github_recon | 50-200 | Free (60/h) / paid (GITHUB_TOKEN = 5000/h) |
| metadata_analysis | 5-20 | Free |
| google_dorking | 10-50 | Free (GHDB) / paid (SerpAPI) |
| breach_data | 10-50 | Free (10/min) / paid (HIBP_API_KEY = 100/min) |
| socmint | 100-500 | Free (manual) / paid (SpiderFoot HX) |
| employee_osint | 50-200 | Free (manual) |
| dark_web_osint | 100-500 | Free (Tor) |
| AI validation | 1 per module | **Paid** (MiniMax M3 API) |

## When to run which modules

- **Quick recon (5 min)**: All Tier 1
- **Standard recon (15 min)**: All Tier 1 + shodan_censys + github_recon
- **Deep recon (30 min)**: All Tier 1 + Tier 2 + breach_data
- **Full recon (60+ min)**: All modules including Tier 3

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [HANDOFF.md](HANDOFF.md)
- [AI_VALIDATION.md](AI_VALIDATION.md)
