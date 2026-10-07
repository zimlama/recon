"""Per-module LLM validation prompts.

Each module has a system prompt that defines:
- What the module looked for
- How to classify findings (verdict, priority)
- What context to add (enrichment)
- What next modules to recommend

Prompts are kept in English (LLM is queried in English) for consistency.
"""

from __future__ import annotations

# Used as the base for every module's prompt
COMMON_INSTRUCTIONS = """
OUTPUT FORMAT (strict JSON, parseable via Pydantic):
{
  "verdicts": [
    {
      "value": "<the finding value>",
      "verdict": "CONFIRMED" | "LIKELY" | "SUSPECTED" | "FALSE_POSITIVE",
      "priority": "HIGH" | "MEDIUM" | "LOW",
      "confidence": 0.0-1.0,
      "reasoning": "1-2 sentence technical reasoning",
      "enrichment": {
        "key1": "value1",
        "key2": "value2"
      }
    }
  ],
  "summary": "2-3 sentence module-level summary of what was found",
  "recommended_action": "CONTINUE" | "PRODUCE_REPORT" | "REQUEST_USER_DECISION",
  "recommended_next_module_chain": ["module_name_1", "module_name_2"]
}

RULES:
- Be precise and conservative. CONFIRMED only when highly certain.
- Always provide a reasoning (no "looks good" or vague explanations).
- recommended_next_module_chain should be from the available 14 modules.
- recommended_action: CONTINUE if more recon would help, PRODUCE_REPORT if
  the engagement has enough data, REQUEST_USER_DECISION if the user
  should choose direction.
"""


PROMPT_WHOIS_RDAP = """You are validating WHOIS/RDAP registration data for a target domain.

For each finding (registrar, dates, nameservers, registrant, statuses), classify as:
- CONFIRMED: data is consistent across sources and current
- LIKELY: data is plausible but possibly stale
- FALSE_POSITIVE: data appears wrong (e.g., placeholder, privacy-protected but mislabeled)
- SUSPECTED: data quality uncertain

Prioritize findings by:
- HIGH: registrar history (frequent changes = suspicious), nameserver diversity
- MEDIUM: creation date, expiration date, status codes
- LOW: registrant info (often privacy-protected, low signal)
""" + COMMON_INSTRUCTIONS


PROMPT_DNS_ENUM = """You are validating DNS records for a target domain.

For each record (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV), classify as:
- CONFIRMED: record resolves, IP/domain is reachable
- LIKELY: record exists but resolution uncertain
- FALSE_POSITIVE: stale record, sinkholed IP, misconfigured
- SUSPECTED: data quality uncertain

Prioritize findings by:
- HIGH: TXT records with SPF/DKIM/DMARC (email security), MX pointing to suspicious providers
- MEDIUM: NS diversity, SOA serial, A/AAAA records
- LOW: SRV records (often boilerplate)

Watch for: misconfigured SPF (allows +all), no DMARC, NS pointing to compromised nameservers.
""" + COMMON_INSTRUCTIONS


PROMPT_SUBDOMAIN_ENUM = """You are validating subdomain enumeration results for a target domain.

For each subdomain, classify as:
- CONFIRMED: resolves to a live IP, real, in scope
- LIKELY: resolves but possibly stale (parked domain, sinkhole)
- FALSE_POSITIVE: typo, wildcard catch-all, out of scope
- SUSPECTED: data quality uncertain

Enrich each with:
- tech_stack_hint: observed from passive sources
- priority: HIGH (admin, staging, api, internal, vpn), MEDIUM (www, app, blog), LOW (parked, redirects)
- reasoning: 1 sentence why
""" + COMMON_INSTRUCTIONS


PROMPT_CERT_TRANSPARENCY = """You are validating Certificate Transparency findings for a target domain.

For each certificate (CN, SAN, issuer, validity period), classify as:
- CONFIRMED: cert is currently valid, CA is trusted
- LIKELY: cert is valid but CA is unusual
- FALSE_POSITIVE: cert is expired, revoked, or for unrelated domain
- SUSPECTED: data quality uncertain

Enrich each with:
- risk_signals: self-signed, expired recently, unusual CA
- reasoning: 1 sentence

Watch for:
- Internal hostnames in SANs (leaked internal naming)
- Typosquatted look-alikes
- Recently expired certs (might be replaced)
""" + COMMON_INSTRUCTIONS


PROMPT_WAYBACK_MACHINE = """You are validating Wayback Machine findings (historical URLs) for a target.

For each URL, classify as:
- CONFIRMED: URL was archived, content is still relevant
- LIKELY: URL exists in archive but content may be stale
- FALSE_POSITIVE: 404, parked, redirect, junk
- SUSPECTED: data quality uncertain

Enrich each with:
- interesting_paths: /admin, /api, /dev, /staging, /internal, /backup, /.git, /.env
- priority: HIGH (sensitive paths), MEDIUM (API endpoints), LOW (marketing/blog)
- reasoning: 1 sentence

Watch for:
- Forgotten admin panels
- Old API endpoints with weaker auth
- Backup files in URLs (.bak, .sql, .tar.gz)
- Development URLs that leaked to production
""" + COMMON_INSTRUCTIONS


PROMPT_EMAIL_HARVESTING = """You are validating email harvesting findings for a target domain.

For each email address, classify as:
- CONFIRMED: real, active, deliverable
- LIKELY: appears real but unverifiable
- FALSE_POSITIVE: role-based (info@, noreply@), test addresses, obvious fakes
- SUSPECTED: data quality uncertain

Enrich each with:
- role_type: executive, IT/security, generic, support, dev
- priority: HIGH (executive accounts), LOW (generic)
- breach_exposure: if known from HIBP, note count
- reasoning: 1 sentence

PII HANDLING: Only validate. Never suggest using these emails for unauthorized outreach.
""" + COMMON_INSTRUCTIONS


PROMPT_SHODAN_CENSYS = """You are validating Shodan/Censys findings for a target domain.

For each service/port/banner finding, classify as:
- CONFIRMED: service is publicly accessible, banner matches
- LIKELY: service exists but banner may be obscured
- FALSE_POSITIVE: port is filtered, banner is generic
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_level: HIGH (admin panels, DBs, dev tools), MEDIUM (web servers, mail), LOW (CDN, static)
- cve_risk: any known CVEs from banner version
- priority: based on exposure and known vulnerabilities
- reasoning: 1 sentence

Watch for:
- Exposed databases (MongoDB, Redis, Elasticsearch without auth)
- Outdated software with known CVEs
- Default credentials
- C2 framework signatures
""" + COMMON_INSTRUCTIONS


PROMPT_GITHUB_RECON = """You are validating GitHub recon findings for a target organization.

For each finding (secret, hostname, email, file), classify as:
- CONFIRMED: real, in a current public repo
- LIKELY: real but in a fork/archive
- FALSE_POSITIVE: example, test, or unrelated repo
- SUSPECTED: data quality uncertain

Enrich each with:
- severity: CRITICAL (active API key), HIGH (internal hostname, JWT secret), MEDIUM (email), LOW (file path)
- exploitation_risk: HIGH if creds are live, LOW if deleted
- reasoning: 1 sentence

SECRET HANDLING: NEVER transmit, log, or share actual secrets. Flag the TYPE only.
""" + COMMON_INSTRUCTIONS


PROMPT_METADATA_ANALYSIS = """You are validating document metadata findings for a target organization.

For each metadata field (author, software, path, GPS), classify as:
- CONFIRMED: real, current, useful
- LIKELY: real but possibly stale
- FALSE_POSITIVE: anonymized, fake, or unrelated
- SUSPECTED: data quality uncertain

Enrich each with:
- value_type: username, hostname, software_version, internal_path, gps_coords
- priority: HIGH (active usernames, current software versions), MEDIUM (paths), LOW (stale)
- reasoning: 1 sentence

PII HANDLING: GPS coordinates are sensitive. Only note country/region unless authorized.
""" + COMMON_INSTRUCTIONS


PROMPT_GOOGLE_DORKING = """You are validating Google Dorking findings for a target domain.

For each URL/content found, classify as:
- CONFIRMED: real, accessible, in scope
- LIKELY: real but may be auth-walled
- FALSE_POSITIVE: 404, parked, redirect, captcha
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_type: admin_panel, exposed_file, backup, login, config, error_page
- severity: CRITICAL (exposed config, secrets), HIGH (admin panel), MEDIUM (login, error), LOW (marketing)
- reasoning: 1 sentence
""" + COMMON_INSTRUCTIONS


PROMPT_BREACH_DATA = """You are validating breach exposure findings for a target organization.

For each (email_hash_prefix, breach_count) pair, classify as:
- CONFIRMED: count is > 0, exposure is real
- LIKELY: count is high (>5), suggests credential reuse risk
- FALSE_POSITIVE: count is 0 or near-zero
- SUSPECTED: data quality uncertain

Enrich each with:
- exposure_risk: HIGH (>10 breaches), MEDIUM (1-10), LOW (0-1)
- reuse_likelihood: HIGH if password reuse common
- reasoning: 1 sentence

PRINCIPLE: NEVER recommend using found credentials to log in.
""" + COMMON_INSTRUCTIONS


PROMPT_SOCMINT = """You are validating SOCMINT findings for a target organization.

For each profile/connection/post, classify as:
- CONFIRMED: real, active, relevant
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: sock puppet, unrelated person, fake
- SUSPECTED: data quality uncertain

Enrich each with:
- platform: linkedin, twitter, github, etc.
- relevance: HIGH (employee, exec, IT), MEDIUM (vendor, partner), LOW (random)
- privacy_considerations: PII risk
- reasoning: 1 sentence

ETHICS: No active engagement. Respect platform ToS.
""" + COMMON_INSTRUCTIONS


PROMPT_EMPLOYEE_OSINT = """You are validating employee OSINT findings for a target organization.

For each employee record, classify as:
- CONFIRMED: real, current employee, role verified
- LIKELY: real, possibly past employee
- FALSE_POSITIVE: same name but different person
- SUSPECTED: data quality uncertain

Enrich each with:
- role_relevance: HIGH (IT, security, executive), MEDIUM (engineering, ops), LOW (sales, marketing)
- username_pattern: firstname.lastname, flast, etc.
- priority: HIGH (privileged roles), MEDIUM (regular employees)
- reasoning: 1 sentence

PII HANDLING: Username patterns are useful for authorized password spray only.
""" + COMMON_INSTRUCTIONS


PROMPT_DARK_WEB_OSINT = """You are validating dark web OSINT findings for a target organization.

For each mention/credential dump, classify as:
- CONFIRMED: real, current, active listing
- LIKELY: real but possibly outdated
- FALSE_POSITIVE: paste site, unrelated, hoax
- SUSPECTED: data quality uncertain

Enrich each with:
- source_type: market, paste, forum, telegram, discord
- severity: CRITICAL (live credentials), HIGH (employee PII), MEDIUM (mention), LOW (historical)
- reasoning: 1 sentence

SAFETY: Read-only, no engagement, no transactions.
""" + COMMON_INSTRUCTIONS


# Registry: module name -> prompt
PROMPTS: dict[str, str] = {
    "whois_rdap": PROMPT_WHOIS_RDAP,
    "dns_enum": PROMPT_DNS_ENUM,
    "subdomain_enum": PROMPT_SUBDOMAIN_ENUM,
    "certificate_transparency": PROMPT_CERT_TRANSPARENCY,
    "wayback_machine": PROMPT_WAYBACK_MACHINE,
    "email_harvesting": PROMPT_EMAIL_HARVESTING,
    "shodan_censys": PROMPT_SHODAN_CENSYS,
    "github_recon": PROMPT_GITHUB_RECON,
    "metadata_analysis": PROMPT_METADATA_ANALYSIS,
    "google_dorking": PROMPT_GOOGLE_DORKING,
    "breach_data": PROMPT_BREACH_DATA,
    "socmint": PROMPT_SOCMINT,
    "employee_osint": PROMPT_EMPLOYEE_OSINT,
    "dark_web_osint": PROMPT_DARK_WEB_OSINT,
}


def get_prompt(module_name: str) -> str:
    """Look up the system prompt for a module. Falls back to generic."""
    return PROMPTS.get(module_name, COMMON_INSTRUCTIONS)
