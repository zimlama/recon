# Security Policy

> Applies to [v0.1.0](https://github.com/zimlama/recon/releases/tag/v0.1.0) and later. The tool is Apache-2.0 licensed — see [LICENSE](LICENSE).

## Authorized Use Only

`zimlama/recon` is a security testing tool. It sends real network requests to your target — both passive (third-party APIs) and active (when Tier 3 modules are explicitly enabled).

**By using this tool you confirm ALL of the following:**

1. You have **WRITTEN AUTHORIZATION** to test the target.
2. You understand this tool sends real requests to third-party systems, including active scans (when Tier 3 modules are enabled).
3. You accept full responsibility for any consequences, legal or otherwise, of running this tool.
4. You will not use this tool against systems you don't own or have explicit permission to test.
5. You understand that unauthorized access to computer systems is a crime under your local laws.

## Applicable Laws (LATAM + Global)

Unauthorized access to computer systems is a crime under local laws, including but not limited to:

### Colombia

- **Código Penal, Art. 269** — *Acceso abusivo a sistemas informáticos*. Pena de prisión de 1 a 4 años, multa de 5 a 100 SMLMV.
- **Ley 1273 de 2009** — *Delitos informáticos*. Adds Art. 269A-E: obstaculización, interceptación, uso de software malicioso, hurto, transferencia no consentida.

### Brasil

- **Art. 154-A Código Penal** — *Invasão de dispositivo informático*. Pena de prisión de 1 a 4 años, multa.
- **Marco Civil da Internet (Ley 12.965/2014)**.

### México

- **Art. 269 Código Penal Federal** — Acceso ilícito a sistemas computacionales. Pena de prisión de 3 meses a 2 años, multa.
- **Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP)**.

### Argentina

- **Art. 153-157 bis Código Penal** — Delitos contra la integridad de sistemas informáticos.
- **Ley 25.036** — Reforma del código penal sobre delitos informáticos.

### Chile

- **Ley 19.223** — *Delitos informáticos*. Pena de presidio menor en su grado medio (541 días a 3 años).

### Perú

- **Art. 186-A Código Penal** — *Delitos contra la intimidad, el secreto de las comunicaciones y la inviolabilidad de las comunicaciones*. Pena de prisión de 1 a 4 años.

### Global

- **US**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
- **EU**: Directive 2013/40/EU on attacks against information systems.

## In-Scope Targets

The tool includes a built-in **banned targets list** that blocks scans against:

- `127.0.0.0/8` (loopback)
- `10.0.0.0/8` (RFC 1918 private)
- `172.16.0.0/12` (RFC 1918 private)
- `192.168.0.0/16` (RFC 1918 private)
- `169.254.0.0/16` (link-local)
- `0.0.0.0/8` (unspecified)
- `224.0.0.0/4` (multicast)
- `240.0.0.0/4` (reserved)
- `::1/128` (IPv6 loopback)
- `fc00::/7` (IPv6 ULA)

If the target resolves to a banned IP, the scan aborts immediately and logs to the audit trail.

## Reporting Vulnerabilities

If you discover a vulnerability in `zimlama/recon` itself, please report it via [GitHub Security Advisories](https://github.com/zimlama/recon/security/advisories/new) (private disclosure).

We commit to:
- Acknowledge within 48 hours
- Triage within 7 days
- Patch within 30 days (or sooner for critical issues)
- Public credit (if you want it) after the patch is released

## Telemetry

`zimlama/recon` collects **zero telemetry**. No analytics, no usage stats, no remote calls except the ones you explicitly configure (LLM provider, free APIs, target scans).

The only outbound traffic is:
- LLM provider (MiniMax M3, configurable)
- Free API sources you enable (Shodan, Censys, HIBP, GitHub, etc.)
- The target itself (this is the point)

All audit logs are stored locally in `./data/audit/`. You own them. You delete them.

## Data Retention

- Recon findings: SQLite DB at `./data/recon.db` (user-controlled)
- Handoff packets: `./data/handoffs/h-*.json` (user-controlled)
- Audit logs: `./data/audit/*.jsonl` (user-controlled)
- Reports: `./data/reports/*.{md,pdf}` (user-controlled)

To delete ALL data for a target:

```bash
docker compose exec backend python -m recon.purge --target example.com
```

This is required for GDPR, Habeas Data (Colombia), and equivalent data subject erasure rights.
