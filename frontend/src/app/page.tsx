import Link from 'next/link';

export default function HomePage() {
  return (
    <div className="space-y-8">
      {/* Hero */}
      <section className="zimlama-card text-center py-12">
        <h1 className="text-4xl font-titulos font-bold mb-3 text-zimlama-blanco">
          zimlama recon
        </h1>
        <p className="text-lg text-zimlama-gris mb-1">Phase 1 ethical hacking reconnaissance</p>
        <p className="text-sm text-zimlama-gris/70 mb-6">
          Self-hosted · Open source · AI-validated · Vendor-neutral
        </p>
        <Link
          href="/jobs/new"
          className="inline-block bg-zimlama-rojo text-zimlama-blanco px-6 py-3 rounded-md font-titulos font-bold no-underline hover:opacity-90"
        >
          Start a new recon →
        </Link>
      </section>

      {/* Stats placeholder */}
      <section className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="zimlama-card">
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">Total Jobs</p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">—</p>
        </div>
        <div className="zimlama-card">
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">Modules Available</p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">14</p>
        </div>
        <div className="zimlama-card">
          <p className="text-xs text-zimlama-gris uppercase tracking-wide">AI Provider</p>
          <p className="text-3xl font-titulos font-bold text-zimlama-blanco mt-1">M3</p>
        </div>
      </section>

      {/* Modules preview */}
      <section>
        <h2 className="text-2xl font-titulos font-bold mb-4">14 Recon Modules</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { name: 'whois_rdap', desc: 'Domain registration intel', tier: 'Tier 1' },
            { name: 'subdomain_enum', desc: 'Subdomain discovery', tier: 'Tier 1' },
            { name: 'certificate_transparency', desc: 'CT log mining', tier: 'Tier 1' },
            { name: 'wayback_machine', desc: 'Historical URL archive', tier: 'Tier 1' },
            { name: 'shodan_censys', desc: 'Internet asset search', tier: 'Tier 2' },
            { name: 'github_recon', desc: 'Code-host OSINT', tier: 'Tier 2' },
            { name: 'breach_data', desc: 'Credential exposure', tier: 'Tier 3' },
            { name: 'dark_web_osint', desc: 'Dark web monitoring', tier: 'Tier 3' },
          ].map((m) => (
            <div key={m.name} className="zimlama-card">
              <p className="font-mono text-xs text-zimlama-piel mb-1">{m.tier}</p>
              <p className="font-titulos font-bold text-zimlama-blanco mb-1">{m.name}</p>
              <p className="text-sm text-zimlama-gris">{m.desc}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 text-center">
          <Link href="/modules" className="text-zimlama-rojo no-underline text-sm">
            See all 14 modules →
          </Link>
        </div>
      </section>

      {/* Disclaimer callout */}
      <section className="zimlama-card border-sev-alto/30 bg-sev-alto/5">
        <h3 className="font-titulos font-bold text-sev-alto mb-2">⚠ Authorized Use Only</h3>
        <p className="text-sm text-zimlama-blanco/80">
          This tool sends real network requests to your target. Use only on systems you have{' '}
          <strong>WRITTEN AUTHORIZATION</strong> to test. Unauthorized access to computer systems is a
          crime under your local laws. See the full{' '}
          <Link href="/disclaimer" className="text-zimlama-rojo no-underline">
            disclaimer
          </Link>{' '}
          before running any recon.
        </p>
      </section>
    </div>
  );
}
