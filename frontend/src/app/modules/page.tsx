'use client';

import { use, useEffect, useState } from 'react';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { listModules, type ModuleInfo } from '@/lib/api-client';

const TIER_DESCRIPTIONS: Record<string, string> = {
  tier_1: 'Always-on, fully passive. No API keys or consent required (except email_harvesting for PII).',
  tier_2: 'Free-tier APIs (Shodan InternetDB, Censys, GitHub). Opt-in. Some require API keys for higher rate limits.',
  tier_3: 'White-hat gated. Require explicit user consent. May touch PII or third-party services (dark web, breach data).',
};

export default function ModulesPage() {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listModules()
      .then((data) => {
        setModules(data.modules);
        setLoading(false);
      })
      .catch((e) => {
        setError((e as Error).message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-1/3" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <p className="text-sev-critico">Error: {error}</p>
        </CardContent>
      </Card>
    );
  }

  const byTier = modules.reduce<Record<string, ModuleInfo[]>>((acc, m) => {
    (acc[m.tier] ??= []).push(m);
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-titulos font-bold text-zimlama-blanco mb-2">
          Module Catalog
        </h1>
        <p className="text-zimlama-gris">
          {modules.length} recon modules organized in 3 tiers. See the{' '}
          <Link href="/docs" className="text-zimlama-rojo no-underline">
            MODULE_GUIDE
          </Link>{' '}
          for detailed documentation.
        </p>
      </div>

      {Object.entries(byTier).map(([tier, mods]) => (
        <div key={tier}>
          <div className="mb-3">
            <h2 className="text-xl font-titulos font-bold text-zimlama-blanco">
              {tier.replace('_', ' ').toUpperCase()}
              <span className="text-sm text-zimlama-gris font-normal ml-2">
                ({mods.length} modules)
              </span>
            </h2>
            <p className="text-sm text-zimlama-gris mt-1">
              {TIER_DESCRIPTIONS[tier]}
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {mods.map((m) => (
              <Card key={m.name}>
                <div className="flex items-start justify-between mb-1">
                  <h3 className="font-mono text-sm text-zimlama-piel">{m.name}</h3>
                  {m.enabled_by_default && (
                    <span className="text-xs text-zimlama-gris">on</span>
                  )}
                </div>
                <p className="text-sm text-zimlama-blanco mb-2">{m.description}</p>
                {m.mitre_techniques.length > 0 && (
                  <div className="text-xs text-zimlama-gris">
                    MITRE:{' '}
                    {m.mitre_techniques.map((t) => (
                      <code key={t} className="font-mono mr-1">
                        {t}
                      </code>
                    ))}
                  </div>
                )}
                {m.requires_api_keys.length > 0 && (
                  <div className="text-xs text-sev-medio mt-1">
                    API keys: {m.requires_api_keys.join(', ')}
                  </div>
                )}
                {m.requires_consent && (
                  <div className="text-xs text-sev-alto mt-1">
                    ⚠ Requires consent
                  </div>
                )}
              </Card>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
