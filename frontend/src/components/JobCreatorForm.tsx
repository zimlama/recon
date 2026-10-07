'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { DisclaimerModal } from '@/components/DisclaimerModal';
import { CONSENT_MODAL_VERSION, APP_NAME } from '@/lib/constants';
import { createJob, listModules, type ModuleInfo, type JobCreate } from '@/lib/api-client';

export function JobCreatorForm() {
  const [target, setTarget] = useState('');
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
  const [availableModules, setAvailableModules] = useState<ModuleInfo[]>([]);
  const [showDisclaimer, setShowDisclaimer] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Load available modules on mount
  useEffect(() => {
    listModules()
      .then((data) => {
        setAvailableModules(data.modules);
        // Pre-select Tier 1 modules (always-on)
        const tier1 = data.modules
          .filter((m) => m.tier === 'tier_1')
          .map((m) => m.name);
        setSelectedModules(new Set(tier1));
        setLoading(false);
      })
      .catch((e) => {
        setError(`Failed to load modules: ${(e as Error).message}`);
        setLoading(false);
      });
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Target is required');
      return;
    }
    if (selectedModules.size === 0) {
      setError('Select at least one module');
      return;
    }
    setError(null);
    setShowDisclaimer(true);
  };

  const handleConfirm = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const payload: JobCreate = {
        target: target.trim(),
        selected_modules: Array.from(selectedModules),
        user_consent: true,
        typed_confirmation: target.trim(),
        consent_modal_version: CONSENT_MODAL_VERSION,
      };
      const job = await createJob(payload);
      // Redirect to job detail
      window.location.href = `/jobs/${job.id}`;
    } catch (e) {
      setError((e as Error).message);
      setSubmitting(false);
    }
  };

  const toggleModule = (name: string) => {
    const next = new Set(selectedModules);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    setSelectedModules(next);
  };

  const modulesByTier = availableModules.reduce<Record<string, ModuleInfo[]>>(
    (acc, m) => {
      (acc[m.tier] ??= []).push(m);
      return acc;
    },
    {},
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>New Recon Job</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target */}
          <div>
            <label
              htmlFor="target"
              className="block text-sm font-titulos font-bold text-zimlama-blanco mb-2"
            >
              Target Domain
            </label>
            <Input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              data-testid="target-input"
            />
            <p className="text-xs text-zimlama-gris mt-1">
              The domain or URL you have <strong>written authorization</strong> to test.
            </p>
          </div>

          {/* Modules */}
          <div>
            <label className="block text-sm font-titulos font-bold text-zimlama-blanco mb-2">
              Modules to run
            </label>
            {loading && <p className="text-sm text-zimlama-gris">Loading modules...</p>}
            {Object.entries(modulesByTier).map(([tier, mods]) => (
              <div key={tier} className="mb-4">
                <h3 className="text-xs uppercase tracking-wide text-zimlama-gris mb-2">
                  {tier.replace('_', ' ')} ({mods.length})
                </h3>
                <div className="space-y-1">
                  {mods.map((m) => (
                    <label
                      key={m.name}
                      className="flex items-start gap-2 p-2 rounded hover:bg-zimlama-gris/10 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={selectedModules.has(m.name)}
                        onChange={() => toggleModule(m.name)}
                        disabled={m.tier === 'tier_3'}
                        className="mt-1"
                        data-testid={`module-${m.name}`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="font-mono text-sm text-zimlama-blanco">
                          {m.name}
                        </div>
                        <div className="text-xs text-zimlama-gris">{m.description}</div>
                        {m.requires_consent && (
                          <div className="text-xs text-sev-alto mt-0.5">
                            ⚠ Requires explicit consent (PII)
                          </div>
                        )}
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Error */}
          {error && (
            <div className="p-3 bg-sev-critico/20 border border-sev-critico rounded text-sm text-sev-critico">
              {error}
            </div>
          )}

          {/* Submit */}
          <div className="flex gap-3 justify-end">
            <Button
              type="submit"
              disabled={loading || !target.trim() || selectedModules.size === 0}
              data-testid="submit-job"
            >
              Start Recon →
            </Button>
          </div>
        </form>
      </CardContent>

      <DisclaimerModal
        open={showDisclaimer}
        target={target}
        onCancel={() => setShowDisclaimer(false)}
        onConfirm={handleConfirm}
      />
    </Card>
  );
}
