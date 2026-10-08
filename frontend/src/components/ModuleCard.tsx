'use client';

import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { AIValidationBadge } from './AIValidationBadge';
import { formatDuration } from '@/lib/utils';
import type { ModuleRun, AIValidation } from '@/lib/api-client';

const statusVariants: Record<string, 'default' | 'success' | 'warning' | 'danger' | 'info'> = {
  pending: 'neutral',
  running: 'info',
  completed: 'success',
  failed: 'danger',
  skipped: 'warning',
};

// Modules rendered by this component are entirely data-driven — the
// backend's MODULE_REGISTRY (see backend/app/modules/__init__.py) is the
// single source of truth. PR 4 added the `person_dossier` aggregator
// (Tier 3, gated) to that registry; this component renders it
// automatically without any change here. New modules surface here for
// free as long as the backend registers them.

export function ModuleCard({
  moduleRun,
  loading = false,
}: {
  moduleRun?: ModuleRun;
  loading?: boolean;
}) {
  if (loading || !moduleRun) {
    return (
      <Card>
        <Skeleton className="h-4 w-1/2 mb-2" />
        <Skeleton className="h-3 w-1/3" />
      </Card>
    );
  }

  const validation: AIValidation | null | undefined = moduleRun.validation;

  return (
    <Card data-testid={`module-run-${moduleRun.module_name}`}>
      <div className="flex items-start justify-between mb-2">
        <div>
          <h3 className="font-mono text-base text-zimlama-blanco">
            {moduleRun.module_name}
          </h3>
          <p className="text-xs text-zimlama-gris">
            Tier {moduleRun.module_tier.replace('_', ' ')} ·{' '}
            {formatDuration(moduleRun.duration_seconds)}
          </p>
        </div>
        <Badge variant={statusVariants[moduleRun.status] ?? 'default'}>
          {moduleRun.status}
        </Badge>
      </div>
      <div className="text-sm">
        <span className="text-zimlama-gris">Findings:</span>{' '}
        <span className="text-zimlama-blanco font-mono">
          {moduleRun.findings_count}
        </span>
      </div>
      {validation && (
        <div className="mt-3 pt-3 border-t border-zimlama-gris/30 text-xs">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-zimlama-gris">AI verdict:</span>
            {/* AIValidationBadge expects Verdict from a Finding; we render the action instead */}
            <span className="font-mono text-zimlama-piel">
              {validation.recommended_action}
            </span>
          </div>
          <p className="text-zimlama-gris/80 italic line-clamp-3">
            {validation.summary}
          </p>
        </div>
      )}
      {moduleRun.errors && moduleRun.errors.length > 0 && (
        <div className="mt-2 p-2 bg-sev-critico/20 border border-sev-critico/50 rounded text-xs text-sev-critico">
          {moduleRun.errors.join('; ')}
        </div>
      )}
    </Card>
  );
}
