'use client';

import { cn } from '@/lib/utils';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const colors: Record<Severity, string> = {
  critical: 'bg-sev-critico text-white',
  high: 'bg-sev-alto text-white',
  medium: 'bg-sev-medio text-zimlama-negro',
  low: 'bg-sev-bajo text-white',
  info: 'bg-sev-info text-white',
};

const labels: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-block px-2 py-0.5 text-xs font-mono font-semibold rounded',
        colors[severity],
        className,
      )}
    >
      {labels[severity]}
    </span>
  );
}
