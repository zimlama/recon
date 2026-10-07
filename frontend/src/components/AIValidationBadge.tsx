'use client';

import { cn } from '@/lib/utils';

export type Verdict = 'CONFIRMED' | 'LIKELY' | 'SUSPECTED' | 'FALSE_POSITIVE';

const colors: Record<Verdict, string> = {
  CONFIRMED: 'bg-sev-bajo text-white',
  LIKELY: 'bg-sev-medio text-zimlama-negro',
  SUSPECTED: 'bg-sev-info text-white',
  FALSE_POSITIVE: 'bg-zimlama-gris/60 text-zimlama-blanco',
};

const labels: Record<Verdict, string> = {
  CONFIRMED: 'Confirmed',
  LIKELY: 'Likely',
  SUSPECTED: 'Suspected',
  FALSE_POSITIVE: 'False Positive',
};

export function AIValidationBadge({
  verdict,
  className,
}: {
  verdict: Verdict;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-block px-2 py-0.5 text-xs font-mono font-semibold rounded',
        colors[verdict],
        className,
      )}
      title={`AI verdict: ${verdict}`}
    >
      {labels[verdict]}
    </span>
  );
}
