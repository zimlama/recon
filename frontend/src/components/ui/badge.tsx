import * as React from 'react';
import { cn } from '@/lib/utils';

export type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'neutral';

const variants: Record<BadgeVariant, string> = {
  default: 'bg-zimlama-gris/40 text-zimlama-blanco',
  success: 'bg-sev-bajo text-white',
  warning: 'bg-sev-medio text-zimlama-negro',
  danger: 'bg-sev-critico text-white',
  info: 'bg-zimlama-piel/80 text-zimlama-negro',
  neutral: 'bg-zimlama-gris/20 text-zimlama-gris',
};

export function Badge({
  variant = 'default',
  className,
  ...props
}: { variant?: BadgeVariant } & React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        'inline-block px-2 py-0.5 text-xs font-mono font-semibold rounded-pill',
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
