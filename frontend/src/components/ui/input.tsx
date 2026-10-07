import * as React from 'react';
import { cn } from '@/lib/utils';

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export function Input({ className, ...props }: InputProps) {
  return (
    <input
      className={cn(
        'w-full px-3 py-2 text-sm bg-zimlama-negro/60 border border-zimlama-gris/50 rounded-md',
        'text-zimlama-blanco placeholder:text-zimlama-gris/60',
        'focus:outline-none focus:border-zimlama-rojo focus:ring-1 focus:ring-zimlama-rojo',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        className,
      )}
      {...props}
    />
  );
}
