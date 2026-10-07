import * as React from 'react';
import { cn } from '@/lib/utils';

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
};

const variants = {
  primary:
    'bg-zimlama-rojo text-zimlama-blanco hover:opacity-90 disabled:opacity-50',
  secondary:
    'bg-zimlama-gris/20 text-zimlama-blanco border border-zimlama-gris/50 hover:bg-zimlama-gris/30',
  danger:
    'bg-sev-critico text-white hover:opacity-90',
  ghost: 'bg-transparent text-zimlama-blanco/80 hover:text-zimlama-blanco',
};

const sizes = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2 text-base',
  lg: 'px-6 py-3 text-lg',
};

export function Button({
  className,
  variant = 'primary',
  size = 'md',
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center font-titulos font-bold rounded-md transition-opacity disabled:cursor-not-allowed',
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
}
