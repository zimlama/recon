import * as React from 'react';

export function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`animate-pulse bg-zimlama-gris/20 rounded ${className ?? ''}`}
      {...props}
    />
  );
}
