import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Skeleton } from '@/components/ui/skeleton';

describe('Skeleton', () => {
  it('renders with animate-pulse class', () => {
    const { container } = render(<Skeleton />);
    const el = container.firstChild as HTMLElement;
    expect(el.className).toContain('animate-pulse');
    expect(el.className).toContain('bg-zimlama-gris/20');
  });

  it('applies custom className', () => {
    const { container } = render(<Skeleton className="h-12 w-full" />);
    const el = container.firstChild as HTMLElement;
    expect(el.className).toContain('h-12');
    expect(el.className).toContain('w-full');
  });
});
