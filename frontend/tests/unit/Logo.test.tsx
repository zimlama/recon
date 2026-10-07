import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Logo } from '@/components/Logo';

describe('Logo', () => {
  it('renders isotipo by default', () => {
    const { container } = render(<Logo />);
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute('aria-label')).toBe('zimlama');
  });

  it('renders horizontal variant', () => {
    const { container } = render(<Logo variant="horizontal" />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('aria-label')).toBe('zimlama recon');
  });

  it('renders vertical variant', () => {
    const { container } = render(<Logo variant="vertical" />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('aria-label')).toBe('zimlama recon');
  });

  it('respects size prop', () => {
    const { container } = render(<Logo size={64} />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('width')).toBe('64');
  });
});
