import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from '@/components/ui/badge';

describe('Badge', () => {
  it('renders default variant with neutral color', () => {
    render(<Badge>Default</Badge>);
    const el = screen.getByText('Default');
    expect(el.className).toContain('bg-zimlama-gris/40');
  });

  it('renders success variant', () => {
    render(<Badge variant="success">Success</Badge>);
    const el = screen.getByText('Success');
    expect(el.className).toContain('bg-sev-bajo');
  });

  it('renders warning variant', () => {
    render(<Badge variant="warning">Warning</Badge>);
    const el = screen.getByText('Warning');
    expect(el.className).toContain('bg-sev-medio');
  });

  it('renders danger variant', () => {
    render(<Badge variant="danger">Danger</Badge>);
    const el = screen.getByText('Danger');
    expect(el.className).toContain('bg-sev-critico');
  });

  it('renders info variant', () => {
    render(<Badge variant="info">Info</Badge>);
    const el = screen.getByText('Info');
    expect(el.className).toContain('bg-zimlama-piel');
  });

  it('renders neutral variant', () => {
    render(<Badge variant="neutral">Neutral</Badge>);
    const el = screen.getByText('Neutral');
    expect(el.className).toContain('bg-zimlama-gris/20');
  });

  it('uses pill border radius', () => {
    const { container } = render(<Badge>x</Badge>);
    const el = container.firstChild as HTMLElement;
    expect(el.className).toContain('rounded-pill');
  });
});
