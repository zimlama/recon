import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AIValidationBadge } from '@/components/AIValidationBadge';

describe('AIValidationBadge', () => {
  it('renders CONFIRMED with correct color', () => {
    render(<AIValidationBadge verdict="CONFIRMED" />);
    const badge = screen.getByText('Confirmed');
    expect(badge.className).toContain('bg-sev-bajo');
    expect(badge.getAttribute('title')).toContain('CONFIRMED');
  });

  it('renders LIKELY', () => {
    render(<AIValidationBadge verdict="LIKELY" />);
    const badge = screen.getByText('Likely');
    expect(badge.className).toContain('bg-sev-medio');
  });

  it('renders SUSPECTED', () => {
    render(<AIValidationBadge verdict="SUSPECTED" />);
    const badge = screen.getByText('Suspected');
    expect(badge.className).toContain('bg-sev-info');
  });

  it('renders FALSE_POSITIVE in neutral color', () => {
    render(<AIValidationBadge verdict="FALSE_POSITIVE" />);
    const badge = screen.getByText('False Positive');
    expect(badge.className).toContain('bg-zimlama-gris');
  });
});
