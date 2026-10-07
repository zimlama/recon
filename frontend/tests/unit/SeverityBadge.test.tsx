import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge } from '@/components/SeverityBadge';

describe('SeverityBadge', () => {
  it('renders CRITICAL with correct color', () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByText('CRITICAL');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('bg-sev-critico');
  });

  it('renders HIGH', () => {
    render(<SeverityBadge severity="high" />);
    const badge = screen.getByText('HIGH');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain('bg-sev-alto');
  });

  it('renders MEDIUM', () => {
    render(<SeverityBadge severity="medium" />);
    const badge = screen.getByText('MEDIUM');
    expect(badge.className).toContain('bg-sev-medio');
  });

  it('renders LOW', () => {
    render(<SeverityBadge severity="low" />);
    const badge = screen.getByText('LOW');
    expect(badge.className).toContain('bg-sev-bajo');
  });

  it('renders INFO', () => {
    render(<SeverityBadge severity="info" />);
    const badge = screen.getByText('INFO');
    expect(badge.className).toContain('bg-sev-info');
  });

  it('applies custom className', () => {
    render(<SeverityBadge severity="high" className="ml-2" />);
    const badge = screen.getByText('HIGH');
    expect(badge.className).toContain('ml-2');
  });
});
