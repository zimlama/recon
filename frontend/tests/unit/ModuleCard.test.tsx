import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { ModuleCard } from '@/components/ModuleCard';
import type { ModuleRun } from '@/lib/api-client';

const baseRun: ModuleRun = {
  id: 'mr-1',
  module_name: 'whois_rdap',
  module_tier: 'tier_1',
  status: 'completed',
  started_at: '2026-10-06T14:00:00Z',
  completed_at: '2026-10-06T14:00:05Z',
  duration_seconds: 5.0,
  findings_count: 3,
  errors: [],
  findings: [],
  validation: null,
};

describe('ModuleCard', () => {
  it('shows loading state when no data', () => {
    const { container } = render(<ModuleCard />);
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
  });

  it('shows loading state when loading=true', () => {
    const { container } = render(<ModuleCard loading={true} />);
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument();
  });

  it('renders module name + status + findings count', () => {
    render(<ModuleCard moduleRun={baseRun} />);
    expect(screen.getByText('whois_rdap')).toBeInTheDocument();
    expect(screen.getByText('completed')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('renders AI validation summary when present', () => {
    const run: ModuleRun = {
      ...baseRun,
      validation: {
        id: 'av-1',
        module_run_id: 'mr-1',
        summary: 'Found 5 confirmed subdomains with high confidence.',
        confidence: 0.9,
        recommended_action: 'CONTINUE',
        recommended_next_modules: ['port_scanning'],
        model: 'MiniMax-M3',
        total_tokens: 1000,
        cost_usd: 0.01,
        validated_at: '2026-10-06T14:00:05Z',
      },
    };
    render(<ModuleCard moduleRun={run} />);
    expect(screen.getByText('CONTINUE')).toBeInTheDocument();
    expect(screen.getByText(/Found 5 confirmed/)).toBeInTheDocument();
  });

  it('shows error message when module has errors', () => {
    const run: ModuleRun = {
      ...baseRun,
      status: 'failed',
      errors: ['Subfinder not installed', 'CDX API unreachable'],
    };
    render(<ModuleCard moduleRun={run} />);
    expect(screen.getByText(/Subfinder not installed/)).toBeInTheDocument();
  });

  it('handles different module tiers (tier_1, tier_2, tier_3)', () => {
    // Use within() to search the meta paragraph (which contains the split text)
    const run1: ModuleRun = { ...baseRun, module_tier: 'tier_1' };
    const { rerender, container } = render(<ModuleCard moduleRun={run1} />);
    const meta1 = container.querySelector('p');
    expect(meta1?.textContent).toContain('Tier tier 1');

    const run2: ModuleRun = { ...baseRun, module_tier: 'tier_2' };
    rerender(<ModuleCard moduleRun={run2} />);
    expect(container.querySelector('p')?.textContent).toContain('Tier tier 2');

    const run3: ModuleRun = { ...baseRun, module_tier: 'tier_3' };
    rerender(<ModuleCard moduleRun={run3} />);
    expect(container.querySelector('p')?.textContent).toContain('Tier tier 3');
  });
});
