import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';

vi.mock('@/lib/api-client', () => ({
  listModules: vi.fn(),
  getJob: vi.fn(),
  createJob: vi.fn(),
  cancelJob: vi.fn(),
  deleteJob: vi.fn(),
}));

import { JobCreatorForm } from '@/components/JobCreatorForm';
import { listModules } from '@/lib/api-client';

const mockedListModules = vi.mocked(listModules);

describe('JobCreatorForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('loads modules on mount and pre-selects Tier 1', async () => {
    mockedListModules.mockResolvedValue({
      modules: [
        { name: 'whois_rdap', tier: 'tier_1' } as any,
        { name: 'dns_enum', tier: 'tier_1' } as any,
        { name: 'shodan_censys', tier: 'tier_2' } as any,
      ],
      total: 3,
    });
    render(<JobCreatorForm />);
    await waitFor(() => {
      expect(screen.getByText('whois_rdap')).toBeInTheDocument();
    });
    // Tier 1 modules are pre-checked
    const whoisCheckbox = screen.getByTestId('module-whois_rdap') as HTMLInputElement;
    const dnsCheckbox = screen.getByTestId('module-dns_enum') as HTMLInputElement;
    const shodanCheckbox = screen.getByTestId('module-shodan_censys') as HTMLInputElement;
    expect(whoisCheckbox.checked).toBe(true);
    expect(dnsCheckbox.checked).toBe(true);
    expect(shodanCheckbox.checked).toBe(false);
  });

  it('shows error message on module load failure', async () => {
    mockedListModules.mockRejectedValue(new Error('API down'));
    render(<JobCreatorForm />);
    await waitFor(() => {
      expect(screen.getByText(/Failed to load modules/)).toBeInTheDocument();
    });
  });

  it('disables submit when no modules selected', async () => {
    mockedListModules.mockResolvedValue({
      modules: [{ name: 'tier3only', tier: 'tier_3' } as any],  // tier_3 not pre-selected
      total: 1,
    });
    render(<JobCreatorForm />);
    await waitFor(() => {
      expect(screen.getByText('tier3only')).toBeInTheDocument();
    });
    const input = screen.getByTestId('target-input');
    fireEvent.change(input, { target: { value: 'acmecorp.com' } });
    const submit = screen.getByTestId('submit-job') as HTMLButtonElement;
    // Submit is disabled because no module is selected (tier_3 is disabled in form)
    expect(submit.disabled).toBe(true);
  });

  it('opens disclaimer modal on valid submit', async () => {
    mockedListModules.mockResolvedValue({
      modules: [{ name: 'whois_rdap', tier: 'tier_1' } as any],
      total: 1,
    });
    render(<JobCreatorForm />);
    await waitFor(() => screen.getByText('whois_rdap'));
    const input = screen.getByTestId('target-input');
    fireEvent.change(input, { target: { value: 'acmecorp.com' } });
    const submit = screen.getByTestId('submit-job');
    fireEvent.click(submit);
    // Disclaimer modal opens
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
  });
});
