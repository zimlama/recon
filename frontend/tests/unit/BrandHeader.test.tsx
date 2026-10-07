import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrandHeader } from '@/components/BrandHeader';

describe('BrandHeader', () => {
  it('renders the logo', () => {
    render(<BrandHeader />);
    const logo = screen.getByLabelText('zimlama');
    expect(logo).toBeInTheDocument();
  });

  it('renders the wordmark', () => {
    render(<BrandHeader />);
    expect(screen.getByText('zimlama recon')).toBeInTheDocument();
  });

  it('renders nav links', () => {
    render(<BrandHeader />);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Jobs')).toBeInTheDocument();
    expect(screen.getByText('Modules')).toBeInTheDocument();
  });

  it('renders the New Job CTA', () => {
    render(<BrandHeader />);
    const cta = screen.getByText(/new job/i);
    expect(cta).toBeInTheDocument();
    expect(cta.closest('a')).toHaveAttribute('href', '/jobs/new');
  });
});
