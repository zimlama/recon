import { describe, it, expect } from '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { BrandFooter } from '@/components/BrandFooter';

describe('BrandFooter', () => {
  it('renders copyright', () => {
    render(<BrandFooter />);
    expect(screen.getByText(/zimlama/)).toBeInTheDocument();
  });

  it('renders GitHub link', () => {
    render(<BrandFooter />);
    const link = screen.getByText('GitHub');
    expect(link.closest('a')).toHaveAttribute('href', 'https://github.com/zimlama/recon');
  });

  it('renders Disclaimer link', () => {
    render(<BrandFooter />);
    const link = screen.getByText('Disclaimer');
    expect(link.closest('a')).toHaveAttribute('href', '/disclaimer');
  });
});
