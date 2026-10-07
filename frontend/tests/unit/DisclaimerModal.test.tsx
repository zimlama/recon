import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DisclaimerModal } from '@/components/DisclaimerModal';

describe('DisclaimerModal', () => {
  const target = 'example.com';

  it('does not render when closed', () => {
    const { container } = render(
      <DisclaimerModal open={false} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    expect(container.querySelector('[role="dialog"]')).not.toBeInTheDocument();
  });

  it('renders the LATAM-aware disclaimer when open', () => {
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    // Country names appear in details summary + country list (multiple times)
    expect(screen.getAllByText(/Colombia/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Brasil/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/México/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Argentina/).length).toBeGreaterThan(0);
  });

  it('shows the target domain', () => {
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    expect(screen.getAllByText(target).length).toBeGreaterThan(0);
  });

  it('Confirm button is disabled until target is typed', () => {
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    const confirmBtn = screen.getByRole('button', { name: /confirm.*run/i });
    expect(confirmBtn).toBeDisabled();
  });

  it('Confirm button enables when target is typed correctly', () => {
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    const input = screen.getByLabelText(/type target to confirm/i);
    fireEvent.change(input, { target: { value: target } });
    const confirmBtn = screen.getByRole('button', { name: /confirm.*run/i });
    expect(confirmBtn).not.toBeDisabled();
  });

  it('Confirm button stays disabled for wrong input', () => {
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={() => {}} />,
    );
    const input = screen.getByLabelText(/type target to confirm/i);
    fireEvent.change(input, { target: { value: 'wrong-domain.com' } });
    const confirmBtn = screen.getByRole('button', { name: /confirm.*run/i });
    expect(confirmBtn).toBeDisabled();
  });

  it('onCancel is called when Cancel is clicked', () => {
    const onCancel = vi.fn();
    render(
      <DisclaimerModal open={true} target={target} onCancel={onCancel} onConfirm={() => {}} />,
    );
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('onConfirm is called when Confirm is clicked after correct input', () => {
    const onConfirm = vi.fn();
    render(
      <DisclaimerModal open={true} target={target} onCancel={() => {}} onConfirm={onConfirm} />,
    );
    const input = screen.getByLabelText(/type target to confirm/i);
    fireEvent.change(input, { target: { value: target } });
    fireEvent.click(screen.getByRole('button', { name: /confirm.*run/i }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
