import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from '@/components/ui/button';

describe('Button', () => {
  it('renders children', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Click</Button>);
    fireEvent.click(screen.getByText('Click'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('respects disabled prop', () => {
    const onClick = vi.fn();
    render(<Button disabled onClick={onClick}>Disabled</Button>);
    const btn = screen.getByText('Disabled');
    expect(btn).toBeDisabled();
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('renders primary variant with correct classes', () => {
    render(<Button variant="primary">Primary</Button>);
    const btn = screen.getByText('Primary');
    expect(btn.className).toContain('bg-zimlama-rojo');
  });

  it('renders danger variant with correct classes', () => {
    render(<Button variant="danger">Danger</Button>);
    const btn = screen.getByText('Danger');
    expect(btn.className).toContain('bg-sev-critico');
  });

  it('renders different sizes', () => {
    const { rerender } = render(<Button size="sm">Small</Button>);
    expect(screen.getByText('Small').className).toContain('px-3');

    rerender(<Button size="lg">Large</Button>);
    expect(screen.getByText('Large').className).toContain('px-6');
  });
});
