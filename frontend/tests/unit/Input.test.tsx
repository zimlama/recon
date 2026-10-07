import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Input } from '@/components/ui/input';

describe('Input', () => {
  it('renders and accepts text', () => {
    render(<Input placeholder="Type here" />);
    const input = screen.getByPlaceholderText('Type here') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'hello' } });
    expect(input.value).toBe('hello');
  });

  it('respects disabled prop', () => {
    render(<Input disabled placeholder="Disabled" />);
    const input = screen.getByPlaceholderText('Disabled');
    expect(input).toBeDisabled();
  });

  it('applies custom className', () => {
    render(<Input className="custom-class" placeholder="x" />);
    const input = screen.getByPlaceholderText('x');
    expect(input.className).toContain('custom-class');
  });

  it('has focus styles (zimlama-rojo border)', () => {
    render(<Input placeholder="x" />);
    const input = screen.getByPlaceholderText('x');
    expect(input.className).toContain('focus:border-zimlama-rojo');
  });
});
