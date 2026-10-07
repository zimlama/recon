import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';

describe('Card primitives', () => {
  it('renders all subcomponents', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Desc</CardDescription>
        </CardHeader>
        <CardContent>Body</CardContent>
        <CardFooter>Foot</CardFooter>
      </Card>,
    );
    expect(screen.getByText('Title')).toBeInTheDocument();
    expect(screen.getByText('Desc')).toBeInTheDocument();
    expect(screen.getByText('Body')).toBeInTheDocument();
    expect(screen.getByText('Foot')).toBeInTheDocument();
  });

  it('CardTitle has bold font-titulos', () => {
    render(<CardTitle>Bold</CardTitle>);
    const el = screen.getByText('Bold');
    expect(el.className).toContain('font-titulos');
    expect(el.className).toContain('font-bold');
  });

  it('CardFooter has top border', () => {
    const { container } = render(<CardFooter>x</CardFooter>);
    const el = container.firstChild as HTMLElement;
    expect(el.className).toContain('border-t');
  });
});
