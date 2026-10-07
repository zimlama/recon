import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Table, THead, TBody, TR, TH, TD } from '@/components/ui/table';

describe('Table primitives', () => {
  it('renders a table with header and body', () => {
    render(
      <Table>
        <THead>
          <TR><TH>Name</TH><TH>Value</TH></TR>
        </THead>
        <TBody>
          <TR><TD>foo</TD><TD>bar</TD></TR>
        </TBody>
      </Table>,
    );
    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.getByText('Value')).toBeInTheDocument();
    expect(screen.getByText('foo')).toBeInTheDocument();
    expect(screen.getByText('bar')).toBeInTheDocument();
  });
});
