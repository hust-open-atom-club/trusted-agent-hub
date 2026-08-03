import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import ScoreBadge from './ScoreBadge';

describe('ScoreBadge', () => {
  it('maps A/B grades to the trusted class', () => {
    const { rerender } = render(<ScoreBadge grade="A" />);
    expect(screen.getByText('A')).toHaveClass('score-badge', 'trusted');

    rerender(<ScoreBadge grade="B" />);
    expect(screen.getByText('B')).toHaveClass('trusted');
  });

  it('maps C to caution and D/E to danger', () => {
    const { rerender } = render(<ScoreBadge grade="C" />);
    expect(screen.getByText('C')).toHaveClass('caution');

    rerender(<ScoreBadge grade="E" />);
    expect(screen.getByText('E')).toHaveClass('danger');
  });

  it('renders unknown state for null or unrecognized grades', () => {
    const { rerender } = render(<ScoreBadge grade={null} />);
    expect(screen.getByText('--')).toHaveClass('unknown');

    rerender(<ScoreBadge grade="Z" />);
    expect(screen.getByText('Z')).toHaveClass('unknown');
  });

  it('adds the size-lg class when large', () => {
    render(<ScoreBadge grade="A" size="lg" />);
    expect(screen.getByText('A')).toHaveClass('size-lg');
  });
});
