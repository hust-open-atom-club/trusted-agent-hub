import { fireEvent, render, screen } from '@testing-library/react';
import { useRouter } from 'next/navigation';
import { describe, expect, it, vi } from 'vitest';

import type { Package } from '@/types';

import PackageCard from './PackageCard';

function makePackage(overrides: Partial<Package> = {}): Package {
  return {
    id: 'pkg-1',
    name: 'demo-summarizer',
    description: 'Summarizes documents safely.',
    type: 'skill',
    license: 'MIT',
    keywords: ['summary'],
    category: 'productivity',
    homepage: null,
    icon_url: null,
    owner: { id: 'u1', display_name: 'Alice', role: 'submitter' },
    latest_version: '1.2.0',
    status: 'published',
    risk_level: 'low_risk',
    grade: 'B',
    install_count: 1500,
    avg_rating: 4.2,
    feedback_counts: { positive: 3, neutral: 1, negative: 1 },
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
    ...overrides,
  };
}

describe('PackageCard', () => {
  it('renders name, description, badges and metadata', () => {
    render(<PackageCard pkg={makePackage()} />);

    expect(screen.getByText('demo-summarizer')).toBeInTheDocument();
    expect(screen.getByText('Summarizes documents safely.')).toBeInTheDocument();
    expect(screen.getByText('B')).toBeInTheDocument();
    expect(screen.getByText('好评 3 · 差评 1')).toBeInTheDocument();
    expect(screen.getByText('1.5k')).toBeInTheDocument();
    expect(screen.getByText('v1.2.0')).toBeInTheDocument();
  });

  it('formats install count under 1000 without suffix', () => {
    render(<PackageCard pkg={makePackage({ install_count: 999 })} />);
    expect(screen.getByText('999')).toBeInTheDocument();
  });

  it('shows no-rating hint when feedback counts are missing', () => {
    render(
      <PackageCard pkg={makePackage({ feedback_counts: null })} />,
    );
    expect(screen.getByText('暂无评分')).toBeInTheDocument();
  });

  it('navigates to the package detail page on click', () => {
    const push = vi.fn();
    vi.mocked(useRouter).mockReturnValue({
      push,
      replace: vi.fn(),
      back: vi.fn(),
      forward: vi.fn(),
      refresh: vi.fn(),
      prefetch: vi.fn(),
    });

    render(<PackageCard pkg={makePackage({ name: 'my package' })} />);
    fireEvent.click(screen.getByText('my package'));
    expect(push).toHaveBeenCalledWith('/package/my%20package');
  });
});
