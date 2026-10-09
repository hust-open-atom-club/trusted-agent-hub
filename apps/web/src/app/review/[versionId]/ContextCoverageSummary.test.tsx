import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import ContextCoverageSummary from './ContextCoverageSummary';

describe('ContextCoverageSummary', () => {
  it('renders missing-source, unresolved and omitted-reference counts and source files', () => {
    render(<ContextCoverageSummary coverage={{
      candidates: 6, complete: 2, partial: 1, missing: 3,
      source_missing: 1, location_unresolved: 2, evidence_limit: 1,
      reason_counts: { provider_failure: 3 },
      top_finding_files: { 'src/run.py': 4, 'SKILL.md': 2 },
    }} />);
    const region = screen.getByRole('region', { name: '复核证据覆盖' });
    expect(within(region).getByText('语义候选')).toBeInTheDocument();
    expect(within(region).getByText(/引用的源码或字段缺失.*1 个候选/)).toBeInTheDocument();
    expect(within(region).getByText(/证据位置缺少有效行号范围.*2 个候选/)).toBeInTheDocument();
    expect(within(region).getByText(/证据标识超出长度限制.*1 个候选/)).toBeInTheDocument();
    expect(within(region).getByText(/复核服务调用失败.*3 个候选/)).toBeInTheDocument();
    expect(within(region).getByText('src/run.py')).toBeInTheDocument();
    expect(within(region).getByText('src/run.py').closest('li')).toHaveTextContent('4 个候选');
    expect(region).not.toHaveTextContent('provider_failure');
  });

  it('accepts historical reports without coverage', () => {
    const { container } = render(<ContextCoverageSummary />);
    expect(container).toBeEmptyDOMElement();
  });
});
