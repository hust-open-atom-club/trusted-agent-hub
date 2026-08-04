import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { TrustScore } from '@/types';

import TrustScoreDetail from './TrustScoreDetail';

function makeTrustScore(overrides: Partial<TrustScore> = {}): TrustScore {
  return {
    score: 76,
    risk_summary: {
      grade: 'B',
      level: 'low_risk',
      top_risks: ['Uses shell permission', 'Network access declared'],
      install_recommendation: 'review_recommended',
    },
    explanations: [
      {
        dimension: 'permission_minimization',
        message: 'Permissions exceed declared intent.',
        deduction: 10,
      },
    ],
    calculated_at: '2026-08-03T00:00:00Z',
    model_version: '0.2.0',
    ...overrides,
  };
}

describe('TrustScoreDetail', () => {
  it('renders nothing without a trust score', () => {
    const { container } = render(<TrustScoreDetail trustScore={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows grade badge, risk level and recommendation', () => {
    render(<TrustScoreDetail trustScore={makeTrustScore()} />);

    expect(screen.getByText('B · 低风险')).toBeInTheDocument();
    expect(screen.getByText('低风险')).toBeInTheDocument();
    expect(screen.getByText('建议查看详情后安装')).toBeInTheDocument();
  });

  it('lists top risks and explanation messages', () => {
    render(<TrustScoreDetail trustScore={makeTrustScore()} />);

    expect(screen.getByText('Uses shell permission')).toBeInTheDocument();
    expect(screen.getByText('Network access declared')).toBeInTheDocument();
    expect(
      screen.getByText('Permissions exceed declared intent.'),
    ).toBeInTheDocument();
  });

  it('prefers effectiveGrade over risk_summary grade', () => {
    render(
      <TrustScoreDetail
        trustScore={makeTrustScore()}
        effectiveGrade="C"
      />,
    );
    expect(screen.getByText('C · 需注意')).toBeInTheDocument();
    expect(screen.queryByText('B · 低风险')).not.toBeInTheDocument();
  });

  it('shows manual grade override and reason', () => {
    render(
      <TrustScoreDetail
        trustScore={makeTrustScore()}
        autoGrade="B"
        manualGrade="C"
        manualGradeReason="Prompt injection risk"
      />,
    );

    expect(screen.getByText(/自动评级/)).toBeInTheDocument();
    expect(screen.getByText(/人工评级/)).toBeInTheDocument();
    expect(screen.getByText('— Prompt injection risk')).toBeInTheDocument();
  });

  it('shows the empty state when there is nothing to display', () => {
    render(
      <TrustScoreDetail
        trustScore={{ risk_summary: {}, explanations: [] }}
      />,
    );
    expect(screen.getByText('暂无可用的信任评分信息')).toBeInTheDocument();
  });
});
