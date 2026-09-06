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
    model_fingerprint: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
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

  it('shows the model version and a shortened fingerprint with the full value in a tooltip', () => {
    const modelFingerprint = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
    render(
      <TrustScoreDetail
        trustScore={makeTrustScore({ model_fingerprint: modelFingerprint })}
      />,
    );

    expect(screen.getByText(/模型版本/)).toBeInTheDocument();
    expect(screen.getByText('0.2.0')).toBeInTheDocument();
    expect(screen.getByText(/模型指纹/)).toBeInTheDocument();
    expect(screen.getByTitle(modelFingerprint)).toHaveTextContent('abcdef012345…');
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

  it('shows separate security and evidence assessments', () => {
    render(
      <TrustScoreDetail
        trustScore={makeTrustScore({
          security_assessment: {
            score: 81,
            level: 'low_risk',
            grade: 'B',
            status: 'review_required',
            input_dimensions: ['permission_minimization', 'scan_results'],
            unresolved_findings: 2,
          },
          evidence_assessment: {
            score: 70,
            coverage: 0.75,
            level: 'moderate',
            assessed_dimensions: ['source_trust'],
            unavailable_dimensions: ['author_reputation'],
            verification_statuses: { signature: 'not_available' },
            author_reputation: {
              status: 'unavailable',
              level: 'unavailable',
              score: null,
            },
          },
        })}
      />,
    );

    const assessments = screen.getByTestId('trust-assessments');
    expect(assessments).toHaveTextContent('安全结论');
    expect(assessments).toHaveTextContent('2 个未决发现');
    expect(assessments).toHaveTextContent('证据质量');
    expect(assessments).toHaveTextContent('覆盖率 75%');
    expect(assessments).not.toHaveTextContent('signature');
  });

  it('can hide duplicate grade summaries in the review page', () => {
    render(
      <TrustScoreDetail
        trustScore={makeTrustScore()}
        effectiveGrade="B"
        autoGrade="B"
        showGradeSummary={false}
        showGradeSource={false}
      />,
    );

    expect(screen.queryByText('B · 低风险')).not.toBeInTheDocument();
    expect(screen.queryByText(/自动评级/)).not.toBeInTheDocument();
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
