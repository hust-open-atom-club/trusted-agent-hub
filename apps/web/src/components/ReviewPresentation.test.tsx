import { render, screen } from '@testing-library/react';
import { createInstance } from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { describe, expect, it, vi } from 'vitest';
import TrustScoreDetail from './TrustScoreDetail';
import PermissionEvidenceList from './PermissionEvidenceList';
import zh from '@/i18n/locales/zh/common.json';
import en from '@/i18n/locales/en/common.json';
import { advisoryMessages } from '@/lib/review-messages';

vi.unmock('react-i18next');

describe('review presentation localization', () => {
  it.each(['zh', 'en'])('localizes system messages and preserves raw evidence in %s', async (language) => {
    const i18n = createInstance();
    await i18n.use(initReactI18next).init({
      lng: language,
      resources: { zh: { translation: zh }, en: { translation: en } },
      interpolation: { escapeValue: false },
    });
    const messages = [
      "Evidence source is 'traceable' (no security deduction)",
      "scan_results: assessed as 'dangerous'",
      'Behavior consistency check: deceptive',
      "Author reputation is 'inconsistent' (independent from security score)",
    ];
    const advisory = advisoryMessages({
      id: 'unavailable', code: 'artifact_verifiers_unavailable', category: 'provenance', level: 'info',
      title: '供应链证据验证器尚未配置',
      description: '以下验证能力在本次扫描环境中不可用：signature, attestation, sbom。',
      evidence: 'verifier capability is unavailable',
      deduction: 0, affects_grade: false, grade_downgrade_steps: 0, requires_manual_review: false,
    }, i18n.t);
    render(<I18nextProvider i18n={i18n}>
      <TrustScoreDetail mode="review" trustScore={{
        calculated_at: '2026-10-12T00:00:00Z', model_version: 'auto-example',
        explanations: messages.map(message => ({ dimension: 'scan_results', message, deduction: 0 })),
      }} />
      <PermissionEvidenceList items={[
        { capability: 'filesystem.read', status: 'declared', confidence: 1, source: 'manifest', evidence: '包元数据明确声明该权限' },
        { capability: 'shell', status: 'observed', confidence: 0.9, source: 'code', file: 'server.py', evidence: 'Custom tool description: read_notes' },
      ]} />
      <article><h2>{advisory.title}</h2><p>{advisory.description}</p><p>{advisory.evidence}</p></article>
    </I18nextProvider>);
    if (language === 'zh') {
      expect(screen.getByText('证据来源为“可追溯”（不扣安全分）')).toBeInTheDocument();
      expect(screen.getByText('作者信誉为“不稳定”（与安全评分独立）')).toBeInTheDocument();
      expect(screen.getByText('扫描结果：评估结果为“危险”')).toBeInTheDocument();
      expect(screen.getByText('行为一致性检查：欺骗性')).toBeInTheDocument();
      expect(screen.getByText('已声明 · 100% · 包清单')).toBeInTheDocument();
      expect(screen.getByText('命令执行')).toBeInTheDocument();
      expect(screen.getByText(/本次扫描环境不支持以下验证能力：签名, 证明（Attestation）, SBOM/)).toBeInTheDocument();
    } else {
      expect(screen.getByText('Evidence source is traceable (no security deduction)')).toBeInTheDocument();
      expect(screen.getByText('Author reputation is inconsistent (independent from security score)')).toBeInTheDocument();
      expect(screen.getByText('Declared · 100% · Package manifest')).toBeInTheDocument();
      expect(screen.getByText('Package metadata explicitly declares this permission')).toBeInTheDocument();
      expect(screen.getByText('Scoring engine version:')).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Supply-chain evidence verifiers are not configured' })).toBeInTheDocument();
    }
    expect(screen.getByText('Custom tool description: read_notes')).toBeInTheDocument();
    expect(screen.getByTitle('filesystem.read')).toBeInTheDocument();
  });
});
