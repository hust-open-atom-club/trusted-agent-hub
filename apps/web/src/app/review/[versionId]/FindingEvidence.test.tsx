import { render, screen } from '@testing-library/react';
import { createInstance } from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { describe, expect, it, vi } from 'vitest';
import FindingEvidence, { findingLocations } from './FindingEvidence';
import type { Finding } from '@/types';
import zh from '@/i18n/locales/zh/common.json';
import en from '@/i18n/locales/en/common.json';

vi.unmock('react-i18next');

async function renderEvidence(value: Finding, language = 'zh') {
  const i18n = createInstance();
  await i18n.use(initReactI18next).init({
    lng: language,
    resources: { zh: { translation: zh }, en: { translation: en } },
    interpolation: { escapeValue: false },
  });
  return render(
    <I18nextProvider i18n={i18n}>
      <FindingEvidence finding={value} versionId="version-1" />
    </I18nextProvider>,
  );
}

const finding: Finding = { rule_id: 'SR-008', severity: 'high', title: 'Dependency', evidence_type: 'dependency', location: {
  file: 'packages/tool/package-lock.json', line: 8, end_line: 13,
  source_ref: '#/packages/node_modules~1demo', dependency_name: 'demo', version: '1.0.0',
  field_locations: {
    resolved: { source_ref: '#/packages/node_modules~1demo/resolved', line: 10 },
    integrity: { source_ref: '#/packages/node_modules~1demo/integrity', missing_reason: 'field_missing' },
  },
} };

describe('FindingEvidence', () => {
  it.each(['zh', 'en'])('shows withheld credentials without a source link in %s', async language => {
    const { container } = await renderEvidence({
      ...finding,
      evidence_missing_reason: 'sensitive_identifier',
      location: {
        file: 'package-lock.json',
        missing_reason: 'sensitive_identifier',
        source_ref_sha256: 'a'.repeat(64),
      },
      llm_context_reasons: ['evidence_redacted'],
      requires_manual_review: true,
    }, language);
    expect(container).toHaveTextContent(language === 'zh'
      ? '证据标识包含凭据，已隐藏，需要人工复核'
      : 'The evidence identifier contains a credential and has been withheld; manual review is required');
    expect(container).toHaveTextContent('SHA-256: ' + 'a'.repeat(64));
    expect(container).not.toHaveTextContent('undefined');
    expect(container).not.toHaveTextContent('sensitive_identifier');
    expect(container).not.toHaveTextContent('evidence_redacted');
    expect(container.querySelector('a')).toBeNull();
  });
  it.each(['zh', 'en'])('renders audit details as readable messages in %s', async language => {
    const { container } = await renderEvidence({
      ...finding,
      llm_context_audit: { reasons: [
        'source_missing:src/run.py', 'per_finding_byte_limit',
        'delivery_missing:src/run.py:10-20',
      ] },
    }, language);
    expect(container).not.toHaveTextContent('source_missing');
    expect(container).not.toHaveTextContent('per_finding_byte_limit');
    expect(container).not.toHaveTextContent('delivery_missing');
    expect(container).toHaveTextContent('src/run.py:10-20');
    expect(container).toHaveTextContent(language === 'zh'
      ? '此项证据超出单项上下文字节上限。'
      : 'This evidence exceeds the context byte limit for one finding.');
  });
  it('links to the real dependency record and field line without inventing a missing field line', async () => {
    await renderEvidence(finding);
    const link = screen.getByRole('link', { name: 'packages/tool/package-lock.json:8-13 #/packages/node_modules~1demo' });
    const url = new URL(link.getAttribute('href')!, 'http://localhost');
    expect(url.searchParams.get('path')).toBe('packages/tool/package-lock.json');
    expect(url.searchParams.get('line')).toBe('8');
    expect(screen.getByText('demo@1.0.0')).toBeInTheDocument();
    expect(screen.getByText(/字段未声明/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /integrity/ })).not.toBeInTheDocument();
  });

  it('distinguishes source, budget, delivery and provider failures', async () => {
    await renderEvidence({
      ...finding,
      llm_context_reasons: ['source_missing', 'context_budget', 'delivery_missing'],
      llm_review_state: 'unavailable',
    });
    expect(screen.getByText('引用的源码或字段缺失，需要人工复核。')).toBeInTheDocument();
    expect(screen.getByText('上下文超出投递预算，仅投递了部分内容。')).toBeInTheDocument();
    expect(screen.getByText('引用的证据未实际投递给复核模型。')).toBeInTheDocument();
    expect(screen.getByText('复核服务调用失败，未完成裁决。')).toBeInTheDocument();
  });

  it('shows synthetic missing evidence without an invented source link', async () => {
    await renderEvidence({
      ...finding,
      evidence_type: 'synthetic',
      location: {},
      evidence_missing_reason: 'missing_location',
    });
    expect(screen.getByText(/合成证据/)).toBeInTheDocument();
    expect(screen.getByText(/未提供证据位置/)).toBeInTheDocument();
    expect(screen.queryByText(/missing_location/)).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it.each([
    ['missing_location', '未提供证据位置', 'No evidence location was provided'],
    ['invalid_path', '证据文件路径无效', 'The evidence file path is invalid'],
    ['source_missing', '引用的源文件缺失', 'The referenced source file is missing'],
    ['field_missing', '引用的字段不存在', 'The referenced field does not exist'],
    ['invalid_span', '证据行列范围无效', 'The evidence line or column range is invalid'],
    ['line_out_of_range', '证据行号超出文件范围', 'The evidence line is outside the file'],
    ['missing_line', '未提供证据行号', 'No evidence line was provided'],
    ['source_ref_too_long', '字段标识超出长度限制，已省略并保留摘要', 'The field reference exceeds the length limit; a digest is retained'],
  ])('translates %s in both languages', async (reason, chinese, english) => {
    const value = { ...finding, location: {}, evidence_missing_reason: reason };
    const view = await renderEvidence(value, 'zh');
    expect(screen.getByText(`· 证据缺失: ${chinese}`)).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(reason))).not.toBeInTheDocument();
    view.unmount();
    await renderEvidence(value, 'en');
    expect(screen.getByText(`· Evidence unavailable: ${english}`)).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(reason))).not.toBeInTheDocument();
  });

  it('uses a readable fallback for an unrecognized missing reason', async () => {
    await renderEvidence({
      ...finding,
      location: {},
      evidence_missing_reason: 'future_reason',
    }, 'en');
    expect(screen.getByText(/manual review is required/)).toBeInTheDocument();
    expect(screen.queryByText(/future_reason/)).not.toBeInTheDocument();
  });

  it.each(['zh', 'en'])('distinguishes unresolved positions from missing source in %s', async language => {
    await renderEvidence({ ...finding, llm_context_reasons: ['location_unresolved', 'evidence_limit'] }, language);
    expect(screen.getByText(language === 'zh'
      ? '证据位置缺少有效行号范围，需要人工复核。'
      : 'The evidence location has no valid line range; manual review is required.')).toBeInTheDocument();
    expect(screen.getByText(language === 'zh'
      ? '证据标识超出长度限制，需人工核对源文件。'
      : 'The evidence reference exceeds the length limit; check the source manually.')).toBeInTheDocument();
    expect(screen.queryByText(/引用的源码或字段缺失|referenced source or field is unavailable/)).not.toBeInTheDocument();
  });
});

describe('findingLocations', () => {
  it.each([0, 1])('does not display phantom occurrences for an empty count=%s report', count => {
    const locations = findingLocations({
      ...finding,
      occurrences: { count, items: [], truncated: false },
    });
    expect(locations).toEqual({ count: 0, items: [], truncated: false });
  });

  it('preserves known omitted occurrences only when truncation is explicit', () => {
    const occurrences = {
      count: 110,
      items: [{ file: 'package-lock.json', line: 1 }],
      truncated: true,
    };
    expect(findingLocations({ ...finding, occurrences })).toEqual(occurrences);
  });

  it('uses the primary location for older reports without occurrences', () => {
    expect(findingLocations(finding)).toEqual({
      count: 1, items: [finding.location], truncated: false,
    });
    expect(findingLocations({ ...finding, location: {} }).count).toBe(0);
  });
});
