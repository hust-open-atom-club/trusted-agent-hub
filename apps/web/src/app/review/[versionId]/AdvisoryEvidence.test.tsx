import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ReviewAdvisory } from '@/types';
import AdvisoryEvidence from './AdvisoryEvidence';

const advisory: ReviewAdvisory = {
  id: 'advisory-1', code: 'dependency_registry_policy', category: 'registry_policy',
  level: 'warning', title: 'Registry policy', description: 'Check the source',
  deduction: 0, affects_grade: false, grade_downgrade_steps: 0,
  requires_manual_review: true, evidence_type: 'registry_policy',
  location: {
    file: 'manifest.json', line: 4, column: 5, end_line: 8, end_column: 9,
    source_ref: '#/dependencies/npm/0',
  },
};

describe('AdvisoryEvidence', () => {
  it('labels registry source declarations without a dependency name', () => {
    render(<AdvisoryEvidence advisory={{
      ...advisory,
      registry_policy: {
        ecosystem: 'npm', registry_host: 'private.example', policy_reason: 'unapproved',
        source_file: '.npmrc', scope: 'runtime', occurrence_count: 1, truncated: false,
        occurrences: [{
          file: '.npmrc', source_ref: 'registry', line: 1,
          dependency_name: null, resolved_url: 'https://private.example',
          scope: 'runtime', usage: 'registry_api',
        }],
      },
    }} versionId="v-1" />);
    expect(screen.getByText('来源配置')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '.npmrc:1 registry' })).toBeInTheDocument();
  });
  it('links the advisory to its full source span and field pointer', () => {
    render(<AdvisoryEvidence advisory={advisory} versionId="v-1" />);
    const link = screen.getByRole('link', {
      name: 'manifest.json:4:5-8:9 #/dependencies/npm/0',
    });
    const url = new URL(link.getAttribute('href')!, 'http://localhost');
    expect(url.searchParams.get('versionId')).toBe('v-1');
    expect(url.searchParams.get('path')).toBe('manifest.json');
    expect(url.searchParams.get('line')).toBe('4');
    expect(screen.getByText(/来源策略证据/)).toBeInTheDocument();
  });

  it('renders each registry occurrence with exact field links and missing fields', () => {
    render(<AdvisoryEvidence advisory={{
      ...advisory,
      registry_policy: {
        ecosystem: 'npm', registry_host: 'private.example', policy_reason: 'unapproved',
        source_file: 'package-lock.json', scope: 'runtime', occurrence_count: 2,
        truncated: false,
        occurrences: ['package-lock.json', 'tools/package-lock.json'].map((file, index) => ({
          file, line: index + 10, end_line: index + 14,
          source_ref: '#/packages/node_modules~1demo',
          dependency_name: 'demo', version: '1.0.0',
          scope: 'runtime', usage: 'resolved_download', resolved_url: 'https://private.example/demo.tgz',
          field_locations: {
            resolved: {
              source_ref: '#/packages/node_modules~1demo/resolved',
              line: index + 12, column: 9, end_line: index + 12, end_column: 45,
            },
            integrity: {
              source_ref: '#/packages/node_modules~1demo/integrity', missing_reason: 'field_missing',
            },
          },
        })),
      },
    }} versionId="v-1" />);

    expect(screen.getByText('private.example')).toBeInTheDocument();
    const link = screen.getByRole('link', {
      name: 'tools/package-lock.json:13:9-13:45 #/packages/node_modules~1demo/resolved',
    });
    const url = new URL(link.getAttribute('href')!, 'http://localhost');
    expect(url.searchParams.get('path')).toBe('tools/package-lock.json');
    expect(url.searchParams.get('line')).toBe('13');
    expect(screen.queryByRole('link', { name: /integrity/ })).not.toBeInTheDocument();
    expect(screen.getAllByText(/字段未声明/)).toHaveLength(2);
  });

  it('shows missing evidence without an invented or unavailable source link', () => {
    const view = render(<AdvisoryEvidence advisory={{
      ...advisory, location: {}, evidence_type: 'synthetic',
      evidence_missing_reason: 'missing_location',
    }} versionId="v-1" />);
    expect(screen.getByText(/未提供证据位置/)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    view.rerender(<AdvisoryEvidence advisory={{
      ...advisory, evidence_missing_reason: 'source_missing',
    }} versionId="v-1" />);
    expect(screen.getByText(/引用的源文件缺失/)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('explains omitted identifiers and retains their digest without a fake pointer', () => {
    render(<AdvisoryEvidence advisory={{
      ...advisory,
      location: {
        file: 'package-lock.json', source_ref_length: 100_000,
        source_ref_sha256: 'a'.repeat(64), missing_reason: 'source_ref_too_long',
      },
    }} versionId="v-1" />);
    expect(screen.getByText(/字段标识超出长度限制/)).toBeInTheDocument();
    expect(screen.getByText(/100000 字符/)).toBeInTheDocument();
    expect(screen.getByText(`SHA-256: ${'a'.repeat(64)}`)).toBeInTheDocument();
    expect(screen.getByRole('link').textContent).toBe('package-lock.json');
  });
});
