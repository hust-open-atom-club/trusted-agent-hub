import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { apiFetch } from '@/lib/api-fetch';
import type { Finding } from '@/types';
import FindingCodeView, { canPreviewFinding } from './FindingCodeView';

vi.mock('@/lib/api-fetch', () => ({ apiFetch: vi.fn() }));
const finding: Finding = {
  id: 'f', rule_id: 'SR-001', severity: 'high', title: 'Review',
  location: { file: 'run.py', line: 1 },
};
const preview = {
  file: 'run.py', start_line: 1, end_line: 1, total_lines: 1,
  content: 'safe()', redacted: true, truncated: false,
};

describe('FindingCodeView', () => {
  beforeEach(() => vi.mocked(apiFetch).mockReset());

  it('shows loading, a readable failure and a working retry', async () => {
    let reject!: (error: Error) => void;
    vi.mocked(apiFetch).mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
    render(<FindingCodeView finding={finding} versionId="v" token="token" />);
    expect(screen.getByRole('status')).toBeInTheDocument();
    reject(new Error('404 internal failure'));
    expect(await screen.findByRole('alert')).toHaveTextContent('源码预览加载失败');
    expect(screen.queryByText(/404 internal/)).not.toBeInTheDocument();
    vi.mocked(apiFetch).mockResolvedValueOnce(preview);
    fireEvent.click(screen.getByRole('button', { name: '重试加载' }));
    expect(await screen.findByText('safe()')).toBeInTheDocument();
    expect(apiFetch).toHaveBeenCalledTimes(2);
  });

  it('hides the expand action for known missing source and performs no request', () => {
    const missing = { ...finding, evidence_missing_reason: 'source_missing' };
    expect(canPreviewFinding(missing)).toBe(false);
    render(<FindingCodeView finding={missing} versionId="v" token="token" />);
    expect(screen.getByRole('alert')).toHaveTextContent('引用的源文件缺失');
    expect(apiFetch).not.toHaveBeenCalled();
  });

  it('retains a supplied snippet when a remote preview fails', async () => {
    vi.mocked(apiFetch).mockRejectedValueOnce(new Error('offline'));
    const withSnippet = { ...finding, location: { ...finding.location, snippet: 'saved snippet' } };
    expect(canPreviewFinding(withSnippet)).toBe(true);
    render(<FindingCodeView finding={withSnippet} versionId="v" token="token" />);
    expect(screen.getByText('saved snippet')).toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent('源码预览加载失败');
  });

  it('does not offer or fetch source withheld for a sensitive identifier', () => {
    const withheld = { ...finding, evidence_missing_reason: 'sensitive_identifier' };
    expect(canPreviewFinding(withheld)).toBe(false);
    render(<FindingCodeView finding={withheld} versionId="v" token="token" />);
    expect(screen.getByRole('alert')).toHaveTextContent('证据标识包含凭据，已隐藏');
    expect(screen.getByRole('alert')).not.toHaveTextContent('源文件缺失');
    expect(apiFetch).not.toHaveBeenCalled();
  });

  it('renders empty redacted lines and marks a partial long line explicitly', async () => {
    vi.mocked(apiFetch).mockResolvedValueOnce({ ...preview, content: '' });
    const view = render(<FindingCodeView finding={finding} versionId="v" token="token" />);
    await screen.findByText('第 1–1 行 / 共 1 行');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    vi.mocked(apiFetch).mockResolvedValueOnce({ ...preview, partial_line: true, truncated: true });
    view.rerender(<FindingCodeView finding={finding} versionId="next" token="token" />);
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('此行过长'));
  });
});
