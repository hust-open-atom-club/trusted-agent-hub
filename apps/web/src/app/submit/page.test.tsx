import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authFetch: vi.fn(), apiFetch: vi.fn(), push: vi.fn(), replace: vi.fn(),
  params: new URLSearchParams('scan=scan-new'),
  auth: { user: { id: 'owner', role: 'admin' }, token: 'token', loading: false },
}));
vi.mock('@/lib/auth', () => ({ useAuth: () => mocks.auth }));
vi.mock('@/lib/api-fetch', () => ({ authFetch: mocks.authFetch, apiFetch: mocks.apiFetch }));
vi.mock('next/navigation', () => ({
  useSearchParams: () => mocks.params,
  useRouter: () => ({ push: mocks.push, replace: mocks.replace }),
}));
vi.mock('@/lib/scan-polling', async importOriginal => ({
  ...await importOriginal<typeof import('@/lib/scan-polling')>(), scanPollDelayMs: () => 0,
}));
import SubmitPage from './page';

const existing = {
  package_id: 'pkg-1', package_name: 'existing-tool', status: 'changes_requested',
  versions: [{ id: 'ver-1', version: '0.1.0', status: 'changes_requested', submitted_at: null }],
};
const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data });

describe('Generic submission with an existing package name', () => {
  beforeEach(() => {
    localStorage.clear();
    mocks.params = new URLSearchParams('scan=scan-new');
    mocks.authFetch.mockReset().mockImplementation(async (url: string) => {
      if (url.includes('/packages/lookup?')) return ok(existing);
      if (url.endsWith('/metadata')) return ok({ metadata: {
        name: 'existing-tool', version: '0.1.0', description: 'A tool', type: 'mcp_server',
        license: 'MIT', compatibility: ['claude_code'],
        source: { repository_url: 'https://github.com/acme/tool', commit_hash: 'a'.repeat(40) },
      } });
      if (url.endsWith('/scan/scan-new')) return ok({ scan_id: 'scan-new', status: 'complete', lifecycle: 'complete_unsubmitted' });
      throw new Error(`Unexpected request: ${url}`);
    });
  });

  it('detects the existing changes_requested package after restoring a scan and prevents duplicate creation', async () => {
    render(<SubmitPage />);
    await screen.findByRole('region', { name: '已有包提交指引' });
    fireEvent.click(screen.getByRole('checkbox', { name: '我已确认以上信息正确，提交审核' }));
    expect(screen.getByRole('button', { name: '提交审核' })).toBeDisabled();
    expect(screen.getByRole('link', { name: '重新提交' })).toHaveAttribute('href', '/packages/existing-tool/versions/0.1.0/status?vid=ver-1&scan=scan-new#resubmit');
    expect(screen.getByRole('link', { name: '创建新版本' })).toHaveAttribute('href', '/submit?packageId=pkg-1&scan=scan-new');
    expect(mocks.authFetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  });

  it('rechecks before creating a package if another tab created it after the initial lookup', async () => {
    const initial = mocks.authFetch.getMockImplementation()!;
    let lookups = 0;
    mocks.authFetch.mockImplementation(async (url: string, ...args: unknown[]) => {
      if (url.includes('/packages/lookup?')) return ok(++lookups === 1 ? null : existing);
      return initial(url, ...args);
    });
    Element.prototype.scrollIntoView = vi.fn();
    render(<SubmitPage />);
    fireEvent.click(await screen.findByRole('checkbox', { name: '我已确认以上信息正确，提交审核' }));
    const button = screen.getByRole('button', { name: '提交审核' });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    await screen.findByRole('region', { name: '已有包提交指引' });
    expect(lookups).toBeGreaterThanOrEqual(2);
    expect(mocks.authFetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  });
});
