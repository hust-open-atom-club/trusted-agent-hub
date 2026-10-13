import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  auth: { user: null as { id: string } | null, token: null as string | null, loading: true },
  authFetch: vi.fn(), apiFetch: vi.fn(),
  params: new URLSearchParams('vid=ver-1'),
}));
vi.mock('@/lib/auth', () => ({ useAuth: () => mocks.auth }));
vi.mock('@/lib/api-fetch', () => ({ authFetch: mocks.authFetch, apiFetch: mocks.apiFetch }));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => mocks.params,
}));
import StatusPage from './page';

describe('Version status direct link', () => {
  beforeEach(() => {
    mocks.auth = { user: null, token: null, loading: true };
    mocks.params = new URLSearchParams('vid=ver-1');
    mocks.authFetch.mockReset();
    mocks.apiFetch.mockReset().mockResolvedValue({});
    mocks.authFetch.mockResolvedValue({ ok: true, json: async () => ({
      version: '0.1.0', status: 'approved',
      findings: [{ rule_id: 'SR-017', severity: 'high', file: 'server.py', line: 23, suggestion: '在清单中声明工具。' }],
      scan_summary: { total: 1, pass_rate: 70 },
    }) });
  });

  it('waits for restored login and fetches with the new token', async () => {
    const { rerender, container } = render(<StatusPage />);
    expect(screen.getByText('加载中...')).toBeInTheDocument();
    expect(mocks.authFetch).not.toHaveBeenCalled();
    mocks.auth = { user: { id: 'u1' }, token: 'restored-token', loading: false };
    rerender(<StatusPage />);
    await screen.findByRole('heading', { name: 'v0.1.0' });
    expect(mocks.authFetch).toHaveBeenCalledWith(expect.stringContaining('/versions/ver-1'), expect.objectContaining({
      headers: { Authorization: 'Bearer restored-token' },
    }));
    expect(screen.queryByText('版本不存在')).not.toBeInTheDocument();
    expect(screen.getByText('server.py:23')).toBeInTheDocument();
    expect(screen.getByText('修复建议')).toBeInTheDocument();
    expect(screen.getByText('通过率 70%')).toBeInTheDocument();
    expect(container.querySelector('.status-finding-card')).toBeInTheDocument();
    expect(container.querySelector('.finding-card')).not.toBeInTheDocument();
  });

  it('shows a login prompt rather than a false missing-version error', async () => {
    mocks.auth.loading = false;
    render(<StatusPage />);
    await screen.findByText('请先登录后查看版本状态');
    expect(mocks.authFetch).not.toHaveBeenCalled();
    expect(screen.queryByText('版本不存在')).not.toBeInTheDocument();
  });

  it('reports a genuine 404', async () => {
    mocks.auth = { user: { id: 'u1' }, token: 'token', loading: false };
    mocks.authFetch.mockResolvedValue({ ok: false, status: 404 });
    render(<StatusPage />);
    await screen.findByText('版本不存在');
  });

  it('does not request an empty version id', async () => {
    mocks.auth = { user: { id: 'u1' }, token: 'token', loading: false };
    mocks.params = new URLSearchParams();
    render(<StatusPage />);
    await screen.findByText('链接缺少版本 ID');
    expect(mocks.authFetch).not.toHaveBeenCalled();
  });

  it('resubmits the existing version using the completed scan from the generic submission page', async () => {
    mocks.auth = { user: { id: 'u1' }, token: 'token', loading: false };
    mocks.params = new URLSearchParams('vid=ver-1&scan=scan-new');
    mocks.authFetch.mockResolvedValue({ ok: true, json: async () => ({ version: '0.1.0', status: 'changes_requested' }) });
    render(<StatusPage />);
    fireEvent.click(await screen.findByRole('button', { name: '重新提交' }));
    await waitFor(() => expect(mocks.apiFetch).toHaveBeenCalledWith(expect.stringContaining('/versions/ver-1/submit'), expect.objectContaining({
      method: 'POST', body: JSON.stringify({ initial_scan_id: 'scan-new' }),
    })));
  });

  it('offers a new version rather than an unsupported resubmission of a rejected version', async () => {
    mocks.auth = { user: { id: 'u1' }, token: 'token', loading: false };
    mocks.authFetch.mockResolvedValue({ ok: true, json: async () => ({ version: '0.1.0', status: 'rejected', package_id: 'pkg-1' }) });
    render(<StatusPage />);
    await screen.findByRole('heading', { name: 'v0.1.0' });
    expect(screen.queryByRole('button', { name: '重新提交' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '创建新版本' })).toBeInTheDocument();
  });
});
