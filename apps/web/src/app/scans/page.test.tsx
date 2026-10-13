import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  auth: { user: { id: 'owner', role: 'admin' }, token: 'token', loading: false },
  apiFetch: vi.fn(), fetchScanTasks: vi.fn(), deleteScanTask: vi.fn(),
}));
vi.mock('@/lib/auth', () => ({ useAuth: () => mocks.auth }));
vi.mock('@/lib/api-fetch', () => ({ apiFetch: mocks.apiFetch, authFetch: vi.fn() }));
vi.mock('@/data/scans', () => ({ fetchScanTasks: mocks.fetchScanTasks, deleteScanTask: mocks.deleteScanTask }));
import ScansPage from './page';

const version = {
  version_id: 'ver-1', package_id: 'pkg-1', package_name: 'my-package',
  version: '0.1.0', status: 'changes_requested', submitted_at: '2026-10-01T12:00:00Z',
};
const scan = {
  scan_id: 'scan-1', package_name: 'my-package', status: 'complete',
  lifecycle: 'submitted_reviewing', created_at: '2026-10-01T12:00:00Z',
  delete_allowed: true, auto_refresh: false,
  submission: { ...version, id: version.version_id },
};

describe('Personal submissions and scan records', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    mocks.auth.user.role = 'admin';
    mocks.apiFetch.mockReset().mockResolvedValue([version]);
    mocks.fetchScanTasks.mockReset().mockResolvedValue({ items: [], has_more: false });
    mocks.deleteScanTask.mockReset().mockResolvedValue(undefined);
  });

  it.each(['submitter', 'reviewer', 'admin'])('shows %s own versions without a surviving scan', async role => {
    mocks.auth.user.role = role;
    render(<ScansPage />);
    await screen.findByText('my-package');
    expect(mocks.apiFetch).toHaveBeenCalledWith(expect.stringContaining('submitter_id=owner'), expect.anything());
    expect(screen.getByRole('tab', { name: '我的提交版本' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('link', { name: '重新提交' })).toHaveAttribute('href', expect.stringContaining('vid=ver-1#resubmit'));
    expect(screen.getByRole('link', { name: '创建新版本' })).toHaveAttribute('href', '/submit?packageId=pkg-1');
    expect(screen.queryByRole('button', { name: '删除扫描记录' })).not.toBeInTheDocument();
  });

  it('keeps global scans separate from the personal version list', async () => {
    mocks.fetchScanTasks.mockResolvedValue({ items: [{ ...scan, package_name: 'another-users-scan', submission: null }], has_more: false });
    render(<ScansPage />);
    await screen.findByText('my-package');
    expect(screen.queryByText('another-users-scan')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '全站扫描记录' }));
    expect(screen.getByText('another-users-scan')).toBeInTheDocument();
    expect(screen.queryByText('my-package')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '我的提交版本' }));
    expect(screen.getByText('my-package')).toBeInTheDocument();
  });

  it.each(['submitter', 'reviewer'])('only offers personal scan records to %s', async role => {
    mocks.auth.user.role = role;
    mocks.fetchScanTasks.mockResolvedValue({ items: [scan], has_more: false });
    render(<ScansPage />);
    await screen.findByText('my-package');
    expect(screen.queryByRole('tab', { name: '全站扫描记录' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '我的扫描记录' }));
    expect(screen.getByRole('tab', { name: '我的扫描记录' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('my-package')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '查看提交' })).toBeInTheDocument();
  });

  it('confirms only an unbound scan deletion, then keeps personal submissions visible', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    mocks.fetchScanTasks.mockResolvedValueOnce({ items: [{ ...scan, submission: null, lifecycle: 'complete_unsubmitted' }], has_more: false });
    render(<ScansPage />);
    fireEvent.click(await screen.findByRole('tab', { name: '全站扫描记录' }));
    fireEvent.click(await screen.findByRole('button', { name: '删除扫描记录' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: '删除扫描记录' })).not.toBeInTheDocument());
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('已提交的包版本和审核历史仍会保留'));
    expect(mocks.deleteScanTask).toHaveBeenCalledWith('token', 'scan-1');
    expect(screen.getByRole('status')).toHaveTextContent('包版本和审核历史');
    fireEvent.click(screen.getByRole('tab', { name: '我的提交版本' }));
    expect(screen.getByText('my-package')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: '查看状态' })).toHaveLength(1);
    expect(mocks.apiFetch.mock.calls.every(([, options]) => !options.method)).toBe(true);
  });

  it('does not delete anything when confirmation is cancelled', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    mocks.fetchScanTasks.mockResolvedValue({ items: [{ ...scan, submission: null, lifecycle: 'complete_unsubmitted' }], has_more: false });
    render(<ScansPage />);
    fireEvent.click(await screen.findByRole('tab', { name: '全站扫描记录' }));
    fireEvent.click(await screen.findByRole('button', { name: '删除扫描记录' }));
    expect(mocks.deleteScanTask).not.toHaveBeenCalled();
    expect(screen.getByText('my-package')).toBeInTheDocument();
  });

  it('never offers scan deletion for version-bound records, even with a stale delete flag', async () => {
    mocks.fetchScanTasks.mockResolvedValue({ items: [scan], has_more: false });
    render(<ScansPage />);
    await screen.findByText('my-package');
    expect(screen.queryByRole('button', { name: '删除扫描记录' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '全站扫描记录' }));
    expect(screen.queryByRole('button', { name: '删除扫描记录' })).not.toBeInTheDocument();
  });
});
