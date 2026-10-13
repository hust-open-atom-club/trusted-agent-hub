import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  auth: { user: { id: 'owner', role: 'submitter' }, token: 'token' },
  authFetch: vi.fn(), clearFetchCache: vi.fn(), onDeleted: vi.fn(),
}));
vi.mock('@/lib/auth', () => ({ useAuth: () => mocks.auth }));
vi.mock('@/lib/api-fetch', () => ({ authFetch: mocks.authFetch, clearFetchCache: mocks.clearFetchCache }));
import VersionDeleteButton from './VersionDeleteButton';

const plan = {
  version_id: 'ver-1', package_name: 'demo', version: '1.0.0', status: 'draft',
  allowed: true, action: '撤回并删除提交', reason: null,
  scan_count: 2, report_count: 1, review_count: 3,
};
const response = (data: unknown, status = 200) => ({ ok: status === 200, status, json: async () => data });

describe('Version deletion confirmation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mocks.auth.user.role = 'submitter';
    mocks.authFetch.mockReset().mockResolvedValue(response(plan));
    mocks.onDeleted.mockReset();
    mocks.clearFetchCache.mockReset();
  });

  it.each(['draft', 'pending_review', 'changes_requested', 'rejected', 'error'])('offers withdrawal for allowed %s', async status => {
    render(<VersionDeleteButton versionId="ver-1" status={status} onDeleted={mocks.onDeleted} />);
    expect(await screen.findByRole('button', { name: '撤回并删除提交' })).toBeInTheDocument();
  });

  it.each(['submitted', 'scanning', 'resubmitted', 'approved', 'published'])('hides deletion for %s even for admin', status => {
    mocks.auth.user.role = 'admin';
    render(<VersionDeleteButton versionId="ver-1" status={status} onDeleted={mocks.onDeleted} />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(mocks.authFetch).not.toHaveBeenCalled();
  });

  it('offers yanked deletion only to admin', async () => {
    const { rerender } = render(<VersionDeleteButton versionId="ver-1" status="yanked" onDeleted={mocks.onDeleted} />);
    expect(mocks.authFetch).not.toHaveBeenCalled();
    mocks.auth.user.role = 'admin';
    mocks.authFetch.mockResolvedValue(response({ ...plan, status: 'yanked', action: '删除版本' }));
    rerender(<VersionDeleteButton versionId="ver-1" status="yanked" onDeleted={mocks.onDeleted} />);
    expect(await screen.findByRole('button', { name: '删除版本' })).toBeInTheDocument();
  });

  it.each([403, 404, 500])('does not show an unauthorized/unverified deletion button (%s)', async status => {
    mocks.authFetch.mockResolvedValue(response({}, status));
    render(<VersionDeleteButton versionId="ver-1" status="draft" onDeleted={mocks.onDeleted} />);
    await waitFor(() => expect(mocks.authFetch).toHaveBeenCalled());
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('requires checklist acknowledgement and a second confirmation before sending DELETE', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    render(<VersionDeleteButton versionId="ver-1" status="draft" onDeleted={mocks.onDeleted} />);
    fireEvent.click(await screen.findByRole('button', { name: '撤回并删除提交' }));
    await screen.findByRole('dialog', { name: '版本删除范围清单' });
    expect(screen.getByText('关联扫描记录：2 条')).toBeInTheDocument();
    expect(screen.getByText('版本审核记录：3 条')).toBeInTheDocument();
    const next = screen.getByRole('button', { name: '继续二次确认' });
    expect(next).toBeDisabled();
    expect(confirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(next);
    await waitFor(() => expect(mocks.onDeleted).toHaveBeenCalledOnce());
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('demo v1.0.0'));
    expect(mocks.authFetch).toHaveBeenLastCalledWith(expect.stringContaining('/versions/ver-1'), expect.objectContaining({
      method: 'DELETE', body: JSON.stringify({ confirmed: true, expected_status: 'draft' }),
    }));
  });

  it('sends no DELETE if the second confirmation is cancelled', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<VersionDeleteButton versionId="ver-1" status="draft" onDeleted={mocks.onDeleted} />);
    fireEvent.click(await screen.findByRole('button', { name: '撤回并删除提交' }));
    fireEvent.click(await screen.findByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: '继续二次确认' }));
    expect(mocks.authFetch.mock.calls.every(([, options]) => options.method !== 'DELETE')).toBe(true);
    expect(mocks.onDeleted).not.toHaveBeenCalled();
  });

  it('rechecks state before showing the list and blocks a newly published version', async () => {
    mocks.authFetch.mockResolvedValueOnce(response(plan)).mockResolvedValue(response({ ...plan, allowed: false, reason: '当前状态不可删除' }));
    render(<VersionDeleteButton versionId="ver-1" status="draft" onDeleted={mocks.onDeleted} />);
    fireEvent.click(await screen.findByRole('button', { name: '撤回并删除提交' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('当前状态不可删除');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps the checklist open with an error when final transactional validation rejects deletion', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    mocks.authFetch.mockImplementation(async (_url, options) => options.method === 'DELETE'
      ? response({ detail: '版本状态已变化' }, 409) : response(plan));
    render(<VersionDeleteButton versionId="ver-1" status="draft" onDeleted={mocks.onDeleted} />);
    fireEvent.click(await screen.findByRole('button', { name: '撤回并删除提交' }));
    fireEvent.click(await screen.findByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: '继续二次确认' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('版本状态已变化');
    expect(mocks.onDeleted).not.toHaveBeenCalled();
  });
});
