import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import ExistingPackageNotice from './ExistingPackageNotice';
import { blocksNewPackage, type ExistingPackage } from '@/lib/submission-workflow';

const existing: ExistingPackage = {
  package_id: 'pkg-1', package_name: 'my-package', status: 'changes_requested',
  versions: [{ id: 'ver-1', version: '0.1.0', status: 'changes_requested', submitted_at: null }],
};

describe('Same-name package guidance', () => {
  it('routes a changed-requested package to its existing version and passes the new scan', () => {
    render(<ExistingPackageNotice existing={existing} version="0.1.0" scanId="scan-new" onNavigate={vi.fn()} />);
    expect(screen.getByRole('link', { name: '查看状态' })).toHaveAttribute('href', '/packages/my-package/versions/0.1.0/status?vid=ver-1');
    expect(screen.getByRole('link', { name: '重新提交' })).toHaveAttribute('href', '/packages/my-package/versions/0.1.0/status?vid=ver-1&scan=scan-new#resubmit');
    expect(screen.getByRole('link', { name: '创建新版本' })).toHaveAttribute('href', '/submit?packageId=pkg-1&scan=scan-new');
    expect(screen.getByText(/已有包和审核历史会保留/)).toBeInTheDocument();
  });

  it.each(['pending_review', 'approved', 'published', 'rejected'])('does not offer resubmission for %s', status => {
    const pkg = { ...existing, status, versions: [{ ...existing.versions[0], status }] };
    render(<ExistingPackageNotice existing={pkg} version="0.1.0" onNavigate={vi.fn()} />);
    expect(screen.queryByRole('link', { name: '重新提交' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: '查看状态' })).toBeInTheDocument();
    expect(blocksNewPackage(pkg)).toBe(true);
  });

  it('allows an unfinished draft to resume, but blocks an existing non-draft version', () => {
    expect(blocksNewPackage(null)).toBe(false);
    expect(blocksNewPackage({ ...existing, status: 'draft', versions: [] })).toBe(false);
    expect(blocksNewPackage({ ...existing, status: 'draft' })).toBe(true);
  });
});
