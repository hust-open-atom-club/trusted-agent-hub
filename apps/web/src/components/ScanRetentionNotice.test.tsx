import { act, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScanTaskItem } from '@/types';
import ScanRetentionNotice from './ScanRetentionNotice';

const makeTask = (overrides: Partial<ScanTaskItem> = {}): ScanTaskItem => ({
  scan_id: 'scan-1', status: 'complete', lifecycle: 'complete_unsubmitted',
  package_name: 'demo', created_at: '2026-10-01T00:00:00Z',
  updated_at: null, finished_at: '2026-10-02T00:00:00Z',
  expires_at: '2026-11-01T00:00:00Z', client_request_id: null,
  execution_deadline_at: null, auto_refresh: false, delete_allowed: true,
  owner_user_id: 'user-1', submission: null, ...overrides,
});

describe('ScanRetentionNotice', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-12T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('prompts submission and counts down from the server deadline, not creation', () => {
    const { container } = render(<ScanRetentionNotice item={makeTask()} />);
    expect(screen.getByText(/尚未提交审核，请尽快提交/)).toBeInTheDocument();
    expect(screen.getByText('距离自动清理还剩 19 天 12 小时')).toBeInTheDocument();
    expect(container.querySelector('time')).toHaveAttribute('dateTime', '2026-11-01T00:00:00Z');
  });

  it('updates in minutes and shows an expired state without negative time', () => {
    render(<ScanRetentionNotice item={makeTask({ expires_at: '2026-10-12T12:02:00Z' })} />);
    expect(screen.getByText('距离自动清理还剩 2 分钟')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(60_000));
    expect(screen.getByText('距离自动清理还剩 1 分钟')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(120_000));
    expect(screen.getByText(/已到期，等待自动清理/)).toBeInTheDocument();
    expect(screen.queryByText(/距离自动清理还剩/)).not.toBeInTheDocument();
    expect(screen.queryByText(/请尽快提交/)).not.toBeInTheDocument();
  });

  it.each(['pending_review', 'approved', 'published', 'rejected'])('hides all cleanup hints for %s submissions, including stale deadlines', (status) => {
    const { container } = render(<ScanRetentionNotice item={makeTask({
      lifecycle: 'submitted_reviewing',
      submission: { version_id: 'v1', package_name: 'demo', version: '1.0', status },
    })} />);
    expect(container).toBeEmptyDOMElement();
  });

  it.each(['callback_pending', 'submitted_reviewing'])('does not depend on optional submission labels for %s', (lifecycle) => {
    const { container } = render(<ScanRetentionNotice item={makeTask({ lifecycle })} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows retention for a failed standalone scan without urging submission', () => {
    render(<ScanRetentionNotice item={makeTask({ status: 'error', lifecycle: 'error' })} />);
    expect(screen.getByText(/扫描未成功，可发起新扫描/)).toBeInTheDocument();
    expect(screen.queryByText(/请尽快提交/)).not.toBeInTheDocument();
  });

  it.each([null, 'invalid-date'])('ignores missing or invalid deadlines (%s)', (expires_at) => {
    const { container } = render(<ScanRetentionNotice item={makeTask({ expires_at })} />);
    expect(container).toBeEmptyDOMElement();
  });
});
