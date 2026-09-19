import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  clearPendingSubmitContext,
  patchPendingSubmitContext,
  PENDING_SUBMIT_STORAGE_KEY,
  PENDING_SUBMIT_TTL_MS,
  readPendingSubmitContext,
  writePendingSubmitContext,
} from './pending-submit';

describe('pending submit context (localStorage, 6h TTL)', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('round-trips a submission anchor', () => {
    writePendingSubmitContext({
      packageId: 'pkg-1',
      versionId: null,
      packageName: 'demo',
      version: '0.1.0',
    });
    patchPendingSubmitContext({ versionId: 'ver-1' });

    expect(readPendingSubmitContext()).toMatchObject({
      packageId: 'pkg-1',
      versionId: 'ver-1',
      packageName: 'demo',
      version: '0.1.0',
    });
  });

  it('drops the context after the 6h TTL and removes the stored copy', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-18T08:00:00Z'));
    writePendingSubmitContext({
      packageId: 'pkg-1',
      versionId: 'ver-1',
      packageName: 'demo',
      version: '0.1.0',
    });
    vi.advanceTimersByTime(PENDING_SUBMIT_TTL_MS + 1);

    expect(readPendingSubmitContext()).toBeNull();
    expect(window.localStorage.getItem(PENDING_SUBMIT_STORAGE_KEY)).toBeNull();
  });

  it('keeps the context inside the TTL window', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-18T08:00:00Z'));
    writePendingSubmitContext({
      packageId: 'pkg-1',
      versionId: 'ver-1',
      packageName: 'demo',
      version: '0.1.0',
    });
    vi.advanceTimersByTime(PENDING_SUBMIT_TTL_MS - 1000);

    expect(readPendingSubmitContext()?.versionId).toBe('ver-1');
  });

  it('ignores malformed storage instead of crashing the page', () => {
    window.localStorage.setItem(PENDING_SUBMIT_STORAGE_KEY, 'not-json');
    expect(readPendingSubmitContext()).toBeNull();

    window.localStorage.setItem(
      PENDING_SUBMIT_STORAGE_KEY,
      JSON.stringify({ packageId: 'pkg-1' }),
    );
    expect(readPendingSubmitContext()).toBeNull();
  });

  it('patch without a live context is a no-op', () => {
    patchPendingSubmitContext({ versionId: 'ver-ghost' });
    expect(readPendingSubmitContext()).toBeNull();
  });

  it('clear removes the stored context', () => {
    writePendingSubmitContext({
      packageId: null,
      versionId: null,
      packageName: 'demo',
      version: '0.1.0',
    });
    clearPendingSubmitContext();
    expect(readPendingSubmitContext()).toBeNull();
  });
});
