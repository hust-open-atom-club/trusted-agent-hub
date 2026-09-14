import { beforeEach, describe, expect, it } from 'vitest';

import {
  clearPendingScanIfMatches,
  PENDING_SCAN_STORAGE_KEY,
  readPendingScanState,
  writePendingScanState,
} from './pending-scan';

describe('pending scan session state', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it('round-trips the current structured format', () => {
    const state = {
      scanId: 'scan-current',
      clientRequestId: 'request-current',
      repoUrl: 'https://github.com/acme/demo',
    };

    writePendingScanState(state);

    expect(readPendingScanState()).toEqual(state);
  });

  it('reads and clears the legacy raw scan id format', () => {
    window.sessionStorage.setItem(PENDING_SCAN_STORAGE_KEY, 'scan-legacy');

    expect(readPendingScanState()).toEqual({
      scanId: 'scan-legacy',
      clientRequestId: '',
      repoUrl: '',
    });

    clearPendingScanIfMatches('scan-legacy');
    expect(readPendingScanState()).toBeNull();
  });

  it('clears a matching structured scan', () => {
    writePendingScanState({
      scanId: 'scan-matching',
      clientRequestId: 'request-matching',
      repoUrl: 'https://github.com/acme/matching',
    });

    clearPendingScanIfMatches('scan-matching');

    expect(readPendingScanState()).toBeNull();
  });

  it('preserves a different pending scan', () => {
    writePendingScanState({
      scanId: 'scan-other',
      clientRequestId: 'request-other',
      repoUrl: 'https://github.com/acme/other',
    });

    clearPendingScanIfMatches('scan-unrelated');

    expect(readPendingScanState()?.scanId).toBe('scan-other');
  });
});
