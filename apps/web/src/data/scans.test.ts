import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch } from '@/lib/api-fetch';
import { fetchScanTasks, scanPageAfterDeletion } from './scans';

vi.mock('@/lib/api-fetch', () => ({
  apiFetch: vi.fn(),
}));

const mockedApiFetch = vi.mocked(apiFetch);
const API_BASE = 'http://localhost:8000';

afterEach(() => {
  vi.clearAllMocks();
});

describe('fetchScanTasks', () => {
  it('requests the versioned paginated endpoint with the bearer token', async () => {
    mockedApiFetch.mockResolvedValue({
      items: [],
      total: 0,
      limit: 20,
      offset: 40,
      has_more: false,
    });

    await fetchScanTasks('token-123', { limit: 20, offset: 40 });

    expect(mockedApiFetch).toHaveBeenCalledWith(
      API_BASE + '/api/v1/scans?limit=20&offset=40',
      {
        cache: 'no-store',
        headers: { Authorization: 'Bearer token-123' },
      },
    );
  });

  it('rejects invalid pagination values before making a request', () => {
    expect(() => fetchScanTasks('token-123', { limit: 0 })).toThrow(
      'limit must be an integer between 1 and 200',
    );
    expect(() => fetchScanTasks('token-123', { offset: -1 })).toThrow(
      'offset must be a non-negative integer',
    );
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });
});

describe('scanPageAfterDeletion', () => {
  it('returns to the previous page only when deletion empties a later page', () => {
    expect(scanPageAfterDeletion(1, 1)).toBe(0);
    expect(scanPageAfterDeletion(2, 1)).toBe(1);
    expect(scanPageAfterDeletion(1, 2)).toBe(1);
    expect(scanPageAfterDeletion(0, 1)).toBe(0);
  });
});
