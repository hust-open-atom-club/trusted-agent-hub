import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch } from '@/lib/api-fetch';
import { fetchScanTasks } from './scans';

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
