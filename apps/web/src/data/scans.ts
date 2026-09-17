import { apiFetch } from '@/lib/api-fetch';
import { API_BASE } from '@/lib/runtime-config';
import type { ScanTaskItem, ScanTaskPage } from '@/types';

export type { ScanTaskItem, ScanTaskPage } from '@/types';

export interface ScanTaskPageQuery {
  limit?: number;
  offset?: number;
}

export interface ScanTaskDeleteResult {
  scan_id: string;
  deleted: boolean;
  lifecycle: string;
}

/** Fetch the versioned, owner-scoped scan management page. */
export function fetchScanTasks(
  token: string,
  query: ScanTaskPageQuery = {},
): Promise<ScanTaskPage> {
  const limit = query.limit ?? 20;
  const offset = query.offset ?? 0;
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new Error('limit must be an integer between 1 and 200');
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw new Error('offset must be a non-negative integer');
  }

  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  return apiFetch<ScanTaskPage>(
    API_BASE + '/api/v1/scans?' + params.toString(),
    {
      cache: 'no-store',
      headers: { Authorization: 'Bearer ' + token },
    },
  );
}

/**
 * Delete one terminal scan task.
 */
export function deleteScanTask(
  token: string,
  scanId: string,
): Promise<ScanTaskDeleteResult> {
  return apiFetch<ScanTaskDeleteResult>(
    API_BASE + '/api/v0/scan/' + encodeURIComponent(scanId),
    {
      method: 'DELETE',
      cache: 'no-store',
      headers: { Authorization: 'Bearer ' + token },
    },
  );
}
