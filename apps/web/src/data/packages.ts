import type { Package, PackageListResponse } from '@/types';

export type { Owner, Package, PackageListResponse } from '@/types';

import { API_BASE } from '@/lib/runtime-config';

/* ── 查询参数 ── */

export type SortField = 'updated_at' | 'install_count' | 'avg_rating' | 'name' | 'grade';
export type SortOrder = 'asc' | 'desc';

export interface PackageQuery {
  q?: string;
  type?: string;
  client?: string;
  category?: string;
  tag?: string;
  min_grade?: string;
  min_score?: number;
  max_score?: number;
  updated_since?: string;
  sort_by?: SortField;
  order?: SortOrder;
  page?: number;
  page_size?: number;
}

/* ── API 调用 ── */

export async function fetchPackages(query: PackageQuery = {}): Promise<PackageListResponse> {
  const params = new URLSearchParams();

  if (query.q) params.set('q', query.q);
  if (query.type) params.set('type', query.type);
  if (query.client) params.set('client', query.client);
  if (query.category) params.set('category', query.category);
  if (query.tag) params.set('tag', query.tag);
  if (query.min_grade) params.set('min_grade', query.min_grade);
  if (query.min_score !== undefined) params.set('min_score', String(query.min_score));
  if (query.max_score !== undefined) params.set('max_score', String(query.max_score));
  if (query.updated_since) params.set('updated_since', query.updated_since);
  if (query.sort_by) params.set('sort_by', query.sort_by);
  if (query.order) params.set('order', query.order);
  if (query.page && query.page > 1) params.set('page', String(query.page));
  if (query.page_size) params.set('page_size', String(query.page_size));

  const qs = params.toString();
  const url = `${API_BASE}/api/v0/packages${qs ? `?${qs}` : ''}`;

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch packages: ${res.status}`);
  }
  return res.json();
}

export async function fetchPackage(name: string): Promise<Package | null> {
  const res = await fetch(`${API_BASE}/api/v0/packages/${encodeURIComponent(name)}`);
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Failed to fetch package ${name}: ${res.status}`);
  }
  return res.json();
}

export async function fetchPackageVersion(
  name: string,
  version: string,
): Promise<import('@/types').VersionDetail | null> {
  const res = await fetch(
    `${API_BASE}/api/v0/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
  );
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Failed to fetch version ${name}@${version}: ${res.status}`);
  }
  return res.json();
}

export async function fetchPackageVersions(
  name: string,
): Promise<import('@/types').VersionDetail[]> {
  const res = await fetch(
    `${API_BASE}/api/v0/packages/${encodeURIComponent(name)}/versions`,
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch versions for ${name}: ${res.status}`);
  }
  return res.json();
}

export async function fetchTrustHistory(
  name: string,
): Promise<import('@/types').TrustHistoryPoint[]> {
  const res = await fetch(
    `${API_BASE}/api/v0/packages/${encodeURIComponent(name)}/trust-history`,
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch trust history for ${name}: ${res.status}`);
  }
  return res.json();
}

/* ── 用户反馈 ── */

export async function fetchFeedback(
  name: string,
  page = 1,
  pageSize = 10,
): Promise<import('@/types').FeedbackPage> {
  const res = await fetch(
    `${API_BASE}/api/v0/packages/${encodeURIComponent(name)}/feedback?page=${page}&page_size=${pageSize}`,
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch feedback: ${res.status}`);
  }
  return res.json();
}

export async function submitFeedback(
  name: string,
  level: import('@/types').FeedbackLevel,
  comment: string | null,
  token: string,
): Promise<import('@/types').FeedbackRecord> {
  const res = await fetch(
    `${API_BASE}/api/v0/packages/${encodeURIComponent(name)}/feedback`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ level, comment }),
    },
  );
  if (!res.ok) {
    if (res.status === 401) throw new Error('Please login to submit feedback');
    throw new Error(`Failed to submit feedback: ${res.status}`);
  }
  return res.json();
}
