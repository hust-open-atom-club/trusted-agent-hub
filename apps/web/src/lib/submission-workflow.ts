import { authFetch } from '@/lib/api-fetch';
import { API_BASE } from '@/lib/runtime-config';

export interface ExistingPackage {
  package_id: string;
  package_name: string;
  status: string;
  versions: { id: string; version: string; status: string; submitted_at: string | null }[];
}

export const RESUBMITTABLE_STATUSES = new Set(['changes_requested', 'error', 'resubmitted']);

export function versionStatusHref(name: string, version: string, id: string, scanId?: string): string {
  const query = new URLSearchParams({ vid: id });
  if (scanId) query.set('scan', scanId);
  return `/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}/status?${query}`;
}

export function blocksNewPackage(existing: ExistingPackage | null): boolean {
  return !!existing && (existing.status !== 'draft' || existing.versions.some(v => v.status !== 'draft'));
}

export async function lookupExistingPackage(name: string, token: string, signal?: AbortSignal): Promise<ExistingPackage | null> {
  const response = await authFetch(`${API_BASE}/api/v0/producer/packages/lookup?name=${encodeURIComponent(name.trim())}`, {
    headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal,
  });
  if (response.status === 403) throw new Error('该包名已被其他账号使用，当前账号无法访问。请使用其他包名。');
  if (!response.ok) throw new Error('无法检查已有包，请稍后重试。');
  return response.json();
}
