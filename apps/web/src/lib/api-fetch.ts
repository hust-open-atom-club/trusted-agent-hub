const CACHE_TTL = 60_000;
const cache = new Map<string, { data: unknown; ts: number }>();
const pending = new Map<string, Promise<unknown>>();

let _onUnauthorized: (() => void) | null = null;

export function setOnUnauthorized(callback: (() => void) | null): void {
  _onUnauthorized = callback;
}

function buildKey(url: string, init?: RequestInit): string {
  const method = init?.method ?? 'GET';
  const auth = (init?.headers as Record<string, string>)?.Authorization ?? '';
  return `${method}|${auth}|${url}`;
}

function withPage(url: string, limit: number, offset: number): string {
  const [base, query = ''] = url.split('?', 2);
  const params = new URLSearchParams(query);
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  return `${base}?${params.toString()}`;
}

export function clearFetchCache(pattern?: string): void {
  if (!pattern) {
    cache.clear();
    return;
  }
  for (const key of Array.from(cache.keys())) {
    if (key.includes(pattern)) cache.delete(key);
  }
}

export async function apiFetch<T = unknown>(url: string, init?: RequestInit): Promise<T> {
  const key = buildKey(url, init);
  const cacheable = init?.cache !== 'no-store';

  if (cacheable) {
    const cached = cache.get(key);
    if (cached && Date.now() - cached.ts < CACHE_TTL) {
      return cached.data as T;
    }
  }

  const inflight = pending.get(key);
  if (inflight) return inflight as Promise<T>;

  const promise = fetch(url, init)
    .then(async (res) => {
      if (res.status === 401 && _onUnauthorized) {
        _onUnauthorized();
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      return res.json();
    })
    .then((data) => {
      if (cacheable) cache.set(key, { data, ts: Date.now() });
      pending.delete(key);
      return data as T;
    })
    .catch((err) => {
      pending.delete(key);
      throw err;
    });

  pending.set(key, promise);
  return promise as Promise<T>;
}

/** Fetch every page from an array-based endpoint that supports limit/offset. */
export async function apiFetchAll<T>(
  url: string,
  init?: RequestInit,
  pageSize = 200,
): Promise<T[]> {
  if (!Number.isInteger(pageSize) || pageSize < 1) {
    throw new Error('pageSize must be a positive integer');
  }

  const items: T[] = [];
  for (let offset = 0; ; offset += pageSize) {
    const page = await apiFetch<T[]>(withPage(url, pageSize, offset), init);
    items.push(...page);
    if (page.length < pageSize) return items;
  }
}
