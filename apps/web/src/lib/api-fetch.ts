const CACHE_TTL = 60_000;
const cache = new Map<string, { data: unknown; ts: number }>();
const pending = new Map<string, Promise<unknown>>();

function buildKey(url: string, init?: RequestInit): string {
  const method = init?.method ?? 'GET';
  const auth = (init?.headers as Record<string, string>)?.Authorization ?? '';
  return `${method}|${auth}|${url}`;
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

  const cached = cache.get(key);
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return cached.data as T;
  }

  const inflight = pending.get(key);
  if (inflight) return inflight as Promise<T>;

  const promise = fetch(url, init)
    .then(async (res) => {
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      return res.json();
    })
    .then((data) => {
      cache.set(key, { data, ts: Date.now() });
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
