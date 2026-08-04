import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch, clearFetchCache, setOnUnauthorized } from './api-fetch';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  clearFetchCache();
  setOnUnauthorized(null);
  vi.useRealTimers();
});

describe('apiFetch', () => {
  it('GETs and parses JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/api/v0/health')).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith('/api/v0/health', undefined);
  });

  it('caches identical GET requests within TTL', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ n: 1 }));
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/same');
    await apiFetch('/same');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('deduplicates concurrent requests', async () => {
    let resolveFetch: (value: Response) => void = () => undefined;
    const fetchMock = vi.fn().mockReturnValue(new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    }));
    vi.stubGlobal('fetch', fetchMock);

    const first = apiFetch('/inflight');
    const second = apiFetch('/inflight');
    resolveFetch(jsonResponse({ done: true }));

    await expect(first).resolves.toEqual({ done: true });
    await expect(second).resolves.toEqual({ done: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not reuse cache when Authorization header differs', async () => {
    const fetchMock = vi.fn().mockImplementation(
      () => Promise.resolve(jsonResponse({ ok: true })),
    );
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/private', { headers: { Authorization: 'Bearer a' } });
    await apiFetch('/private', { headers: { Authorization: 'Bearer b' } });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('invokes the unauthorized callback on 401', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ detail: 'unauthorized' }, 401),
    );
    vi.stubGlobal('fetch', fetchMock);
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);

    await expect(apiFetch('/expired')).rejects.toThrow('unauthorized');
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('throws HTTP detail from error responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ detail: 'not found' }, 404),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/missing')).rejects.toThrow('not found');
  });

  it('falls back to HTTP status when body has no detail', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('boom', { status: 500 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/boom')).rejects.toThrow('HTTP 500');
  });

  it('expires cache after TTL', async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(
      () => Promise.resolve(jsonResponse({ n: 1 })),
    );
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/ttl');
    vi.advanceTimersByTime(60_001);
    await apiFetch('/ttl');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('clearFetchCache removes entries matching a pattern', async () => {
    const fetchMock = vi.fn().mockImplementation(
      () => Promise.resolve(jsonResponse({ n: 1 })),
    );
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/packages/a');
    await apiFetch('/packages/b');
    clearFetchCache('/packages/');
    await apiFetch('/packages/a');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
