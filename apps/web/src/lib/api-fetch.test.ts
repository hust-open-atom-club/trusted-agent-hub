import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  apiFetch,
  apiFetchAll,
  authFetch,
  clearFetchCache,
  setOnTokenRefresh,
  setOnUnauthorized,
} from './api-fetch';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  clearFetchCache();
  setOnTokenRefresh(null);
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

  it('bypasses the cache for no-store requests', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ n: 1 }))
      .mockResolvedValueOnce(jsonResponse({ n: 2 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/fresh')).resolves.toEqual({ n: 1 });
    await expect(apiFetch('/fresh', { cache: 'no-store' })).resolves.toEqual({ n: 2 });

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('fetches all pages from an array endpoint', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([{ id: 1 }, { id: 2 }]))
      .mockResolvedValueOnce(jsonResponse([{ id: 3 }]));
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      apiFetchAll<{ id: number }>(
        '/versions?status=approved',
        { cache: 'no-store' },
        2,
      ),
    ).resolves.toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/versions?status=approved&limit=2&offset=0',
      '/versions?status=approved&limit=2&offset=2',
    ]);
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

  it('refreshes an expired authorized request and retries with the rotated token', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ detail: 'expired' }, 401))
      .mockResolvedValueOnce(jsonResponse({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    const refresh = vi.fn().mockResolvedValue('rotated-access-token');
    const onUnauthorized = vi.fn();
    setOnTokenRefresh(refresh);
    setOnUnauthorized(onUnauthorized);

    await expect(
      apiFetch('/private', { headers: { Authorization: 'Bearer old-token' } }),
    ).resolves.toEqual({ ok: true });

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const retryInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(new Headers(retryInit.headers).get('Authorization')).toBe(
      'Bearer rotated-access-token',
    );
  });

  it('authFetch exposes the retried Response to direct authenticated callers', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(jsonResponse({ saved: true }));
    vi.stubGlobal('fetch', fetchMock);
    setOnTokenRefresh(vi.fn().mockResolvedValue('fresh-token'));

    const response = await authFetch('/account', {
      headers: { Authorization: 'Bearer stale-token' },
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ saved: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry a cancelled request after token refresh', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(null, { status: 401 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const controller = new AbortController();
    let resolveRefresh: (token: string | null) => void = () => undefined;
    const refreshResult = new Promise<string | null>((resolve) => {
      resolveRefresh = resolve;
    });
    let signalSeen: AbortSignal | null | undefined;
    let resolveRefreshStarted: () => void = () => undefined;
    const refreshStarted = new Promise<void>((resolve) => {
      resolveRefreshStarted = resolve;
    });
    setOnTokenRefresh((signal) => {
      signalSeen = signal;
      resolveRefreshStarted();
      return refreshResult;
    });

    const request = apiFetch('/mutate', {
      method: 'POST',
      headers: { Authorization: 'Bearer stale-token' },
      body: '{}',
      signal: controller.signal,
    });

    await refreshStarted;
    controller.abort();
    resolveRefresh('fresh-token');

    await expect(request).rejects.toMatchObject({ name: 'AbortError' });
    expect(signalSeen).toBe(controller.signal);
    expect(fetchMock).toHaveBeenCalledTimes(1);
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
