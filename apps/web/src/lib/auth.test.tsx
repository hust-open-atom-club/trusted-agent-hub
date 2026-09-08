import { render, waitFor } from '@testing-library/react';
import { useEffect } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch } from './api-fetch';
import { AuthProvider, useAuth } from './auth';
import { API_BASE } from './runtime-config';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function ReadyProbe({ onLoading }: { onLoading: (loading: boolean) => void }) {
  const { loading } = useAuth();
  useEffect(() => onLoading(loading), [loading, onLoading]);
  return null;
}

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe('AuthProvider refresh coordination', () => {
  it('keeps a shared refresh alive when one caller is cancelled', async () => {
    let resolveRefresh: (response: Response) => void = () => undefined;
    const refreshResult = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    let resolveRefreshStarted: () => void = () => undefined;
    const refreshStarted = new Promise<void>((resolve) => {
      resolveRefreshStarted = resolve;
    });
    let refreshSignal: AbortSignal | null | undefined;
    const requestCounts = new Map<string, number>();

    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v0/auth/refresh/browser')) {
        refreshSignal = init?.signal;
        resolveRefreshStarted();
        return refreshResult;
      }

      const count = requestCounts.get(url) ?? 0;
      requestCounts.set(url, count + 1);
      return Promise.resolve(
        count === 0
          ? jsonResponse({ detail: 'expired' }, 401)
          : jsonResponse({ ok: true }),
      );
    });
    vi.stubGlobal('fetch', fetchMock);

    const onLoading = vi.fn();
    const view = render(
      <AuthProvider>
        <ReadyProbe onLoading={onLoading} />
      </AuthProvider>,
    );
    await waitFor(() => expect(onLoading).toHaveBeenCalledWith(false));

    const firstController = new AbortController();
    const secondController = new AbortController();
    const first = apiFetch('/private/first', {
      cache: 'no-store',
      headers: { Authorization: 'Bearer stale-token' },
      signal: firstController.signal,
    });
    const second = apiFetch('/private/second', {
      cache: 'no-store',
      headers: { Authorization: 'Bearer stale-token' },
      signal: secondController.signal,
    });

    await refreshStarted;
    firstController.abort();
    resolveRefresh(jsonResponse({
      access_token: 'fresh-token',
      user: {
        id: 'user-1',
        email: 'user@example.com',
        role: 'submitter',
        display_name: 'User',
      },
    }));

    await expect(first).rejects.toMatchObject({ name: 'AbortError' });
    await expect(second).resolves.toEqual({ ok: true });
    expect(refreshSignal).not.toBe(firstController.signal);
    expect(fetchMock.mock.calls.filter(([input]) => (
      String(input).endsWith('/api/v0/auth/refresh/browser')
    ))).toHaveLength(1);

    view.unmount();
  });
});
