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

type Login = (email: string, password: string) => Promise<boolean>;

function LoginProbe({ onReady }: { onReady: (login: Login) => void }) {
  const { loading, login } = useAuth();
  useEffect(() => {
    if (!loading) onReady(login);
  }, [loading, login, onReady]);
  return null;
}

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe('AuthProvider refresh coordination', () => {
  it('keeps the access-token cookie for the refresh session lifetime', async () => {
    const token = [
      'header',
      btoa(JSON.stringify({
        sub: 'user-1',
        email: 'user@example.com',
        role: 'user',
        display_name: 'User',
        exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60,
      })),
      'signature',
    ].join('.');
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      expect(String(input)).toContain('/api/v0/auth/login');
      return Promise.resolve(jsonResponse({
        access_token: token,
        user: {
          id: 'user-1',
          email: 'user@example.com',
          role: 'user',
          display_name: 'User',
        },
      }));
    });
    vi.stubGlobal('fetch', fetchMock);

    const cookieSetter = vi.spyOn(Document.prototype, 'cookie', 'set');
    let resolveLogin: (login: Login) => void = () => undefined;
    const loginReady = new Promise<Login>((resolve) => {
      resolveLogin = resolve;
    });
    const onReady = vi.fn((callback: Login) => resolveLogin(callback));
    const view = render(
      <AuthProvider>
        <LoginProbe onReady={onReady} />
      </AuthProvider>,
    );

    const loginSession = await loginReady;
    await expect(loginSession('user@example.com', 'password')).resolves.toBe(true);

    expect(cookieSetter).toHaveBeenCalledWith(
      `tah_token=${token}; path=/; max-age=${7 * 24 * 60 * 60}; SameSite=Lax`,
    );

    view.unmount();
  });

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
