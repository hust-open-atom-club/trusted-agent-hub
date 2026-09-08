'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import {
  apiFetch,
  authFetch,
  clearFetchCache,
  setOnTokenRefresh,
  setOnUnauthorized,
} from './api-fetch';

import { API_BASE } from '@/lib/runtime-config';

interface AuthUser {
  id: string;
  email: string;
  role: 'user' | 'submitter' | 'reviewer' | 'admin';
  display_name: string;
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<boolean>;
  register: (email: string, password: string, display_name?: string) => Promise<boolean>;
  updateProfile: (display_name: string) => Promise<boolean>;
  changePassword: (current_password: string, new_password: string) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function parseJwt(token: string): { sub: string; role: string; email: string; display_name: string; exp: number } | null {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

function deriveUser(token: string): AuthUser | null {
  const payload = parseJwt(token);
  if (!payload) return null;
  if (payload.exp * 1000 < Date.now()) return null;

  return {
    id: payload.sub,
    email: payload.email || '',
    role: (payload.role as AuthUser['role']) || 'user',
    display_name: payload.display_name || '',
  };
}

function storeSession(token: string) {
  localStorage.setItem('tah_token', token);
  document.cookie = `tah_token=${token}; path=/; max-age=${2 * 60 * 60}; SameSite=Lax`;
}

function clearStoredSession() {
  localStorage.removeItem('tah_token');
  document.cookie = 'tah_token=; path=/; max-age=0';
}

async function responseError(res: Response, fallback: string): Promise<Error> {
  const err = await res.json().catch(() => ({ detail: fallback }));
  return new Error(err.detail || `${fallback} (${res.status})`);
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function createAbortError(): Error {
  const error = new Error('The request was aborted');
  error.name = 'AbortError';
  return error;
}

function throwIfAborted(signal?: AbortSignal | null): void {
  if (signal?.aborted) throw createAbortError();
}

function waitForAbort<T>(
  promise: Promise<T>,
  signal?: AbortSignal | null,
): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(createAbortError());

  return new Promise<T>((resolve, reject) => {
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const onAbort = () => {
      cleanup();
      reject(createAbortError());
    };

    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(error);
      },
    );
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, token: null, loading: true });
  const wasAuthenticated = useRef(false);
  const sessionGeneration = useRef(0);
  const pendingControllers = useRef(new Set<AbortController>());
  const refreshPromise = useRef<Promise<string | null> | null>(null);
  const refreshController = useRef<AbortController | null>(null);

  const invalidateRequests = useCallback(() => {
    sessionGeneration.current += 1;
    pendingControllers.current.forEach((controller) => controller.abort());
    pendingControllers.current.clear();
    refreshController.current?.abort();
    refreshController.current = null;
    refreshPromise.current = null;
  }, []);

  const beginRequest = useCallback((token?: string) => {
    const controller = new AbortController();
    const generation = sessionGeneration.current;
    const requestUserId = token ? parseJwt(token)?.sub : undefined;
    pendingControllers.current.add(controller);

    return {
      controller,
      isCurrent: () => (
        sessionGeneration.current === generation
        && (
          token === undefined
          || localStorage.getItem('tah_token') === token
          || (
            requestUserId !== undefined
            && parseJwt(localStorage.getItem('tah_token') || '')?.sub === requestUserId
          )
        )
      ),
      finish: () => pendingControllers.current.delete(controller),
    };
  }, []);

  const logout = useCallback(() => {
    invalidateRequests();
    clearStoredSession();
    clearFetchCache();
    void fetch(`${API_BASE}/api/v0/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      keepalive: true,
    }).catch(() => undefined);
    setState({ user: null, token: null, loading: false });
  }, [invalidateRequests]);

  const refreshAccessToken = useCallback(async (
    externalSignal?: AbortSignal | null,
  ): Promise<string | null> => {
    throwIfAborted(externalSignal);
    let shared = refreshPromise.current;
    if (!shared) {
      const request = beginRequest();
      const controller = new AbortController();
      const execute = async (): Promise<string | null> => {
        let res: Response;
        try {
          res = await fetch(`${API_BASE}/api/v0/auth/refresh/browser`, {
            method: 'POST',
            credentials: 'include',
            cache: 'no-store',
            signal: controller.signal,
          });
        } catch (error: unknown) {
          if (!request.isCurrent() || isAbortError(error)) return null;
          throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
        }

        if (!request.isCurrent()) return null;
        if (res.status === 401 || res.status === 403) return null;
        if (!res.ok) throw await responseError(res, '会话刷新失败');

        const data = await res.json();
        if (!request.isCurrent()) return null;
        const token: string = data.access_token;
        const user = (data.user as AuthUser | undefined) || deriveUser(token);
        if (!user) throw new Error('Token 解析失败');

        storeSession(token);
        clearFetchCache();
        setState({ user, token, loading: false });
        return token;
      };

      const promise = execute();
      let tracked: Promise<string | null>;
      tracked = promise.finally(() => {
        request.finish();
        if (refreshPromise.current === tracked) {
          refreshPromise.current = null;
          refreshController.current = null;
        }
      });
      refreshController.current = controller;
      refreshPromise.current = tracked;
      shared = tracked;
    }

    return waitForAbort(shared, externalSignal);
  }, [beginRequest]);

  useEffect(() => {
    if (state.loading) return;
    if (!state.user && wasAuthenticated.current) {
      window.location.href = '/login';
      return;
    }
    if (state.user) {
      wasAuthenticated.current = true;
    }
  }, [state.user, state.loading]);

  useEffect(() => () => invalidateRequests(), [invalidateRequests]);

  useEffect(() => {
    setOnUnauthorized(logout);
    setOnTokenRefresh(refreshAccessToken);
    return () => {
      setOnUnauthorized(null);
      setOnTokenRefresh(null);
    };
  }, [logout, refreshAccessToken]);

  useEffect(() => {
    let cancelled = false;
    let activeRequest: ReturnType<typeof beginRequest> | null = null;

    const restore = async () => {
      const saved = localStorage.getItem('tah_token');
      let token = saved;
      let user = saved ? deriveUser(saved) : null;

      // An expired access token can still be restored with the HttpOnly
      // refresh cookie. If there is no saved access token, stay logged out so
      // a cleared browser session is not silently revived.
      if (saved && !user) {
        try {
          token = await refreshAccessToken();
        } catch {
          token = null;
        }
        if (cancelled) return;
        user = token ? deriveUser(token) : null;
      }

      if (!token || !user) {
        if (saved) {
          logout();
        } else {
          setState((s) => ({ ...s, loading: false }));
        }
        return;
      }

      if (!document.cookie.includes('tah_token=')) {
        document.cookie =
          `tah_token=${token}; path=/; max-age=${2 * 60 * 60}; SameSite=Lax`;
      }
      setState({ user, token, loading: false });

      // Mutable profile fields are also stored in the JWT for navigation
      // compatibility. apiFetch refreshes the access token once on 401 and
      // retries this request with the rotated token when needed.
      const request = beginRequest(token);
      activeRequest = request;
      try {
        const currentUser = await apiFetch<AuthUser>(`${API_BASE}/api/v0/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
          cache: 'no-store',
          credentials: 'include',
          signal: request.controller.signal,
        });
        const currentToken = localStorage.getItem('tah_token');
        const currentSessionUser = currentToken ? deriveUser(currentToken) : null;
        if (
          !cancelled
          && currentSessionUser?.id === user?.id
        ) {
          setState((s) => ({
            ...s,
            token: currentToken || s.token,
            user: currentUser,
          }));
        }
      } catch (error: unknown) {
        if (cancelled || isAbortError(error)) return;
        // Keep a valid locally decoded session when the API is temporarily
        // unavailable. 401 responses are handled by apiFetch/logout.
      } finally {
        request.finish();
        activeRequest = null;
      }
    };

    void restore();
    return () => {
      cancelled = true;
      activeRequest?.controller.abort();
      activeRequest?.finish();
    };
  }, [apiFetch, beginRequest, logout, refreshAccessToken]);

  const login = useCallback(async (email: string, password: string) => {
    invalidateRequests();
    const request = beginRequest();
    try {
      let res: Response;
      try {
        res = await fetch(`${API_BASE}/api/v0/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-TAH-Browser': '1',
          },
          body: JSON.stringify({ email, password }),
          credentials: 'include',
          signal: request.controller.signal,
        });
      } catch (error: unknown) {
        if (!request.isCurrent() || isAbortError(error)) return false;
        throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
      }

      if (!request.isCurrent()) return false;
      if (!res.ok) throw await responseError(res, '登录失败');

      const data = await res.json();
      if (!request.isCurrent()) return false;
      const token: string = data.access_token;
      const user = (data.user as AuthUser | undefined) || deriveUser(token);
      if (!user) throw new Error('Token 解析失败');

      invalidateRequests();
      storeSession(token);
      setState({ user, token, loading: false });
      return true;
    } finally {
      request.finish();
    }
  }, [beginRequest, invalidateRequests]);

  const register = useCallback(async (
    email: string,
    password: string,
    display_name?: string,
  ) => {
    const body: Record<string, string> = { email, password };
    if (display_name) body.display_name = display_name;

    invalidateRequests();
    const request = beginRequest();
    try {
      let res: Response;
      try {
        res = await fetch(`${API_BASE}/api/v0/auth/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-TAH-Browser': '1',
          },
          body: JSON.stringify(body),
          credentials: 'include',
          signal: request.controller.signal,
        });
      } catch (error: unknown) {
        if (!request.isCurrent() || isAbortError(error)) return false;
        throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
      }

      if (!request.isCurrent()) return false;
      if (!res.ok) throw await responseError(res, '注册失败');

      const data = await res.json();
      if (!request.isCurrent()) return false;
      const token: string = data.access_token;
      const user = (data.user as AuthUser | undefined) || deriveUser(token);
      if (!user) throw new Error('Token 解析失败');

      invalidateRequests();
      storeSession(token);
      setState({ user, token, loading: false });
      return true;
    } finally {
      request.finish();
    }
  }, [beginRequest, invalidateRequests]);

  const updateProfile = useCallback(async (display_name: string) => {
    const token = localStorage.getItem('tah_token');
    if (!token) throw new Error('请先登录');

    const request = beginRequest(token);
    try {
      let res: Response;
      try {
        res = await authFetch(`${API_BASE}/api/v0/auth/me`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ display_name }),
          cache: 'no-store',
          credentials: 'include',
          signal: request.controller.signal,
        });
      } catch (error: unknown) {
        if (!request.isCurrent() || isAbortError(error)) return false;
        throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
      }

      if (!request.isCurrent()) return false;
      if (res.status === 401) {
        return false;
      }
      if (res.status === 403) {
        logout();
        return false;
      }
      if (!res.ok) throw await responseError(res, '资料保存失败');

      const user = await res.json() as AuthUser;
      if (!request.isCurrent()) return false;
      setState((s) => ({ ...s, user }));
      return true;
    } finally {
      request.finish();
    }
  }, [beginRequest, logout]);

  const changePassword = useCallback(async (
    current_password: string,
    new_password: string,
  ) => {
    const token = localStorage.getItem('tah_token');
    if (!token) throw new Error('请先登录');

    const request = beginRequest(token);
    try {
      let res: Response;
      try {
        res = await authFetch(`${API_BASE}/api/v0/auth/change-password`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
            'X-TAH-Browser': '1',
          },
          body: JSON.stringify({ current_password, new_password }),
          cache: 'no-store',
          credentials: 'include',
          signal: request.controller.signal,
        });
      } catch (error: unknown) {
        if (!request.isCurrent() || isAbortError(error)) return false;
        throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
      }

      if (!request.isCurrent()) return false;
      if (res.status === 401) {
        return false;
      }
      if (res.status === 403) {
        logout();
        return false;
      }
      if (!res.ok) throw await responseError(res, '密码修改失败');

      const data = await res.json();
      if (!request.isCurrent()) return false;
      const nextToken: string = data.access_token;
      const user = (data.user as AuthUser | undefined) || deriveUser(nextToken);
      if (!user) throw new Error('Token 解析失败');

      // Password changes rotate the session. Invalidate all requests tied to
      // the old token before storing the replacement token.
      invalidateRequests();
      storeSession(nextToken);
      setState({ user, token: nextToken, loading: false });
      return true;
    } finally {
      request.finish();
    }
  }, [beginRequest, invalidateRequests, logout]);

  return (
    <AuthContext.Provider
      value={{ ...state, login, register, updateProfile, changePassword, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
