'use client';

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface AuthUser {
  id: string;
  username: string;
  role: 'user' | 'submitter' | 'reviewer' | 'admin';
  email: string | null;
  display_name: string | null;
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string, email?: string, display_name?: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function parseJwt(token: string): { sub: string; role: string; exp: number } | null {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

function deriveUser(token: string, extra?: { email?: string | null; display_name?: string | null }): AuthUser | null {
  const payload = parseJwt(token);
  if (!payload) return null;

  const username =
    typeof (payload as Record<string, unknown>).username === 'string'
      ? (payload as Record<string, unknown>).username as string
      : payload.sub;

  return {
    id: payload.sub,
    username,
    role: (payload.role as AuthUser['role']) || 'user',
    email: extra?.email ?? null,
    display_name: extra?.display_name ?? null,
  };
}

function storeSession(token: string, user: { email: string | null; display_name: string | null }) {
  localStorage.setItem('tah_token', token);
  localStorage.setItem('tah_user', JSON.stringify({ email: user.email, display_name: user.display_name }));
  document.cookie = `tah_token=${token}; path=/; max-age=${2 * 60 * 60}; SameSite=Lax`;
}

function restoreUser(token: string): AuthUser | null {
  const user = deriveUser(token);
  if (!user) return null;
  try {
    const saved = JSON.parse(localStorage.getItem('tah_user') || '{}');
    user.email = saved.email ?? null;
    user.display_name = saved.display_name ?? null;
  } catch { /* ignore */ }
  return user;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, token: null, loading: true });

  useEffect(() => {
    const saved = localStorage.getItem('tah_token');
    if (saved) {
      const user = restoreUser(saved);
      if (user) {
        if (!document.cookie.includes('tah_token=')) {
          document.cookie =
            `tah_token=${saved}; path=/; max-age=${2 * 60 * 60}; SameSite=Lax`;
        }
        setState({ user, token: saved, loading: false });
        return;
      }
      localStorage.removeItem('tah_token');
      localStorage.removeItem('tah_user');
    }
    setState((s) => ({ ...s, loading: false }));
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    let res: Response;
    try {
      res = await fetch(`${API_BASE}/api/v0/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
    } catch {
      throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: '登录失败' }));
      throw new Error(err.detail || `登录失败 (${res.status})`);
    }

    const data = await res.json();
    const token: string = data.access_token;
    const respUser = data.user || {};
    const user = deriveUser(token, { email: respUser.email, display_name: respUser.display_name });
    if (!user) throw new Error('Token 解析失败');

    storeSession(token, { email: user.email, display_name: user.display_name });
    setState({ user, token, loading: false });
  }, []);

  const register = useCallback(async (
    username: string,
    password: string,
    email?: string,
    display_name?: string,
  ) => {
    const body: Record<string, string> = { username, password };
    if (email) body.email = email;
    if (display_name) body.display_name = display_name;

    let res: Response;
    try {
      res = await fetch(`${API_BASE}/api/v0/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch {
      throw new Error(`无法连接到后端服务，请确认 API 已启动 (${API_BASE})`);
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: '注册失败' }));
      throw new Error(err.detail || `注册失败 (${res.status})`);
    }

    const data = await res.json();
    const token: string = data.access_token;
    const respUser = data.user || {};
    const user = deriveUser(token, { email: respUser.email, display_name: respUser.display_name });
    if (!user) throw new Error('Token 解析失败');

    storeSession(token, { email: user.email, display_name: user.display_name });
    setState({ user, token, loading: false });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('tah_token');
    localStorage.removeItem('tah_user');
    document.cookie = 'tah_token=; path=/; max-age=0';
    setState({ user: null, token: null, loading: false });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
