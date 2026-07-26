'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { setOnUnauthorized } from './api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

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
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, display_name?: string) => Promise<void>;
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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, token: null, loading: true });
  const wasAuthenticated = useRef(false);

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

  useEffect(() => {
    const saved = localStorage.getItem('tah_token');
    if (saved) {
      const user = deriveUser(saved);
      if (user) {
        if (!document.cookie.includes('tah_token=')) {
          document.cookie =
            `tah_token=${saved}; path=/; max-age=${2 * 60 * 60}; SameSite=Lax`;
        }
        setState({ user, token: saved, loading: false });
        return;
      }
      localStorage.removeItem('tah_token');
    }
    setState((s) => ({ ...s, loading: false }));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    let res: Response;
    try {
      res = await fetch(`${API_BASE}/api/v0/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
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
    const user = deriveUser(token);
    if (!user) throw new Error('Token 解析失败');

    storeSession(token);
    setState({ user, token, loading: false });
  }, []);

  const register = useCallback(async (
    email: string,
    password: string,
    display_name?: string,
  ) => {
    const body: Record<string, string> = { email, password };
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
    const user = deriveUser(token);
    if (!user) throw new Error('Token 解析失败');

    storeSession(token);
    setState({ user, token, loading: false });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('tah_token');
    document.cookie = 'tah_token=; path=/; max-age=0';
    setState({ user: null, token: null, loading: false });
  }, []);

  useEffect(() => {
    setOnUnauthorized(logout);
    return () => setOnUnauthorized(null);
  }, [logout]);

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
