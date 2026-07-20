'use client';

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface AuthUser {
  id: string;
  username: string;
  role: 'user' | 'submitter' | 'reviewer' | 'admin';
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>;
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

function deriveUser(token: string): AuthUser | null {
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
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, token: null, loading: true });

  // 初始化：从 localStorage 恢复 session
  useEffect(() => {
    const saved = localStorage.getItem('tah_token');
    if (saved) {
      const user = deriveUser(saved);
      if (user) {
        setState({ user, token: saved, loading: false });
        return;
      }
      localStorage.removeItem('tah_token');
    }
    setState((s) => ({ ...s, loading: false }));
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await fetch(`${API_BASE}/api/v0/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: '登录失败' }));
      throw new Error(err.detail || `登录失败 (${res.status})`);
    }

    const data = await res.json();
    const token: string = data.access_token;
    const user = deriveUser(token);
    if (!user) throw new Error('Token 解析失败');

    localStorage.setItem('tah_token', token);
    setState({ user, token, loading: false });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('tah_token');
    setState({ user: null, token: null, loading: false });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
