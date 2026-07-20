'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const ROLE_REDIRECT: Record<string, string> = {
  admin: '/admin',
  reviewer: '/review',
  submitter: '/submit',
  user: '/',
};

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    setError('');
    setSubmitting(true);
    try {
      await login(username.trim(), password);
      // 从 localStorage 读 token 解析 role 决定跳转
      const token = localStorage.getItem('tah_token');
      if (token) {
        try {
          const payload = JSON.parse(atob(token.split('.')[1]));
          const target = ROLE_REDIRECT[payload.role] || '/';
          router.push(target);
        } catch {
          router.push('/');
        }
      } else {
        router.push('/');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '登录失败，请重试');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <h1>登录</h1>
          <p>登录以提交和审核 Agent Skills</p>
        </div>

        {error && <div className="login-error">{error}</div>}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-field">
            <label htmlFor="username">用户名</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="输入用户名"
              autoComplete="username"
              disabled={submitting}
              required
            />
          </div>

          <div className="form-field">
            <label htmlFor="password">密码</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="输入密码"
              autoComplete="current-password"
              disabled={submitting}
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? '登录中...' : '登录'}
          </button>
        </form>

        <div className="login-footer">
          <p className="login-hint">
            测试账号：submitter / submit123
          </p>
          <a href="/register" className="login-register-link">
            没有账号？注册
          </a>
        </div>
      </div>
    </div>
  );
}
