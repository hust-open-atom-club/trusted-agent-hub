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
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;

    setError('');
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      setSuccess(true);
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
      setSubmitting(false);
      setError(err instanceof Error ? err.message : '登录失败，请重试');
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
            <label htmlFor="email">邮箱</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              autoComplete="email"
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
            {success ? '登录成功，正在跳转...' : submitting ? '登录中...' : '登录'}
          </button>
        </form>

        <div className="login-footer">
          <p className="login-hint">
            测试账号：submitter@local.dev / submit123
          </p>
          <a href="/register" className="login-register-link">
            没有账号？注册
          </a>
        </div>
      </div>
    </div>
  );
}
