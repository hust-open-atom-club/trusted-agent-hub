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

export default function RegisterPage() {
  const router = useRouter();
  const { register } = useAuth();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!username.trim() || !password.trim()) {
      setError('用户名和密码为必填');
      return;
    }

    if (password.length < 6) {
      setError('密码长度不能少于 6 位');
      return;
    }

    if (password !== confirmPassword) {
      setError('两次输入的密码不一致');
      return;
    }

    setSubmitting(true);
    try {
      await register(
        username.trim(),
        password,
        email.trim() || undefined,
        displayName.trim() || undefined,
      );
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
      setError(err instanceof Error ? err.message : '注册失败，请重试');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <h1>注册</h1>
          <p>创建账号以提交 Agent Skills</p>
        </div>

        {error && <div className="login-error">{error}</div>}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-field">
            <label htmlFor="username">用户名 *</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="2-64 个字符"
              autoComplete="username"
              disabled={submitting}
              required
            />
          </div>

          <div className="form-field">
            <label htmlFor="email">邮箱</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="选填"
              autoComplete="email"
              disabled={submitting}
            />
          </div>

          <div className="form-field">
            <label htmlFor="displayName">昵称</label>
            <input
              id="displayName"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="选填，默认自动生成"
              autoComplete="name"
              disabled={submitting}
            />
          </div>

          <div className="form-field">
            <label htmlFor="password">密码 *</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="至少 6 位"
              autoComplete="new-password"
              disabled={submitting}
              required
            />
          </div>

          <div className="form-field">
            <label htmlFor="confirmPassword">确认密码 *</label>
            <input
              id="confirmPassword"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="再次输入密码"
              autoComplete="new-password"
              disabled={submitting}
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? '注册中...' : '注册'}
          </button>
        </form>

        <div className="login-footer">
          <a href="/login" className="login-register-link">
            已有账号？登录
          </a>
        </div>
      </div>
    </div>
  );
}
