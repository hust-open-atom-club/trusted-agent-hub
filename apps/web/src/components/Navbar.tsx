'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useAuth } from '@/lib/auth';

const ROLE_LEVEL: Record<string, number> = { admin: 0, reviewer: 1, submitter: 2, user: 3 };

export default function Navbar() {
  const { user, loading, logout } = useAuth();
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  useEffect(() => {
    const saved = localStorage.getItem('tah-theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      setTheme('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  }, []);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('tah-theme', next);
    if (next === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  };

  const roleLevel = user ? (ROLE_LEVEL[user.role] ?? 99) : 99;

  return (
    <nav className="nav-pill" aria-label="Primary">
      <Link href="/" className="nav-pill__logo">
        Trusted <span>Agent Hub</span>
      </Link>

      <ul className="nav-pill__links">
        <li>
          <Link href="/">Browse</Link>
        </li>
        {roleLevel <= ROLE_LEVEL.submitter && (
          <>
            <li>
              <Link href="/submit">Submit</Link>
            </li>
            <li>
              <Link href="/versions/lookup">我的提交</Link>
            </li>
          </>
        )}
        {roleLevel <= ROLE_LEVEL.reviewer && (
          <li>
            <Link href="/review">Review</Link>
          </li>
        )}
        {roleLevel <= ROLE_LEVEL.admin && (
          <li>
            <Link href="/admin">Admin</Link>
          </li>
        )}
      </ul>

      <div className="nav-pill__actions">
        <button
          className="nav-pill__theme-btn"
          onClick={toggleTheme}
          aria-label={theme === 'dark' ? '切换浅色模式' : '切换深色模式'}
          title={theme === 'dark' ? '切换浅色模式' : '切换深色模式'}
        >
          {theme === 'dark' ? '\u2600' : '\u263D'}
        </button>

        {loading ? null : user ? (
          <div className="nav-pill__user">
            <span className="nav-pill__username" title={`角色: ${user.role}`}>
              {user.username}
            </span>
            <button className="nav-pill__logout" onClick={logout}>
              退出
            </button>
          </div>
        ) : (
          <Link href="/login" className="nav-pill__login">
            登录
          </Link>
        )}
      </div>
    </nav>
  );
}
