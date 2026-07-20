'use client';

import Link from 'next/link';
import { useAuth } from '@/lib/auth';

const ROLE_LEVEL: Record<string, number> = { admin: 0, reviewer: 1, submitter: 2, user: 3 };

export default function Navbar() {
  const { user, loading, logout } = useAuth();

  const roleLevel = user ? (ROLE_LEVEL[user.role] ?? 99) : 99;

  return (
    <header className="header">
      <div className="header-inner">
        <Link href="/" className="header-logo">
          Trusted <span>Agent Hub</span>
        </Link>

        <nav className="header-nav">
          <Link href="/">Browse</Link>

          {roleLevel <= ROLE_LEVEL.submitter && (
            <Link href="/submit">Submit</Link>
          )}
          {roleLevel <= ROLE_LEVEL.reviewer && (
            <Link href="/review">Review</Link>
          )}
          {roleLevel <= ROLE_LEVEL.admin && (
            <Link href="/admin">Admin</Link>
          )}
        </nav>

        <div className="header-actions">
          {/* 主题切换占位 */}
          <button className="header-theme-btn" title="主题切换（开发中）" disabled>
            &#9788;
          </button>

          {loading ? (
            <span className="header-user-placeholder" />
          ) : user ? (
            <div className="header-user">
              <span className="header-username" title={`角色: ${user.role}`}>
                {user.username}
              </span>
              <button className="header-logout-btn" onClick={logout}>
                退出
              </button>
            </div>
          ) : (
            <Link href="/login" className="header-login-link">
              登录
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}
