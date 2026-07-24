'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';

const ROLE_LEVEL: Record<string, number> = { admin: 0, reviewer: 1, submitter: 2, user: 3 };
const SCROLL_THRESHOLD = 60;

export default function Navbar() {
  const { t, i18n } = useTranslation();
  const { user, loading, logout } = useAuth();
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [scrolled, setScrolled] = useState(false);
  const [langReady, setLangReady] = useState(false);
  const rafId = useRef<number | null>(null);

  const handleScroll = useCallback(() => {
    if (rafId.current !== null) return;
    rafId.current = requestAnimationFrame(() => {
      setScrolled(window.scrollY > SCROLL_THRESHOLD);
      rafId.current = null;
    });
  }, []);

  useEffect(() => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    setTheme(isDark ? 'dark' : 'light');
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  useEffect(() => {
    setLangReady(true);
  }, []);

  const toggleLang = () => {
    const next = i18n.language === 'zh' ? 'en' : 'zh';
    i18n.changeLanguage(next);
    localStorage.setItem('tah-lang', next);
    document.cookie = `tah-lang=${next}; path=/; max-age=31536000; SameSite=Lax`;
  };

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('tah-theme', next);
    document.cookie = `tah-theme=${next}; path=/; max-age=31536000; SameSite=Lax`;
    if (next === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  };

  const roleLevel = user ? (ROLE_LEVEL[user.role] ?? 99) : 99;

  return (
    <nav className={`nav-pill${scrolled ? ' is-scrolled' : ''}`} aria-label="Primary">
      <Link href="/" className="nav-pill__logo">
        Trusted <span>Agent Hub</span>
      </Link>

      <ul className="nav-pill__links">
        <li>
          <Link href="/">{t('nav.browse')}</Link>
        </li>
        {roleLevel <= ROLE_LEVEL.submitter && (
          <>
            <li>
              <Link href="/submit">{t('nav.submit')}</Link>
            </li>
            <li>
              <Link href="/submissions">{t('nav.submissions')}</Link>
            </li>
          </>
        )}
        {roleLevel <= ROLE_LEVEL.reviewer && (
          <li>
            <Link href="/review">{t('nav.review')}</Link>
          </li>
        )}
        {roleLevel <= ROLE_LEVEL.admin && (
          <li>
            <Link href="/admin">{t('nav.admin')}</Link>
          </li>
        )}
      </ul>

      <div className="nav-pill__actions">
        {langReady && (
          <button
            className="nav-pill__theme-btn"
            onClick={toggleLang}
            aria-label={t('lang.label')}
            title={t('lang.label')}
            style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.8rem' }}
          >
            {i18n.language === 'zh' ? 'EN' : '中'}
          </button>
        )}
        <button
          className="nav-pill__theme-btn"
          onClick={toggleTheme}
          aria-label={theme === 'dark' ? t('nav.theme_light') : t('nav.theme_dark')}
          title={theme === 'dark' ? t('nav.theme_light') : t('nav.theme_dark')}
        >
          {theme === 'dark' ? '\u2600' : '\u263D'}
        </button>

        {loading ? null : user ? (
          <div className="nav-pill__user">
            <span className="nav-pill__username" title={`角色: ${user.role}`}>
              {user.display_name || user.username}
            </span>
            <button className="nav-pill__logout" onClick={logout}>
              {t('nav.logout')}
            </button>
          </div>
        ) : (
          <Link href="/login" className="nav-pill__login">
            {t('nav.login')}
          </Link>
        )}
      </div>
    </nav>
  );
}
