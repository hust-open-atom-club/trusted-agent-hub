'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';

const ROLE_LEVEL: Record<string, number> = { admin: 0, reviewer: 1, submitter: 2, user: 3 };
const SCROLL_THRESHOLD = 60;

export default function Navbar() {
  const { t, i18n } = useTranslation();
  const router = useRouter();
  const pathname = usePathname();
  const { user, loading, logout } = useAuth();
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [scrolled, setScrolled] = useState(false);
  const [langReady, setLangReady] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
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

  /* 路由变化时关闭移动端菜单 */
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  /* 移动端菜单打开时锁定页面滚动；窗口回到桌面宽度时自动收起 */
  useEffect(() => {
    if (!menuOpen) return;
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onResize = () => {
      if (window.innerWidth > 768) setMenuOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false);
    };
    window.addEventListener('resize', onResize);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('resize', onResize);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [menuOpen]);

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

  const navLinks = [
    { href: '/', label: t('nav.browse') },
    ...(roleLevel <= ROLE_LEVEL.submitter
      ? [
          { href: '/submit', label: t('nav.submit') },
          { href: '/scans', label: t('nav.scans') },
        ]
      : []),
    ...(roleLevel <= ROLE_LEVEL.reviewer ? [{ href: '/review', label: t('nav.review') }] : []),
    ...(roleLevel <= ROLE_LEVEL.admin ? [{ href: '/admin', label: t('nav.admin') }] : []),
  ];

  const langButton = (className: string) =>
    langReady ? (
      <button
        className={className}
        onClick={toggleLang}
        aria-label={t('lang.label')}
        title={t('lang.label')}
        style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.8rem' }}
      >
        {i18n.language === 'zh' ? 'EN' : '中'}
      </button>
    ) : null;

  return (
    <>
      <nav className={`nav-pill${scrolled ? ' is-scrolled' : ''}`} aria-label="Primary">
        <Link href="/" className="nav-pill__logo" onClick={() => setMenuOpen(false)}>
          Trusted <span>Agent Hub</span>
        </Link>

        <ul className="nav-pill__links">
          {navLinks.map((link) => (
            <li key={link.href}>
              <Link href={link.href}>{link.label}</Link>
            </li>
          ))}
        </ul>

        <div className="nav-pill__actions">
          <button
            className="nav-pill__burger"
            type="button"
            aria-expanded={menuOpen}
            aria-controls="nav-pill-menu"
            aria-label={menuOpen ? t('nav.menu_close') : t('nav.menu_open')}
            onClick={() => setMenuOpen((open) => !open)}
          >
            <svg
              className="nav-pill__burger-icon"
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              {menuOpen ? (
                <>
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </>
              ) : (
                <>
                  <path d="M4 6h16" />
                  <path d="M4 12h16" />
                  <path d="M4 18h16" />
                </>
              )}
            </svg>
          </button>

          {langButton('nav-pill__theme-btn nav-pill__theme-btn--lang')}

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
              <Link href="/account" className="nav-pill__username" title={`角色: ${user.role}`}>
                {user.display_name || user.email}
              </Link>
              <button className="nav-pill__logout" onClick={() => { logout(); router.push('/'); }}>
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

      {menuOpen && (
        <div className="nav-pill__menu" id="nav-pill-menu" role="dialog" aria-modal="false" aria-label={t('nav.menu_open')}>
          <ul className="nav-pill__menu-links">
            {navLinks.map((link) => (
              <li key={link.href}>
                <Link href={link.href} onClick={() => setMenuOpen(false)}>
                  {link.label}
                </Link>
              </li>
            ))}
          </ul>

          <div className="nav-pill__menu-section">
            {langButton('nav-pill__menu-lang')}
            {loading ? null : user ? (
              <div className="nav-pill__menu-user">
                <Link
                  href="/account"
                  className="nav-pill__menu-username"
                  title={`角色: ${user.role}`}
                  onClick={() => setMenuOpen(false)}
                >
                  {user.display_name || user.email}
                </Link>
                <button className="nav-pill__menu-logout" onClick={() => { setMenuOpen(false); logout(); router.push('/'); }}>
                  {t('nav.logout')}
                </button>
              </div>
            ) : (
              <Link href="/login" className="nav-pill__menu-login" onClick={() => setMenuOpen(false)}>
                {t('nav.login')}
              </Link>
            )}
          </div>
        </div>
      )}
    </>
  );
}
