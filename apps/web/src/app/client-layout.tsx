'use client';

import { useEffect, type ReactNode } from 'react';
import { AuthProvider } from '@/lib/auth';
import Navbar from '@/components/Navbar';
import { initI18n } from '@/i18n/i18n';

function ThemeProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

function RevealProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-in');
          }
        });
      },
      { threshold: 0.15 }
    );

    const targets = document.querySelectorAll('.reveal');
    targets.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  return <>{children}</>;
}

export function ClientLayout({ children, serverLang }: { children: React.ReactNode; serverLang?: string }) {
  initI18n(serverLang || 'zh');

  return (
    <AuthProvider>
      <ThemeProvider>
        <RevealProvider>
          <Navbar />
          <div className="nav-spacer" />
          <main>{children}</main>
        </RevealProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}
