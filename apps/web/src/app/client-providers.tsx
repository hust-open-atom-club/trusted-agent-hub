'use client';

import { useEffect, type ReactNode } from 'react';
import { AuthProvider } from '@/lib/auth';
import { initI18n } from '@/i18n/i18n';
import { Toaster } from 'sonner';
import { MotionProvider } from '@/components/Motion';

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

export function ClientProviders({ children, serverLang }: { children: React.ReactNode; serverLang?: string }) {
  initI18n(serverLang || 'zh');

  return (
    <AuthProvider>
      <MotionProvider>
        <ThemeProvider>
          <RevealProvider>
            <Toaster position="top-right" richColors duration={3000} />
            {children}
          </RevealProvider>
        </ThemeProvider>
      </MotionProvider>
    </AuthProvider>
  );
}
