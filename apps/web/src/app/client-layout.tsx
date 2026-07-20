'use client';

import { useEffect, type ReactNode } from 'react';
import { AuthProvider } from '@/lib/auth';
import Navbar from '@/components/Navbar';

function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    const saved = localStorage.getItem('tah-theme');
    if (saved === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }, []);

  return <>{children}</>;
}

export function ClientLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <ThemeProvider>
        <Navbar />
        <div className="nav-spacer" />
        <main>{children}</main>
      </ThemeProvider>
    </AuthProvider>
  );
}
