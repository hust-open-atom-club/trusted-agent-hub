'use client';

import { AuthProvider } from '@/lib/auth';
import Navbar from '@/components/Navbar';

export function ClientLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <Navbar />
      <main>{children}</main>
    </AuthProvider>
  );
}
