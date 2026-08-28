import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import { ClientProviders } from './client-providers';
import Navbar from '@/components/Navbar';
import { SITE_URL } from '@/lib/runtime-config';
import './globals.css';

export const metadata: Metadata = {
  title: 'Trusted Agent Hub',
  description: 'Discover and install trusted AI agent capability packages',
  alternates: {
    languages: {
      en: `${SITE_URL}/en`,
      zh: `${SITE_URL}/zh`,
    },
  },
};

const INIT_SCRIPT = `
  (function(){
    try {
      var t = localStorage.getItem('tah-theme');
      if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    } catch(e){}
  })();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  let lang = 'zh';
  try {
    const cookieStore = cookies();
    lang = cookieStore.get('tah-lang')?.value || 'zh';
  } catch { /* cookieStore unavailable during build */ }

  return (
    <html lang={lang} suppressHydrationWarning>
      <body style={{ fontFamily: 'var(--font-sans)' }}>
        <script dangerouslySetInnerHTML={{ __html: INIT_SCRIPT }} />
        <ClientProviders serverLang={lang}>
          <Navbar />
          <div className="nav-spacer" />
          <main>{children}</main>
        </ClientProviders>
      </body>
    </html>
  );
}
