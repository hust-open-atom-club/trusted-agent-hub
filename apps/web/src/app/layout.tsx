import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import { Plus_Jakarta_Sans, JetBrains_Mono } from 'next/font/google';
import { ClientLayout } from './client-layout';
import './globals.css';

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-jakarta',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-jetbrains',
});

export const metadata: Metadata = {
  title: 'Trusted Agent Hub',
  description: 'Discover and install trusted AI agent capability packages',
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
    <html lang={lang} className={`${jakarta.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <body style={{ fontFamily: 'var(--font-jakarta), var(--font-sans)' }}>
        <script dangerouslySetInnerHTML={{ __html: INIT_SCRIPT }} />
        <ClientLayout serverLang={lang}>{children}</ClientLayout>
      </body>
    </html>
  );
}
