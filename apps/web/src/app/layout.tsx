import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { ClientLayout } from './client-layout';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
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

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-Hans" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body style={{ fontFamily: 'var(--font-inter), var(--font-sans)' }}>
        <ClientLayout>{children}</ClientLayout>
      </body>
    </html>
  );
}
