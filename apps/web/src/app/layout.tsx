import type { Metadata } from 'next';
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

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-Hans" className={`${jakarta.variable} ${jetbrainsMono.variable}`}>
      <body style={{ fontFamily: 'var(--font-jakarta), var(--font-sans)' }}>
        <ClientLayout>{children}</ClientLayout>
      </body>
    </html>
  );
}
