import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';
import zh from '../src/i18n/locales/zh/common.json';

afterEach(() => {
  cleanup();
});

// Next.js app-router hooks used by client components.
vi.mock('next/navigation', () => ({
  useRouter: vi.fn(() => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    prefetch: vi.fn(),
  })),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}));

// i18n hook — components render with fallback strings in tests.
function translate(key: string, fallbackOrOptions?: unknown): string {
  const value = key.split('.').reduce<unknown>((current, part) => {
    if (current && typeof current === 'object' && part in current) {
      return (current as Record<string, unknown>)[part];
    }
    return undefined;
  }, zh);

  const template = typeof value === 'string'
    ? value
    : typeof fallbackOrOptions === 'string'
      ? fallbackOrOptions
      : key;
  const options = typeof fallbackOrOptions === 'object' && fallbackOrOptions !== null
    ? fallbackOrOptions as Record<string, unknown>
    : {};

  return template.replace(/{{(\w+)}}/g, (_, name: string) => String(options[name] ?? `{{${name}}}`));
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: translate,
    i18n: {
      language: 'zh',
      changeLanguage: vi.fn(),
    },
  }),
  initReactI18next: {
    type: 3 as const,
    init: vi.fn(),
  },
}));
