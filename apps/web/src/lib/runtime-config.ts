function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

export const API_BASE = trimTrailingSlash(
  process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
);

export const SITE_URL = trimTrailingSlash(
  process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000',
);

export const SUPPORT_EMAIL =
  process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'support@example.com';

// Deliberately public: use only for a disposable demo account.
export const DEMO_ACCOUNT_EMAIL = process.env.NEXT_PUBLIC_DEMO_ACCOUNT_EMAIL || '';
export const DEMO_ACCOUNT_PASSWORD = process.env.NEXT_PUBLIC_DEMO_ACCOUNT_PASSWORD || '';
