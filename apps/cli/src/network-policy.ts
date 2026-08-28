import './load-root-env';
import { loadConfig, normalizeApiUrl } from './config-store';

export const DEFAULT_API_BASE = 'http://127.0.0.1:8000';

const LOCALHOST_ORIGINS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function allowInsecureHttp(): boolean {
  return process.env.TAH_ALLOW_INSECURE_HTTP === 'true';
}

function readConfig(homeDir?: string) {
  try {
    return loadConfig(homeDir);
  } catch {
    return {};
  }
}

function getEnvApiBase(): string | null {
  const value = process.env.TRUSTED_AGENT_HUB_API_URL || process.env.NEXT_PUBLIC_API_URL;
  if (!value) return null;
  return normalizeApiUrl(value);
}

export function getApiBase(homeDir?: string): string {
  const envBase = getEnvApiBase();
  if (envBase) return envBase;

  const config = readConfig(homeDir);
  if (config.apiUrl) return config.apiUrl;

  return DEFAULT_API_BASE;
}

function isTrustedApiHttpOrigin(url: URL, homeDir?: string): boolean {
  if (allowInsecureHttp()) {
    const envBase = getEnvApiBase();
    if (envBase) {
      const apiUrl = new URL(envBase);
      return apiUrl.protocol === 'http:' && apiUrl.origin === url.origin;
    }
  }

  const config = readConfig(homeDir);
  if (!config.allowInsecureHttp || !config.apiUrl) return false;

  try {
    const apiUrl = new URL(config.apiUrl);
    return apiUrl.protocol === 'http:' && apiUrl.origin === url.origin;
  } catch {
    return false;
  }
}

export function isAllowedUrl(value: string, homeDir?: string): boolean {
  if (value.startsWith('https://')) return true;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && (
      LOCALHOST_ORIGINS.has(url.hostname)
      || isTrustedApiHttpOrigin(url, homeDir)
    );
  } catch {
    return false;
  }
}
