import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const CONFIG_DIR = '.trusted-agent-hub';
const CONFIG_FILE = 'config.json';

export interface CliConfig {
  apiUrl?: string;
  allowInsecureHttp?: boolean;
}

export class ConfigStoreError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = 'ConfigStoreError';
  }
}

export function getConfigPath(homeDir = os.homedir()): string {
  return path.join(path.resolve(homeDir, CONFIG_DIR), CONFIG_FILE);
}

export function normalizeApiUrl(value: string): string {
  const raw = value.trim();
  if (!raw) {
    throw new ConfigStoreError('API URL cannot be empty.', 'invalid_api_url');
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigStoreError(`Invalid API URL: ${value}`, 'invalid_api_url');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigStoreError('API URL must start with http:// or https://.', 'invalid_api_url');
  }
  if (url.search || url.hash) {
    throw new ConfigStoreError('API URL must not include a query string or fragment.', 'invalid_api_url');
  }

  return url.toString().replace(/\/+$/, '');
}

function validateConfig(raw: unknown): CliConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigStoreError('CLI config must be a JSON object.', 'config_invalid');
  }

  const source = raw as Record<string, unknown>;
  const config: CliConfig = {};

  if (source.apiUrl !== undefined) {
    if (typeof source.apiUrl !== 'string') {
      throw new ConfigStoreError('CLI config apiUrl must be a string.', 'config_invalid');
    }
    config.apiUrl = normalizeApiUrl(source.apiUrl);
  }

  if (source.allowInsecureHttp !== undefined) {
    if (typeof source.allowInsecureHttp !== 'boolean') {
      throw new ConfigStoreError('CLI config allowInsecureHttp must be a boolean.', 'config_invalid');
    }
    config.allowInsecureHttp = source.allowInsecureHttp;
  }

  return config;
}

export function loadConfig(homeDir = os.homedir()): CliConfig {
  const filePath = getConfigPath(homeDir);
  if (!fs.existsSync(filePath)) {
    return {};
  }

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err: unknown) {
    throw new ConfigStoreError(
      `CLI config is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      'config_invalid',
    );
  }

  return validateConfig(raw);
}

export function saveConfig(config: CliConfig, homeDir = os.homedir()): CliConfig {
  const normalized = validateConfig(config);
  const filePath = getConfigPath(homeDir);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(normalized, null, 2) + '\n', 'utf-8');
  return normalized;
}
