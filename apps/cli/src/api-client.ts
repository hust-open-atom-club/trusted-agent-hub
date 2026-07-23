/**
 * TrustedAgentHub Consumer API Client.
 *
 * API_BASE is read from TRUSTED_AGENT_HUB_API_URL env var, defaulting to
 * http://localhost:8000.  A custom fetch implementation can be injected
 * (useful for testing).
 */

// ---------------------------------------------------------------------------
// Shared types (kept here so CLI does not depend on mock-loader at runtime)
// ---------------------------------------------------------------------------

export interface PackageOwner {
  id: string;
  username: string;
  display_name: string;
  role: string;
}

export interface PackageSummary {
  id: string;
  name: string;
  description: string;
  type: string;
  license: string;
  keywords: string[];
  category: string | null;
  homepage: string | null;
  icon_url: string | null;
  owner: PackageOwner | null;
  latest_version: string;
  status: string;
  risk_level: string | null;
  grade: string | null;
  install_count: number;
  avg_rating: number | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface VersionDetail {
  id: string;
  package_id: string;
  version: string;
  author?: { name: string; email?: string; url?: string };
  source?: {
    type: string; repository_url: string; owner?: string; repo?: string;
    ref_type?: string; ref: string; commit_hash: string; verified_owner?: boolean;
  };
  compatibility?: string[];
  permissions?: Record<string, unknown>;
  installation?: {
    method: string;
    targets?: Array<{ client: string; destination: string }>;
    post_install_message?: string;
    command?: string;
  };
  status: string;
  trust_score?: {
    risk_summary?: {
      level: string;
      grade?: 'A' | 'B' | 'C' | 'D' | 'E';
      top_risks?: string[];
      install_recommendation?: string;
    };
  } | null;
  created_at?: string | null;
  submitted_at?: string | null;
}

export interface PackagePage {
  items: PackageSummary[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface InstallReportRequest {
  package_name: string;
  version: string;
  client: string;
  install_path: string;
  integrity_verified: boolean;
}

export interface InstallRecordResponse {
  id: string;
  package_name: string;
  version: string;
  version_id: string;
  user_id: string;
  client: string;
  install_path: string;
  integrity_verified: boolean;
  installed_at: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_BASE =
  process.env.TRUSTED_AGENT_HUB_API_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  'http://localhost:8000';

const API_TOKEN = process.env.TRUSTED_AGENT_HUB_TOKEN || '';

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_PAGE_SIZE = 100;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public cause?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// ---------------------------------------------------------------------------
// Runtime validators — check that API responses have required fields
// ---------------------------------------------------------------------------

function requireArray(val: unknown, field: string, context: string): unknown[] {
  if (!Array.isArray(val)) {
    throw new ApiError(`Invalid ${context}: "${field}" must be an array`);
  }
  return val;
}

function requireInt(val: unknown, field: string, context: string, min?: number, max?: number): number {
  if (typeof val !== 'number' || !Number.isFinite(val) || !Number.isInteger(val)) {
    throw new ApiError(`Invalid ${context}: "${field}" must be an integer, got ${typeof val}`);
  }
  if (min !== undefined && val < min) {
    throw new ApiError(`Invalid ${context}: "${field}" must be >= ${min}, got ${val}`);
  }
  if (max !== undefined && val > max) {
    throw new ApiError(`Invalid ${context}: "${field}" must be <= ${max}, got ${val}`);
  }
  return val;
}

function requireNumberOrNull(val: unknown, field: string, context: string): number | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'number' && Number.isFinite(val)) return val;
  throw new ApiError(`Invalid ${context}: "${field}" must be a number or null`);
}

function requireString(val: unknown, field: string, context: string): string {
  if (typeof val !== 'string') {
    throw new ApiError(`Invalid ${context}: "${field}" must be a string, got ${typeof val}`);
  }
  return val;
}

function requireNullableString(val: unknown, field: string, context: string): string | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'string') return val;
  throw new ApiError(`Invalid ${context}: "${field}" must be a string or null`);
}

function requireBoolean(val: unknown, field: string, context: string): boolean {
  if (typeof val !== 'boolean') {
    throw new ApiError(`Invalid ${context}: "${field}" must be a boolean`);
  }
  return val;
}

function validateOwner(val: unknown): PackageOwner | null {
  if (val === null || val === undefined) return null;
  if (typeof val !== 'object') {
    throw new ApiError('Invalid PackageSummary.owner: expected object or null');
  }
  const o = val as Record<string, unknown>;
  return {
    id: requireString(o.id, 'id', 'owner'),
    username: requireString(o.username, 'username', 'owner'),
    display_name: requireString(o.display_name, 'display_name', 'owner'),
    role: requireString(o.role, 'role', 'owner'),
  };
}

function validatePackageSummary(raw: unknown): PackageSummary {
  if (typeof raw !== 'object' || raw === null) {
    throw new ApiError('Invalid PackageSummary: expected object');
  }
  const o = raw as Record<string, unknown>;
  return {
    id: requireString(o.id, 'id', 'PackageSummary'),
    name: requireString(o.name, 'name', 'PackageSummary'),
    description: requireString(o.description, 'description', 'PackageSummary'),
    type: requireString(o.type, 'type', 'PackageSummary'),
    license: requireNullableString(o.license, 'license', 'PackageSummary') || '',
    keywords: Array.isArray(o.keywords) ? o.keywords.map((k, i) => {
      if (typeof k !== 'string') throw new ApiError(`Invalid PackageSummary.keywords[${i}]: must be string`);
      return k;
    }) : [],
    category: requireNullableString(o.category, 'category', 'PackageSummary'),
    homepage: requireNullableString(o.homepage, 'homepage', 'PackageSummary'),
    icon_url: requireNullableString(o.icon_url, 'icon_url', 'PackageSummary'),
    owner: validateOwner(o.owner),
    latest_version: requireString(o.latest_version, 'latest_version', 'PackageSummary'),
    status: requireString(o.status, 'status', 'PackageSummary'),
    risk_level: requireNullableString(o.risk_level, 'risk_level', 'PackageSummary'),
    grade: requireNullableString(o.grade, 'grade', 'PackageSummary'),
    install_count: requireInt(o.install_count, 'install_count', 'PackageSummary', 0),
    avg_rating: requireNumberOrNull(o.avg_rating, 'avg_rating', 'PackageSummary'),
    created_at: requireNullableString(o.created_at, 'created_at', 'PackageSummary'),
    updated_at: requireNullableString(o.updated_at, 'updated_at', 'PackageSummary'),
  };
}

function validatePackagePage(raw: unknown): PackagePage {
  if (typeof raw !== 'object' || raw === null) {
    throw new ApiError('Invalid PackagePage: expected object');
  }
  const o = raw as Record<string, unknown>;
  const items = requireArray(o.items, 'items', 'PackagePage');
  return {
    items: items.map((item) => validatePackageSummary(item)),
    total: requireInt(o.total, 'total', 'PackagePage', 0),
    page: requireInt(o.page, 'page', 'PackagePage', 1),
    page_size: requireInt(o.page_size, 'page_size', 'PackagePage', 1, MAX_PAGE_SIZE),
    total_pages: requireInt(o.total_pages, 'total_pages', 'PackagePage', 0),
  };
}

function validateVersionDetail(raw: unknown): VersionDetail {
  if (typeof raw !== 'object' || raw === null) {
    throw new ApiError('Invalid VersionDetail: expected object');
  }
  const o = raw as Record<string, unknown>;
  requireString(o.id, 'id', 'VersionDetail');
  requireString(o.package_id, 'package_id', 'VersionDetail');
  requireString(o.version, 'version', 'VersionDetail');
  requireString(o.status, 'status', 'VersionDetail');
  return raw as unknown as VersionDetail;
}

// ---------------------------------------------------------------------------
// Client factory — accepts an optional fetch implementation
// ---------------------------------------------------------------------------

export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

export function createApiClient(customFetch?: FetchFn) {
  const fetcher: FetchFn = customFetch || ((url, init) => fetch(url, init));

  async function apiFetch<T>(
    path: string,
    params?: Record<string, string>,
    validator?: (raw: unknown) => T,
  ): Promise<T> {
    const url = new URL(`${API_BASE}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value) url.searchParams.set(key, value);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetcher(url.toString(), {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof Error && (
        err.name === 'AbortError' || err.message.toLowerCase().includes('abort')
      )) {
        throw new ApiError(
          `API request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`,
        );
      }
      throw new ApiError(
        `Cannot reach API at ${API_BASE}. Is the server running?\n  Set TRUSTED_AGENT_HUB_API_URL to configure the address.`,
        undefined,
        err,
      );
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 404) {
      throw new ApiError('Resource not found', 404);
    }

    // 409 Conflict → install manifest unavailable (expected for some packages)
    if (response.status === 409) {
      let detail = '';
      try {
        const body = await response.json();
        detail = body?.error?.message || '';
      } catch { /* ignore */ }
      throw new ApiError(
        detail || 'Install manifest unavailable for this package/client combination',
        409,
      );
    }

    if (!response.ok) {
      let detail = '';
      try {
        const body = await response.json();
        detail = body?.error?.message || body?.detail || '';
      } catch { /* ignore */ }
      throw new ApiError(
        `API error ${response.status}${detail ? ': ' + detail : ''}`,
        response.status,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (err: unknown) {
      throw new ApiError('Failed to parse API response', undefined, err);
    }

    if (validator) {
      return validator(body);
    }
    return body as T;
  }

  // -----------------------------------------------------------------------
  // Public methods
  // -----------------------------------------------------------------------

  return {
    async searchPackages(
      opts: {
        q?: string;
        type?: string;
        client?: string;
        category?: string;
        page?: number;
        page_size?: number;
      } = {},
    ): Promise<PackagePage> {
      const params: Record<string, string> = {};
      if (opts.q) params.q = opts.q;
      if (opts.type) params.type = opts.type;
      if (opts.client) params.client = opts.client;
      if (opts.category) params.category = opts.category;
      if (opts.page !== undefined) params.page = String(opts.page);
      // Clamp page_size to API limit
      const ps = opts.page_size !== undefined
        ? Math.max(1, Math.min(opts.page_size, MAX_PAGE_SIZE))
        : undefined;
      if (ps !== undefined) params.page_size = String(ps);
      return apiFetch<PackagePage>('/api/v0/packages', params, validatePackagePage);
    },

    async getPackage(name: string): Promise<PackageSummary> {
      const raw = await apiFetch<unknown>(
        `/api/v0/packages/${encodeURIComponent(name)}`,
      );
      return validatePackageSummary(raw);
    },

    async getVersionDetail(name: string, version: string): Promise<VersionDetail> {
      const raw = await apiFetch<unknown>(
        `/api/v0/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      );
      return validateVersionDetail(raw);
    },

    async getInstallManifest(
      name: string,
      client: string,
      version?: string,
    ): Promise<unknown> {
      const params: Record<string, string> = { client };
      if (version) params.version = version;
      return apiFetch<unknown>(
        `/api/v0/packages/${encodeURIComponent(name)}/install-manifest`,
        params,
      );
    },

    async recordInstall(request: InstallReportRequest): Promise<InstallRecordResponse> {
      const url = new URL(`${API_BASE}/api/v0/installs`);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const headers: Record<string, string> = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      };
      // P1 fix: include Bearer token when available (POST /api/v0/installs requires auth)
      if (API_TOKEN) {
        headers['Authorization'] = `Bearer ${API_TOKEN}`;
      }

      let response: Response;
      try {
        response = await fetcher(url.toString(), {
          method: 'POST',
          signal: controller.signal,
          headers,
          body: JSON.stringify(request),
        });
      } catch (err: unknown) {
        clearTimeout(timer);
        if (err instanceof Error && (
          err.name === 'AbortError' || err.message.toLowerCase().includes('abort')
        )) {
          throw new ApiError(
            `API request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`,
          );
        }
        throw new ApiError(
          `Cannot reach API at ${API_BASE}. Is the server running?`,
          undefined,
          err,
        );
      } finally {
        clearTimeout(timer);
      }

      if (!response.ok) {
        let detail = '';
        try {
          const body = await response.json();
          detail = body?.error?.message || body?.detail || '';
        } catch { /* ignore */ }
        throw new ApiError(
          `Install record failed (${response.status})${detail ? ': ' + detail : ''}`,
          response.status,
        );
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch (err: unknown) {
        throw new ApiError('Failed to parse install record response', undefined, err);
      }

      return body as InstallRecordResponse;
    },

    async isApiReachable(): Promise<boolean> {
      try {
        await apiFetch<unknown>('/api/v0/health');
        return true;
      } catch {
        return false;
      }
    },

    getApiBase(): string {
      return API_BASE;
    },
  };
}

export const client = createApiClient();

export { API_BASE };
