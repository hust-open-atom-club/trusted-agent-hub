import * as fs from 'fs';
import * as path from 'path';

/**
 * Resolve the mock data directory relative to this source file.
 * From apps/cli/src/mock-loader.ts → ../../../packages/schema/mock/
 */
const MOCK_DIR = path.resolve(__dirname, '..', '..', '..', 'packages', 'schema', 'mock');

// ── Type definitions matching mock/packages.json structure ──────────────

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
  category: string;
  homepage: string | null;
  icon_url: string | null;
  owner: PackageOwner;
  latest_version: string;
  status: string;
  risk_level: string | null;
  grade: string | null;
  install_count: number;
  avg_rating: number | null;
  created_at: string;
  updated_at: string;
}

// ── Version detail (subset of fields we care about) ─────────────────────

export interface VersionDetail {
  id: string;
  package_id: string;
  version: string;
  author: {
    name: string;
    email?: string;
    url?: string;
  };
  source: {
    type: string;
    repository_url: string;
    owner: string;
    repo: string;
    ref_type: string;
    ref: string;
    commit_hash: string;
    verified_owner: boolean;
  };
  compatibility: string[];
  permissions: Record<string, unknown>;
  installation: {
    method: string;
    targets: Array<{ client: string; destination: string }>;
    post_install_message?: string;
    command?: string;
  };
  status: string;
  trust_score: {
    risk_summary: {
      level: string;
      grade?: 'A' | 'B' | 'C' | 'D' | 'E';
      top_risks: string[];
      install_recommendation: string;
    };
  } | null;
}

// ── Loader functions ────────────────────────────────────────────────────

/**
 * Load the full package list from mock packages.json.
 * Exits with an error if the file cannot be found.
 */
export function loadPackages(): PackageSummary[] {
  const filePath = path.join(MOCK_DIR, 'packages.json');
  if (!fs.existsSync(filePath)) {
    console.error(`Error: Mock packages file not found at ${filePath}`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as PackageSummary[];
}

/**
 * Load the version detail for a specific package name + version string.
 * Returns null when no mock version file exists for that combination.
 */
export function loadVersion(packageName: string, version: string): VersionDetail | null {
  const fileName = `${packageName}-${version}.json`;
  const filePath = path.join(MOCK_DIR, 'versions', fileName);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as VersionDetail;
}

/**
 * Load the version detail for a package's latest_version.
 */
export function loadVersionForPackage(pkg: PackageSummary): VersionDetail | null {
  return loadVersion(pkg.name, pkg.latest_version);
}
