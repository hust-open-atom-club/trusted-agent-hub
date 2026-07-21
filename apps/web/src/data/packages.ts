export interface Owner {
  id: string;
  username: string;
  display_name: string;
  role: string;
}

export interface Package {
  id: string;
  name: string;
  description: string;
  type: 'skill' | 'mcp_server' | 'plugin' | 'subagent' | 'command' | 'prompt';
  license: string;
  keywords: string[];
  category: string;
  homepage: string | null;
  icon_url: string | null;
  owner: Owner;
  latest_version: string;
  status: string;
  trust_score: number | null;
  risk_level: string | null;
  grade: string | null;
  install_count: number;
  avg_rating: number | null;
  created_at: string;
  updated_at: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface PackageListResponse {
  items: Package[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export async function fetchPackages(): Promise<Package[]> {
  const res = await fetch(`${API_BASE}/api/v0/packages`);
  if (!res.ok) {
    throw new Error(`Failed to fetch packages: ${res.status}`);
  }
  const data: PackageListResponse = await res.json();
  return data.items;
}

export async function fetchPackage(name: string): Promise<Package | null> {
  const res = await fetch(`${API_BASE}/api/v0/packages/${encodeURIComponent(name)}`);
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Failed to fetch package ${name}: ${res.status}`);
  }
  return res.json();
}
