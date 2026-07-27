import type { Package } from '@/data/packages';
import HomeClient from './home-client';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface PackageListResponse {
  items: Package[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

async function fetchPackagesServer(): Promise<{ items: Package[]; total: number }> {
  const res = await fetch(`${API_BASE}/api/v0/packages?page_size=100`, { cache: 'no-store' });
  if (!res.ok) {
    return { items: [], total: 0 };
  }
  const data: PackageListResponse = await res.json();
  return { items: data.items, total: data.total };
}

export default async function HomePage() {
  const { items, total } = await fetchPackagesServer();

  return <HomeClient initialPackages={items} totalPackages={total} />;
}
