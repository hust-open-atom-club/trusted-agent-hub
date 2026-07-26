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

async function fetchPackagesServer(): Promise<Package[]> {
  const res = await fetch(`${API_BASE}/api/v0/packages`, { cache: 'no-store' });
  if (!res.ok) {
    return [];
  }
  const data: PackageListResponse = await res.json();
  return data.items;
}

export default async function HomePage() {
  const packages = await fetchPackagesServer();

  return <HomeClient initialPackages={packages} />;
}
