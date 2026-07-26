import { cookies } from 'next/headers';
import AdminDashboardClient from './dashboard-client';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface DashboardStats {
  total_packages: number;
  total_versions: number;
  pending_review: number;
  today_submissions: number;
  approved: number;
  published: number;
  rejected: number;
  yanked: number;
}

export default async function AdminDashboardPage() {
  const token = cookies().get('tah_token')?.value;
  let stats: DashboardStats | null = null;

  if (token) {
    try {
      const res = await fetch(`${API_BASE}/api/v0/producer/stats/dashboard`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      });
      if (res.ok) {
        stats = await res.json();
      }
    } catch {
      // fall back to null — client shows "—"
    }
  }

  return <AdminDashboardClient initialStats={stats} />;
}
