'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';

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
  total_users: number;
  today_audit_actions: number;
}

interface StatCard {
  title: string;
  count: number | null;
  description: string;
  path: string;
}

export default function AdminDashboardClient() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      return;
    }

    fetch(`${API_BASE}/api/v0/producer/stats/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.ok ? res.json() : null)
      .then((data) => { if (data) setStats(data); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [user, token, authLoading]);

  const cards: StatCard[] = [
    {
      title: t('admin.dashboard.total_packages'),
      count: stats?.total_packages ?? null,
      description: t('admin.dashboard.total_packages_desc'),
      path: '/admin/packages',
    },
    {
      title: t('admin.dashboard.pending_review'),
      count: stats?.pending_review ?? null,
      description: t('admin.dashboard.pending_review_desc'),
      path: '/review',
    },
    {
      title: t('admin.dashboard.today_submissions'),
      count: stats?.today_submissions ?? null,
      description: t('admin.dashboard.today_submissions_desc'),
      path: '/admin/submissions/today',
    },
    {
      title: t('admin.dashboard.approved'),
      count: stats?.approved ?? null,
      description: t('admin.dashboard.approved_desc'),
      path: '/admin/publish',
    },
    {
      title: t('admin.dashboard.published'),
      count: stats?.published ?? null,
      description: t('admin.dashboard.published_desc'),
      path: '/admin/yank',
    },
    {
      title: t('admin.dashboard.rejected'),
      count: stats?.rejected ?? null,
      description: t('admin.dashboard.rejected_desc'),
      path: '/admin/rejected',
    },
    {
      title: t('admin.dashboard.users'),
      count: stats?.total_users ?? null,
      description: t('admin.dashboard.users_desc'),
      path: '/admin/users',
    },
    {
      title: t('admin.dashboard.audit_logs'),
      count: stats?.today_audit_actions ?? null,
      description: t('admin.dashboard.audit_logs_desc'),
      path: '/admin/audit-logs',
    },
  ];

  return (
    <div className="admin-page">
      <div className="admin-dashboard">
        <div className="admin-dashboard-header">
          <h1>{t('admin.dashboard.title')}</h1>
          <p>{t('admin.dashboard.subtitle')}</p>
        </div>

        <div className="admin-stat-grid">
          {cards.map((card) => (
            <button
              key={card.path}
              className="admin-stat-card"
              onClick={() => router.push(card.path)}
            >
              <span className="admin-stat-count">
                {loading ? '—' : card.count !== null ? card.count : '—'}
              </span>
              <span className="admin-stat-title">{card.title}</span>
              <span className="admin-stat-desc">{card.description}</span>
              <span className="admin-stat-arrow">→</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
