'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface StatCard {
  title: string;
  count: number | null;
  description: string;
  path: string;
}

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

export default function AdminDashboardPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading || !user || !token) return;

    fetch(`${API_BASE}/api/v0/producer/stats/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => setStats(data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [user, token, authLoading]);

  if (authLoading) return null;

  const cards: StatCard[] = [
    {
      title: '总包数',
      count: stats?.total_packages ?? null,
      description: '已入库的能力包总数',
      path: '/admin',
    },
    {
      title: '待审核',
      count: stats?.pending_review ?? null,
      description: '等待审核员处理的版本',
      path: '/review',
    },
    {
      title: '今日提交',
      count: stats?.today_submissions ?? null,
      description: '今天新提交的版本',
      path: '/admin',
    },
    {
      title: '审核通过',
      count: stats?.approved ?? null,
      description: '已审核通过，等待发布上线',
      path: '/admin/publish',
    },
    {
      title: '已发布',
      count: stats?.published ?? null,
      description: '已上线运行的版本',
      path: '/admin/yank',
    },
    {
      title: '已驳回',
      count: stats?.rejected ?? null,
      description: '审核未通过的版本',
      path: '/admin',
    },
  ];

  return (
    <div className="admin-page">
      <div className="admin-dashboard">
        <div className="admin-dashboard-header">
          <h1>管理员面板</h1>
          <p>管理能力包的发布、下架与审计</p>
        </div>

        <div className="admin-stat-grid">
          {cards.map((card) => (
            <button
              key={card.path}
              className="admin-stat-card"
              onClick={() => router.push(card.path)}
            >
              <span className="admin-stat-count">
                {loading
                  ? '—'
                  : card.count !== null
                    ? card.count
                    : '查看'}
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
