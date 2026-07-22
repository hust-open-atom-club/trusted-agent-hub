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

export default function AdminDashboardPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [approvedCount, setApprovedCount] = useState<number | null>(null);
  const [publishedCount, setPublishedCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading || !user || !token) return;

    const fetchCounts = async () => {
      try {
        const [approvedRes, publishedRes] = await Promise.all([
          fetch(`${API_BASE}/api/v0/producer/versions?status=approved`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(`${API_BASE}/api/v0/producer/versions?status=published`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        if (approvedRes.ok) {
          const data = await approvedRes.json();
          setApprovedCount(Array.isArray(data) ? data.length : 0);
        }
        if (publishedRes.ok) {
          const data = await publishedRes.json();
          setPublishedCount(Array.isArray(data) ? data.length : 0);
        }
      } catch {
        // 静默处理统计加载失败
      } finally {
        setLoading(false);
      }
    };

    fetchCounts();
  }, [user, token, authLoading]);

  if (authLoading) return null;

  const cards: StatCard[] = [
    {
      title: '待发布',
      count: approvedCount,
      description: '已审核通过，等待发布上线',
      path: '/admin/publish',
    },
    {
      title: '已发布',
      count: publishedCount,
      description: '已上线运行的版本',
      path: '/admin/yank',
    },
    {
      title: '审计日志',
      count: null,
      description: '查看所有操作记录',
      path: '/admin/audit-logs',
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
