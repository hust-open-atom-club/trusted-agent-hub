'use client';

import { useRouter } from 'next/navigation';

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

interface StatCard {
  title: string;
  count: number | null;
  description: string;
  path: string;
}

interface AdminDashboardClientProps {
  initialStats: DashboardStats | null;
}

export default function AdminDashboardClient({ initialStats }: AdminDashboardClientProps) {
  const router = useRouter();

  const cards: StatCard[] = [
    {
      title: '总包数',
      count: initialStats?.total_packages ?? null,
      description: '已入库的能力包总数',
      path: '/admin',
    },
    {
      title: '待审核',
      count: initialStats?.pending_review ?? null,
      description: '等待审核员处理的版本',
      path: '/review',
    },
    {
      title: '今日提交',
      count: initialStats?.today_submissions ?? null,
      description: '今天新提交的版本',
      path: '/admin',
    },
    {
      title: '审核通过',
      count: initialStats?.approved ?? null,
      description: '已审核通过，等待发布上线',
      path: '/admin/publish',
    },
    {
      title: '已发布',
      count: initialStats?.published ?? null,
      description: '已上线运行的版本',
      path: '/admin/yank',
    },
    {
      title: '已驳回',
      count: initialStats?.rejected ?? null,
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
                {card.count !== null ? card.count : '—'}
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
