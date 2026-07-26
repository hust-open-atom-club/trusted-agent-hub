'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface RejectedItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
  grade: string | null;
  findings_count: number;
}

const PACKAGE_TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export default function AdminRejectedPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<RejectedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<RejectedItem[]>(`${API_BASE}/api/v0/producer/versions?status=rejected&limit=200`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data) => setItems(data))
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError('请先登录管理员账号');
      return;
    }
    fetchItems();
  }, [user, token, authLoading]);

  if (authLoading || loading) {
    return (
      <div className="admin-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-page">
      <nav className="admin-nav">
        <button onClick={() => router.push('/admin')} className="link-btn">
          ← 返回管理面板
        </button>
      </nav>

      <div className="admin-section-header">
        <h1>已驳回版本</h1>
        <p>审核未通过的版本 · 共 {items.length} 个</p>
      </div>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && items.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x2705;</div>
          <h3>暂无被驳回版本</h3>
          <p>所有提交的版本都已通过审核</p>
        </div>
      )}

      {!error && items.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>评分</th>
                <th>包名称</th>
                <th>版本</th>
                <th>类型</th>
                <th>提交时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.version_id}>
                  <td data-label="评分">
                    <span className={`grade-badge grade-${item.grade?.toLowerCase() || 'unknown'}`}>
                      {item.grade || '—'}
                    </span>
                  </td>
                  <td data-label="包名称" className="admin-pkg-name">
                    {item.package_name}
                  </td>
                  <td data-label="版本">
                    <code>v{item.version}</code>
                  </td>
                  <td data-label="类型">
                    {item.package_type && (
                      <span className={`type-badge ${item.package_type}`}>
                        {PACKAGE_TYPE_LABELS[item.package_type] || item.package_type}
                      </span>
                    )}
                  </td>
                  <td data-label="提交时间">{formatDate(item.submitted_at)}</td>
                  <td data-label="操作">
                    <button
                      className="btn btn-sm btn-secondary"
                      onClick={() => router.push(`/review/${item.version_id}?returnTo=/admin/rejected`)}
                    >
                      查看审核
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
