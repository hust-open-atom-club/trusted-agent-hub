'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface PackageItem {
  package_id: string;
  package_name: string;
  package_type: string | null;
  description: string | null;
  status: string;
  latest_version: string;
  created_at: string | null;
  updated_at: string | null;
}

const PACKAGE_TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

const STATUS_LABELS: Record<string, string> = {
  draft: '草稿',
  published: '已发布',
  yanked: '已下架',
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

export default function AdminPackagesPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<PackageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<PackageItem[]>(`${API_BASE}/api/v0/producer/packages?limit=200`, {
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
        <h1>全部能力包</h1>
        <p>已入库的能力包 · 共 {items.length} 个</p>
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
          <div className="empty-state-icon">&#x1F4E6;</div>
          <h3>暂无数据</h3>
          <p>还没有提交任何能力包</p>
        </div>
      )}

      {!error && items.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>包名称</th>
                <th>类型</th>
                <th>状态</th>
                <th>最新版本</th>
                <th>描述</th>
                <th>创建时间</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.package_id}>
                  <td data-label="包名称" className="admin-pkg-name">
                    {item.package_name}
                  </td>
                  <td data-label="类型">
                    {item.package_type && (
                      <span className={`type-badge ${item.package_type}`}>
                        {PACKAGE_TYPE_LABELS[item.package_type] || item.package_type}
                      </span>
                    )}
                  </td>
                  <td data-label="状态">
                    <span className={`status-badge ${item.status}`}>
                      {STATUS_LABELS[item.status] || item.status}
                    </span>
                  </td>
                  <td data-label="最新版本">
                    <code>v{item.latest_version}</code>
                  </td>
                  <td data-label="描述" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.description || '—'}
                  </td>
                  <td data-label="创建时间">{formatDate(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
