'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ReviewRecord {
  id: string;
  version_id: string;
  conclusion: string;
  comment: string | null;
  created_at: string;
  version: string;
  version_status: string;
  package_name: string;
}

const CONCLUSION_LABELS: Record<string, string> = {
  approved: '通过',
  rejected: '驳回',
  changes_requested: '需修改',
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

export default function ReviewHistoryPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [records, setRecords] = useState<ReviewRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 20;

  const fetchRecords = () => {
    if (!token || !user) return;
    setLoading(true);
    setError(null);
    const offset = page * pageSize;
    apiFetch<ReviewRecord[]>(
      `${API_BASE}/api/v0/producer/reviews?reviewer_id=${encodeURIComponent(user.id)}&limit=${pageSize}&offset=${offset}`,
      {
        headers: { Authorization: `Bearer ${token}` },
      },
    )
      .then((data) => setRecords(data))
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError('请先登录审核员账号');
      return;
    }
    fetchRecords();
  }, [user, token, authLoading, page]);

  if (authLoading || loading) {
    return (
      <div className="review-detail-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      </div>
    );
  }

  return (
    <div className="review-detail-page">
      <nav className="review-detail-nav">
        <button onClick={() => router.push('/review')} className="link-btn">
          ← 返回待审核列表
        </button>
        <span className="review-detail-nav-user">{user?.username}</span>
      </nav>

      <div className="admin-section-header">
        <h1>审核历史</h1>
        <p>共 {records.length}+ 条审核记录</p>
      </div>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && records.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4CB;</div>
          <h3>暂无审核记录</h3>
          <p>你还没有审核过任何版本</p>
        </div>
      )}

      {!error && records.length > 0 && (
        <>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>结论</th>
                  <th>包名称</th>
                  <th>版本</th>
                  <th>当前状态</th>
                  <th>意见</th>
                  <th>审核时间</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td data-label="结论">
                      <span className={`status-badge ${r.conclusion}`}>
                        {CONCLUSION_LABELS[r.conclusion] || r.conclusion}
                      </span>
                    </td>
                    <td data-label="包名称" className="admin-pkg-name">
                      {r.package_name}
                    </td>
                    <td data-label="版本">
                      <code>v{r.version}</code>
                    </td>
                    <td data-label="当前状态">
                      <span className={`status-badge ${r.version_status}`}>
                        {r.version_status}
                      </span>
                    </td>
                    <td data-label="意见" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {r.comment || '—'}
                    </td>
                    <td data-label="审核时间">{formatDate(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem', marginTop: '1.5rem' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              上一页
            </button>
            <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>第 {page + 1} 页</span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={records.length < pageSize}
            >
              下一页
            </button>
          </div>
        </>
      )}
    </div>
  );
}
