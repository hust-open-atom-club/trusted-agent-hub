'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface AuditLogEntry {
  id: string;
  action: string;
  target_type: string;
  target_id: string;
  operator_id: string;
  operator_name: string | null;
  timestamp: string;
  detail: Record<string, unknown> | null;
}

const ACTION_LABELS: Record<string, string> = {
  publish: '发布',
  yank: '下架',
  approved: '审核通过',
  rejected: '审核驳回',
  changes_requested: '要求修改',
  submit: '提交审核',
  scan_complete: '扫描完成',
  request_changes: '要求修改',
};

const ACTION_OPTIONS = [
  { value: '', label: '全部操作' },
  { value: 'publish', label: '发布' },
  { value: 'yank', label: '下架' },
  { value: 'approved', label: '审核通过' },
  { value: 'rejected', label: '审核驳回' },
  { value: 'changes_requested', label: '要求修改' },
  { value: 'submit', label: '提交审核' },
  { value: 'scan_complete', label: '扫描完成' },
];

const PAGE_SIZES = [10, 30, 50, 100];

function formatDate(iso: string | null | undefined): string {
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

function getActionLabel(action: string): string {
  return ACTION_LABELS[action] || action;
}

export default function AdminAuditLogsPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // 筛选
  const [action, setAction] = useState('');
  const [targetId, setTargetId] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // 分页
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(30);
  const [totalCount, setTotalCount] = useState(0);

  const fetchLogs = useCallback(() => {
    if (!token) return;
    setLoading(true);
    setError(null);

    const params = new URLSearchParams();
    if (action) params.set('action', action);
    if (targetId.trim()) params.set('target_id', targetId.trim());
    if (startDate) params.set('start_date', new Date(startDate).toISOString());
    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      params.set('end_date', end.toISOString());
    }
    params.set('limit', String(pageSize));
    params.set('offset', String(page * pageSize));

    fetch(`${API_BASE}/api/v0/producer/audit-logs?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) return res.json().then((e) => { throw new Error(e.detail || `HTTP ${res.status}`); });
        return res.json();
      })
      .then((data: AuditLogEntry[]) => {
        setLogs(data);
        setTotalCount(data.length);
      })
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  }, [token, action, targetId, startDate, endDate, page, pageSize]);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError('请先登录管理员账号');
      return;
    }
    fetchLogs();
  }, [user, token, authLoading, fetchLogs]);

  const handleSearch = () => {
    setPage(0);
    // fetchLogs will be triggered via dependency change
    // We force a refetch by incrementing a key or directly calling
    fetchLogs();
  };

  const hasMore = logs.length === pageSize;

  if (authLoading) return null;

  return (
    <div className="admin-page">
      <nav className="admin-nav">
        <button onClick={() => router.push('/admin')} className="link-btn">
          ← 返回管理面板
        </button>
      </nav>

      <div className="admin-section-header">
        <h1>审计日志</h1>
        <p>查看所有操作记录</p>
      </div>

      {/* 筛选栏 */}
      <div className="admin-filter-row">
        <div className="admin-filter-item">
          <select
            className="admin-select"
            value={action}
            onChange={(e) => { setAction(e.target.value); setPage(0); }}
          >
            {ACTION_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div className="admin-filter-item">
          <input
            className="admin-filter-input"
            type="text"
            placeholder="目标 ID..."
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          />
        </div>

        <div className="admin-filter-item">
          <label className="admin-filter-label">开始</label>
          <input
            className="admin-filter-date"
            type="date"
            value={startDate}
            onChange={(e) => { setStartDate(e.target.value); setPage(0); }}
          />
        </div>

        <div className="admin-filter-item">
          <label className="admin-filter-label">结束</label>
          <input
            className="admin-filter-date"
            type="date"
            value={endDate}
            onChange={(e) => { setEndDate(e.target.value); setPage(0); }}
          />
        </div>

        <div className="admin-filter-item">
          <button className="btn btn-secondary btn-sm" onClick={handleSearch}>
            查询
          </button>
        </div>
      </div>

      {/* 内容区 */}
      {loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      )}

      {error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && logs.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4CB;</div>
          <h3>暂无审计日志</h3>
          <p>当前筛选条件下没有匹配的操作记录</p>
        </div>
      )}

      {!loading && !error && logs.length > 0 && (
        <>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作</th>
                  <th>目标类型</th>
                  <th>目标 ID</th>
                  <th>操作人</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td data-label="时间">{formatDate(log.timestamp)}</td>
                    <td data-label="操作">
                      <span className={`status-badge ${log.action}`}>
                        {getActionLabel(log.action)}
                      </span>
                    </td>
                    <td data-label="目标类型" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                      {log.target_type}
                    </td>
                    <td data-label="目标 ID" className="admin-mono-cell">
                      {log.target_id}
                    </td>
                    <td data-label="操作人">
                      {log.operator_name || log.operator_id}
                    </td>
                    <td data-label="详情" className="admin-detail-cell">
                      {log.detail
                        ? JSON.stringify(log.detail).slice(0, 60) +
                          (JSON.stringify(log.detail).length > 60 ? '...' : '')
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* 分页器 */}
          <div className="pagination">
            <div className="pagination-info">
              共 {totalCount + page * pageSize}+ 条
            </div>

            <div className="pagination-controls">
              <span className="pagination-select-label">每页</span>
              <select
                className="admin-select pagination-select"
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
              <span className="pagination-select-label">条</span>

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                上一页
              </button>

              <span className="pagination-page-num">第 {page + 1} 页</span>

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={!hasMore}
              >
                下一页
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
