'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch, clearFetchCache } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface YankItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
  published_at: string | null;
  grade: string | null;
  grade_label: string | null;
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

export default function AdminYankPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<YankItem[]>([]);
  const [yankedItems, setYankedItems] = useState<YankItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showModal, setShowModal] = useState(false);
  const [selectedItem, setSelectedItem] = useState<YankItem | null>(null);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    Promise.all([
      apiFetch<YankItem[]>(`${API_BASE}/api/v0/producer/versions?status=published`, {
        headers: { Authorization: `Bearer ${token}` },
      }),
      apiFetch<YankItem[]>(`${API_BASE}/api/v0/producer/versions?status=yanked`, {
        headers: { Authorization: `Bearer ${token}` },
      }),
    ])
      .then(([published, yanked]) => {
        setItems(published);
        setYankedItems(yanked);
      })
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

  const handleYank = async () => {
    if (!selectedItem || !token) return;

    if (!reason.trim()) {
      setSubmitError('下架原因不能为空');
      return;
    }

    setSubmitError(null);
    setSubmitting(true);

    try {
      const res = await fetch(
        `${API_BASE}/api/v0/producer/versions/${selectedItem.version_id}/yank?reason=${encodeURIComponent(reason.trim())}`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: '下架失败' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      setSuccessMsg(`${selectedItem.package_name} v${selectedItem.version} 已下架`);
      setShowModal(false);
      setSelectedItem(null);
      setReason('');
      clearFetchCache('versions');
      fetchItems();

      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : '下架失败');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUnyank = async (item: YankItem) => {
    if (!token) return;
    try {
      const res = await fetch(
        `${API_BASE}/api/v0/producer/versions/${item.version_id}/unyank`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: '撤销失败' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setSuccessMsg(`${item.package_name} v${item.version} 已重新发布`);
      clearFetchCache('versions');
      fetchItems();
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : '撤销失败');
    }
  };

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
        <h1>下架管理</h1>
        <p>已发布版本 · 共 {items.length} 个</p>
        {successMsg && <span className="admin-success-msg">{successMsg}</span>}
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
          <h3>暂无已发布版本</h3>
          <p>还没有版本被发布上线</p>
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
                <th>发布时间</th>
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
                  <td data-label="发布时间">{formatDate(item.published_at)}</td>
                  <td data-label="操作">
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => {
                        setSelectedItem(item);
                        setReason('');
                        setSubmitError(null);
                        setShowModal(true);
                      }}
                    >
                      下架
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* 已下架版本 */}
      <div className="admin-section-header" style={{ marginTop: '3rem' }}>
        <h2>已下架版本</h2>
        <p>已下架版本 · 共 {yankedItems.length} 个</p>
      </div>

      {!error && yankedItems.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>包名称</th>
                <th>版本</th>
                <th>类型</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {yankedItems.map((item) => (
                <tr key={item.version_id}>
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
                  <td data-label="操作">
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => handleUnyank(item)}
                    >
                      重新发布
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && selectedItem && (
        <div className="modal-overlay" onClick={() => !submitting && setShowModal(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>确认下架</h3>
              <button
                className="modal-close"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <p>
                确认下架 <strong>{selectedItem.package_name}</strong> v{selectedItem.version}？
              </p>
              <p className="modal-hint">下架后该版本将不再对用户可见。</p>

              <div className="form-field modal-form-field">
                <label className="modal-comment-label">
                  下架原因 <span className="required-star">*</span>
                </label>
                <textarea
                  className="modal-comment-textarea"
                  rows={3}
                  placeholder="请填写下架原因..."
                  value={reason}
                  onChange={(e) => {
                    setReason(e.target.value);
                    setSubmitError(null);
                  }}
                  disabled={submitting}
                />
              </div>
            </div>

            {submitError && <div className="modal-error">{submitError}</div>}

            <div className="modal-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                取消
              </button>
              <button
                className="btn btn-danger"
                onClick={handleYank}
                disabled={submitting || !reason.trim()}
              >
                {submitting ? '下架中...' : '确认下架'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
