'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface PublishItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
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

export default function AdminPublishPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<PublishItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showModal, setShowModal] = useState(false);
  const [selectedItem, setSelectedItem] = useState<PublishItem | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    fetch(`${API_BASE}/api/v0/producer/versions?status=approved`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) return res.json().then((e) => { throw new Error(e.detail || `HTTP ${res.status}`); });
        return res.json();
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

  const handlePublish = async () => {
    if (!selectedItem || !token) return;
    setSubmitError(null);
    setSubmitting(true);

    try {
      const res = await fetch(
        `${API_BASE}/api/v0/producer/versions/${selectedItem.version_id}/publish`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: '发布失败' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      setSuccessMsg(`${selectedItem.package_name} v${selectedItem.version} 发布成功`);
      setShowModal(false);
      setSelectedItem(null);
      fetchItems();

      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : '发布失败');
    } finally {
      setSubmitting(false);
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
        <h1>发布管理</h1>
        <p>待发布版本 · 共 {items.length} 个</p>
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
          <h3>暂无待发布版本</h3>
          <p>所有审核通过的版本都已发布</p>
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
                      className="btn btn-primary btn-sm"
                      onClick={() => {
                        setSelectedItem(item);
                        setSubmitError(null);
                        setShowModal(true);
                      }}
                    >
                      发布上线
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
              <h3>确认发布</h3>
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
                确认将 <strong>{selectedItem.package_name}</strong> v{selectedItem.version} 发布上线？
              </p>
              <p className="modal-hint">发布后将立即对用户可见，消费侧可查询到该版本。</p>
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
                className="btn btn-primary"
                onClick={handlePublish}
                disabled={submitting}
              >
                {submitting ? '发布中...' : '确认发布'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
