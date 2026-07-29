'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch, clearFetchCache } from '@/lib/api-fetch';
import GradeOverrideModal from '@/components/GradeOverrideModal';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface PublishItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
  auto_grade: string | null;
  manual_grade: string | null;
  manual_grade_by: string | null;
  manual_grade_by_name: string | null;
  manual_grade_reason: string | null;
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

function levelLabel(grade: string): string {
  const m: Record<string, string> = {
    A: '高度可信', B: '可信', C: '需注意', D: '有风险', E: '高风险',
  };
  return m[grade] ?? grade;
}

export default function AdminPublishPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<PublishItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showModal, setShowModal] = useState(false);
  const [selectedItem, setSelectedItem] = useState<PublishItem | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [showGradeModal, setShowGradeModal] = useState(false);
  const [gradeTarget, setGradeTarget] = useState<PublishItem | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<PublishItem[]>(`${API_BASE}/api/v0/producer/versions?status=approved`, {
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
      setConfirmed(false);
      clearFetchCache('versions');
      fetchItems();

      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : '发布失败');
    } finally {
      setSubmitting(false);
    }
  };

  const openPublishModal = (item: PublishItem) => {
    setSelectedItem(item);
    setConfirmed(false);
    setSubmitError(null);
    setShowModal(true);
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
                <th>自动评分</th>
                <th>手动评级</th>
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
                  <td data-label="自动评分">
                    <span className={`grade-badge grade-${item.auto_grade?.toLowerCase() || 'unknown'}`}>
                      {item.auto_grade || '—'}
                    </span>
                  </td>
                  <td data-label="手动评级">
                    {item.manual_grade ? (
                      <span
                        style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-ink)' }}
                        title={`由 ${item.manual_grade_by_name || item.manual_grade_by || '未知'} 修改${item.manual_grade_reason ? '：' + item.manual_grade_reason : ''}`}
                      >
                        {item.manual_grade} *
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>—</span>
                    )}
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
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <button
                        className="link-btn"
                        style={{ fontSize: '0.78rem' }}
                        onClick={() => router.push(`/review/${item.version_id}?returnTo=/admin/publish`)}
                      >
                        详情
                      </button>
                      {(user?.role === 'admin' || user?.role === 'reviewer') && (
                        <button
                          className="link-btn"
                          style={{ fontSize: '0.78rem' }}
                          onClick={() => {
                            setGradeTarget(item);
                            setShowGradeModal(true);
                          }}
                        >
                          修改评级
                        </button>
                      )}
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => openPublishModal(item)}
                      >
                        发布
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && selectedItem && (
        <div className="modal-overlay" onClick={() => !submitting && setShowModal(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '500px' }}>
            <div className="modal-header">
              <h3>确认发布</h3>
              <button className="modal-close" onClick={() => setShowModal(false)} disabled={submitting}>
                ✕
              </button>
            </div>

            <div style={{ padding: '1.25rem' }}>
              <p style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-ink)', marginBottom: '1rem' }}>
                确认将 {selectedItem.package_name} v{selectedItem.version} 发布上线？
              </p>

              <div style={{
                padding: '1rem',
                marginBottom: '1rem',
                background: 'var(--color-paper-2)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-rule)',
              }}>
                <div style={{
                  display: 'grid', gridTemplateColumns: 'auto 1fr 1fr',
                  gap: '0.4rem 0.75rem', fontSize: '0.82rem',
                }}>
                  <span style={{ color: 'var(--color-muted)' }}>自动评分</span>
                  <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>
                    {selectedItem.auto_grade ? `${selectedItem.auto_grade} (${levelLabel(selectedItem.auto_grade)})` : '—'}
                  </span>
                  <span></span>

                  <span style={{ color: 'var(--color-muted)' }}>手动评级</span>
                  <span style={{
                    fontWeight: 600,
                    color: selectedItem.manual_grade ? 'var(--color-accent)' : 'var(--color-muted)',
                  }}>
                    {selectedItem.manual_grade ? `${selectedItem.manual_grade} (${levelLabel(selectedItem.manual_grade)}) *` : '— (使用自动)'}
                  </span>
                  <span></span>

                  <span style={{ color: 'var(--color-muted)', borderTop: '1px solid var(--color-rule)', paddingTop: '0.3rem' }}>
                    生效评级
                  </span>
                  <span style={{
                    fontWeight: 700, fontSize: '0.92rem',
                    color: 'var(--color-ink)',
                    borderTop: '1px solid var(--color-rule)', paddingTop: '0.3rem',
                  }}>
                    {selectedItem.grade ? `${selectedItem.grade} (${levelLabel(selectedItem.grade)})` : '—'}
                  </span>
                  <span></span>
                </div>

                {selectedItem.manual_grade_reason && (
                  <div style={{
                    marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--color-muted)',
                    borderTop: '1px solid var(--color-rule)', paddingTop: '0.5rem',
                  }}>
                    修正理由: {selectedItem.manual_grade_reason}
                    {selectedItem.manual_grade_by_name && <> · 由 {selectedItem.manual_grade_by_name} 修改</>}
                  </div>
                )}

                {selectedItem.auto_grade && selectedItem.manual_grade &&
                  Math.abs(['A','B','C','D','E'].indexOf(selectedItem.auto_grade) - ['A','B','C','D','E'].indexOf(selectedItem.manual_grade)) >= 3 && (
                  <div style={{
                    marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--color-danger)',
                    fontWeight: 600,
                  }}>
                    自动评分与手动评级存在显著差异，请确认此操作。
                  </div>
                )}
              </div>

              <label style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem',
                cursor: 'pointer', fontSize: '0.82rem', color: 'var(--color-ink)',
              }}>
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  disabled={submitting}
                  style={{ width: '1rem', height: '1rem', cursor: 'pointer', accentColor: 'var(--color-accent)' }}
                />
                我确认发布此包，以生效评级 {selectedItem.grade || '—'} 为准。
              </label>

              <p style={{ fontSize: '0.8rem', color: 'var(--color-muted)', marginBottom: '1rem' }}>
                发布后将立即对用户可见，消费侧可查询到该版本。
              </p>

              {submitError && <div className="modal-error">{submitError}</div>}

              <div className="modal-actions">
                <button className="btn btn-secondary" onClick={() => setShowModal(false)} disabled={submitting}>
                  取消
                </button>
                <button className="btn btn-primary" onClick={handlePublish} disabled={submitting || !confirmed}>
                  {submitting ? '发布中...' : '确认发布'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showGradeModal && gradeTarget && token && (
        <GradeOverrideModal
          versionId={gradeTarget.version_id}
          autoGrade={gradeTarget.auto_grade}
          currentManualGrade={gradeTarget.manual_grade}
          currentReason={gradeTarget.manual_grade_reason ?? null}
          token={token}
          onClose={() => { setShowGradeModal(false); setGradeTarget(null); }}
          onComplete={() => {
            setShowGradeModal(false);
            setGradeTarget(null);
            clearFetchCache('versions');
            fetchItems();
          }}
        />
      )}
    </div>
  );
}
