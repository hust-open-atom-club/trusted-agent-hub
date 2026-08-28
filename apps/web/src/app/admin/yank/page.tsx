'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch, clearFetchCache } from '@/lib/api-fetch';

import { API_BASE } from '@/lib/runtime-config';

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
  yank_reason?: string | null;
}

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
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<YankItem[]>([]);
  const [yankedItems, setYankedItems] = useState<YankItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showModal, setShowModal] = useState(false);
  const [selectedItem, setSelectedItem] = useState<YankItem | null>(null);
  const [actionType, setActionType] = useState<'yank' | 're-review'>('yank');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

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
      .catch((err) => setError(err instanceof Error ? err.message : t('admin.dashboard.load_failed')))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError(t('admin.auth_required'));
      return;
    }
    fetchItems();
  }, [user, token, authLoading]);

  const handleYank = async () => {
    if (!selectedItem || !token) return;

    if (actionType === 'yank' && !reason.trim()) {
      setSubmitError(t('admin.yank.reason_required'));
      return;
    }

    setSubmitError(null);
    setSubmitting(true);

    try {
      if (actionType === 're-review') {
        const res = await fetch(
          `${API_BASE}/api/v0/producer/versions/${selectedItem.version_id}/re-review`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
          },
        );
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: t('admin.yank.error') }));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
        setSuccessMsg(t('admin.yank.re_review_success', { name: selectedItem.package_name, version: selectedItem.version }));
      } else {
        const res = await fetch(
          `${API_BASE}/api/v0/producer/versions/${selectedItem.version_id}/yank?reason=${encodeURIComponent(reason.trim())}`,
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
          },
        );
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: t('admin.yank.error') }));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
        setSuccessMsg(t('admin.yank.yank_success', { name: selectedItem.package_name, version: selectedItem.version }));
      }

      setShowModal(false);
      setSelectedItem(null);
      setReason('');
      setActionType('yank');
      clearFetchCache('versions');
      fetchItems();

      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : t('admin.yank.error'));
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
        const err = await res.json().catch(() => ({ detail: t('admin.yank.error') }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setSuccessMsg(t('admin.yank.unyank_success', { name: item.package_name, version: item.version }));
      clearFetchCache('versions');
      fetchItems();
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : t('admin.yank.error'));
    }
  };

  const handleDelete = async (item: YankItem) => {
    if (!token) return;
    if (!confirm(t('admin.yank.delete_confirm', { name: item.package_name, version: item.version }))) return;
    setDeletingId(item.version_id);
    try {
      const res = await fetch(
        `${API_BASE}/api/v0/producer/versions/${item.version_id}`,
        { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: t('admin.yank.delete_error') }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setSuccessMsg(t('admin.yank.delete_success', { name: item.package_name, version: item.version }));
      clearFetchCache('versions');
      fetchItems();
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : t('admin.yank.delete_error'));
    } finally {
      setDeletingId(null);
    }
  };

  if (authLoading || loading) {
    return (
      <div className="admin-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>{t('common.loading')}</h3>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-page">
      <nav className="admin-nav">
        <button onClick={() => router.push('/admin')} className="link-btn">
          {t('admin.back_to_dashboard')}
        </button>
      </nav>

      <div className="admin-section-header">
        <h1>{t('admin.yank.title')}</h1>
        <p>{t('admin.yank.published_subtitle')} · {items.length}</p>
        {successMsg && <span className="admin-success-msg">{successMsg}</span>}
      </div>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && items.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x2705;</div>
          <h3>{t('admin.yank.no_published')}</h3>
          <p>{t('admin.yank.no_published_hint')}</p>
        </div>
      )}

      {!error && items.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t('admin.table.grade')}</th>
                <th>{t('admin.table.package_name')}</th>
                <th>{t('admin.table.version')}</th>
                <th>{t('admin.table.type')}</th>
                <th>{t('admin.table.published_at')}</th>
                <th>{t('admin.table.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.version_id}>
                  <td data-label={t('admin.table.grade')}>
                    <span className={`grade-badge grade-${item.grade?.toLowerCase() || 'unknown'}`}>
                      {item.grade || '—'}
                    </span>
                  </td>
                  <td data-label={t('admin.table.package_name')} className="admin-pkg-name">
                    {item.package_name}
                  </td>
                  <td data-label={t('admin.table.version')}>
                    <code>v{item.version}</code>
                  </td>
                  <td data-label={t('admin.table.type')}>
                    {item.package_type && (
                      <span className={`type-badge ${item.package_type}`}>
                        {t(`search.${item.package_type}`, '') || item.package_type}
                      </span>
                    )}
                  </td>
                  <td data-label={t('admin.table.published_at')}>{formatDate(item.published_at)}</td>
                  <td data-label={t('admin.table.actions')}>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => {
                        setSelectedItem(item);
                        setActionType('yank');
                        setReason('');
                        setSubmitError(null);
                        setShowModal(true);
                      }}
                    >
                      {t('admin.yank.yank_btn')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="admin-section-header" style={{ marginTop: '3rem' }}>
        <h2>{t('admin.yank.yanked_title')}</h2>
        <p>{t('admin.yank.yanked_subtitle')} · {yankedItems.length}</p>
      </div>

      {!error && yankedItems.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t('admin.table.package_name')}</th>
                <th>{t('admin.table.version')}</th>
                <th>{t('admin.table.type')}</th>
                <th>{t('admin.yank.yank_reason')}</th>
                <th>{t('admin.table.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {yankedItems.map((item) => (
                <tr key={item.version_id}>
                  <td data-label={t('admin.table.package_name')} className="admin-pkg-name">
                    {item.package_name}
                  </td>
                  <td data-label={t('admin.table.version')}>
                    <code>v{item.version}</code>
                  </td>
                  <td data-label={t('admin.table.type')}>
                    {item.package_type && (
                      <span className={`type-badge ${item.package_type}`}>
                        {t(`search.${item.package_type}`, '') || item.package_type}
                      </span>
                    )}
                  </td>
                  <td data-label={t('admin.yank.yank_reason')} style={{ fontSize: '0.85rem', color: 'var(--color-muted)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.yank_reason || '—'}
                  </td>
                  <td data-label={t('admin.table.actions')}>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleUnyank(item)}
                      >
                        {t('admin.yank.unyank_btn')}
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDelete(item)}
                        disabled={deletingId === item.version_id}
                      >
                        {deletingId === item.version_id ? t('admin.yank.deleting') : t('admin.yank.delete_btn')}
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
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{actionType === 're-review' ? t('admin.yank.re_review_title') : t('admin.yank.confirm_yank_title')}</h3>
              <button
                className="modal-close"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="modal-confirm-icon">&#x26A0;</div>
              <p className="modal-confirm-title">
                <strong>{selectedItem.package_name}</strong> v{selectedItem.version}
              </p>

              <div className="form-field modal-form-field" style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', padding: '0.5rem 0' }}>
                  <input
                    type="radio"
                    name="actionType"
                    value="yank"
                    checked={actionType === 'yank'}
                    onChange={() => { setActionType('yank'); setSubmitError(null); }}
                    disabled={submitting}
                  />
                  <span>{t('admin.yank.yank_option_label')}</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', padding: '0.5rem 0' }}>
                  <input
                    type="radio"
                    name="actionType"
                    value="re-review"
                    checked={actionType === 're-review'}
                    onChange={() => { setActionType('re-review'); setSubmitError(null); }}
                    disabled={submitting}
                  />
                  <span>{t('admin.yank.re_review_option_label')}</span>
                </label>
              </div>

              {actionType === 'yank' && (
                <div className="form-field modal-form-field">
                  <label className="modal-comment-label">
                    {t('admin.yank.yank_reason_label')} <span className="required-star">*</span>
                  </label>
                  <textarea
                    className="modal-comment-textarea"
                    rows={3}
                    placeholder={t('admin.yank.reason_placeholder')}
                    value={reason}
                    onChange={(e) => {
                      setReason(e.target.value);
                      setSubmitError(null);
                    }}
                    disabled={submitting}
                  />
                </div>
              )}
            </div>

            {submitError && <div className="modal-error">{submitError}</div>}

            <div className="modal-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                {t('admin.common.cancel')}
              </button>
              <button
                className="btn btn-danger"
                onClick={handleYank}
                disabled={submitting || (actionType === 'yank' && !reason.trim())}
              >
                {submitting ? t('admin.yank.processing') : actionType === 're-review' ? t('admin.yank.confirm_re_review') : t('admin.yank.confirm_yank')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
