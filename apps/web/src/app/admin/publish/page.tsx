'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
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
  const { t } = useTranslation();
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

  const gradeLabelMap: Record<string, string> = {
    A: t('admin.grade.A'),
    B: t('admin.grade.B'),
    C: t('admin.grade.C'),
    D: t('admin.grade.D'),
    E: t('admin.grade.E'),
    F: t('admin.grade.F'),
  };

  const gradeOrder = ['A', 'B', 'C', 'D', 'E', 'F'];

  const dedupedItems = (() => {
    const byName = new Map<string, PublishItem>();
    for (const item of items) {
      const existing = byName.get(item.package_name);
      if (!existing || item.version.localeCompare(existing.version, undefined, { numeric: true }) > 0) {
        byName.set(item.package_name, item);
      }
    }
    return Array.from(byName.values());
  })();

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<PublishItem[]>(`${API_BASE}/api/v0/producer/versions?status=approved`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data) => setItems(data))
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
        const err = await res.json().catch(() => ({ detail: t('admin.common.error') }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      setSuccessMsg(`${selectedItem.package_name} v${selectedItem.version} ${t('admin.publish.publish_success')}`);
      setShowModal(false);
      setSelectedItem(null);
      setConfirmed(false);
      clearFetchCache('versions');
      fetchItems();

      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : t('admin.common.error'));
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
        <h1>{t('admin.publish.title')}</h1>
        <p>{t('admin.publish.subtitle')} · {dedupedItems.length}</p>
        {successMsg && <span className="admin-success-msg">{successMsg}</span>}
      </div>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && dedupedItems.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x2705;</div>
          <h3>{t('admin.publish.empty')}</h3>
          <p>{t('admin.publish.empty_hint')}</p>
        </div>
      )}

      {!error && dedupedItems.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t('admin.publish.auto_grade')}</th>
                <th>{t('admin.publish.manual_grade')}</th>
                <th>{t('admin.table.package_name')}</th>
                <th>{t('admin.table.version')}</th>
                <th>{t('admin.table.type')}</th>
                <th>{t('admin.table.submitted_at')}</th>
                <th>{t('admin.table.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {dedupedItems.map((item) => (
                <tr key={item.version_id}>
                  <td data-label={t('admin.publish.auto_grade')}>
                    <span className={`grade-badge grade-${item.auto_grade?.toLowerCase() || 'unknown'}`}>
                      {item.auto_grade || '—'}
                    </span>
                  </td>
                  <td data-label={t('admin.publish.manual_grade')}>
                    {item.manual_grade ? (
                      <span
                        style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-ink)' }}
                        title={`${t('admin.publish.overridden_by', { name: item.manual_grade_by_name || item.manual_grade_by || '' })}${item.manual_grade_reason ? ': ' + item.manual_grade_reason : ''}`}
                      >
                        {item.manual_grade} *
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>—</span>
                    )}
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
                  <td data-label={t('admin.table.submitted_at')}>{formatDate(item.submitted_at)}</td>
                  <td data-label={t('admin.table.actions')}>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <button
                        className="link-btn"
                        style={{ fontSize: '0.78rem' }}
                        onClick={() => router.push(`/review/${item.version_id}?returnTo=/admin/publish`)}
                      >
                        {t('admin.publish.details')}
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
                          {t('admin.publish.override_grade')}
                        </button>
                      )}
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => openPublishModal(item)}
                      >
                        {t('admin.publish.publish_btn')}
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
              <h3>{t('admin.publish.confirm_title')}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)} disabled={submitting}>
                ✕
              </button>
            </div>

            <div style={{ padding: '1.25rem' }}>
              <p style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-ink)', marginBottom: '1rem' }}>
                {t('admin.publish.confirm_text', { name: selectedItem.package_name, version: selectedItem.version })}
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
                  <span style={{ color: 'var(--color-muted)' }}>{t('admin.publish.auto_grade')}</span>
                  <span style={{ fontWeight: 600, color: 'var(--color-ink)' }}>
                    {selectedItem.auto_grade ? `${selectedItem.auto_grade} (${gradeLabelMap[selectedItem.auto_grade] ?? selectedItem.auto_grade})` : '—'}
                  </span>
                  <span></span>

                  <span style={{ color: 'var(--color-muted)' }}>{t('admin.publish.manual_grade')}</span>
                  <span style={{
                    fontWeight: 600,
                    color: selectedItem.manual_grade ? 'var(--color-accent)' : 'var(--color-muted)',
                  }}>
                    {selectedItem.manual_grade ? `${selectedItem.manual_grade} (${gradeLabelMap[selectedItem.manual_grade] ?? selectedItem.manual_grade}) *` : `— (${t('admin.publish.use_auto')})`}
                  </span>
                  <span></span>

                  <span style={{ color: 'var(--color-muted)', borderTop: '1px solid var(--color-rule)', paddingTop: '0.3rem' }}>
                    {t('admin.publish.effective_grade')}
                  </span>
                  <span style={{
                    fontWeight: 700, fontSize: '0.92rem',
                    color: 'var(--color-ink)',
                    borderTop: '1px solid var(--color-rule)', paddingTop: '0.3rem',
                  }}>
                    {selectedItem.grade ? `${selectedItem.grade} (${gradeLabelMap[selectedItem.grade] ?? selectedItem.grade})` : '—'}
                  </span>
                  <span></span>
                </div>

                {selectedItem.manual_grade_reason && (
                  <div style={{
                    marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--color-muted)',
                    borderTop: '1px solid var(--color-rule)', paddingTop: '0.5rem',
                  }}>
                    {t('admin.publish.override_reason')}: {selectedItem.manual_grade_reason}
                    {selectedItem.manual_grade_by_name && <> · {t('admin.publish.overridden_by', { name: selectedItem.manual_grade_by_name })}</>}
                  </div>
                )}

                {selectedItem.auto_grade && selectedItem.manual_grade &&
                  Math.abs(gradeOrder.indexOf(selectedItem.auto_grade) - gradeOrder.indexOf(selectedItem.manual_grade)) >= 3 && (
                  <div style={{
                    marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--color-danger)',
                    fontWeight: 600,
                  }}>
                    {t('admin.publish.significant_gap_warning')}
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
                {t('admin.publish.confirm_checkbox', { grade: selectedItem.grade || '—' })}
              </label>

              <p style={{ fontSize: '0.8rem', color: 'var(--color-muted)', marginBottom: '1rem' }}>
                {t('admin.publish.post_publish_hint')}
              </p>

              {submitError && <div className="modal-error">{submitError}</div>}

              <div className="modal-actions">
                <button className="btn btn-secondary" onClick={() => setShowModal(false)} disabled={submitting}>
                  {t('admin.common.cancel')}
                </button>
                <button className="btn btn-primary" onClick={handlePublish} disabled={submitting || !confirmed}>
                  {submitting ? t('admin.publish.publishing') : t('admin.publish.confirm_publish')}
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
