'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import type { ReviewRecord } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface HistoryReviewRecord extends ReviewRecord {
  version: string;
  version_status: string;
  package_name: string;
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

export default function ReviewHistoryPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [records, setRecords] = useState<HistoryReviewRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 20;

  const conclusionLabels: Record<string, string> = {
    approved: t('review.conclusion.approved'),
    rejected: t('review.conclusion.rejected'),
    changes_requested: t('review.conclusion.changes_requested'),
  };

  const fetchRecords = () => {
    if (!token || !user) return;
    setLoading(true);
    setError(null);
    const offset = page * pageSize;
    apiFetch<HistoryReviewRecord[]>(
      `${API_BASE}/api/v0/producer/reviews?reviewer_id=${encodeURIComponent(user.id)}&limit=${pageSize}&offset=${offset}`,
      { headers: { Authorization: `Bearer ${token}` } },
    )
      .then((data) => setRecords(data))
      .catch((err) => setError(err instanceof Error ? err.message : t('admin.dashboard.load_failed')))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError(t('review.auth_required'));
      return;
    }
    fetchRecords();
  }, [user, token, authLoading, page]);

  const isFirstLoad = loading && records.length === 0;

  return (
    <div className="review-detail-page">
      <nav className="review-detail-nav">
        <button onClick={() => router.push('/review')} className="link-btn">
          {t('review.history.back_to_review')}
        </button>
        <span className="review-detail-nav-user">{user?.display_name || user?.email}</span>
      </nav>

      <div className="admin-section-header">
        <h1>{t('review.history.title')}</h1>
        <p>{t('review.history.subtitle', { count: records.length })}</p>
      </div>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
          <button className="btn btn-secondary btn-sm" style={{ marginTop: '1rem' }} onClick={fetchRecords}>
            {t('common.retry')}
          </button>
        </div>
      )}

      {!error && isFirstLoad && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t('review.history.table.conclusion')}</th>
                <th>{t('review.history.table.package_name')}</th>
                <th>{t('review.history.table.version')}</th>
                <th>{t('review.history.table.status')}</th>
                <th>{t('review.history.table.comment')}</th>
                <th>{t('review.history.table.time')}</th>
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '3rem', height: '1.4rem', borderRadius: 'var(--radius-pill)' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '70%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '60%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '4rem', height: '1.4rem', borderRadius: 'var(--radius-pill)' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '80%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '80%' }} /></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!error && !isFirstLoad && records.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4CB;</div>
          <h3>{t('review.history.empty')}</h3>
          <p>{t('review.history.empty_hint')}</p>
        </div>
      )}

      {!error && !isFirstLoad && records.length > 0 && (
        <>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>{t('review.history.table.conclusion')}</th>
                  <th>{t('review.history.table.package_name')}</th>
                  <th>{t('review.history.table.version')}</th>
                  <th>{t('review.history.table.status')}</th>
                  <th>{t('review.history.table.comment')}</th>
                  <th>{t('review.history.table.time')}</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td data-label={t('review.history.table.conclusion')}>
                      <span className={`status-badge ${r.conclusion}`}>
                        {conclusionLabels[r.conclusion] || r.conclusion}
                      </span>
                    </td>
                    <td data-label={t('review.history.table.package_name')} className="admin-pkg-name">
                      {r.package_name}
                    </td>
                    <td data-label={t('review.history.table.version')}>
                      <code>v{r.version}</code>
                    </td>
                    <td data-label={t('review.history.table.status')}>
                      <span className={`status-badge ${r.version_status}`}>
                        {r.version_status}
                      </span>
                    </td>
                    <td data-label={t('review.history.table.comment')} style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {r.comment || '—'}
                    </td>
                    <td data-label={t('review.history.table.time')}>{formatDate(r.created_at)}</td>
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
              {t('review.history.prev')}
            </button>
            <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>{t('review.history.page_num', { page: page + 1 })}</span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={records.length < pageSize}
            >
              {t('review.history.next')}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
