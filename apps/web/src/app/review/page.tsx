'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ReviewItem {
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
    const d = new Date(iso);
    return d.toLocaleString('zh-CN', {
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

export default function ReviewPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const [items, setItems] = useState<ReviewItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gradeFilter, setGradeFilter] = useState(t('review.filter.all'));

  const GRADE_OPTIONS = [t('review.filter.all'), 'A', 'B', 'C', 'D', 'E', 'F'];

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError(t('review.auth_required'));
      return;
    }

    setLoading(true);
    setError(null);
    apiFetch(
      `${API_BASE}/api/v0/producer/versions?status=pending_review`,
      { headers: { Authorization: `Bearer ${token}` } },
    )
      .then((data) => setItems(data as ReviewItem[]))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user, token, authLoading]);

  const filtered = useMemo(() => {
    if (gradeFilter === t('review.filter.all')) return items;
    return items.filter((item) => item.grade === gradeFilter);
  }, [items, gradeFilter]);

  const gradeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      const g = item.grade || '—';
      counts[g] = (counts[g] || 0) + 1;
    }
    return counts;
  }, [items]);

  const hasResults = filtered.length > 0;
  const isFirstLoad = loading && items.length === 0;

  return (
    <div className="review-page">
      <nav className="admin-nav" style={{ display: 'flex', gap: '0.75rem' }}>
        {user?.role === 'admin' && (
          <button onClick={() => router.push('/admin')} className="link-btn">
            {t('review.back_to_admin')}
          </button>
        )}
        <Link href="/review/history" className="link-btn">
          {t('review.view_history')}
        </Link>
      </nav>

      <div className="admin-section-header">
        <h1>{t('review.title')}</h1>
        <p>
          {t('review.subtitle', { count: items.length })}
          {gradeFilter !== t('review.filter.all') && (
            <span>{t('review.filter.active', { grade: gradeFilter })}</span>
          )}
        </p>
      </div>

      <div className="review-toolbar">
        <div className="review-filter">
          <label htmlFor="grade-filter">{t('review.filter.filter_grade_label')}</label>
          <select
            id="grade-filter"
            value={gradeFilter}
            onChange={(e) => setGradeFilter(e.target.value)}
            className="review-select"
          >
            {GRADE_OPTIONS.map((g) => (
              <option key={g} value={g}>
                {g}
                {g !== t('review.filter.all') && gradeCounts[g]
                  ? ` (${gradeCounts[g]})`
                  : g === t('review.filter.all')
                    ? ` (${items.length})`
                    : ''}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && isFirstLoad && (
        <div className="review-table-wrapper">
          <table className="review-table">
            <thead>
              <tr>
                <th>{t('review.table.package_name')}</th>
                <th>{t('review.table.version')}</th>
                <th>{t('review.table.risk')}</th>
                <th>{t('review.table.findings_count')}</th>
                <th>{t('review.table.submitted_at')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '70%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '60%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '2rem', height: '1.5rem', borderRadius: 'var(--radius-sm)' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '2rem' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '80%' }} /></div></td>
                  <td><div className="skeleton"><div className="skeleton-bar" style={{ width: '1rem' }} /></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!error && !isFirstLoad && !hasResults && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x2705;</div>
          <h3>{t('review.empty')}</h3>
          <p>
            {gradeFilter !== t('review.filter.all')
              ? t('review.empty_filter', { grade: gradeFilter })
              : t('review.empty_all')}
          </p>
        </div>
      )}

      {!error && !isFirstLoad && hasResults && (
        <div className="review-table-wrapper">
          <table className="review-table">
            <thead>
              <tr>
                <th>{t('review.table.package_name')}</th>
                <th>{t('review.table.version')}</th>
                <th>{t('review.table.risk')}</th>
                <th>{t('review.table.findings_count')}</th>
                <th>{t('review.table.submitted_at')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.version_id}
                  onClick={() => router.push(`/review/${item.version_id}?returnTo=/review`)}
                  className="review-row"
                >
                  <td className="review-pkg-name" data-label={t('review.table.package_name')}>
                    <div className="review-pkg-title">
                      {item.package_type && (
                        <span className={`type-badge ${item.package_type}`}>
                          {t(`search.${item.package_type}`, '') || item.package_type}
                        </span>
                      )}
                      <span>{item.package_name}</span>
                    </div>
                  </td>
                  <td className="review-version" data-label={t('review.table.version')}>
                    <code>v{item.version}</code>
                  </td>
                  <td className="review-grade" data-label={t('review.table.risk')}>
                    <span
                      className={`grade-badge grade-${item.grade?.toLowerCase() || 'unknown'}`}
                      title={item.manual_grade ? `${t('review.detail.manual_grade_label')}: ${item.manual_grade}${(item.manual_grade_by_name || item.manual_grade_by) ? ' ' + t('review.detail.modified_by', { name: item.manual_grade_by_name || item.manual_grade_by }) : ''}` : ''}
                    >
                      {item.grade || '—'}
                      {item.manual_grade && '*'}
                    </span>
                  </td>
                  <td className="review-findings" data-label={t('review.table.findings_count')}>
                    <span
                      className={
                        item.findings_count > 0
                          ? 'review-findings-danger'
                          : 'review-findings-ok'
                      }
                    >
                      {item.findings_count}
                    </span>
                  </td>
                  <td className="review-date" data-label={t('review.table.submitted_at')}>
                    {formatDate(item.submitted_at)}
                  </td>
                  <td className="review-action">
                    <span className="review-arrow">→</span>
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
