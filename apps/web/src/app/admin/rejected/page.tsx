'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

import { API_BASE } from '@/lib/runtime-config';

interface RejectedItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
  grade: string | null;
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

export default function AdminRejectedPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<RejectedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<RejectedItem[]>(`${API_BASE}/api/v0/producer/versions?status=rejected&limit=200`, {
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
        <h1>{t('admin.rejected.title')}</h1>
        <p>{t('admin.rejected.subtitle')} · {items.length}</p>
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
          <h3>{t('admin.rejected.empty')}</h3>
          <p>{t('admin.rejected.empty_hint')}</p>
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
                <th>{t('admin.table.submitted_at')}</th>
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
                  <td data-label={t('admin.table.submitted_at')}>{formatDate(item.submitted_at)}</td>
                  <td data-label={t('admin.table.actions')}>
                    <button
                      className="btn btn-sm btn-secondary"
                      onClick={() => router.push(`/review/${item.version_id}?returnTo=/admin/rejected`)}
                    >
                      {t('admin.rejected.view_review')}
                    </button>
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
