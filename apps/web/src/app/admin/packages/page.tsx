'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

import { API_BASE } from '@/lib/runtime-config';

interface PackageItem {
  package_id: string;
  package_name: string;
  package_type: string | null;
  description: string | null;
  status: string;
  latest_version: string;
  created_at: string | null;
  updated_at: string | null;
}

const PACKAGE_TYPE_KEYS = ['skill', 'mcp_server', 'plugin', 'subagent', 'command', 'prompt'] as const;

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

export default function AdminPackagesPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<PackageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const statusLabels: Record<string, string> = {
    draft: t('admin.status.draft'),
    published: t('admin.status.published'),
    yanked: t('admin.status.yanked'),
  };

  const fetchItems = () => {
    if (!token) return;
    setLoading(true);
    setError(null);

    apiFetch<PackageItem[]>(`${API_BASE}/api/v0/producer/packages?limit=200`, {
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
        <h1>{t('admin.packages.title')}</h1>
        <p>{t('admin.packages.subtitle')} · {t('admin.packages.subtitle')} / {items.length}</p>
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
          <div className="empty-state-icon">&#x1F4E6;</div>
          <h3>{t('admin.packages.empty')}</h3>
          <p>{t('admin.packages.empty_hint')}</p>
        </div>
      )}

      {!error && items.length > 0 && (
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th>{t('admin.table.package_name')}</th>
                <th>{t('admin.table.type')}</th>
                <th>{t('admin.table.status')}</th>
                <th>{t('admin.table.latest_version')}</th>
                <th>{t('admin.table.description')}</th>
                <th>{t('admin.table.created_at')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.package_id}>
                  <td data-label={t('admin.table.package_name')} className="admin-pkg-name">
                    {item.package_name}
                  </td>
                  <td data-label={t('admin.table.type')}>
                    {item.package_type && (
                      <span className={`type-badge ${item.package_type}`}>
                        {t(`search.${item.package_type}`, '') || item.package_type}
                      </span>
                    )}
                  </td>
                  <td data-label={t('admin.table.status')}>
                    <span className={`status-badge ${item.status}`}>
                      {statusLabels[item.status] || item.status}
                    </span>
                  </td>
                  <td data-label={t('admin.table.latest_version')}>
                    <code>v{item.latest_version}</code>
                  </td>
                  <td data-label={t('admin.table.description')} style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.description || '—'}
                  </td>
                  <td data-label={t('admin.table.created_at')}>{formatDate(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
