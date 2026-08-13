'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const SUPPORT_EMAIL = process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'support@trustedagenthub.com';

interface VersionItem {
  version_id: string;
  package_id: string;
  package_name: string;
  version: string;
  status: string;
  submitted_at: string | null;
  yank_reason?: string | null;
}

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
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

export default function MySubmissionsPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const [items, setItems] = useState<VersionItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 20;

  const statusLabels: Record<string, { label: string; className: string }> = {
    draft:        { label: t('submissions.status.draft'),     className: 'draft' },
    submitted:    { label: t('submissions.status.draft'),   className: 'submitted' },
    scanning:     { label: t('submissions.status.scanning'),   className: 'scanning' },
    pending_review: { label: t('submissions.status.pending_review'), className: 'pending_review' },
    approved:     { label: t('submissions.status.approved'), className: 'approved' },
    published:    { label: t('submissions.status.published'),   className: 'published' },
    rejected:     { label: t('submissions.status.rejected'),   className: 'rejected' },
    changes_requested: { label: t('submissions.status.changes_requested'), className: 'changes_requested' },
    error:        { label: t('submissions.status.error'),     className: 'error' },
    yanked:       { label: t('submissions.status.yanked'),   className: 'yanked' },
  };

  const fetchItems = () => {
    if (!user) return;
    setLoading(true);
    setError(null);
    const offset = page * pageSize;
    apiFetch<VersionItem[]>(`${API_BASE}/api/v0/producer/versions?submitter_id=${encodeURIComponent(user.id)}&limit=${pageSize}&offset=${offset}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data: VersionItem[]) => {
        setItems(data);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      setLoading(false);
      setError(t('submissions.login_required'));
      return;
    }
    fetchItems();
  }, [user, authLoading, page]);

  const filtered = search.trim()
    ? items.filter(
        (item) =>
          item.version_id.toLowerCase().includes(search.toLowerCase()) ||
          item.package_name.toLowerCase().includes(search.toLowerCase())
      )
    : items;

  const hasResults = filtered.length > 0;
  const isFirstLoad = loading && items.length === 0;

  return (
    <div className="status-page">
      <div className="status-header">
        <h1>{t('submissions.title')}</h1>
        <p>{t('submissions.subtitle')}</p>
      </div>

      <div style={{ maxWidth: '640px', margin: '0 auto 2rem' }}>
        <form
          onSubmit={(e) => e.preventDefault()}
          style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}
        >
          <input
            type="text"
            className="scanner-url-input"
            placeholder={t('submissions.search_placeholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              flex: 1,
              borderRadius: 'var(--radius-pill)',
              padding: '0.7rem 1rem',
              fontFamily: 'var(--font-mono)',
            }}
          />
          <Link href="/submit" className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
            {t('submissions.submit_new')}
          </Link>
        </form>
      </div>

      <div style={{ maxWidth: '720px', margin: '0 auto' }}>
        {error && (
          <div className="empty-state">
            <div className="empty-state-icon">&#x26A0;</div>
            <h3>{t('admin.dashboard.load_failed')}</h3>
            <p>{error}</p>
            <button className="btn btn-secondary btn-sm" style={{ marginTop: '1rem' }} onClick={fetchItems}>
              {t('common.retry')}
            </button>
          </div>
        )}

        {!error && isFirstLoad && (
          Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              style={{
                background: 'var(--color-paper-2)',
                borderRadius: 'var(--radius-lg)',
                padding: '1.25rem 1.5rem',
                marginBottom: '0.75rem',
                border: '1px solid var(--color-rule)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="skeleton" style={{ marginBottom: '0.5rem' }}>
                  <div className="skeleton-bar" style={{ width: '40%', height: '1.2rem' }} />
                </div>
                <div className="skeleton">
                  <div className="skeleton-bar" style={{ width: '60%' }} />
                </div>
                <div className="skeleton" style={{ marginTop: '0.4rem' }}>
                  <div className="skeleton-bar" style={{ width: '30%' }} />
                </div>
              </div>
              <div className="skeleton">
                <div className="skeleton-bar" style={{ width: '5rem', height: '2rem', borderRadius: 'var(--radius-pill)' }} />
              </div>
            </div>
          ))
        )}

        {!error && !isFirstLoad && !hasResults && (
          <div className="empty-state">
            <div className="empty-state-icon">&#x1F4E6;</div>
            <h3>{t('submissions.empty')}</h3>
            <p>{t('submissions.empty_hint')}</p>
            <Link href="/submit" className="btn btn-primary" style={{ marginTop: '1rem' }}>
              {t('submissions.go_submit')}
            </Link>
          </div>
        )}

        {!isFirstLoad && hasResults && (
          <>
            {filtered.map((item) => {
              const st = statusLabels[item.status] || { label: item.status, className: 'status-unknown' };
              const statusUrl = `/packages/${encodeURIComponent(item.package_name)}/versions/${encodeURIComponent(item.version)}/status?vid=${encodeURIComponent(item.version_id)}`;
              return (
                <div
                  key={item.version_id}
                  className="submission-card"
                  style={{
                    background: 'var(--color-paper-2)',
                    borderRadius: 'var(--radius-lg)',
                    padding: '1.25rem 1.5rem',
                    marginBottom: '0.75rem',
                    border: '1px solid var(--color-rule)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <strong style={{ fontSize: '1.05rem', color: 'var(--color-ink)' }}>
                        {item.package_name}
                      </strong>
                      <span className={`status-badge ${st.className}`} style={{
                        display: 'inline-block',
                        padding: '0.15rem 0.6rem',
                        borderRadius: 'var(--radius-pill)',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                      }}>
                        {st.label}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>
                      <span>v{item.version}</span>
                      <span style={{ margin: '0 0.5rem', opacity: 0.4 }}>|</span>
                      <span title={item.version_id} style={{ fontSize: '0.75rem', opacity: 0.7 }}>
                        {item.version_id.slice(0, 12)}...
                      </span>
                    </div>
                    {item.submitted_at && (
                      <div style={{ fontSize: '0.78rem', color: 'var(--color-muted)', marginTop: '0.3rem' }}>
                        {formatDate(item.submitted_at)}
                      </div>
                    )}
                    {item.status === 'yanked' && (
                      <div style={{ marginTop: '0.5rem', padding: '0.5rem 0.75rem', background: 'var(--color-danger-light)', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem', color: 'var(--color-ink-2)', lineHeight: 1.5 }}>
                        {item.yank_reason && (
                          <div style={{ marginBottom: '0.25rem' }}>
                            <strong>{t('submissions.yank_reason_label')}</strong>{item.yank_reason}
                          </div>
                        )}
                        <div style={{ color: 'var(--color-muted)', fontSize: '0.75rem' }}>
                          {t('submissions.contact_support', { email: SUPPORT_EMAIL })}
                        </div>
                      </div>
                    )}
                  </div>
                  <button
                    className="btn btn-primary"
                    onClick={() => router.push(statusUrl)}
                    style={{ flexShrink: 0 }}
                  >
                    {t('submissions.view_status')}
                  </button>
                </div>
              );
            })}

            <div className="pagination" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem', marginTop: '1.5rem' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                {t('submissions.prev')}
              </button>
              <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>{t('submissions.page_num', { page: page + 1 })}</span>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={items.length < pageSize}
              >
                {t('submissions.next')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
