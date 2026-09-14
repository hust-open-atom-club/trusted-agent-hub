'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import {
  deleteScanTask,
  fetchScanTasks,
  scanPageAfterDeletion,
} from '@/data/scans';
import { clearPendingScanIfMatches } from '@/lib/pending-scan';
import type { ScanTaskItem } from '@/types';

const PAGE_SIZE = 20;
const SCAN_LIST_REFRESH_MS = 5_000;

const STATUS_CLASSES: Record<string, string> = {
  pending: 'scanning',
  downloading: 'scanning',
  scanning: 'scanning',
  llm_review: 'scanning',
  scoring: 'scanning',
  saving: 'scanning',
  complete: 'approved',
  complete_unsubmitted: 'approved',
  callback_pending: 'scanning',
  submitted_reviewing: 'scanning',
  error: 'error',
  llm_timeout: 'error',
  total_timeout: 'error',
};

const STATUS_KEYS: Record<string, string> = {
  pending: 'scans.status.pending',
  downloading: 'scans.status.downloading',
  scanning: 'scans.status.scanning',
  llm_review: 'scans.status.llm_review',
  scoring: 'scans.status.scoring',
  saving: 'scans.status.saving',
  complete: 'scans.status.complete',
  complete_unsubmitted: 'scans.status.complete_unsubmitted',
  callback_pending: 'scans.status.callback_pending',
  submitted_reviewing: 'scans.status.submitted_reviewing',
  error: 'scans.status.error',
  llm_timeout: 'scans.status.llm_timeout',
  total_timeout: 'scans.status.total_timeout',
};

function formatDate(value: string | null, language: string): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(language === 'zh' ? 'zh-CN' : 'en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

function ScanCard({ item, language, t, onDelete, deleting }: {
  item: ScanTaskItem;
  language: string;
  t: (key: string, options?: Record<string, unknown>) => string;
  onDelete: (item: ScanTaskItem) => void;
  deleting: boolean;
}) {
  const displayStatus = item.lifecycle || item.status;
  const statusKey = STATUS_KEYS[displayStatus];
  const statusLabel = statusKey ? t(statusKey) : displayStatus;
  const statusClass = STATUS_CLASSES[displayStatus] || STATUS_CLASSES[item.status] || 'status-unknown';

  return (
    <div
      style={{
        background: 'var(--color-paper-2)',
        borderRadius: 'var(--radius-lg)',
        padding: '1.25rem 1.5rem',
        marginBottom: '0.75rem',
        border: '1px solid var(--color-rule)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <strong style={{ color: 'var(--color-ink)', fontSize: '1.05rem' }}>
              {item.package_name || t('scans.unnamed')}
            </strong>
            <span className={'status-badge ' + statusClass}>{statusLabel}</span>
          </div>
          <div
            title={item.scan_id}
            style={{
              marginTop: '0.45rem',
              color: 'var(--color-muted)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.78rem',
              overflowWrap: 'anywhere',
            }}
          >
            {t('scans.scan_id')}: {item.scan_id}
          </div>
          <div style={{ marginTop: '0.35rem', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
            {t('scans.created_at')}: {formatDate(item.created_at, language)}
          </div>
          {item.finished_at && (
            <div style={{ marginTop: '0.25rem', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
              {t('scans.finished_at')}: {formatDate(item.finished_at, language)}
            </div>
          )}
          {item.expires_at ? (
            <div style={{ marginTop: '0.25rem', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
              {t('scans.retained_until')}: {formatDate(item.expires_at, language)}
            </div>
          ) : displayStatus === 'submitted_reviewing' ? (
            <div style={{ marginTop: '0.25rem', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
              {t('scans.retained_forever')}
            </div>
          ) : null}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Link href="/submit" className="btn btn-secondary btn-sm" style={{ whiteSpace: 'nowrap' }}>
            {t('scans.new_scan')}
          </Link>
          {item.delete_allowed && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onDelete(item)}
              disabled={deleting}
              style={{ whiteSpace: 'nowrap' }}
            >
              {deleting ? t('scans.deleting') : t('scans.delete')}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ScansPage() {
  const { t, i18n } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const [items, setItems] = useState<ScanTaskItem[]>([]);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingScanId, setDeletingScanId] = useState<string | null>(null);

  const loadPage = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchScanTasks(token, {
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setItems(data.items);
      setTotal(data.total);
      setHasMore(data.has_more);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('scans.load_failed'));
    } finally {
      setLoading(false);
    }
  }, [page, t, token]);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      return;
    }
    void loadPage();
  }, [authLoading, loadPage, token, user]);

  useEffect(() => {
    if (authLoading || !user || !token || !items.some((item) => item.auto_refresh)) {
      return;
    }
    const interval = window.setInterval(() => {
      void loadPage();
    }, SCAN_LIST_REFRESH_MS);
    return () => window.clearInterval(interval);
  }, [authLoading, items, loadPage, token, user]);

  const handleDelete = async (item: ScanTaskItem) => {
    if (!token || deletingScanId) return;
    if (!window.confirm(t('scans.delete_confirm'))) return;
    setDeletingScanId(item.scan_id);
    setError(null);
    try {
      await deleteScanTask(token, item.scan_id);
      clearPendingScanIfMatches(item.scan_id);
      const nextPage = scanPageAfterDeletion(page, items.length);
      if (nextPage !== page) {
        setPage(nextPage);
      } else {
        await loadPage();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('scans.delete_failed'));
    } finally {
      setDeletingScanId(null);
    }
  };

  const isFirstLoad = loading && items.length === 0;
  const isEmpty = !loading && !error && items.length === 0;

  return (
    <div className="status-page">
      <div className="status-header">
        <h1>{t('scans.title')}</h1>
        <p>{t('scans.subtitle')}</p>
      </div>

      <div style={{ maxWidth: '760px', margin: '0 auto' }}>
        {!authLoading && !user && (
          <div className="empty-state">
            <div className="empty-state-icon">&#x1F512;</div>
            <h3>{t('scans.login_required')}</h3>
            <Link href="/login" className="btn btn-primary" style={{ marginTop: '1rem' }}>
              {t('nav.login')}
            </Link>
          </div>
        )}

        {error && (
          <div className="empty-state">
            <div className="empty-state-icon">&#x26A0;</div>
            <h3>{t('scans.load_failed')}</h3>
            <p>{error}</p>
            <button className="btn btn-secondary btn-sm" style={{ marginTop: '1rem' }} onClick={() => void loadPage()}>
              {t('common.retry')}
            </button>
          </div>
        )}

        {isFirstLoad && Array.from({ length: 5 }).map((_, index) => (
          <div
            key={index}
            style={{
              height: '7rem',
              background: 'var(--color-paper-2)',
              borderRadius: 'var(--radius-lg)',
              marginBottom: '0.75rem',
              border: '1px solid var(--color-rule)',
              opacity: 0.65,
            }}
          />
        ))}

        {isEmpty && (
          <div className="empty-state">
            <div className="empty-state-icon">&#x1F50D;</div>
            <h3>{t('scans.empty')}</h3>
            <p>{t('scans.empty_hint')}</p>
            <Link href="/submit" className="btn btn-primary" style={{ marginTop: '1rem' }}>
              {t('scans.new_scan')}
            </Link>
          </div>
        )}

        {!loading && !error && user && items.map((item) => (
          <ScanCard
            key={item.scan_id}
            item={item}
            language={i18n.language}
            t={t}
            onDelete={handleDelete}
            deleting={deletingScanId === item.scan_id}
          />
        ))}

        {!loading && !error && user && items.length > 0 && (
          <div className="pagination" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem', marginTop: '1.5rem' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((current) => Math.max(0, current - 1))}
              disabled={page === 0}
            >
              {t('scans.prev')}
            </button>
            <span style={{ color: 'var(--color-muted)', fontSize: '0.85rem' }}>
              {t('scans.page_num', { page: page + 1, total: Math.max(1, Math.ceil(total / PAGE_SIZE)) })}
            </span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((current) => current + 1)}
              disabled={!hasMore}
            >
              {t('scans.next')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
