'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { deleteScanTask, fetchScanTasks } from '@/data/scans';
import { apiFetch } from '@/lib/api-fetch';
import { clearPendingScanIfMatches } from '@/lib/pending-scan';
import { readScanPackageContext } from '@/lib/scan-package-context';
import { API_BASE } from '@/lib/runtime-config';
import type { ScanTaskItem } from '@/types';
import ScanRetentionNotice from '@/components/ScanRetentionNotice';
import VersionDeleteButton from '@/components/VersionDeleteButton';
import { RESUBMITTABLE_STATUSES, versionStatusHref } from '@/lib/submission-workflow';

const PAGE_SIZE = 20;
const SCAN_LIST_REFRESH_MS = 5_000;
// Load each source in growing windows for client-side search and pagination.
const FETCH_PAGE = 200;

interface SubmittedVersionItem {
  version_id: string;
  package_id: string;
  package_name: string;
  version: string;
  status: string;
  submitted_at: string | null;
}

const VERSION_STATUS_CLASSES: Record<string, string> = {
  draft: 'draft',
  submitted: 'submitted',
  scanning: 'scanning',
  pending_review: 'pending_review',
  under_review: 'pending_review',
  approved: 'approved',
  published: 'published',
  rejected: 'rejected',
  changes_requested: 'changes_requested',
  resubmitted: 'resubmitted',
  error: 'error',
  yanked: 'yanked',
};

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

interface SourceWindow<T> {
  items: T[];
  hasMore: boolean;
}

/** Load up to `size` scan tasks, one API page at a time (the API caps a page at 200). */
async function fetchScanWindow(
  token: string,
  size: number,
): Promise<SourceWindow<ScanTaskItem>> {
  const items: ScanTaskItem[] = [];
  let hasMore = false;
  for (let offset = 0; offset < size; offset += FETCH_PAGE) {
    const page = await fetchScanTasks(token, { limit: FETCH_PAGE, offset });
    items.push(...page.items);
    hasMore = page.has_more;
    if (!hasMore || page.items.length === 0) break;
  }
  return { items, hasMore };
}

/** Load up to `size` own versions; the endpoint returns bare arrays, so a full page means "more". */
async function fetchVersionWindow(
  token: string,
  userId: string,
  size: number,
): Promise<SourceWindow<SubmittedVersionItem>> {
  const items: SubmittedVersionItem[] = [];
  let hasMore = false;
  for (let offset = 0; offset < size; offset += FETCH_PAGE) {
    const batch = await apiFetch<SubmittedVersionItem[]>(
      `${API_BASE}/api/v0/producer/versions?submitter_id=${encodeURIComponent(userId)}&limit=${FETCH_PAGE}&offset=${offset}`,
      {
        cache: 'no-store',
        headers: { Authorization: `Bearer ${token}` },
      },
    );
    const page = Array.isArray(batch) ? batch : [];
    items.push(...page);
    hasMore = page.length === FETCH_PAGE;
    if (!hasMore) break;
  }
  return { items, hasMore };
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
  const versionStatus = displayStatus === 'submitted_reviewing' ? item.submission?.status : null;
  const statusLabel = versionStatus
    ? t('submissions.status.' + versionStatus, { defaultValue: versionStatus })
    : statusKey ? t(statusKey) : displayStatus;
  const statusClass = (versionStatus && VERSION_STATUS_CLASSES[versionStatus])
    || STATUS_CLASSES[displayStatus] || STATUS_CLASSES[item.status] || 'status-unknown';
  // Resolved after mount: the scan-to-package hint lives in localStorage,
  // which is unavailable during server rendering.
  const [continueHref, setContinueHref] = useState<string | null>(null);
  useEffect(() => {
    if (displayStatus !== 'complete_unsubmitted') return;
    const packageId = readScanPackageContext(item.scan_id);
    const suffix = packageId
      ? `&packageId=${encodeURIComponent(packageId)}`
      : '';
    setContinueHref(`/submit?scan=${encodeURIComponent(item.scan_id)}${suffix}`);
  }, [displayStatus, item.scan_id]);

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
          <ScanRetentionNotice item={item} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {item.submission && (
            <Link
              href={`/packages/${encodeURIComponent(item.submission.package_name)}/versions/${encodeURIComponent(item.submission.version)}/status?vid=${encodeURIComponent(item.submission.version_id)}`}
              className="btn btn-secondary btn-sm"
              style={{ whiteSpace: 'nowrap' }}
            >
              {t('scans.view_submission')}
            </Link>
          )}
          {continueHref && (
            <Link href={continueHref} className="btn btn-primary btn-sm" style={{ whiteSpace: 'nowrap' }}>
              {t('scans.continue_submission')}
            </Link>
          )}
          <Link href="/submit" className="btn btn-secondary btn-sm" style={{ whiteSpace: 'nowrap' }}>
            {t('scans.new_scan')}
          </Link>
          {item.delete_allowed && !item.submission && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onDelete(item)}
              disabled={deleting}
              style={{ whiteSpace: 'nowrap' }}
            >
              {deleting ? t('scans.deleting') : t('scans.delete_scan_record')}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function VersionCard({ item, language, t, onDeleted }: {
  item: SubmittedVersionItem;
  language: string;
  t: (key: string, options?: Record<string, unknown>) => string;
  onDeleted: () => void;
}) {
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
              {item.package_name}
            </strong>
            <span className={'status-badge ' + (VERSION_STATUS_CLASSES[item.status] || 'status-unknown')}>
              {t('submissions.status.' + item.status, { defaultValue: item.status })}
            </span>
          </div>
          <div style={{ marginTop: '0.4rem', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
            v{item.version}
            {item.submitted_at ? ' · ' + formatDate(item.submitted_at, language) : ''}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Link
            href={`/packages/${encodeURIComponent(item.package_name)}/versions/${encodeURIComponent(item.version)}/status?vid=${encodeURIComponent(item.version_id)}`}
            className="btn btn-secondary btn-sm"
            style={{ whiteSpace: 'nowrap' }}
          >
            {t('submissions.view_status')}
          </Link>
          {RESUBMITTABLE_STATUSES.has(item.status) && (
            <Link href={`${versionStatusHref(item.package_name, item.version, item.version_id)}#resubmit`}
              className="btn btn-secondary btn-sm">{t('scans.resubmit')}</Link>
          )}
          <Link href={`/submit?packageId=${encodeURIComponent(item.package_id)}`}
            className="btn btn-secondary btn-sm">{t('scans.create_version')}</Link>
          <VersionDeleteButton versionId={item.version_id} status={item.status} onDeleted={onDeleted} />
        </div>
      </div>
    </div>
  );
}

type ActivityItem =
  | { kind: 'scan'; id: string; sortKey: number; scan: ScanTaskItem }
  | { kind: 'version'; id: string; sortKey: number; version: SubmittedVersionItem };

export default function SubmissionsAndScansPage() {
  const { t, i18n } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const [items, setItems] = useState<ScanTaskItem[]>([]);
  const [submittedVersions, setSubmittedVersions] = useState<SubmittedVersionItem[]>([]);
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState('');
  const [windowSize, setWindowSize] = useState(FETCH_PAGE);
  const [scansHaveMore, setScansHaveMore] = useState(false);
  const [versionsHaveMore, setVersionsHaveMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingScanId, setDeletingScanId] = useState<string | null>(null);
  const [view, setView] = useState<'mine' | 'scans'>('mine');
  const [deletedScan, setDeletedScan] = useState<ScanTaskItem | null>(null);

  // Every role has personal submissions. Global scans are a separate view,
  // so deleting a scan cannot make its surviving version disappear.
  const seesAllScans = user?.role === 'admin';

  const loadAll = useCallback(async (size: number) => {
    if (!token || !user) return;
    setLoading(true);
    setError(null);
    try {
      const [scanWindow, versionWindow] = await Promise.all([
        fetchScanWindow(token, size),
        fetchVersionWindow(token, user.id, size),
      ]);
      setItems(scanWindow.items);
      setScansHaveMore(scanWindow.hasMore);
      setSubmittedVersions(versionWindow.items);
      setVersionsHaveMore(versionWindow.hasMore);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('scans.load_failed'));
    } finally {
      setLoading(false);
    }
  }, [t, token, user]);

  // Window growth is reloaded by the pager itself; this effect only covers
  // sign-in changes, so it deliberately does not depend on `windowSize`.
  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      return;
    }
    void loadAll(windowSize);
  }, [authLoading, loadAll, token, user]);

  useEffect(() => {
    if (authLoading || !user || !token || !items.some((item) => item.auto_refresh)) {
      return;
    }
    const interval = window.setInterval(() => {
      void loadAll(windowSize);
    }, SCAN_LIST_REFRESH_MS);
    return () => window.clearInterval(interval);
  }, [authLoading, items, loadAll, token, user, windowSize]);

  // Paginate the selected source independently: global scan traffic must not
  // push the user's own versions out of their submissions view.
  const activity = useMemo<ActivityItem[]>(() => {
    const needle = query.trim().toLowerCase();
    const rows: ActivityItem[] = [];
    for (const item of view === 'scans' ? items : []) {
      const haystack = `${item.package_name ?? ''} ${item.scan_id}`.toLowerCase();
      if (needle && !haystack.includes(needle)) continue;
      rows.push({
        kind: 'scan',
        id: item.scan_id,
        sortKey: Date.parse(item.created_at) || 0,
        scan: item,
      });
    }
    for (const version of view === 'mine' ? submittedVersions : []) {
      const haystack = `${version.package_name} ${version.version} ${version.version_id}`.toLowerCase();
      if (needle && !haystack.includes(needle)) continue;
      rows.push({
        kind: 'version',
        id: version.version_id,
        sortKey: Date.parse(version.submitted_at ?? '') || 0,
        version,
      });
    }
    rows.sort((a, b) => b.sortKey - a.sortKey);
    return rows;
  }, [items, query, submittedVersions, view]);

  const totalPages = Math.max(1, Math.ceil(activity.length / PAGE_SIZE));
  const moreAvailable = view === 'mine' ? versionsHaveMore : scansHaveMore;

  // Deletions and refreshes can shrink the list below the current page.
  useEffect(() => {
    setPage((current) => Math.min(current, totalPages - 1));
  }, [totalPages]);

  const pageItems = activity.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);

  const handleNextPage = async () => {
    const nextPage = page + 1;
    if (nextPage * PAGE_SIZE >= activity.length && moreAvailable) {
      // Older records live beyond the loaded window: grow it, then page on.
      const grown = windowSize + FETCH_PAGE;
      setWindowSize(grown);
      await loadAll(grown);
    }
    setPage(nextPage);
  };

  const handleDelete = async (item: ScanTaskItem) => {
    if (!token || deletingScanId) return;
    if (!window.confirm(t('scans.delete_confirm'))) return;
    setDeletingScanId(item.scan_id);
    setError(null);
    try {
      await deleteScanTask(token, item.scan_id);
      clearPendingScanIfMatches(item.scan_id);
      setDeletedScan(item);
      await loadAll(windowSize);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('scans.delete_failed'));
    } finally {
      setDeletingScanId(null);
    }
  };

  const isFirstLoad = loading && activity.length === 0;
  const isEmpty = !loading && !error && activity.length === 0;
  const hasQuery = query.trim().length > 0;

  return (
    <div className="status-page">
      <div className="status-header">
        <h1>{t('scans.title')}</h1>
        <p>{t(seesAllScans ? 'scans.subtitle_admin' : 'scans.subtitle')}</p>
      </div>

      <div style={{ maxWidth: '760px', margin: '0 auto' }}>
        {user && (
          <div role="tablist" aria-label={t('scans.title')} style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            {(['mine', 'scans'] as const).map((tab) => (
              <button key={tab} type="button" role="tab" aria-selected={view === tab}
                className={`btn ${view === tab ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => { setView(tab); setPage(0); setQuery(''); }}>
                {t(tab === 'mine' ? 'scans.my_versions' : seesAllScans ? 'scans.all_records' : 'scans.my_records')}
              </button>
            ))}
          </div>
        )}
        {deletedScan && (
          <div className="submit-notice" role="status">
            <p>{t('scans.delete_success')}</p>
            {deletedScan.submission && (
              <Link className="btn btn-secondary btn-sm"
                href={`/packages/${encodeURIComponent(deletedScan.submission.package_name)}/versions/${encodeURIComponent(deletedScan.submission.version)}/status?vid=${encodeURIComponent(deletedScan.submission.version_id)}`}>
                {t('submissions.view_status')}
              </Link>
            )}
          </div>
        )}
        {!authLoading && user && (
          <form
            onSubmit={(e) => e.preventDefault()}
            style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}
          >
            <input
              type="text"
              className="scanner-url-input"
              placeholder={t('scans.search_placeholder')}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
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
        )}

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
            <button className="btn btn-secondary btn-sm" style={{ marginTop: '1rem' }} onClick={() => void loadAll(windowSize)}>
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
            <h3>{hasQuery ? t('scans.no_match') : t(view === 'mine' ? 'scans.empty_versions' : 'scans.empty')}</h3>
            <p>{hasQuery ? t('scans.no_match_hint') : t('scans.empty_hint')}</p>
            <Link href="/submit" className="btn btn-primary" style={{ marginTop: '1rem' }}>
              {t('scans.new_scan')}
            </Link>
          </div>
        )}

        {!isFirstLoad && !error && user && pageItems.map((row) => {
          if (row.kind === 'scan') {
            return (
              <ScanCard
                key={row.id}
                item={row.scan}
                language={i18n.language}
                t={t}
                onDelete={handleDelete}
                deleting={deletingScanId === row.id}
              />
            );
          }
          return (
            <VersionCard
              key={row.id}
              item={row.version}
              language={i18n.language}
              t={t}
              onDeleted={() => void loadAll(windowSize)}
            />
          );
        })}

        {!isFirstLoad && !error && user && activity.length > 0 && (
          <div className="pagination" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem', marginTop: '1.5rem' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setPage((current) => Math.max(0, current - 1))}
              disabled={page === 0}
            >
              {t('scans.prev')}
            </button>
            <span style={{ color: 'var(--color-muted)', fontSize: '0.85rem' }}>
              {t('scans.page_num', {
                page: page + 1,
                total: moreAvailable ? `${totalPages}+` : totalPages,
              })}
            </span>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => void handleNextPage()}
              disabled={page >= totalPages - 1 && !moreAvailable}
            >
              {t('scans.next')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
