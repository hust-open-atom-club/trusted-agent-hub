'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

import { API_BASE } from '@/lib/runtime-config';

interface AuditLogEntry {
  id: string;
  action: string;
  target_type: string;
  target_id: string;
  operator_id: string;
  operator_name: string | null;
  timestamp: string;
  detail: Record<string, unknown> | null;
}

const ACTION_OPTIONS_KEYS = [
  '', 'publish', 'yank', 'approve', 'reject', 'request_changes', 'submit', 'scan_start', 'scan_complete',
] as const;

const PAGE_SIZES = [10, 30, 50, 100];

function formatDate(iso: string | null | undefined): string {
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

export default function AdminAuditLogsPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [action, setAction] = useState('');
  const [targetId, setTargetId] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(30);
  const [totalCount, setTotalCount] = useState(0);

  const actionLabels: Record<string, string> = {
    publish: t('admin.audit.action.publish'),
    yank: t('admin.audit.action.yank'),
    approve: t('admin.audit.action.approve'),
    reject: t('admin.audit.action.reject'),
    request_changes: t('admin.audit.action.changes_requested'),
    submit: t('admin.audit.action.submitted'),
    scan_start: t('admin.audit.action.scan_start'),
    scan_complete: t('admin.audit.action.scan_complete'),
    approved: t('admin.audit.action.approve'),
    rejected: t('admin.audit.action.reject'),
    changes_requested: t('admin.audit.action.changes_requested'),
  };

  const actionOptions = ACTION_OPTIONS_KEYS.map((key) => ({
    value: key,
    label: key ? (actionLabels[key] || key) : t('admin.audit.filter_all'),
  }));

  const fetchLogs = useCallback(() => {
    if (!token) return;
    setLoading(true);
    setError(null);

    const params = new URLSearchParams();
    if (action) params.set('action', action);
    if (targetId.trim()) params.set('target_id', targetId.trim());
    if (startDate) params.set('start_date', new Date(startDate).toISOString());
    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      params.set('end_date', end.toISOString());
    }
    params.set('limit', String(pageSize));
    params.set('offset', String(page * pageSize));

    apiFetch<AuditLogEntry[]>(`${API_BASE}/api/v0/producer/audit-logs?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data: AuditLogEntry[]) => {
        setLogs(data);
        setTotalCount(data.length);
      })
      .catch((err) => setError(err instanceof Error ? err.message : t('admin.dashboard.load_failed')))
      .finally(() => setLoading(false));
  }, [token, action, targetId, startDate, endDate, page, pageSize]);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError(t('admin.auth_required'));
      return;
    }
    fetchLogs();
  }, [user, token, authLoading, fetchLogs]);

  const handleSearch = () => {
    setPage(0);
    fetchLogs();
  };

  const hasMore = logs.length === pageSize;

  if (authLoading) return null;

  return (
    <div className="admin-page">
      <nav className="admin-nav">
        <button onClick={() => router.push('/admin')} className="link-btn">
          {t('admin.back_to_dashboard')}
        </button>
      </nav>

      <div className="admin-section-header">
        <h1>{t('admin.audit.title')}</h1>
        <p>{t('admin.audit.subtitle')}</p>
      </div>

      <div className="admin-filter-row">
        <div className="admin-filter-item">
          <select
            className="admin-select"
            value={action}
            onChange={(e) => { setAction(e.target.value); setPage(0); }}
          >
            {actionOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div className="admin-filter-item">
          <input
            className="admin-filter-input"
            type="text"
            placeholder={t('admin.audit.target_id_placeholder')}
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          />
        </div>

        <div className="admin-filter-item">
          <label className="admin-filter-label">{t('admin.audit.start_date')}</label>
          <input
            className="admin-filter-date"
            type="date"
            value={startDate}
            onChange={(e) => { setStartDate(e.target.value); setPage(0); }}
          />
        </div>

        <div className="admin-filter-item">
          <label className="admin-filter-label">{t('admin.audit.end_date')}</label>
          <input
            className="admin-filter-date"
            type="date"
            value={endDate}
            onChange={(e) => { setEndDate(e.target.value); setPage(0); }}
          />
        </div>

        <div className="admin-filter-item">
          <button className="btn btn-primary btn-sm admin-search-btn" onClick={handleSearch}>
            {t('admin.audit.search_btn')}
          </button>
        </div>
      </div>

      {loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>{t('common.loading')}</h3>
        </div>
      )}

      {error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && logs.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4CB;</div>
          <h3>{t('admin.audit.empty')}</h3>
          <p>{t('admin.audit.empty_hint')}</p>
        </div>
      )}

      {!loading && !error && logs.length > 0 && (
        <>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>{t('admin.audit.col_timestamp')}</th>
                  <th>{t('admin.audit.col_action')}</th>
                  <th>{t('admin.audit.col_target_type')}</th>
                  <th>{t('admin.audit.col_target_id')}</th>
                  <th>{t('admin.audit.col_operator')}</th>
                  <th>{t('admin.audit.col_detail')}</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <React.Fragment key={log.id}>
                  <tr key={log.id}>
                    <td data-label={t('admin.audit.col_timestamp')}>{formatDate(log.timestamp)}</td>
                    <td data-label={t('admin.audit.col_action')}>
                      <span className={`status-badge ${log.action}`}>
                        {actionLabels[log.action] || log.action}
                      </span>
                    </td>
                    <td data-label={t('admin.audit.col_target_type')} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                      {log.target_type}
                    </td>
                    <td data-label={t('admin.audit.col_target_id')} className="admin-mono-cell">
                      {log.target_id}
                    </td>
                    <td data-label={t('admin.audit.col_operator')}>
                      {log.operator_name || log.operator_id}
                    </td>
                    <td data-label={t('admin.audit.col_detail')} className="admin-detail-cell" style={{ cursor: 'pointer' }} onClick={() => {
                      const detailStr = log.detail ? JSON.stringify(log.detail, null, 2) : '';
                      const el = document.getElementById(`detail-${log.id}`);
                      if (el) {
                        const isHidden = el.style.display === 'none';
                        el.style.display = isHidden ? 'block' : 'none';
                      }
                    }}>
                      {log.detail
                        ? JSON.stringify(log.detail).slice(0, 60) +
                          (JSON.stringify(log.detail).length > 60 ? '...' : '')
                        : '—'}
                      {log.detail && JSON.stringify(log.detail).length > 60 && (
                        <span style={{ fontSize: '0.7rem', marginLeft: '0.3rem', opacity: 0.5 }}>&#x25BC;</span>
                      )}
                    </td>
                  </tr>
                  {log.detail && (
                    <tr key={`detail-${log.id}`} id={`detail-${log.id}`} style={{ display: 'none' }}>
                      <td colSpan={6} style={{ padding: '0.75rem 1.25rem', background: 'var(--color-paper-1)' }}>
                        <pre style={{
                          margin: 0,
                          fontSize: '0.78rem',
                          fontFamily: 'var(--font-mono)',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          color: 'var(--color-ink)',
                          maxHeight: '300px',
                          overflowY: 'auto',
                        }}>{JSON.stringify(log.detail, null, 2)}</pre>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <div className="pagination-info">
              {t('admin.audit.total_count', { count: totalCount + page * pageSize })}
            </div>

            <div className="pagination-controls">
              <span className="pagination-select-label">{t('admin.audit.per_page')}</span>
              <select
                className="admin-select pagination-select"
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
              <span className="pagination-select-label">{t('admin.audit.per_page_unit')}</span>

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                {t('admin.audit.prev_page')}
              </button>

              <span className="pagination-page-num">{t('admin.audit.page_num', { page: page + 1 })}</span>

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => p + 1)}
                disabled={!hasMore}
              >
                {t('admin.audit.next_page')}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
