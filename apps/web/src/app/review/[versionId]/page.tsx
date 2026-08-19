'use client';

import { useState, useEffect, useMemo, useRef } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import TrustScoreDetail from '@/components/TrustScoreDetail';
import GradeOverrideModal from '@/components/GradeOverrideModal';
import { toast } from 'sonner';
import type {
  Finding, ScanSummary, TrustScore, VersionDetail, ReviewRecord,
  PackagePermissions, PackageAuthor, PackageDetail, FindingLocation,
} from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface FileGroup {
  file: string;
  items: Finding[];
}


const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CODE_CONTEXT_RANGE = 50;

function formatDate(iso: string | null | undefined): string {
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

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname + u.pathname;
  } catch {
    return url.length > 50 ? url.slice(0, 50) + '…' : url;
  }
}

function FindingCodeView({
  finding,
  fileContents,
  versionId,
}: {
  finding: Finding;
  fileContents?: Record<string, string>;
  versionId: string;
}) {
  const { t } = useTranslation();
  const targetRef = useRef<HTMLDivElement>(null);
  const fileContent = fileContents?.[finding.location?.file || ''];

  useEffect(() => {
    if (targetRef.current) {
      targetRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, []);

  if (!fileContent) {
    return finding.location?.snippet ? (
      <div className="finding-snippet">
        <pre><code>{finding.location.snippet}</code></pre>
      </div>
    ) : null;
  }

  const lines = fileContent.split('\n');
  const targetLine = finding.location?.line || 1;
  const displayStart = Math.max(1, targetLine - CODE_CONTEXT_RANGE);
  const displayEnd = Math.min(lines.length, targetLine + CODE_CONTEXT_RANGE);
  const displayLines = lines.slice(displayStart - 1, displayEnd);
  const lineNumWidth = String(displayEnd).length;
  const filePath = finding.location?.file || '';

  return (
    <div className="finding-snippet finding-snippet-expanded">
      <div className="finding-snippet-info">
        <span>{t('review.finding.lines_range', { start: displayStart, end: displayEnd, total: lines.length })}</span>
        <a
          className="finding-full-file-toggle"
          href={`/review/files?versionId=${encodeURIComponent(versionId)}&path=${encodeURIComponent(filePath)}&line=${targetLine}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t('review.finding.view_full_file')}
        </a>
      </div>
      <pre><code>
        {displayLines.map((line, i) => {
          const lineNum = displayStart + i;
          const isTarget = lineNum === targetLine;
          return (
            <div
              key={lineNum}
              ref={isTarget ? targetRef : undefined}
              className={`code-line ${isTarget ? 'code-line-target' : ''}`}
            >
              <span className="code-line-num">{String(lineNum).padStart(lineNumWidth, ' ')}</span>
              <span className="code-line-content">{line}</span>
            </div>
          );
        })}
      </code></pre>
    </div>
  );
}

export default function ReviewDetailPage() {
  const params = useParams();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const versionId = params.versionId as string;
  const returnTo = searchParams.get('returnTo') || '/review';

  const [version, setVersion] = useState<VersionDetail | null>(null);
  const [pkg, setPkg] = useState<PackageDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [filter, setFilter] = useState('all');
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [showCodeFor, setShowCodeFor] = useState<Record<string, boolean>>({});

  const [showModal, setShowModal] = useState(false);
  const [conclusion, setConclusion] = useState<string | null>(null);
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [reviewHistory, setReviewHistory] = useState<ReviewRecord[]>([]);
  const [showGradeModal, setShowGradeModal] = useState(false);

  const severityLabels: Record<string, string> = {
    critical: t('review.severity.critical'),
    high: t('review.severity.high'),
    medium: t('review.severity.medium'),
    low: t('review.severity.low'),
    info: t('review.severity.info'),
  };

  const statusLabels: Record<string, string> = {
    draft: t('review.status.draft'),
    scanning: t('review.status.scanning'),
    pending_review: t('review.status.pending_review'),
    approved: t('review.status.approved'),
    rejected: t('review.status.rejected'),
    changes_requested: t('review.status.changes_requested'),
    published: t('review.status.published'),
    yanked: t('review.status.yanked'),
    error: t('review.status.error'),
  };

  const severityFilters = [
    { value: 'all', label: t('review.severity_filter.all') },
    { value: 'critical', label: t('review.severity.critical') },
    { value: 'high', label: t('review.severity.high') },
    { value: 'medium', label: t('review.severity.medium') },
    { value: 'low', label: t('review.severity.low') },
    { value: 'info', label: t('review.severity.info') },
  ];

  const returnLabels: Record<string, string> = {
    '/admin/rejected': t('review.detail.return_rejected_list'),
    '/review': t('review.detail.return_pending_list'),
  };

  const canModifyGrade = (user?.role === 'admin' || user?.role === 'reviewer')
    && version && !['draft', 'scanning', 'error'].includes(version.status);

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      router.replace('/login?redirect=' + encodeURIComponent('/review/' + versionId));
    }
  }, [authLoading, user, token, router, versionId]);

  useEffect(() => {
    if (!token || !versionId) return;

    let cancelled = false;
    const fetchData = async () => {
      try {
        const vData = await apiFetch<VersionDetail>(`${API_BASE}/api/v0/producer/versions/${versionId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (cancelled) return;

        if (vData.package_id) {
          try {
            const pkgData = await apiFetch<PackageDetail>(`${API_BASE}/api/v0/producer/packages/${vData.package_id}`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            setPkg(pkgData);
          } catch { /* ignore */ }
        }

        setVersion(vData);

        apiFetch<ReviewRecord[]>(`${API_BASE}/api/v0/producer/versions/${versionId}/reviews`, {
          headers: { Authorization: `Bearer ${token}` },
        })
          .then((data) => { if (!cancelled) setReviewHistory(data); })
          .catch(() => {});

        const findings = vData.findings || [];
        const initCollapsed: Record<string, boolean> = {};
        const seen = new Set<string>();
        for (const f of findings) {
          const file = f.location?.file || '(unknown)';
          if (!seen.has(file)) {
            initCollapsed[file] = false;
            seen.add(file);
          }
        }
        setCollapsed(initCollapsed);
      } catch (err: unknown) {
        if (!cancelled) {
          setFetchError(err instanceof Error ? err.message : t('admin.dashboard.load_failed'));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    fetchData();
    return () => {
      cancelled = true;
    };
  }, [token, versionId]);

  const groupedFindings = useMemo<FileGroup[]>(() => {
    const findings = version?.findings || [];
    const groups: Record<string, Finding[]> = {};
    for (const f of findings) {
      const file = f.location?.file || '(unknown)';
      if (!groups[file]) groups[file] = [];
      groups[file].push(f);
    }
    return Object.entries(groups)
      .map(([file, items]) => ({ file, items }))
      .sort((a, b) => {
        const aMin = Math.min(...a.items.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
        const bMin = Math.min(...b.items.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
        return aMin - bMin;
      });
  }, [version?.findings]);

  const filteredGroups = useMemo(() => {
    if (filter === 'all') return groupedFindings;
    return groupedFindings
      .map((g) => ({
        ...g,
        items: g.items.filter((f) => f.severity === filter),
      }))
      .filter((g) => g.items.length > 0);
  }, [groupedFindings, filter]);

  const toggleFile = (file: string) => {
    setCollapsed((prev) => ({ ...prev, [file]: !prev[file] }));
  };

  const handleSubmitReview = async () => {
    if (!conclusion) return;
    if (
      (conclusion === 'rejected' || conclusion === 'changes_requested') &&
      !comment.trim()
    ) {
      setSubmitError(t('review.detail.comment_required'));
      return;
    }
    setSubmitError(null);
    setSubmitting(true);

    try {
      const res = await fetch(
        `${API_BASE}/api/v0/producer/versions/${versionId}/reviews`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ conclusion, comment: comment.trim() || null }),
        },
      );

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: t('review.detail.submit_error') }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      if (conclusion === 'approved') {
        toast.success(t('review.detail.toast_approved'), { description: t('review.detail.toast_approved_desc') });
      } else if (conclusion === 'rejected') {
        toast.error(t('review.detail.toast_rejected'), { description: t('review.detail.toast_rejected_desc') });
      } else if (conclusion === 'changes_requested') {
        toast(t('review.detail.toast_changes_requested'), { description: t('review.detail.toast_changes_desc') });
      }

      setShowModal(false);
      router.push('/review');
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : t('review.detail.submit_error'));
    } finally {
      setSubmitting(false);
    }
  };

  const isPending = version?.status === 'pending_review';
  const grade = version?.effective_grade ?? version?.trust_score?.risk_summary?.grade;

  const reviewResultLabel = version?.review_conclusion
    ? (version.review_conclusion === 'approved'
        ? t('review.status.approved')
        : version.review_conclusion === 'rejected'
          ? t('review.status.rejected')
          : version.review_conclusion === 'changes_requested'
            ? t('review.status.changes_requested')
            : version.review_conclusion)
    : null;

  if (loading || authLoading) {
    return (
      <div className="review-detail-page">
        <div className="review-detail-header skeleton">
          <div className="skeleton-bar" style={{ width: '60%' }} />
          <div className="skeleton-bar" style={{ width: '40%' }} />
        </div>
        <div className="review-detail-meta skeleton">
          <div className="skeleton-block" />
        </div>
        <div className="review-detail-findings skeleton">
          {[1, 2, 3].map((i) => (
            <div key={i} className="skeleton-block" />
          ))}
        </div>
      </div>
    );
  }

  if (fetchError) {
    return (
      <div className="review-detail-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{fetchError}</p>
          <button className="btn btn-secondary" onClick={() => router.push('/review')}>
            {returnLabels['/review']}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="review-detail-page">
      <nav className="review-detail-nav">
        <button onClick={() => router.push(returnTo)} className="link-btn">
          ← {returnLabels[returnTo] || t('review.detail.return_default')}
        </button>
        <button
          onClick={() => router.push(`/review/diff?versionId=${encodeURIComponent(versionId)}`)}
          className="link-btn"
        >
          代码变更 →
        </button>
        <span className="review-detail-nav-user">{user?.display_name || user?.email}</span>
      </nav>

      <div className="review-detail-bar">
        <div className="review-detail-bar-main">
          <div className="review-detail-bar-top">
            <h1 className="review-detail-bar-name">{pkg?.name || t('review.detail.loading_name')}</h1>
            {version?.effective_grade && (
              <span className={`grade-badge ${version.effective_grade.toLowerCase()}`}>
                {version.effective_grade}
                {version.manual_grade && '*'}
              </span>
            )}
            <span className={`status-badge ${version?.status}`}>
              {statusLabels[version?.status || ''] || version?.status}
            </span>
          </div>
          <div className="review-detail-bar-meta">
            {pkg?.type && (
              <span className="meta-chip">
                {t(`search.${pkg.type}`, '') || pkg.type}
              </span>
            )}
            <span>v{version?.version}</span>
            <span>{t('review.detail.submitted_at', { date: formatDate(version?.submitted_at) })}</span>
          </div>
          {version?.source?.repository_url && (
            <div className="review-detail-bar-repo">
              <a
                href={version.source.repository_url}
                target="_blank"
                rel="noopener noreferrer"
                className="repo-link"
              >
                {shortUrl(version.source.repository_url)}
              </a>
            </div>
          )}
          {grade && (
            <div className="review-detail-bar-grade-label">
              {t('review.detail.risk_level')}: {version?.effective_grade} — {grade}
            </div>
          )}
          {reviewResultLabel && (
            <div className="review-detail-bar-result">
              {t('review.detail.review_conclusion')}: {reviewResultLabel}
            </div>
          )}
        </div>

        <div className="review-detail-bar-action">
          {isPending ? (
            <button
              className="btn btn-primary btn-review-start"
              onClick={() => {
                setConclusion(null);
                setComment('');
                setSubmitError(null);
                setShowModal(true);
              }}
            >
              {t('review.detail.start_review_btn')}
            </button>
          ) : (
            reviewResultLabel && (
              <span className={`review-result-pill ${version?.review_conclusion || ''}`}>
                {reviewResultLabel}
              </span>
            )
          )}
        </div>
      </div>

      {version?.manual_grade && version.auto_grade && version.manual_grade !== version.auto_grade && (
        <div style={{
          marginBottom: '1rem', padding: '0.85rem 1.25rem',
          background: 'oklch(94% 0.03 85)',
          borderLeft: '4px solid var(--color-accent)',
          borderRadius: '0 var(--radius-md) var(--radius-md) 0',
          fontSize: '0.82rem', color: 'var(--color-ink)',
          display: 'flex', alignItems: 'center', gap: '1rem',
          flexWrap: 'wrap',
        }}>
          <span style={{ fontWeight: 600 }}>
            {t('review.detail.grade_overridden_banner', { from: version.auto_grade, to: version.manual_grade })}
          </span>
          {version.manual_grade_reason && (
            <span style={{ color: 'var(--color-muted)', fontSize: '0.76rem' }}>
              {t('review.detail.reason')}: {version.manual_grade_reason}
            </span>
          )}
          {version.manual_grade_by && (
            <span style={{ color: 'var(--color-muted)', fontSize: '0.72rem', marginLeft: 'auto' }}>
              {t('review.detail.modified_by', { name: version.manual_grade_by_name || version.manual_grade_by })}
            </span>
          )}
        </div>
      )}

      {version?.trust_score && (
        <section className="review-detail-section">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <h2 className="review-detail-section-title" style={{ margin: 0 }}>{t('review.detail.trust_score_title')}</h2>
            {canModifyGrade && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setShowGradeModal(true)}
              >
                {t('review.detail.override_grade_btn')}
              </button>
            )}
          </div>

          <div style={{
            display: 'flex', gap: '1.5rem', marginBottom: '1rem', flexWrap: 'wrap',
            padding: '0.75rem 1rem',
            background: 'var(--color-paper-2)',
            borderRadius: 'var(--radius-md)',
          }}>
            <div>
              <span style={{ fontSize: '0.7rem', color: 'var(--color-muted)', textTransform: 'uppercase' }}>{t('review.detail.auto_grade_label')}</span>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-ink)' }}>
                {version.auto_grade ? (
                  <span className={`grade-badge ${version.auto_grade.toLowerCase()}`}>{version.auto_grade}</span>
                ) : '—'}
              </div>
            </div>
            <div style={{ color: 'var(--color-muted)', alignSelf: 'center', fontSize: '1.2rem' }}>→</div>
            <div>
              <span style={{ fontSize: '0.7rem', color: 'var(--color-muted)', textTransform: 'uppercase' }}>
                {t('review.detail.manual_grade_label')} {version.manual_grade ? '' : `(${t('review.detail.manual_grade_none')})`}
              </span>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-ink)' }}>
                {version.manual_grade ? (
                  <span style={{ color: 'var(--color-ink)' }}>{version.manual_grade} *</span>
                ) : <span style={{ color: 'var(--color-muted)' }}>{t('review.detail.auto_grade_label')}</span>}
              </div>
            </div>
            <div style={{ color: 'var(--color-muted)', alignSelf: 'center', fontSize: '1.2rem' }}>=</div>
            <div>
              <span style={{ fontSize: '0.7rem', color: 'var(--color-muted)', textTransform: 'uppercase' }}>{t('review.detail.effective_grade_label')}</span>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-ink)' }}>
                {version.effective_grade ? (
                  <span className={`grade-badge ${version.effective_grade.toLowerCase()}`}>{version.effective_grade}</span>
                ) : '—'}
              </div>
            </div>
          </div>

          <TrustScoreDetail
            trustScore={version.trust_score}
            effectiveGrade={version.effective_grade}
            autoGrade={version.auto_grade}
            manualGrade={version.manual_grade}
            manualGradeReason={version.manual_grade_reason}
          />
        </section>
      )}

      {reviewHistory.length > 0 && (
        <section className="review-detail-section">
          <h2 className="review-detail-section-title">{t('review.detail.review_history_title', { count: reviewHistory.length })}</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {reviewHistory.map((record) => {
              const cLabels: Record<string, { label: string; color: string }> = {
                approved: { label: t('review.status.approved'), color: 'var(--color-success)' },
                rejected: { label: t('review.status.rejected'), color: 'var(--color-danger)' },
                changes_requested: { label: t('review.status.changes_requested'), color: 'var(--color-warning)' },
              };
              const c = cLabels[record.conclusion] || { label: record.conclusion, color: 'var(--color-muted)' };
              return (
                <div key={record.id} style={{
                  padding: '0.85rem 1rem',
                  borderLeft: `3px solid ${c.color}`,
                  background: 'var(--color-paper-2)',
                  borderRadius: '0 var(--radius-md) var(--radius-md) 0',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span style={{
                      display: 'inline-block',
                      padding: '0.1rem 0.5rem',
                      borderRadius: 'var(--radius-pill)',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      background: c.color,
                      color: '#fff',
                    }}>{c.label}</span>
                    <span style={{ fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                      {record.reviewer_display_name || record.reviewer_name || record.reviewer_id}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginLeft: 'auto' }}>
                      {formatDate(record.created_at)}
                    </span>
                  </div>
                  {record.comment && (
                    <p style={{ fontSize: '0.82rem', color: 'var(--color-ink)', margin: '0.25rem 0 0', lineHeight: 1.5 }}>
                      {record.comment}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      <section className="review-detail-section">
        <h2 className="review-detail-section-title">{t('review.detail.package_meta')}</h2>
        <div className="review-meta-grid">
          {pkg?.description && (
            <div className="review-meta-field full">
              <span className="review-meta-label">{t('review.detail.meta_description')}</span>
              <span className="review-meta-value">{pkg.description}</span>
            </div>
          )}
          {(version?.license || pkg?.license) && (
            <div className="review-meta-field">
              <span className="review-meta-label">{t('review.detail.meta_license')}</span>
              <span className="review-meta-value">{version?.license || pkg?.license}</span>
            </div>
          )}
          {pkg?.category && (
            <div className="review-meta-field">
              <span className="review-meta-label">{t('review.detail.meta_category')}</span>
              <span className="review-meta-value">{pkg.category}</span>
            </div>
          )}
          {(version?.author || pkg?.author) && (
            <div className="review-meta-field">
              <span className="review-meta-label">{t('review.detail.meta_author')}</span>
              <span className="review-meta-value">
                {(version?.author || pkg?.author) &&
                  ((version?.author || pkg?.author)!.name ||
                    (version?.author || pkg?.author)!.email ||
                    (version?.author || pkg?.author)!.url ||
                    '—')}
              </span>
            </div>
          )}
          {pkg?.keywords && pkg.keywords.length > 0 && (
            <div className="review-meta-field full">
              <span className="review-meta-label">{t('review.detail.meta_keywords')}</span>
              <span className="review-meta-value">
                {pkg.keywords.map((kw) => (
                  <span key={kw} className="keyword-pill">
                    {kw}
                  </span>
                ))}
              </span>
            </div>
          )}
          {pkg?.homepage && (
            <div className="review-meta-field full">
              <span className="review-meta-label">{t('review.detail.meta_homepage')}</span>
              <span className="review-meta-value">
                <a href={pkg.homepage} target="_blank" rel="noopener noreferrer">
                  {pkg.homepage}
                </a>
              </span>
            </div>
          )}
        </div>

        {pkg?.permissions && Object.keys(pkg.permissions).length > 0 && (
          <>
            <h3 className="review-meta-subtitle">{t('review.detail.permissions_title')}</h3>
            <div className="review-meta-grid">
              {Object.entries(pkg.permissions).map(([key, value]) => (
                <div className="review-meta-field" key={key}>
                  <span className="review-meta-label">{key}</span>
                  <span
                    className={`review-meta-value permission-value ${
                      typeof value === 'string' && ['required', 'any', 'read+write'].includes(value)
                        ? 'danger'
                        : ''
                    }`}
                  >
                    {String(value)}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}

        {pkg?.installation && Object.keys(pkg.installation).length > 0 && (
          <>
            <h3 className="review-meta-subtitle">{t('review.detail.installation_title')}</h3>
            <pre className="review-code-block">
              {JSON.stringify(pkg.installation, null, 2)}
            </pre>
          </>
        )}
      </section>

      <section className="review-detail-section">
        <div className="review-findings-header">
          <h2 className="review-detail-section-title">
            {t('review.detail.scan_findings_title')} · {t('review.detail.scan_findings_title')} / {version?.scan_summary?.total ?? (version?.findings || []).length}
          </h2>

          <div className="findings-toolbar">
            <div className="findings-stats">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = version?.scan_summary?.[sev];
                if (!count) return null;
                return (
                  <span key={sev} className={`finding-stat-chip ${sev}`}>
                    {severityLabels[sev]} {count}
                  </span>
                );
              })}
            </div>
            <select
              className="review-select"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              {severityFilters.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {filteredGroups.length === 0 ? (
          <div className="empty-state small">
            <div className="empty-state-icon">&#x2705;</div>
            <h3>{t('review.detail.no_findings')}</h3>
          </div>
        ) : (
          <div className="findings-list">
            {filteredGroups.map((group) => (
              <div key={group.file} className="finding-file-group">
                <button
                  className="finding-file-header"
                  onClick={() => toggleFile(group.file)}
                >
                  <span className="finding-file-chevron">
                    {collapsed[group.file] ? '▸' : '▾'}
                  </span>
                  <span className="finding-file-name">{group.file}</span>
                  <span className="finding-file-count">
                    {t('review.detail.file_findings_count', { count: group.items.length })}
                  </span>
                </button>

                {!collapsed[group.file] && (
                  <div className="finding-file-body">
                    {group.items
                      .sort(
                        (a, b) =>
                          (SEVERITY_ORDER[a.severity] ?? 99) -
                          (SEVERITY_ORDER[b.severity] ?? 99),
                      )
                      .map((finding) => (
                         <div key={finding.id!} className={`finding-card ${finding.severity}`}>
                          <div className="finding-card-left" />
                          <div className="finding-card-body">
                            <div className="finding-card-header">
                              <span className={`finding-severity-chip ${finding.severity}`}>
                                {severityLabels[finding.severity] || finding.severity}
                              </span>
                              <span className="finding-rule-id">{finding.rule_id}</span>
                              <span className="finding-title-text">{finding.title}</span>
                              {finding.location?.line && (
                                <span className="finding-line">L{finding.location.line}</span>
                              )}
                            </div>

                            {finding.evidence && (
                              <div className="finding-evidence-line">{finding.evidence}</div>
                            )}

                            <div className="finding-actions">
                              {finding.location?.snippet && (
                                <button
                                  className="finding-code-toggle"
                                  onClick={() => {
                                    setShowCodeFor((prev) => ({
                                      ...prev,
                                      [finding.id!!]: !prev[finding.id!!],
                                    }));
                                  }}
                                >
                                  {showCodeFor[finding.id!!] ? t('review.finding.collapse_code') : t('review.finding.expand_code')}
                                </button>
                              )}
                              <div className="finding-meta-pills">
                                {finding.cwe_id && (
                                  <span className="finding-meta-pill cwe" title={finding.cwe_id}>CWE</span>
                                )}
                                {finding.remediation && (
                                  <span className="finding-meta-pill remediation" title={finding.remediation}>{t('review.finding.remediation')}</span>
                                )}
                              </div>
                            </div>

                            {showCodeFor[finding.id!] && (
                              <FindingCodeView
                                finding={finding}
                                fileContents={version?.scan_file_contents}
                                versionId={versionId}
                              />
                            )}
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {showModal && (
        <div className="modal-overlay" onClick={() => !submitting && setShowModal(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{t('review.detail.review_modal_title')}</h3>
              <button
                className="modal-close"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                ✕
              </button>
            </div>

            <div className="modal-conclusion-options">
              {[
                { value: 'approved', label: t('review.detail.option_approved'), desc: t('review.detail.option_approved_desc') },
                { value: 'rejected', label: t('review.detail.option_rejected'), desc: t('review.detail.option_rejected_desc') },
                {
                  value: 'changes_requested',
                  label: t('review.detail.option_changes_requested'),
                  desc: t('review.detail.option_changes_desc'),
                },
              ].map((opt) => (
                <button
                  key={opt.value}
                  className={`conclusion-option ${conclusion === opt.value ? 'selected' : ''} ${opt.value}`}
                  onClick={() => {
                    setConclusion(opt.value);
                    setSubmitError(null);
                  }}
                  disabled={submitting}
                >
                  <span className="conclusion-option-label">{opt.label}</span>
                  <span className="conclusion-option-desc">{opt.desc}</span>
                </button>
              ))}
            </div>

            {conclusion && (conclusion === 'rejected' || conclusion === 'changes_requested') && (
              <div className="modal-comment">
                <label className="modal-comment-label">
                  {t('review.detail.review_comment_label')} <span className="required-star">*</span>
                </label>
                <textarea
                  className="modal-comment-textarea"
                  rows={4}
                  placeholder={
                    conclusion === 'rejected'
                      ? t('review.detail.comment_placeholder_reject')
                      : t('review.detail.comment_placeholder_changes')
                  }
                  value={comment}
                  onChange={(e) => {
                    setComment(e.target.value);
                    setSubmitError(null);
                  }}
                  disabled={submitting}
                />
                {!comment.trim() && (
                  <span className="modal-comment-hint">{t('review.detail.comment_required')}</span>
                )}
              </div>
            )}

            {submitError && <div className="modal-error">{submitError}</div>}

            <div className="modal-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                {t('review.detail.cancel')}
              </button>
              <button
                className="btn btn-primary"
                onClick={handleSubmitReview}
                disabled={
                  submitting ||
                  !conclusion ||
                  ((conclusion === 'rejected' || conclusion === 'changes_requested') &&
                    !comment.trim())
                }
              >
                {submitting ? t('review.detail.submitting') : t('review.detail.submit_review')}
              </button>
            </div>
          </div>
        </div>
      )}

      {showGradeModal && token && version && (
        <GradeOverrideModal
          versionId={versionId}
          autoGrade={version.auto_grade ?? null}
          currentManualGrade={version.manual_grade ?? null}
          currentReason={version.manual_grade_reason ?? null}
          token={token}
          onClose={() => setShowGradeModal(false)}
          onComplete={() => {
            setShowGradeModal(false);
            window.location.reload();
          }}
        />
      )}
    </div>
  );
}
