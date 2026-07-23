'use client';

import { useEffect, useState, useCallback, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const POLL_INTERVAL_MS = 10_000;
const TERMINAL_STATUSES = new Set(['approved', 'published', 'yanked', 'rejected', 'changes_requested', 'error']);

const STATUS_LABELS: Record<string, string> = {
  draft: '草稿',
  submitted: '已提交',
  scanning: '扫描中',
  pending_review: '等待审核',
  approved: '审核通过',
  published: '已发布',
  yanked: '已下架',
  rejected: '已驳回',
  changes_requested: '需要修改',
  scan_failed: '扫描失败',
};

const STATUS_ORDER = [
  'draft', 'submitted', 'scanning', 'pending_review',
  'approved', 'published',
];

const TERMINAL_BAD: Record<string, string> = {
  rejected: '已驳回',
  scan_failed: '扫描失败',
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

const CONCLUSION_LABELS: Record<string, { text: string; className: string }> = {
  approved: { text: '审核通过', className: 'conclusion-approved' },
  rejected: { text: '已驳回', className: 'conclusion-rejected' },
  changes_requested: { text: '需要修改', className: 'conclusion-changes_requested' },
};

function getGradeClass(grade: string | null): string {
  if (!grade) return '';
  return `grade-${grade}`;
}

function getGrade(grade: string | null): string {
  return grade ?? '\u2014';
}

interface Finding {
  rule_id: string;
  severity: string;
  title: string;
  file?: string;
  line?: number;
  evidence?: string;
  suggestion?: string;
}

interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  pass_rate?: number;
  findings?: Finding[];
}

interface TrustScore {
  level?: string;
  grade?: string;
  recommendation?: string;
  risk_summary?: {
    grade?: string;
    level?: string;
    top_risks?: string[];
    install_recommendation?: string;
  };
  dimensions?: Record<string, unknown>;
}

interface VersionDetail {
  id: string;
  package_id: string;
  version: string;
  status: string;
  source?: { repository_url?: string };
  description?: string;
  scan_summary?: ScanSummary | null;
  trust_score?: TrustScore | null;
  review_conclusion?: string | null;
  submitted_at?: string;
  created_at?: string;
}

function StatusContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const versionId = searchParams.get('vid') || '';
  const { user, loading: authLoading } = useAuth();

  const [detail, setDetail] = useState<VersionDetail | null>(null);
  const [packageName, setPackageName] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchDetail = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}`);
      if (!res.ok) {
        if (res.status === 404) throw new Error('版本不存在');
        throw new Error(`请求失败 (${res.status})`);
      }
      const data = await res.json();
      setDetail(data);

      if (data.package_id && !packageName) {
        try {
          const pkgRes = await fetch(`${API_BASE}/api/v0/producer/packages/${data.package_id}`);
          if (pkgRes.ok) {
            const pkgData = await pkgRes.json();
            setPackageName(pkgData.name || null);
          }
        } catch { /* 包名获取失败不影响主流程 */ }
      }

      return data;
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '加载失败');
      return null;
    }
  }, [versionId, packageName]);

  useEffect(() => {
    setLoading(true);
    fetchDetail().finally(() => setLoading(false));

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchDetail]);

  useEffect(() => {
    if (!detail) return;
    if (TERMINAL_STATUSES.has(detail.status)) {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      return;
    }

    if (intervalRef.current) return;

    intervalRef.current = setInterval(async () => {
      const latest = await fetchDetail();
      if (latest && TERMINAL_STATUSES.has(latest.status)) {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
      }
    }, POLL_INTERVAL_MS);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [detail?.status, fetchDetail]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchDetail();
    setRefreshing(false);
  };

  const buildTimeline = () => {
    if (!detail) return [];
    const current = detail.status;
    const stages: { key: string; label: string; phase: 'done' | 'active' | 'pending' | 'rejected' }[] = [];

    for (const s of STATUS_ORDER) {
      const idx = STATUS_ORDER.indexOf(s);
      const curIdx = STATUS_ORDER.indexOf(current);
      let phase: 'done' | 'active' | 'pending' | 'rejected' = 'pending';

      if (current === s) phase = 'active';
      else if (curIdx > idx) phase = 'done';
      else if (TERMINAL_BAD[current] && idx <= STATUS_ORDER.indexOf('pending_review')) {
        if (idx < curIdx || (curIdx === -1 && idx < STATUS_ORDER.indexOf('pending_review'))) phase = 'done';
      }

      stages.push({ key: s, label: STATUS_LABELS[s] || s, phase });
    }

    if (TERMINAL_BAD[current]) {
      stages.push({
        key: current,
        label: TERMINAL_BAD[current],
        phase: 'rejected',
      });
    }

    if (!STATUS_ORDER.includes(current) && !TERMINAL_BAD[current]) {
      stages.push({
        key: current,
        label: STATUS_LABELS[current] || current,
        phase: 'active',
      });
    }

    return stages;
  };

  if (authLoading || loading) {
    return (
      <div className="status-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="status-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{error || '版本不存在'}</h3>
          <p>请检查版本 ID 是否正确</p>
          <button className="btn btn-secondary" style={{ marginTop: '1rem' }} onClick={() => router.push('/')}>
            返回首页
          </button>
        </div>
      </div>
    );
  }

  const timeline = buildTimeline();
  const statusLabel = STATUS_LABELS[detail.status] || detail.status;
  const grade = getGrade(detail.trust_score?.risk_summary?.grade ?? null);
  const gradeClass = getGradeClass(detail.trust_score?.risk_summary?.grade ?? null);
  const conclusion = detail.review_conclusion;
  const conclusionMeta = conclusion ? CONCLUSION_LABELS[conclusion] : null;
  const pageTitle = packageName
    ? `${packageName} v${detail.version}`
    : detail.version
      ? `v${detail.version}`
      : '版本状态';
  const isScanning = detail.status === 'scanning';

  return (
    <div className="status-page">
      <div className="status-header">
        <h1>{pageTitle}</h1>
        <p>
          {detail.source?.repository_url ? (
            <span style={{ color: 'var(--color-muted)', fontSize: '0.83rem' }}>
              {detail.source.repository_url}
            </span>
          ) : detail.description ? (
            detail.description
          ) : (
            `版本 ID: ${versionId}`
          )}
        </p>
      </div>

      <div className="status-refresh">
        <span className="status-refresh-meta">
          当前状态: <strong style={{ color: 'var(--color-ink)' }}>{statusLabel}</strong>
          {detail.submitted_at && (
            <> · 提交于 {new Date(detail.submitted_at).toLocaleString('zh-CN')}</>
          )}
          {isScanning && (
            <span className="status-auto-refresh-hint"> · 每 10 秒自动刷新</span>
          )}
        </span>
        <button className="btn btn-sm btn-secondary" onClick={handleRefresh} disabled={refreshing}>
          {refreshing ? '刷新中...' : '\u21BB 刷新状态'}
        </button>
      </div>

      <div className="timeline">
        {timeline.map((stage) => (
          <div key={stage.key} className={`timeline-stage ${stage.key === detail.status ? `timeline-stage-${stage.key}` : ''}`}>
            <div className={`timeline-dot ${stage.phase}`} />
            <div className="timeline-stage-header">
              <span className="timeline-stage-number">
                {STATUS_ORDER.indexOf(stage.key) >= 0
                  ? `${STATUS_ORDER.indexOf(stage.key) + 1}.0`
                  : '\u00B7\u00B7'}
              </span>
              <span className="timeline-stage-label">{stage.label}</span>
            </div>
            {stage.phase === 'active' && isScanning && (
              <div className="scanning-block">
                <div className="scanning-animation">
                  <span className="scanning-dot" />
                  <span className="scanning-dot" />
                  <span className="scanning-dot" />
                </div>
                <p className="timeline-stage-desc">
                  系统正在对您的代码进行安全扫描，包括提示注入检测、危险命令识别和凭据泄露检查...
                </p>
                <p className="scanning-estimate">
                  预计耗时 30–90 秒 · 页面每 10 秒自动刷新
                </p>
              </div>
            )}
            {stage.phase === 'active' && detail.status === 'pending_review' && (
              <p className="timeline-stage-desc">
                扫描已完成，正在等待审核员审查您的提交。
              </p>
            )}
            {stage.phase === 'active' && detail.status === 'approved' && (
              <p className="timeline-stage-desc">
                审核已通过，等待管理员发布。
              </p>
            )}
          </div>
        ))}
      </div>

      {detail.trust_score && (
        <div className="trust-score-card">
          <div className={`trust-score-grade ${gradeClass}`}>
            {grade}
          </div>
          <div className="trust-score-detail">
            <h3>信任评分</h3>
            {detail.trust_score.recommendation && (
              <p style={{ fontSize: '0.85rem', color: 'var(--color-ink-2)', marginBottom: '0.75rem' }}>
                {detail.trust_score.recommendation}
              </p>
            )}
            {detail.trust_score.dimensions && (
              <div className="trust-score-dimensions">
                {Object.entries(detail.trust_score.dimensions).map(([key, val]) => (
                  <div key={key} className="trust-score-dim">
                    <span className="trust-score-dim-label">{key}</span>
                    <span className="trust-score-dim-value">
                       {typeof val === 'object' && val !== null
                         ? JSON.stringify(val)
                         : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {detail.scan_summary && detail.scan_summary.findings && detail.scan_summary.findings.length > 0 && (
        <div className="findings-section">
          <h2>
            扫描发现 ({detail.scan_summary.total} 项)
            {detail.scan_summary.pass_rate !== undefined && (
              <span style={{ fontSize: '0.83rem', fontWeight: 400, color: 'var(--color-muted)', marginLeft: '0.5rem' }}>
                通过率 {Math.round(detail.scan_summary.pass_rate * 100)}%
              </span>
            )}
          </h2>

          {detail.scan_summary.findings.map((f: Finding, i: number) => (
            <div key={i} className="finding-card">
              <div className="finding-card-header">
                <span className={`finding-rule-id ${SEVERITY_CLASS[f.severity] || ''}`}>
                  {f.rule_id}
                </span>
                <span className="finding-title">{f.title}</span>
                {f.file && (
                  <span className="finding-location">
                    {f.file}{f.line ? `:${f.line}` : ''}
                  </span>
                )}
              </div>
              {f.evidence && (
                <div className="finding-evidence">{f.evidence}</div>
              )}
              {f.suggestion && (
                <p className="finding-suggestion">{f.suggestion}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {(!detail.scan_summary || !detail.scan_summary.findings) && isScanning && (
        <div className="scanning-block scanning-block-large">
          <div className="scanning-animation">
            <span className="scanning-dot" />
            <span className="scanning-dot" />
            <span className="scanning-dot" />
          </div>
          <p>扫描进行中，完成后将自动展示发现详情。</p>
          <p className="scanning-estimate">预计耗时 30–90 秒 · 页面每 10 秒自动刷新</p>
        </div>
      )}

      {conclusionMeta && (
        <div className={`review-conclusion ${conclusionMeta.className}`}>
          <div className="review-conclusion-header">
            <span className="review-conclusion-badge">{conclusionMeta.text}</span>
          </div>
        </div>
      )}

      <div className="status-bottom-actions">
        {user && (
          <button className="btn btn-secondary" onClick={() => router.push('/submissions')}>
            我的提交列表
          </button>
        )}
        <button className="btn btn-secondary" onClick={() => router.push('/')}>
          返回首页
        </button>
      </div>
    </div>
  );
}

export default function StatusPage() {
  return (
    <Suspense fallback={<div className="status-page"><div className="empty-state"><div className="empty-state-icon">&#x23F3;</div><h3>加载中...</h3></div></div>}>
      <StatusContent />
    </Suspense>
  );
}
