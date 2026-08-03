'use client';

import { useEffect, useState, useCallback, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import type { Finding, ScanSummary, TrustScore, VersionDetail, ReviewRecord } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const SUPPORT_EMAIL = process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'support@trustedagenthub.com';

const POLL_INTERVAL_MS = 10_000;
const MAX_SCAN_POLLS = 18; // 18 × 10s = 3 分钟超时
const TERMINAL_STATUSES = new Set(['approved', 'published', 'yanked', 'rejected', 'changes_requested', 'error', 'scan_failed']);

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
  error: '扫描错误',
};

const STATUS_ORDER = [
  'draft', 'submitted', 'scanning', 'pending_review',
  'approved', 'published',
];

const TERMINAL_BAD: Record<string, string> = {
  rejected: '已驳回',
  changes_requested: '需要修改',
  scan_failed: '扫描失败',
  error: '扫描错误',
  yanked: '已下架',
};

const BAD_STOP_AT = 'pending_review';

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

function StatusContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const versionId = searchParams.get('vid') || '';
  const { user, token, loading: authLoading } = useAuth();

  const [detail, setDetail] = useState<VersionDetail | null>(null);
  const [packageName, setPackageName] = useState<string | null>(null);
  const [reviewComment, setReviewComment] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [scanTimedOut, setScanTimedOut] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollRef = useRef(0);

  const fetchDetail = useCallback(async () => {
    if (!token) return null;
    try {
      setError(null);
      setScanTimedOut(false);
      const res = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        if (res.status === 404) throw new Error('版本不存在');
        throw new Error(`请求失败 (${res.status})`);
      }
      const data = await res.json();
      setDetail(data);

      if (data.package_id && !packageName) {
        try {
          const pkgRes = await fetch(`${API_BASE}/api/v0/producer/packages/${data.package_id}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (pkgRes.ok) {
            const pkgData = await pkgRes.json();
            setPackageName(pkgData.name || null);
          }
        } catch { /* 包名获取失败不影响主流程 */ }
      }

      if (data.status === 'rejected' || data.status === 'changes_requested') {
        try {
          const reviewsRes = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/reviews`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (reviewsRes.ok) {
            const reviews: ReviewRecord[] = await reviewsRes.json();
            const latest = reviews[0];
            if (latest?.comment) setReviewComment(latest.comment);
          }
        } catch { /* 审核意见获取失败不影响主流程 */ }
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

    pollRef.current = 0;

    intervalRef.current = setInterval(async () => {
      pollRef.current += 1;
      if (pollRef.current >= MAX_SCAN_POLLS) {
        clearInterval(intervalRef.current!);
        intervalRef.current = null;
        setScanTimedOut(true);
        return;
      }
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

  const handleResubmit = async () => {
    if (!token || submitting) return;
    setSubmitting(true);
    setSubmitMsg(null);
    try {
      await apiFetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({}),
      });
      setSubmitMsg('已提交，正在扫描中...');
      setTimeout(() => fetchDetail(), 2000);
    } catch (err: unknown) {
      setSubmitMsg(err instanceof Error ? err.message : '提交失败');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateNewVersion = () => {
    if (!detail?.package_id) return;
    router.push(`/submit?packageId=${detail.package_id}`);
  };

  const RESUBMITABLE = new Set(['rejected', 'changes_requested', 'error', 'scan_failed']);

  const buildTimeline = () => {
    if (!detail) return [];
    const current = detail.status;
    const stages: { key: string; label: string; phase: 'done' | 'active' | 'pending' | 'rejected'; num: number }[] = [];
    const stopIdx = STATUS_ORDER.indexOf(BAD_STOP_AT);

    for (const s of STATUS_ORDER) {
      const idx = STATUS_ORDER.indexOf(s);
      const curIdx = STATUS_ORDER.indexOf(current);
      let phase: 'done' | 'active' | 'pending' | 'rejected' = 'pending';

      if (current === 'yanked') {
        phase = 'done';
      } else if (current === s) {
        phase = 'active';
      } else if (curIdx > idx) {
        phase = 'done';
      } else if (TERMINAL_BAD[current] && idx <= stopIdx) {
        phase = 'done';
      }

      stages.push({ key: s, label: STATUS_LABELS[s] || s, phase, num: idx + 1 });
    }

    if (TERMINAL_BAD[current]) {
      stages.push({
        key: current,
        label: STATUS_LABELS[current] || current,
        phase: 'rejected',
        num: stages.length + 1,
      });
    } else if (!STATUS_ORDER.includes(current)) {
      stages.push({
        key: current,
        label: STATUS_LABELS[current] || current,
        phase: 'active',
        num: stages.length + 1,
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
  const effectiveGrade = detail.effective_grade ?? detail.trust_score?.risk_summary?.grade ?? null;
  const grade = getGrade(effectiveGrade);
  const gradeClass = getGradeClass(effectiveGrade);
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

      {RESUBMITABLE.has(detail.status) && (
        <div className="status-action-bar">
          <button
            className="btn btn-primary btn-sm"
            onClick={handleResubmit}
            disabled={submitting || detail.status === 'scanning'}
          >
            {submitting ? '提交中...' : '重新提交'}
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={handleCreateNewVersion}
            disabled={!detail.package_id}
          >
            创建新版本
          </button>
          {submitMsg && (
            <span style={{ fontSize: '0.82rem', marginLeft: '0.75rem', color: submitMsg.includes('失败') ? 'var(--color-danger)' : 'var(--color-success)' }}>
              {submitMsg}
            </span>
          )}
        </div>
      )}

      {detail.status === 'yanked' && (
        <div className="status-alert">
          <div className="status-alert-title">&#x26A0; 该版本已被管理员下架</div>
          {detail.yank_reason && (
            <div className="status-alert-detail">
              <strong>下架原因：</strong>{detail.yank_reason}
            </div>
          )}
          <div className="status-alert-contact">
            如有任何疑问，请联系 {SUPPORT_EMAIL}
          </div>
        </div>
      )}

      {detail.status === 'error' && (
        <div className="status-alert">
          <div className="status-alert-title">&#x26A0; 扫描失败</div>
          {detail.scan_error && (
            <div className="status-alert-detail">
              {detail.scan_error}
            </div>
          )}
          <div className="status-alert-contact">
            请检查仓库链接是否有效，确认后在提交页面重新提交
          </div>
        </div>
      )}

      <div className="timeline">
        {timeline.map((stage) => (
          <div key={stage.key} className={`timeline-stage ${stage.key === detail.status ? `timeline-stage-${stage.key}` : ''}`}>
            <div className={`timeline-dot ${stage.phase}`} />
            <div className="timeline-stage-header">
              <span className="timeline-stage-number">
                {stage.num}.0
              </span>
              <span className="timeline-stage-label">{stage.label}</span>
            </div>
            {stage.phase === 'active' && isScanning && (
              <div className="scanning-block">
                {scanTimedOut ? (
                  <div className="status-alert">
                    <div className="status-alert-title">&#x23F0; 扫描超时</div>
                    <div className="status-alert-detail">
                      扫描已超过 3 分钟未完成，可能出现了异常。
                    </div>
                    <div className="status-alert-contact">
                      请稍后点击"刷新状态"查看结果，或联系 {SUPPORT_EMAIL}
                    </div>
                  </div>
                ) : (
                  <>
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
                  </>
                )}
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
            {stage.phase === 'rejected' && detail.status === 'changes_requested' && (
              <p className="timeline-stage-hint">
                修改后在提交页面重新提交即可
              </p>
            )}
            {stage.phase === 'rejected' && detail.status === 'rejected' && (
              <p className="timeline-stage-hint">
                该提交已被驳回，如有疑问请联系 {SUPPORT_EMAIL}
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
            {detail.trust_score.risk_summary?.level && (
              <p style={{ fontSize: '0.82rem', color: 'var(--color-ink-2)', marginBottom: '0.3rem' }}>
                风险等级: {detail.trust_score.risk_summary.level.replace(/_/g, ' ')}
              </p>
            )}
            {detail.auto_grade && detail.manual_grade && detail.manual_grade !== detail.auto_grade && (
              <p style={{ fontSize: '0.78rem', color: 'var(--color-accent)', marginBottom: '0.3rem' }}>
                审核员已将评级从 {detail.auto_grade} 手动调整为 {detail.manual_grade}
              </p>
            )}
            {detail.trust_score.risk_summary?.install_recommendation && (
              <p style={{ fontSize: '0.85rem', color: 'var(--color-ink-2)', marginBottom: '0.75rem' }}>
                安装建议: {detail.trust_score.risk_summary.install_recommendation}
              </p>
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
        scanTimedOut ? (
          <div className="empty-state">
            <div className="empty-state-icon">&#x23F0;</div>
            <h3>扫描超时</h3>
            <p>扫描已超过 3 分钟未完成，请点击上方"刷新状态"按钮重试</p>
          </div>
        ) : (
          <div className="scanning-block scanning-block-large">
            <div className="scanning-animation">
              <span className="scanning-dot" />
              <span className="scanning-dot" />
              <span className="scanning-dot" />
            </div>
            <p>扫描进行中，完成后将自动展示发现详情。</p>
            <p className="scanning-estimate">预计耗时 30–90 秒 · 页面每 10 秒自动刷新</p>
          </div>
        )
      )}

      {conclusionMeta && (
        <div className={`review-conclusion ${conclusionMeta.className}`}>
          <div className="review-conclusion-header">
            <span className="review-conclusion-badge">{conclusionMeta.text}</span>
          </div>
          {reviewComment && (
            <div className="review-conclusion-comment">
              <strong>审核意见：</strong>{reviewComment}
            </div>
          )}
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
