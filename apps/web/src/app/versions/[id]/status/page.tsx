'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/* ── 状态标签 ── */
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

/* ── 状态流转顺序 ── */
const STATUS_ORDER = [
  'draft', 'submitted', 'scanning', 'pending_review',
  'approved', 'published',
];

const TERMINAL_BAD: Record<string, string> = {
  rejected: '已驳回',
  scan_failed: '扫描失败',
};

/* ── 严重度映射 ── */
const SEVERITY_CLASS: Record<string, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

/* ── 审核结论标签 ── */
const CONCLUSION_LABELS: Record<string, { text: string; className: string }> = {
  approved: { text: '审核通过', className: 'conclusion-approved' },
  rejected: { text: '已驳回', className: 'conclusion-rejected' },
  changes_requested: { text: '需要修改', className: 'conclusion-changes_requested' },
};

/* ── 评分等级 ── */
function getGradeClass(score: number | null): string {
  if (score === null) return '';
  if (score >= 80) return 'grade-A';
  if (score >= 60) return 'grade-B';
  if (score >= 40) return 'grade-C';
  if (score >= 20) return 'grade-D';
  return 'grade-F';
}

function getGrade(score: number | null): string {
  if (score === null) return '—';
  if (score >= 80) return 'A';
  if (score >= 60) return 'B';
  if (score >= 40) return 'C';
  if (score >= 20) return 'D';
  return 'F';
}

/* ── 扫描发现接口 ── */
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
  score: number | null;
  level?: string;
  grade?: string;
  recommendation?: string;
  dimensions?: Record<string, number>;
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

export default function StatusPage() {
  const params = useParams();
  const router = useRouter();
  const versionId = params.id as string;

  const [detail, setDetail] = useState<VersionDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

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
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '加载失败');
    }
  }, [versionId]);

  useEffect(() => {
    setLoading(true);
    fetchDetail().finally(() => setLoading(false));
  }, [fetchDetail]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchDetail();
    setRefreshing(false);
  };

  /* ── 构建时间线 ── */
  const buildTimeline = () => {
    if (!detail) return [];
    const current = detail.status;
    const stages: { key: string; label: string; phase: 'done' | 'active' | 'pending' | 'rejected' }[] = [];

    // 遍历标准流转
    for (const s of STATUS_ORDER) {
      const idx = STATUS_ORDER.indexOf(s);
      const curIdx = STATUS_ORDER.indexOf(current);
      let phase: 'done' | 'active' | 'pending' | 'rejected' = 'pending';

      if (current === s) phase = 'active';
      else if (curIdx > idx) phase = 'done';
      else if (TERMINAL_BAD[current] && idx <= STATUS_ORDER.indexOf('pending_review')) {
        // 如果当前是终态拒绝，已完成部分标记 done
        if (idx < curIdx || (curIdx === -1 && idx < STATUS_ORDER.indexOf('pending_review'))) phase = 'done';
      }

      stages.push({ key: s, label: STATUS_LABELS[s] || s, phase });
    }

    // 检查是否是坏终态
    if (TERMINAL_BAD[current]) {
      stages.push({
        key: current,
        label: TERMINAL_BAD[current],
        phase: 'rejected',
      });
    }

    // 如果状态不在标准流转中（如 changes_requested），追加
    if (!STATUS_ORDER.includes(current) && !TERMINAL_BAD[current]) {
      stages.push({
        key: current,
        label: STATUS_LABELS[current] || current,
        phase: 'active',
      });
    }

    return stages;
  };

  /* ── 渲染 ── */
  if (loading) {
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
  const grade = getGrade(detail.trust_score?.score ?? null);
  const gradeClass = getGradeClass(detail.trust_score?.score ?? null);
  const conclusion = detail.review_conclusion;
  const conclusionMeta = conclusion ? CONCLUSION_LABELS[conclusion] : null;

  return (
    <div className="status-page">
      {/* 头部 */}
      <div className="status-header">
        <h1>{detail.version ? `v${detail.version}` : '版本状态'}</h1>
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

      {/* 刷新栏 */}
      <div className="status-refresh">
        <span className="status-refresh-meta">
          当前状态: <strong style={{ color: 'var(--color-ink)' }}>{statusLabel}</strong>
          {detail.submitted_at && (
            <> · 提交于 {new Date(detail.submitted_at).toLocaleString('zh-CN')}</>
          )}
        </span>
        <button className="btn btn-sm btn-secondary" onClick={handleRefresh} disabled={refreshing}>
          {refreshing ? '刷新中...' : '\u21BB 刷新状态'}
        </button>
      </div>

      {/* 时间线 */}
      <div className="timeline">
        {timeline.map((stage) => (
          <div key={stage.key} className="timeline-stage">
            <div className={`timeline-dot ${stage.phase}`} />
            <div className="timeline-stage-header">
              <span className="timeline-stage-number">
                {STATUS_ORDER.indexOf(stage.key) >= 0
                  ? `${STATUS_ORDER.indexOf(stage.key) + 1}.0`
                  : '··'}
              </span>
              <span className="timeline-stage-label">{stage.label}</span>
            </div>
            {stage.phase === 'active' && detail.status === 'scanning' && (
              <p className="timeline-stage-desc">
                系统正在对您的代码进行安全扫描，包括提示注入检测、危险命令识别和凭据泄露检查...
              </p>
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

      {/* 信任评分 */}
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
                      {typeof val === 'number' ? val.toFixed(1) : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 扫描发现 */}
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

      {/* 扫描中提示 */}
      {(!detail.scan_summary || !detail.scan_summary.findings) && detail.status === 'scanning' && (
        <div className="empty-state" style={{ padding: '2rem 0' }}>
          <p>扫描进行中，完成后将自动展示发现详情。</p>
        </div>
      )}

      {/* 审核结论 */}
      {conclusionMeta && (
        <div className={`review-conclusion ${conclusionMeta.className}`}>
          <div className="review-conclusion-header">
            <span className="review-conclusion-badge">{conclusionMeta.text}</span>
          </div>
        </div>
      )}

      {/* 底部返回 */}
      <div style={{ marginTop: '2rem', textAlign: 'center' }}>
        <button className="btn btn-secondary" onClick={() => router.back()}>
          返回
        </button>
      </div>
    </div>
  );
}
