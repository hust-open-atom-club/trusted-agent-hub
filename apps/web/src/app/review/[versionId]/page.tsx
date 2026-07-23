'use client';

import { useState, useEffect, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/* ── 类型定义 ── */

interface Location {
  file?: string;
  line?: number;
  snippet?: string;
}

interface Finding {
  id: string;
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  location?: Location;
  evidence?: string;
  remediation?: string;
  cwe_id?: string;
}

interface ScanSummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  pass_rate?: number;
}

interface TrustScore {
  risk_summary?: {
    grade?: string;
    level?: string;
    top_risks?: string[];
    install_recommendation?: string;
  };
  calculated_at?: string;
}

interface VersionDetail {
  id: string;
  package_id: string;
  version: string;
  status: string;
  source?: {
    type?: string;
    repository_url?: string;
    ref?: string;
    commit_hash?: string;
  };
  description?: string;
  scan_summary?: ScanSummary;
  findings?: Finding[];
  trust_score?: TrustScore;
  review_conclusion?: string | null;
  submitted_at?: string | null;
  created_at?: string | null;
}

interface ReviewRecord {
  id: string;
  version_id: string;
  reviewer_id: string;
  reviewer_name: string | null;
  reviewer_display_name: string | null;
  conclusion: string;
  comment: string | null;
  created_at: string;
}

interface Permissions {
  filesystem?: string;
  shell?: string;
  network?: string;
  env?: string;
  credentials?: string;
  [key: string]: string | undefined;
}

interface Author {
  name?: string;
  email?: string;
  url?: string;
}

interface PackageDetail {
  id: string;
  name: string;
  type: string;
  description: string;
  license?: string | null;
  keywords?: string[];
  category?: string | null;
  homepage?: string | null;
  icon_url?: string | null;
  author?: Author | null;
  permissions?: Permissions | null;
  installation?: Record<string, unknown> | null;
  compatibility?: string[];
}

interface FileGroup {
  file: string;
  items: Finding[];
}

/* ── 常量 ── */

const PACKAGE_TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

const STATUS_LABELS: Record<string, string> = {
  draft: '草稿',
  submitted: '已提交',
  scanning: '扫描中',
  pending_review: '待审核',
  approved: '已通过',
  rejected: '已驳回',
  changes_requested: '需修改',
  published: '已发布',
  yanked: '已下架',
  error: '扫描失败',
  scan_failed: '扫描失败',
};

const GRADE_LABELS: Record<string, string> = {
  A: '高度可信',
  B: '可信',
  C: '需注意',
  D: '有风险',
  E: '高风险',
  F: '严重风险',
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const SEVERITY_FILTERS = [
  { value: 'all', label: '全部' },
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
  { value: 'info', label: '信息' },
];

/* ── 工具函数 ── */

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

/* ── 组件 ── */

export default function ReviewDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();
  const versionId = params.versionId as string;

  /* ── 状态 ── */
  const [version, setVersion] = useState<VersionDetail | null>(null);
  const [pkg, setPkg] = useState<PackageDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Filtering
  const [filter, setFilter] = useState('all');

  // Finding 折叠：key = file path，value = 是否展开
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Modal
  const [showModal, setShowModal] = useState(false);
  const [conclusion, setConclusion] = useState<string | null>(null);
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [reviewHistory, setReviewHistory] = useState<ReviewRecord[]>([]);

  /* ── 登录检查 ── */
  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      router.replace('/login?redirect=' + encodeURIComponent('/review/' + versionId));
    }
  }, [authLoading, user, token, router, versionId]);

  /* ── 数据获取 ── */
  useEffect(() => {
    if (!token || !versionId) return;

    let cancelled = false;
    const fetchData = async () => {
      try {
        const [vRes] = await Promise.all([
          fetch(`${API_BASE}/api/v0/producer/versions/${versionId}`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        if (cancelled) return;

        if (!vRes.ok) {
          const err = await vRes.json().catch(() => ({ detail: '加载失败' }));
          throw new Error(err.detail || `HTTP ${vRes.status}`);
        }

        const vData: VersionDetail = await vRes.json();

        // 获取包详情
        if (vData.package_id) {
          const pRes = await fetch(`${API_BASE}/api/v0/producer/packages/${vData.package_id}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (pRes.ok) {
            setPkg(await pRes.json());
          }
        }

        setVersion(vData);

        // 获取审核历史
        fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/reviews`, {
          headers: { Authorization: `Bearer ${token}` },
        })
          .then((res) => res.ok ? res.json() : [])
          .then((data) => { if (!cancelled) setReviewHistory(data); })
          .catch(() => {});

        // 初始化文件折叠：默认全部展开
        const findings = vData.findings || [];
        const initCollapsed: Record<string, boolean> = {};
        const seen = new Set<string>();
        for (const f of findings) {
          const file = f.location?.file || '(未知文件)';
          if (!seen.has(file)) {
            initCollapsed[file] = false;
            seen.add(file);
          }
        }
        setCollapsed(initCollapsed);
      } catch (err: unknown) {
        if (!cancelled) {
          setFetchError(err instanceof Error ? err.message : '加载失败');
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

  /* ── Findings 按文件分组 ── */
  const groupedFindings = useMemo<FileGroup[]>(() => {
    const findings = version?.findings || [];
    const groups: Record<string, Finding[]> = {};
    for (const f of findings) {
      const file = f.location?.file || '(未知文件)';
      if (!groups[file]) groups[file] = [];
      groups[file].push(f);
    }
    // 按文件内最多的严重度排序
    return Object.entries(groups)
      .map(([file, items]) => ({ file, items }))
      .sort((a, b) => {
        const aMin = Math.min(...a.items.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
        const bMin = Math.min(...b.items.map((f) => SEVERITY_ORDER[f.severity] ?? 99));
        return aMin - bMin;
      });
  }, [version?.findings]);

  /* ── 按严重度筛选后的分组 ── */
  const filteredGroups = useMemo(() => {
    if (filter === 'all') return groupedFindings;
    return groupedFindings
      .map((g) => ({
        ...g,
        items: g.items.filter((f) => f.severity === filter),
      }))
      .filter((g) => g.items.length > 0);
  }, [groupedFindings, filter]);

  /* ── 切换文件折叠 ── */
  const toggleFile = (file: string) => {
    setCollapsed((prev) => ({ ...prev, [file]: !prev[file] }));
  };

  /* ── 审核提交 ── */
  const handleSubmitReview = async () => {
    if (!conclusion) return;
    if (
      (conclusion === 'rejected' || conclusion === 'changes_requested') &&
      !comment.trim()
    ) {
      setSubmitError('驳回或要求修改时，审核意见不能为空');
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
        const err = await res.json().catch(() => ({ detail: '提交失败' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      setShowModal(false);
      router.push('/review');
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : '提交失败');
    } finally {
      setSubmitting(false);
    }
  };

  /* ── 渲染帮助 ── */

  const isPending = version?.status === 'pending_review';
  const grade = version?.trust_score?.risk_summary?.grade;
  const gradeLabel = grade ? GRADE_LABELS[grade] : null;

  const reviewResultLabel = version?.review_conclusion
    ? (version.review_conclusion === 'approved'
        ? '已通过'
        : version.review_conclusion === 'rejected'
          ? '已驳回'
          : version.review_conclusion === 'changes_requested'
            ? '需修改'
            : version.review_conclusion)
    : null;

  /* ── Loading ── */
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

  /* ── Error ── */
  if (fetchError) {
    return (
      <div className="review-detail-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{fetchError}</p>
          <button className="btn btn-secondary" onClick={() => router.push('/review')}>
            ← 返回待审核列表
          </button>
        </div>
      </div>
    );
  }

  /* ── 主内容 ── */
  return (
    <div className="review-detail-page">
      {/* ── 返回导航 ── */}
      <nav className="review-detail-nav">
        <button onClick={() => router.push('/review')} className="link-btn">
          ← 返回待审核列表
        </button>
        <span className="review-detail-nav-user">{user?.username}</span>
      </nav>

      {/* ── 版本信息栏 ── */}
      <div className="review-detail-bar">
        <div className="review-detail-bar-main">
          <div className="review-detail-bar-top">
            <h1 className="review-detail-bar-name">{pkg?.name || '(加载中…)'}</h1>
            {grade && (
              <span className={`grade-badge ${grade.toLowerCase()}`} title={gradeLabel || ''}>
                {grade}
              </span>
            )}
            <span className={`status-badge ${version?.status}`}>
              {STATUS_LABELS[version?.status || ''] || version?.status}
            </span>
          </div>
          <div className="review-detail-bar-meta">
            {pkg?.type && (
              <span className="meta-chip">
                {PACKAGE_TYPE_LABELS[pkg.type] || pkg.type}
              </span>
            )}
            <span>v{version?.version}</span>
            <span>提交于 {formatDate(version?.submitted_at)}</span>
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
          {gradeLabel && (
            <div className="review-detail-bar-grade-label">
              风险等级：{grade} — {gradeLabel}
            </div>
          )}
          {reviewResultLabel && (
            <div className="review-detail-bar-result">
              审核结论：{reviewResultLabel}
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
              开始审核
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

      {/* ── 审核历史时间线 ── */}
      {reviewHistory.length > 0 && (
        <section className="review-detail-section">
          <h2 className="review-detail-section-title">审核历史（{reviewHistory.length}）</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {reviewHistory.map((record) => {
              const cLabels: Record<string, { label: string; color: string }> = {
                approved: { label: '通过', color: 'var(--color-success)' },
                rejected: { label: '驳回', color: 'var(--color-danger)' },
                changes_requested: { label: '需修改', color: 'var(--color-warning)' },
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

      {/* ── 包元数据 ── */}
      <section className="review-detail-section">
        <h2 className="review-detail-section-title">包元数据</h2>
        <div className="review-meta-grid">
          {pkg?.description && (
            <div className="review-meta-field full">
              <span className="review-meta-label">描述</span>
              <span className="review-meta-value">{pkg.description}</span>
            </div>
          )}
          {pkg?.license && (
            <div className="review-meta-field">
              <span className="review-meta-label">许可</span>
              <span className="review-meta-value">{pkg.license}</span>
            </div>
          )}
          {pkg?.category && (
            <div className="review-meta-field">
              <span className="review-meta-label">分类</span>
              <span className="review-meta-value">{pkg.category}</span>
            </div>
          )}
          {pkg?.author && (
            <div className="review-meta-field">
              <span className="review-meta-label">作者</span>
              <span className="review-meta-value">
                {pkg.author.name || pkg.author.email || pkg.author.url || '—'}
              </span>
            </div>
          )}
          {pkg?.keywords && pkg.keywords.length > 0 && (
            <div className="review-meta-field full">
              <span className="review-meta-label">关键词</span>
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
              <span className="review-meta-label">主页</span>
              <span className="review-meta-value">
                <a href={pkg.homepage} target="_blank" rel="noopener noreferrer">
                  {pkg.homepage}
                </a>
              </span>
            </div>
          )}
        </div>

        {/* 权限声明 */}
        {pkg?.permissions && Object.keys(pkg.permissions).length > 0 && (
          <>
            <h3 className="review-meta-subtitle">权限声明</h3>
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

        {/* 安装方式 */}
        {pkg?.installation && Object.keys(pkg.installation).length > 0 && (
          <>
            <h3 className="review-meta-subtitle">安装方式</h3>
            <pre className="review-code-block">
              {JSON.stringify(pkg.installation, null, 2)}
            </pre>
          </>
        )}
      </section>

      {/* ── 扫描发现 ── */}
      <section className="review-detail-section">
        <div className="review-findings-header">
          <h2 className="review-detail-section-title">
            扫描发现 · 共 {version?.scan_summary?.total ?? (version?.findings || []).length} 个
          </h2>

          {/* 严重度统计 + 筛选 */}
          <div className="findings-toolbar">
            <div className="findings-stats">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = version?.scan_summary?.[sev];
                if (!count) return null;
                return (
                  <span key={sev} className={`finding-stat-chip ${sev}`}>
                    {SEVERITY_LABELS[sev]} {count}
                  </span>
                );
              })}
            </div>
            <select
              className="review-select"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              {SEVERITY_FILTERS.map((f) => (
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
            <h3>未发现风险问题</h3>
          </div>
        ) : (
          <div className="findings-list">
            {filteredGroups.map((group) => (
              <div key={group.file} className="finding-file-group">
                {/* 文件标题栏（折叠切换） */}
                <button
                  className="finding-file-header"
                  onClick={() => toggleFile(group.file)}
                >
                  <span className="finding-file-chevron">
                    {collapsed[group.file] ? '▸' : '▾'}
                  </span>
                  <span className="finding-file-name">{group.file}</span>
                  <span className="finding-file-count">
                    {group.items.length} 个问题
                  </span>
                </button>

                {/* 文件下的 finding 列表 */}
                {!collapsed[group.file] && (
                  <div className="finding-file-body">
                    {group.items
                      .sort(
                        (a, b) =>
                          (SEVERITY_ORDER[a.severity] ?? 99) -
                          (SEVERITY_ORDER[b.severity] ?? 99),
                      )
                      .map((finding) => (
                        <div key={finding.id} className={`finding-card ${finding.severity}`}>
                          <div className="finding-card-left" />
                          <div className="finding-card-body">
                            <div className="finding-card-header">
                              <span className={`finding-severity-chip ${finding.severity}`}>
                                {SEVERITY_LABELS[finding.severity] || finding.severity}
                              </span>
                              <span className="finding-rule-id">{finding.rule_id}</span>
                              <span className="finding-title-text">{finding.title}</span>
                              {finding.location?.line && (
                                <span className="finding-line">L{finding.location.line}</span>
                              )}
                            </div>

                            {finding.location?.snippet && (
                              <div className="finding-snippet">
                                <pre><code>{finding.location.snippet}</code></pre>
                              </div>
                            )}

                            <div className="finding-details">
                              {finding.evidence && (
                                <div className="finding-detail-row">
                                  <span className="finding-detail-label">证据</span>
                                  <span className="finding-detail-value">{finding.evidence}</span>
                                </div>
                              )}
                              {finding.cwe_id && (
                                <div className="finding-detail-row">
                                  <span className="finding-detail-label">CWE</span>
                                  <span className="finding-detail-value">{finding.cwe_id}</span>
                                </div>
                              )}
                              {finding.remediation && (
                                <div className="finding-detail-row">
                                  <span className="finding-detail-label">修复建议</span>
                                  <span className="finding-detail-value">{finding.remediation}</span>
                                </div>
                              )}
                            </div>
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

      {/* ── 审核 Modal ── */}
      {showModal && (
        <div className="modal-overlay" onClick={() => !submitting && setShowModal(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>审核结论</h3>
              <button
                className="modal-close"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                ✕
              </button>
            </div>

            {/* 结论选择 */}
            <div className="modal-conclusion-options">
              {[
                { value: 'approved', label: '✅ 通过', desc: '审核通过，允许发布' },
                { value: 'rejected', label: '❌ 驳回', desc: '审核不通过，拒绝发布' },
                {
                  value: 'changes_requested',
                  label: '🔄 要求修改',
                  desc: '需要修改后重新提交',
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

            {/* 意见文本框 */}
            {conclusion && (conclusion === 'rejected' || conclusion === 'changes_requested') && (
              <div className="modal-comment">
                <label className="modal-comment-label">
                  审核意见 <span className="required-star">*</span>
                </label>
                <textarea
                  className="modal-comment-textarea"
                  rows={4}
                  placeholder={
                    conclusion === 'rejected'
                      ? '请详细说明驳回原因…'
                      : '请说明需要修改的内容…'
                  }
                  value={comment}
                  onChange={(e) => {
                    setComment(e.target.value);
                    setSubmitError(null);
                  }}
                  disabled={submitting}
                />
                {!comment.trim() && (
                  <span className="modal-comment-hint">驳回或要求修改时，审核意见不能为空</span>
                )}
              </div>
            )}

            {/* 错误提示 */}
            {submitError && <div className="modal-error">{submitError}</div>}

            {/* 操作按钮 */}
            <div className="modal-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setShowModal(false)}
                disabled={submitting}
              >
                取消
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
                {submitting ? '提交中…' : '提交审核'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
