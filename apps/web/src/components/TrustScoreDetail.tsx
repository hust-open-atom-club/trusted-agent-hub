'use client';

interface DimensionItem {
  score: number;
  weight: number;
  details?: Record<string, unknown>;
}

interface ExplanationItem {
  dimension: string;
  message: string;
  deduction: number;
  evidence?: string;
}

interface TrustScoreData {
  score?: number;
  risk_summary?: {
    level?: string;
    grade?: string;
    top_risks?: string[];
    install_recommendation?: string;
  };
  dimensions?: Record<string, DimensionItem>;
  explanations?: ExplanationItem[];
  calculated_at?: string;
  model_version?: string;
}

const DIM_LABELS: Record<string, string> = {
  source_trust: '来源可信度',
  author_reputation: '作者信誉',
  metadata_completeness: '元数据完整度',
  permission_minimization: '权限最小化',
  scan_results: '扫描结果',
  manual_review: '人工审核',
  version_stability: '版本稳定性',
  user_feedback: '用户反馈',
  signature_verifiability: '签名验证',
};

function dimensionSummary(key: string, dets: Record<string, unknown> | undefined): string {
  if (!dets) return '—';
  switch (key) {
    case 'source_trust': {
      const verified = dets.is_verified_owner;
      const srcType = dets.source_type;
      const hasHash = dets.has_commit_hash;
      const parts: string[] = [];
      if (srcType) parts.push(`来源: ${srcType}`);
      if (hasHash) parts.push('commit 已锚定'); else parts.push('缺 commit');
      if (verified) parts.push('已验证 owner'); else parts.push('未验证 owner');
      return parts.join(' · ');
    }
    case 'author_reputation': {
      const pkgs = dets.packages_published;
      const avg = dets.avg_historical_score;
      const viol = dets.violations_count;
      if (!pkgs && !viol) return '新作者，无历史记录';
      return `发布 ${pkgs ?? 0} 包 · 均分 ${avg ?? 0} · 违规 ${viol ?? 0}`;
    }
    case 'metadata_completeness': {
      const missing = dets.missing_required_fields as string[] | undefined;
      const hasDesc = dets.has_description;
      const hasLic = dets.has_license;
      const hasKw = dets.has_keywords;
      if (missing && missing.length > 0) return `缺字段: ${missing.join(', ')}`;
      const status: string[] = [];
      if (!hasDesc) status.push('缺描述');
      if (!hasLic) status.push('缺许可证');
      if (!hasKw) status.push('缺关键词');
      return status.length ? status.join(', ') : '元数据完整';
    }
    case 'permission_minimization': {
      const total = dets.total_permissions;
      const high = dets.high_risk_permissions;
      return `声明 ${total ?? 0} 项权限 · 高风险 ${high ?? 0} 项`;
    }
    case 'scan_results': {
      const crit = dets.critical_findings ?? 0;
      const high = dets.high_findings ?? 0;
      const med = dets.medium_findings ?? 0;
      const low = dets.low_findings ?? 0;
      const passRate = dets.scan_pass_rate;
      const total = (crit as number) + (high as number) + (med as number) + (low as number);
      if (total === 0) return '扫描通过，无发现问题';
      return `严重 ${crit} · 高危 ${high} · 中危 ${med} · 低危 ${low} · 通过率 ${passRate ?? 0}%`;
    }
    case 'manual_review': {
      const status = dets.review_status;
      const count = dets.reviewer_count;
      const map: Record<string, string> = {
        approved: '已通过', rejected: '已驳回', unreviewed: '未审核',
        changes_requested: '需修改', pending: '待审核',
      };
      return `${map[String(status)] ?? status ?? '未审核'} · ${count ?? 0} 人已审`;
    }
    case 'version_stability': {
      const stable = dets.is_stable;
      const versions = dets.total_versions;
      return `${stable ? '稳定版' : '预览版'} · 共 ${versions ?? 1} 个版本`;
    }
    case 'user_feedback': {
      const rating = dets.avg_rating;
      const ratings = dets.total_ratings;
      const installs = dets.total_installs;
      if (!ratings && !installs) return '暂无用户反馈';
      return `均分 ${rating ?? 0} · ${ratings ?? 0} 评价 · ${installs ?? 0} 安装`;
    }
    case 'signature_verifiability': {
      const sig = dets.has_signature;
      const att = dets.has_attestation;
      const sbom = dets.has_sbom;
      const parts: string[] = [];
      if (sig) parts.push('有签名'); else parts.push('无签名');
      if (att) parts.push('有 attestation');
      if (sbom) parts.push('有 SBOM');
      return parts.join(' · ');
    }
    default:
      return '—';
  }
}

function scoreColor(s: number): string {
  if (s >= 80) return 'var(--color-success)';
  if (s >= 60) return 'var(--color-accent)';
  if (s >= 40) return 'var(--color-warning)';
  return 'var(--color-danger)';
}

function levelLabel(level: string | undefined): string {
  const m: Record<string, string> = {
    trusted: '可信任', low_risk: '低风险', medium_risk: '中风险',
    high_risk: '高风险', untrusted: '不可信',
  };
  return level ? (m[level] ?? level) : '未知';
}

export default function TrustScoreDetail({
  trustScore,
}: {
  trustScore: TrustScoreData | null | undefined;
}) {
  if (!trustScore) return null;

  const dims = trustScore.dimensions;
  const explanations = trustScore.explanations;
  const score = trustScore.score;
  const summary = trustScore.risk_summary;

  return (
    <div style={{
      background: 'var(--color-paper-2)',
      borderRadius: 'var(--radius-md)',
      border: '1px solid var(--color-rule)',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '1rem 1.25rem',
        borderBottom: '1px solid var(--color-rule)',
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-muted)' }}>
            综合得分
          </span>
          <span style={{
            fontSize: '1.4rem', fontWeight: 700,
            color: score != null ? scoreColor(score) : 'var(--color-muted)',
            fontVariantNumeric: 'tabular-nums',
          }}>
            {score != null ? score : '--'}
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>/ 100</span>
        </div>

        {summary?.level && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '0.3rem',
            padding: '0.15rem 0.6rem',
            borderRadius: 'var(--radius-pill)',
            fontSize: '0.75rem', fontWeight: 600,
            background: score != null && score < 40 ? 'oklch(88% 0.05 20)' : 'oklch(92% 0.03 140)',
            color: score != null && score < 40 ? 'oklch(40% 0.10 20)' : 'oklch(40% 0.10 140)',
          }}>
            {levelLabel(summary.level)}
          </div>
        )}
      </div>

      {dims && Object.keys(dims).length > 0 && (
        <table style={{
          width: '100%', borderCollapse: 'collapse',
          fontSize: '0.78rem',
        }}>
          <thead>
            <tr style={{
              borderBottom: '1px solid var(--color-rule)',
              color: 'var(--color-muted)',
              fontSize: '0.7rem',
              textTransform: 'uppercase',
            }}>
              <th style={thLeft}>维度</th>
              <th style={thRight}>得分</th>
              <th style={thRight}>权重</th>
              <th style={thLeft}>详情</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(dims).map(([key, dim]) => {
              const dets = dim.details as Record<string, unknown> | undefined;
              return (
                <tr key={key} style={{
                  borderBottom: '1px solid var(--color-rule)',
                }}>
                  <td style={{ ...td, fontWeight: 500, color: 'var(--color-ink)' }}>
                    {DIM_LABELS[key] ?? key}
                  </td>
                  <td style={{ ...td, textAlign: 'right', color: scoreColor(dim.score), fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
                    {dim.score}
                  </td>
                  <td style={{ ...td, textAlign: 'right', color: 'var(--color-muted)', fontVariantNumeric: 'tabular-nums' }}>
                    {Math.round(dim.weight * 100)}%
                  </td>
                  <td style={{ ...td, color: 'var(--color-ink-2)', maxWidth: '220px', fontSize: '0.73rem', lineHeight: 1.4 }}>
                    {dimensionSummary(key, dets)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {explanations && explanations.filter(e => e.deduction !== 0).length > 0 && (
        <div style={{ borderTop: '1px solid var(--color-rule)' }}>
          <div style={{
            padding: '0.6rem 1.25rem 0.3rem',
            fontSize: '0.7rem',
            fontWeight: 700,
            color: 'var(--color-muted)',
            textTransform: 'uppercase',
          }}>
            扣分明细
          </div>
          <div style={{ padding: '0 1.25rem 0.8rem' }}>
            {explanations.filter(e => e.deduction !== 0).map((exp, i) => (
              <div key={i} style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.5rem',
                padding: '0.3rem 0',
                fontSize: '0.75rem',
                lineHeight: 1.5,
              }}>
                <span style={{
                  flexShrink: 0,
                  color: exp.deduction < 0 ? 'var(--color-danger)' : 'var(--color-success)',
                  fontWeight: 700,
                  fontVariantNumeric: 'tabular-nums',
                  minWidth: '2.5rem',
                }}>
                  {exp.deduction > 0 ? '+' : ''}{exp.deduction}
                </span>
                <span style={{ color: 'var(--color-ink-2)' }}>
                  {exp.message}
                </span>
                {exp.evidence && (
                  <span style={{
                    color: 'var(--color-muted)',
                    fontSize: '0.68rem',
                    marginLeft: 'auto',
                    maxWidth: '200px',
                    textAlign: 'right',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}>
                    {exp.evidence.slice(0, 60)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const thLeft: React.CSSProperties = {
  padding: '0.5rem 0.75rem',
  textAlign: 'left',
  fontWeight: 600,
};
const thRight: React.CSSProperties = { ...thLeft, textAlign: 'right' };
const td: React.CSSProperties = {
  padding: '0.5rem 0.75rem',
  fontSize: '0.76rem',
};
