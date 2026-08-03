'use client';

import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { fetchPackage, fetchPackageVersion, fetchPackageVersions, fetchTrustHistory } from '@/data/packages';
import type { Package, TrustHistoryPoint, VersionDetail, VersionSummary } from '@/types';
import ScoreBadge from '@/components/ScoreBadge';
import TypeBadge from '@/components/TypeBadge';
import StatusBadge from '@/components/StatusBadge';
import TrustScoreDetail from '@/components/TrustScoreDetail';
import FeedbackSection from '@/components/FeedbackSection';
import { useAuth } from '@/lib/auth';

const TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

const RISK_LEVEL_LABELS: Record<string, string> = {
  trusted: 'Trusted',
  low_risk: 'Low Risk',
  medium_risk: 'Medium Risk',
  high_risk: 'High Risk',
  untrusted: 'Untrusted',
};

function getGradeClass(grade: string | null): string {
  if (grade === null) return 'unknown';
  const g = grade.toUpperCase();
  if (g === 'A' || g === 'B') return 'trusted';
  if (g === 'C') return 'caution';
  return 'danger';
}

function DetailSkeleton() {
  return (
    <div className="detail-page">
      <div className="skeleton" style={{ marginBottom: '1.5rem' }}>
        <div className="skeleton-bar" style={{ width: '10rem' }} />
      </div>
      <div className="detail-header">
        <div className="detail-title-row">
          <div className="skeleton" style={{ flex: 1 }}>
            <div className="skeleton-bar" style={{ width: '16rem', height: '2rem' }} />
          </div>
        </div>
        <div className="skeleton" style={{ marginTop: '0.5rem' }}>
          <div className="skeleton-bar" style={{ width: '12rem' }} />
        </div>
        <div className="skeleton" style={{ marginTop: '0.75rem' }}>
          <div className="skeleton-bar" style={{ width: '100%' }} />
          <div className="skeleton-bar" style={{ width: '60%', marginTop: '0.25rem' }} />
        </div>
        <div className="detail-meta-grid" style={{ marginTop: '1rem' }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div className="detail-meta-item" key={i}>
              <div className="skeleton">
                <div className="skeleton-bar" style={{ width: '3rem', marginBottom: '0.25rem' }} />
                <div className="skeleton-bar" style={{ width: '5rem' }} />
              </div>
            </div>
          ))}
        </div>
      </div>
      {['Trust Score', 'Keywords', 'Permissions', 'Installation', 'Versions'].map((section) => (
        <div className="detail-section" key={section}>
          <div className="skeleton" style={{ marginBottom: '0.75rem' }}>
            <div className="skeleton-bar" style={{ width: '8rem', height: '1.25rem' }} />
          </div>
          <div className="skeleton">
            <div className="skeleton-bar" style={{ width: '70%' }} />
            <div className="skeleton-bar" style={{ width: '50%', marginTop: '0.3rem' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function PackageDetailPage() {
  const params = useParams();
  const router = useRouter();
  const name = decodeURIComponent(params.name as string);

  const { user, token } = useAuth();

  const [pkg, setPkg] = useState<Package | null | undefined>(undefined);
  const [versionDetail, setVersionDetail] = useState<VersionDetail | null>(null);
  const [versions, setVersions] = useState<VersionSummary[]>([]);
  const [trustHistory, setTrustHistory] = useState<TrustHistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setPkg(undefined);
    setVersionDetail(null);
    setVersions([]);
    setTrustHistory([]);

    fetchPackage(name)
      .then(async (p) => {
        setPkg(p);
        if (p) {
          // 并行获取版本详情和版本列表
          const [vDetail, vList, history] = await Promise.all([
            fetchPackageVersion(name, p.latest_version).catch(() => null),
            fetchPackageVersions(name).catch(() => []),
            fetchTrustHistory(name).catch(() => []),
          ]);
          setVersionDetail(vDetail);
          setVersions(vList as VersionSummary[]);
          setTrustHistory(history);
        }
      })
      .catch(() => setPkg(null))
      .finally(() => setLoading(false));
  }, [name]);

  if (loading) {
    return (
      <div className="detail-page">
        <button className="link-btn detail-back" onClick={() => router.push('/')}>
          &larr; Back to packages
        </button>
        <DetailSkeleton />
      </div>
    );
  }

  if (!pkg) {
    return (
      <div className="detail-page">
        <button className="link-btn detail-back" onClick={() => router.push('/')}>
          &larr; Back to packages
        </button>
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4E6;</div>
          <h3>Package not found</h3>
          <p>The package &quot;{name}&quot; does not exist.</p>
        </div>
      </div>
    );
  }

  const gradeClass = getGradeClass(pkg.grade);
  const riskLabel = pkg.risk_level
    ? (RISK_LEVEL_LABELS[pkg.risk_level] ?? pkg.risk_level)
    : 'Unknown';
  const typeLabel = TYPE_LABELS[pkg.type] ?? pkg.type;
  const ratingDisplay =
    pkg.avg_rating !== null ? pkg.avg_rating.toFixed(1) : 'N/A';

  const trustAdvice =
    pkg.grade === null
      ? 'This package has not been evaluated yet.'
      : pkg.grade === 'A'
        ? 'This package has passed all security scans and is safe to install.'
        : pkg.grade === 'B'
          ? 'Low risk. Review permissions before installing.'
          : pkg.grade === 'C'
            ? 'Medium risk. Review the details and confirm before installing.'
            : pkg.grade === 'D'
              ? 'High risk. Installation is not recommended without thorough review.'
              : 'Untrusted. Installation is blocked by safety policy.';

  const source = versionDetail?.source;
  const install = versionDetail?.installation;
  const perms = versionDetail?.permissions;
  const deps = versionDetail?.dependencies;
  const entry = versionDetail?.entry_points;
  const compat = versionDetail?.compatibility ?? [];
  const trustScore = versionDetail?.trust_score;

  return (
    <div className="detail-page">
      <button className="link-btn detail-back" onClick={() => router.push('/')}>
        &larr; Back to packages
      </button>

      {/* ── Header ── */}
      <div className="detail-header">
        <div className="detail-title-row">
          <h1 className="detail-name">{pkg.name}</h1>
          <TypeBadge type={pkg.type} />
          <StatusBadge status={pkg.status} />
        </div>
        {pkg.owner && (
          <p className="detail-owner">
            by <strong>{pkg.owner.display_name}</strong>
          </p>
        )}
        <p className="detail-description">{pkg.description}</p>

        <div className="detail-meta-grid">
          <div className="detail-meta-item">
            <span className="detail-meta-label">Version</span>
            <span className="detail-meta-value">v{pkg.latest_version}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">License</span>
            <span className="detail-meta-value">{pkg.license}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Type</span>
            <span className="detail-meta-value">{typeLabel}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Installs</span>
            <span className="detail-meta-value">
              {pkg.install_count.toLocaleString()}
            </span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Rating</span>
            <span className="detail-meta-value">
              &#11088; {ratingDisplay}
            </span>
          </div>
        </div>
      </div>

      {/* ── Source Repository ── */}
      {source && (
        <div className="detail-section">
          <h2>Source Repository</h2>
          <div className="detail-source-info">
            {source.repository_url && (
              <p>
                <strong>URL: </strong>
                <a
                  href={source.repository_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: 'var(--color-accent)' }}
                >
                  {source.repository_url}
                </a>
              </p>
            )}
            {source.ref && (
              <p>
                <strong>Ref: </strong>
                {source.ref_type ? `${source.ref_type} / ` : ''}
                {source.ref}
                {source.commit_hash && (
                  <code style={{ marginLeft: '0.5rem', fontSize: '0.78rem' }}>
                    {source.commit_hash.slice(0, 7)}
                  </code>
                )}
              </p>
            )}
            {source.verified_owner && (
              <p style={{ color: 'var(--color-success)', fontSize: '0.82rem' }}>
                &#x2713; Verified owner
              </p>
            )}
            {source.stars != null && (
              <p>
                <strong>Stars: </strong>&#11088; {source.stars}
              </p>
            )}
          </div>
        </div>
      )}

      {/* ── Compatibility ── */}
      {compat.length > 0 && (
        <div className="detail-section">
          <h2>Compatible Clients</h2>
          <div className="keyword-list">
            {compat.map((c) => (
              <span key={c} className="keyword-tag">{c}</span>
            ))}
          </div>
        </div>
      )}

      {/* ── Trust Score ── */}
      <div className="detail-section">
        <h2>Trust Score</h2>
        <div className={`trust-level ${gradeClass}`}>
          <ScoreBadge grade={pkg.grade} size="lg" />
          <div>
            <span className="trust-label">{riskLabel}</span>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-ink-2)', marginTop: 4 }}>
              {trustAdvice}
            </p>
          </div>
        </div>
        {trustScore && (
          <div style={{ marginTop: '1rem' }}>
            <TrustScoreDetail
              trustScore={trustScore}
              effectiveGrade={versionDetail?.effective_grade}
              autoGrade={versionDetail?.auto_grade}
              manualGrade={versionDetail?.manual_grade}
              manualGradeReason={versionDetail?.manual_grade_reason}
            />
          </div>
        )}

        {/* Risk summary top risks */}
        {trustScore?.risk_summary?.top_risks && trustScore.risk_summary.top_risks.length > 0 && (
          <div style={{ marginTop: '0.75rem' }}>
            <strong style={{ fontSize: '0.82rem' }}>Top Risks:</strong>
            <ul style={{ marginTop: '0.3rem', paddingLeft: '1.2rem' }}>
              {trustScore.risk_summary.top_risks.map((risk, i) => (
                <li key={i} style={{ fontSize: '0.8rem', color: 'var(--color-ink-2)', marginBottom: '0.2rem' }}>{risk}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Manual grade override */}
        {versionDetail?.manual_grade && versionDetail.manual_grade !== versionDetail.auto_grade && (
          <div style={{
            marginTop: '0.75rem',
            padding: '0.5rem 0.75rem',
            background: 'var(--color-accent-light, oklch(95% 0.02 250))',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.8rem',
          }}>
            &#x270E; Reviewer overrode grade from <strong>{versionDetail.auto_grade}</strong> to{' '}
            <strong>{versionDetail.manual_grade}</strong>
            {versionDetail.manual_grade_reason && (
              <>: {versionDetail.manual_grade_reason}</>
            )}
          </div>
        )}
      </div>

      {/* ── Scan Findings ── */}
      {/* Trust Score History */}
      {trustHistory.length > 0 && (
        <div className="detail-section">
          <h2>Trust Score History</h2>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: '0.82rem',
          }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--color-muted)' }}>
                <th style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>Version</th>
                <th style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>Score</th>
                <th style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>Grade</th>
                <th style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>Calculated</th>
              </tr>
            </thead>
            <tbody>
              {trustHistory.map((point) => (
                <tr key={point.version}>
                  <td style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>
                    <strong>v{point.version}</strong>
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>
                    {point.score !== null && point.score !== undefined ? point.score.toFixed(1) : '\u2014'}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)' }}>
                    {point.grade ?? '\u2014'}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--color-rule)', color: 'var(--color-muted)' }}>
                    {point.calculated_at
                      ? new Date(point.calculated_at).toLocaleString('en-US', {
                          year: 'numeric',
                          month: 'short',
                          day: 'numeric',
                        })
                      : '\u2014'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {versionDetail?.scan_report?.findings && versionDetail.scan_report.findings.length > 0 && (
        <div className="detail-section">
          <h2>
            Scan Findings ({versionDetail.scan_report.findings.length})
            {versionDetail.scan_report.summary && (
              <span style={{ fontSize: '0.83rem', fontWeight: 400, color: 'var(--color-muted)', marginLeft: '0.5rem' }}>
                Pass rate:{' '}
                {versionDetail.scan_report.summary.pass_rate != null
                  ? `${Math.round(Number(versionDetail.scan_report.summary.pass_rate))}%`
                  : 'N/A'}
              </span>
            )}
          </h2>
          <div className="findings-section">
            {versionDetail.scan_report.findings.map((f, i) => (
              <div key={f.id || i} className="finding-card">
                <div className="finding-card-header">
                  <span className={`finding-rule-id severity-${f.severity}`}>
                    {f.rule_id || f.category}
                  </span>
                  <span className="finding-title">{f.title}</span>
                  {f.location && (
                    <span className="finding-location">
                      {typeof f.location === 'object' && 'file' in f.location
                        ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
                        : ''}
                    </span>
                  )}
                </div>
                {f.evidence && (
                  <div className="finding-evidence">{f.evidence}</div>
                )}
                {f.description && (
                  <p className="finding-desc" style={{ fontSize: '0.8rem', color: 'var(--color-ink-2)', marginTop: '0.3rem' }}>
                    {f.description}
                  </p>
                )}
                {f.remediation && (
                  <p className="finding-suggestion">{f.remediation}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Permissions ── */}
      {perms && (
        <div className="detail-section">
          <h2>Permissions</h2>
          <div className="permissions-list">
            {perms.filesystem && (
              <div className="permission-group">
                <strong>Filesystem</strong>
                {perms.filesystem.read && perms.filesystem.read.length > 0 && (
                  <p>Read: {perms.filesystem.read.join(', ')}</p>
                )}
                {perms.filesystem.write && perms.filesystem.write.length > 0 && (
                  <p>Write: {perms.filesystem.write.join(', ')}</p>
                )}
                {perms.filesystem.delete && <p style={{ color: 'var(--color-danger)' }}>Can delete files</p>}
              </div>
            )}
            {perms.shell && (
              <div className="permission-group">
                <strong>Shell</strong>
                <p>{perms.shell.allowed ? 'Allowed' : 'Not allowed'}</p>
                {perms.shell.commands && perms.shell.commands.length > 0 && (
                  <p>Commands: {perms.shell.commands.join(', ')}</p>
                )}
                {perms.shell.description && (
                  <p style={{ color: 'var(--color-muted)', fontSize: '0.82rem' }}>{perms.shell.description}</p>
                )}
              </div>
            )}
            {perms.network && (
              <div className="permission-group">
                <strong>Network</strong>
                <p>{perms.network.allowed ? 'Allowed' : 'Not allowed'}</p>
                {perms.network.domains && perms.network.domains.length > 0 && (
                  <p>Domains: {perms.network.domains.join(', ')}</p>
                )}
              </div>
            )}
            {perms.environment && (
              <div className="permission-group">
                <strong>Environment</strong>
                {perms.environment.read && perms.environment.read.length > 0 && (
                  <p>Read: {perms.environment.read.join(', ')}</p>
                )}
                {perms.environment.write && perms.environment.write.length > 0 && (
                  <p style={{ color: 'var(--color-warning)' }}>Write: {perms.environment.write.join(', ')}</p>
                )}
              </div>
            )}
            {perms.credentials && (
              <div className="permission-group">
                <strong>Credentials</strong>
                {perms.credentials.access && perms.credentials.access.length > 0 && (
                  <p>Access: {perms.credentials.access.join(', ')}</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Dependencies ── */}
      {deps && (
        <div className="detail-section">
          <h2>Dependencies</h2>
          <div className="dependencies-list">
            {deps.npm && deps.npm.length > 0 && (
              <div className="permission-group">
                <strong>NPM</strong>
                <ul>
                  {deps.npm.map((d, i) => (
                    <li key={i}>{d.name || d.package || JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
            {deps.pip && deps.pip.length > 0 && (
              <div className="permission-group">
                <strong>Python (pip)</strong>
                <ul>
                  {deps.pip.map((d, i) => (
                    <li key={i}>{d.name || d.package || JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
            {deps.system && deps.system.length > 0 && (
              <div className="permission-group">
                <strong>System</strong>
                <ul>
                  {deps.system.map((d, i) => <li key={i}>{d}</li>)}
                </ul>
              </div>
            )}
            {deps.docker && deps.docker.length > 0 && (
              <div className="permission-group">
                <strong>Docker</strong>
                <ul>
                  {deps.docker.map((d, i) => (
                    <li key={i}>{d.image || d.name || JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
            {deps.mcp_servers && deps.mcp_servers.length > 0 && (
              <div className="permission-group">
                <strong>MCP Servers</strong>
                <ul>
                  {deps.mcp_servers.map((d, i) => (
                    <li key={i}>{d.name || JSON.stringify(d)}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Entry Points ── */}
      {entry && (entry.main || entry.config || (entry.scripts && entry.scripts.length > 0)) && (
        <div className="detail-section">
          <h2>Entry Points</h2>
          <div className="entry-points-info">
            {entry.main && <p><strong>Main: </strong><code>{entry.main}</code></p>}
            {entry.config && <p><strong>Config: </strong><code>{entry.config}</code></p>}
            {entry.scripts && entry.scripts.length > 0 && (
              <p><strong>Scripts: </strong>{entry.scripts.join(', ')}</p>
            )}
          </div>
        </div>
      )}

      {/* ── Installation ── */}
      <div className="detail-section">
        <h2>Installation</h2>
        {install?.pre_install_message && (
          <div className="install-pre-message" style={{
            padding: '0.75rem 1rem',
            background: 'var(--color-paper-2)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--color-warning-border, var(--color-rule))',
            marginBottom: '0.75rem',
            fontSize: '0.85rem',
            color: 'var(--color-warning)',
          }}>
            &#x26A0; {install.pre_install_message}
          </div>
        )}
        <p style={{ marginBottom: 12 }}>
          Install this {typeLabel.toLowerCase()} using the TrustedAgentHub CLI:
        </p>
        <div className="install-block">
          <span className="comment"># Install {pkg.name}</span>
          {'\n'}
          {install?.command
            ? install.command.replace('{name}', pkg.name)
            : `tah install ${pkg.name}`}
        </div>
        {install?.post_install_message && (
          <p style={{
            marginTop: 12,
            padding: '0.5rem 0.75rem',
            fontSize: '0.82rem',
            color: 'var(--color-success)',
          }}>
            &#x2713; {install.post_install_message}
          </p>
        )}
        {install?.targets && install.targets.length > 0 && (
          <div style={{ marginTop: '1rem' }}>
            <strong style={{ fontSize: '0.85rem' }}>Install Targets:</strong>
            <ul style={{ marginTop: '0.5rem' }}>
              {install.targets.map((t, i) => (
                <li key={i} style={{ fontSize: '0.82rem', marginBottom: '0.3rem' }}>
                  <strong>{t.client}</strong> → {t.destination}
                </li>
              ))}
            </ul>
          </div>
        )}
        {pkg.homepage && (
          <p style={{ marginTop: 16 }}>
            <strong>Homepage: </strong>
            <a
              href={pkg.homepage}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--color-accent)' }}
            >
              {pkg.homepage}
            </a>
          </p>
        )}
      </div>

      {/* ── Keywords ── */}
      {pkg.keywords.length > 0 && (
        <div className="detail-section">
          <h2>Keywords</h2>
          <div className="keyword-list">
            {pkg.keywords.map((kw) => (
              <span key={kw} className="keyword-tag">
                {kw}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Feedback ── */}
      <FeedbackSection
        packageName={pkg.name}
        user={user}
        token={token}
      />

      {/* ── Version History ── */}
      <div className="detail-section">
        <h2>Versions</h2>
        {versions.length > 0 ? (
          <ul>
            {versions.map((v) => (
              <li key={v.id} style={{ marginBottom: '0.5rem' }}>
                <strong>v{v.version}</strong>
                {v.version === pkg.latest_version && (
                  <span style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                    color: 'var(--color-accent)',
                    textTransform: 'uppercase',
                  }}>
                    latest
                  </span>
                )}
                <span style={{
                  marginLeft: '0.5rem',
                  fontSize: '0.75rem',
                  color: 'var(--color-muted)',
                }}>
                  ({v.status.replace(/_/g, ' ')})
                </span>
                {v.submitted_at && (
                  <span style={{ color: 'var(--color-muted)', marginLeft: 8, fontSize: '0.75rem' }}>
                    {new Date(v.submitted_at).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                  </span>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <ul>
            <li>
              <strong>v{pkg.latest_version}</strong> — latest
              {pkg.created_at && (
                <span style={{ color: 'var(--color-muted)', marginLeft: 8 }}>
                  ({new Date(pkg.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                  })})
                </span>
              )}
            </li>
          </ul>
        )}
      </div>
    </div>
  );
}
