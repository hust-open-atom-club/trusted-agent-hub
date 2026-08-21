'use client';

import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchPackage, fetchPackageVersion, fetchPackageVersions, fetchTrustHistory } from '@/data/packages';
import type {
  Dependencies,
  EntryPoints,
  Installation,
  Package,
  TrustHistoryPoint,
  VersionDetail,
  VersionPermissions,
  VersionSource,
  VersionSummary,
} from '@/types';
import {
  buildInstallCommand,
  getClientLabel,
  getClientTargetPath,
  getInstallMethodInfo,
  getSelectableClients,
} from '@/lib/install-info';
import ScoreBadge from '@/components/ScoreBadge';
import TypeBadge from '@/components/TypeBadge';
import StatusBadge from '@/components/StatusBadge';
import TrustScoreDetail from '@/components/TrustScoreDetail';
import FeedbackSection from '@/components/FeedbackSection';
import { fadeUp, listItem, listStagger, motion, pageStagger, softPanel } from '@/components/Motion';
import { useAuth } from '@/lib/auth';
import InstallCommandBlock from './InstallCommandBlock';
import PackageFileBrowser from './PackageFileBrowser';
import PackageIcon from './PackageIcon';
import PackageIntegrityPanel from './PackageIntegrityPanel';
import {
  getFeedbackSummary,
  getGradeClass,
  getPermissionSummary,
  type PermissionSummaryItem,
  getRiskLabelKey,
  getTrustAdvice,
  getTypeLabelKey,
} from './detail-view-model';

type Translate = (key: string, options?: Record<string, unknown>) => string;

function DetailSkeleton() {
  return (
    <div className="detail-page">
      <div className="skeleton detail-back-skeleton">
        <div className="skeleton-bar" />
      </div>
      <section className="detail-hero skeleton">
        <div className="detail-identity-mark" />
        <div className="detail-hero-copy">
          <div className="skeleton-bar detail-skeleton-title" />
          <div className="skeleton-bar detail-skeleton-line" />
          <div className="skeleton-bar detail-skeleton-wide" />
          <div className="detail-meta-grid">
            {Array.from({ length: 5 }).map((_, i) => (
              <div className="detail-meta-item" key={i}>
                <div className="skeleton-bar detail-skeleton-meta" />
                <div className="skeleton-bar detail-skeleton-value" />
              </div>
            ))}
          </div>
        </div>
      </section>
      <div className="detail-shell">
        <main className="detail-main">
          {Array.from({ length: 4 }).map((_, i) => (
            <section className="detail-section skeleton" key={i}>
              <div className="skeleton-bar detail-skeleton-heading" />
              <div className="skeleton-bar detail-skeleton-wide" />
              <div className="skeleton-bar detail-skeleton-line" />
            </section>
          ))}
        </main>
        <aside className="detail-rail">
          <div className="rail-card skeleton">
            <div className="skeleton-bar detail-skeleton-heading" />
            <div className="skeleton-block" />
          </div>
        </aside>
      </div>
    </div>
  );
}

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a className="detail-link" href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

function DetailSection({
  id,
  title,
  kicker,
  children,
}: {
  id: string;
  title: string;
  kicker?: string;
  children: ReactNode;
}) {
  return (
    <motion.section
      className="detail-section"
      id={id}
      variants={fadeUp}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, amount: 0.18 }}
    >
      <div className="detail-section-heading">
        <h2>{title}</h2>
        {kicker && <span>{kicker}</span>}
      </div>
      {children}
    </motion.section>
  );
}

function SourceSummary({
  source,
  homepage,
  t,
}: {
  source?: VersionSource | null;
  homepage?: string | null;
  t: Translate;
}) {
  if (!source && !homepage) {
    return <p className="detail-muted">{t('detail.empty.source')}</p>;
  }

  return (
    <div className="detail-info-list">
      {source?.repository_url && (
        <div className="detail-info-row">
          <span>{t('detail.source.repository')}</span>
          <ExternalLink href={source.repository_url}>{source.repository_url}</ExternalLink>
        </div>
      )}
      {homepage && (
        <div className="detail-info-row">
          <span>{t('detail.homepage')}</span>
          <ExternalLink href={homepage}>{homepage}</ExternalLink>
        </div>
      )}
      {source?.ref && (
        <div className="detail-info-row">
          <span>{t('detail.source.reference')}</span>
          <strong>
            {source.ref_type ? `${source.ref_type} / ` : ''}
            {source.ref}
            {source.commit_hash && <code>{source.commit_hash.slice(0, 7)}</code>}
          </strong>
        </div>
      )}
      {source?.verified_owner != null && (
        <div className="detail-info-row">
          <span>{t('detail.source.owner')}</span>
          <strong className={source.verified_owner ? 'detail-safe-text' : undefined}>
            {source.verified_owner ? t('detail.source.owner_verified') : t('detail.source.owner_unverified')}
          </strong>
        </div>
      )}
      {source?.stars != null && (
        <div className="detail-info-row">
          <span>{t('detail.stars')}</span>
          <strong>{source.stars.toLocaleString()}</strong>
        </div>
      )}
    </div>
  );
}

function PermissionDetails({ perms, t }: { perms?: VersionPermissions | null; t: Translate }) {
  if (!perms) {
    return <p className="detail-muted">{t('detail.empty.permissions')}</p>;
  }

  return (
    <div className="permissions-list">
      {perms.filesystem && (
        <div className="permission-group">
          <strong>{t('detail.filesystem')}</strong>
          {perms.filesystem.read?.length ? <p>{t('detail.permissions.read', { value: perms.filesystem.read.join(', ') })}</p> : null}
          {perms.filesystem.write?.length ? <p>{t('detail.permissions.write', { value: perms.filesystem.write.join(', ') })}</p> : null}
          {perms.filesystem.delete ? <p className="detail-danger-text">{t('detail.permissions.can_delete')}</p> : null}
          {!perms.filesystem.read?.length && !perms.filesystem.write?.length && !perms.filesystem.delete && (
            <p>{t('detail.permissions.no_filesystem')}</p>
          )}
        </div>
      )}
      {perms.shell && (
        <div className="permission-group">
          <strong>{t('detail.shell')}</strong>
          <p>{perms.shell.allowed ? t('detail.permissions.allowed') : t('detail.permissions.not_allowed')}</p>
          {perms.shell.commands?.length ? <p>{t('detail.permissions.commands', { value: perms.shell.commands.join(', ') })}</p> : null}
          {perms.shell.description && <p>{perms.shell.description}</p>}
        </div>
      )}
      {perms.network && (
        <div className="permission-group">
          <strong>{t('detail.network')}</strong>
          <p>{perms.network.allowed ? t('detail.permissions.allowed') : t('detail.permissions.not_allowed')}</p>
          {perms.network.domains?.length ? <p>{t('detail.permissions.domains', { value: perms.network.domains.join(', ') })}</p> : null}
          {perms.network.description && <p>{perms.network.description}</p>}
        </div>
      )}
      {perms.environment && (
        <div className="permission-group">
          <strong>{t('detail.environment')}</strong>
          {perms.environment.read?.length ? <p>{t('detail.permissions.read', { value: perms.environment.read.join(', ') })}</p> : null}
          {perms.environment.write?.length ? <p className="detail-warning-text">{t('detail.permissions.write', { value: perms.environment.write.join(', ') })}</p> : null}
        </div>
      )}
      {perms.credentials && (
        <div className="permission-group">
          <strong>{t('detail.credentials')}</strong>
          {perms.credentials.access?.length ? <p>{t('detail.permissions.access', { value: perms.credentials.access.join(', ') })}</p> : null}
          {perms.credentials.description && <p>{perms.credentials.description}</p>}
        </div>
      )}
    </div>
  );
}

function DependenciesDetails({ deps, t }: { deps?: Dependencies | null; t: Translate }) {
  if (!deps) {
    return <p className="detail-muted">{t('detail.empty.dependencies_manifest')}</p>;
  }

  const hasDependencies = Boolean(
    deps.npm?.length ||
    deps.pip?.length ||
    deps.system?.length ||
    deps.docker?.length ||
    deps.mcp_servers?.length,
  );

  if (!hasDependencies) {
    return <p className="detail-muted">{t('detail.empty.dependencies')}</p>;
  }

  return (
    <div className="dependencies-list">
      {deps.npm?.length ? (
        <div className="permission-group">
          <strong>NPM</strong>
          <ul>{deps.npm.map((d, i) => <li key={i}>{d.name || d.package || JSON.stringify(d)}</li>)}</ul>
        </div>
      ) : null}
      {deps.pip?.length ? (
        <div className="permission-group">
          <strong>Python (pip)</strong>
          <ul>{deps.pip.map((d, i) => <li key={i}>{d.name || d.package || JSON.stringify(d)}</li>)}</ul>
        </div>
      ) : null}
      {deps.system?.length ? (
        <div className="permission-group">
          <strong>System</strong>
          <ul>{deps.system.map((d, i) => <li key={i}>{d}</li>)}</ul>
        </div>
      ) : null}
      {deps.docker?.length ? (
        <div className="permission-group">
          <strong>Docker</strong>
          <ul>{deps.docker.map((d, i) => <li key={i}>{d.image || d.name || JSON.stringify(d)}</li>)}</ul>
        </div>
      ) : null}
      {deps.mcp_servers?.length ? (
        <div className="permission-group">
          <strong>MCP Servers</strong>
          <ul>{deps.mcp_servers.map((d, i) => <li key={i}>{d.name || JSON.stringify(d)}</li>)}</ul>
        </div>
      ) : null}
    </div>
  );
}

function EntryPointDetails({ entry, t }: { entry?: EntryPoints | null; t: Translate }) {
  if (!entry || (!entry.main && !entry.config && !entry.scripts?.length)) {
    return <p className="detail-muted">{t('detail.empty.entry_points')}</p>;
  }

  return (
    <div className="entry-points-info">
      {entry.main && <p><strong>{t('detail.main')}: </strong><code>{entry.main}</code></p>}
      {entry.config && <p><strong>{t('detail.config')}: </strong><code>{entry.config}</code></p>}
      {entry.scripts?.length ? <p><strong>{t('detail.scripts')}: </strong>{entry.scripts.join(', ')}</p> : null}
    </div>
  );
}

function InstallationDetails({
  install,
  deps,
  t,
}: {
  install?: Installation | null;
  deps?: Dependencies | null;
  t: Translate;
}) {
  if (!install) {
    return <p className="detail-muted">{t('detail.empty.installation')}</p>;
  }

  const methodInfo = getInstallMethodInfo(install.method);

  return (
    <div className="detail-info-list">
      <div className="detail-info-row">
        <span>{t('detail.install.method')}</span>
        <strong>{t(`detail.install_method.${methodInfo.key}.label`, { defaultValue: methodInfo.label })}</strong>
      </div>
      <p className="detail-muted">
        {t(`detail.install_method.${methodInfo.key}.description`, { defaultValue: methodInfo.description })}
      </p>
      {methodInfo.requiresExternalCommand && (
        <p className="install-warning">{t('detail.install.external_warning')}</p>
      )}
      {deps?.mcp_servers?.length ? (
        <p className="detail-muted">
          {t('detail.install.mcp_config_hint')}
        </p>
      ) : null}
      {install.pre_install_message && <p className="install-warning">{install.pre_install_message}</p>}
      {install.post_install_message && <p className="install-success">{install.post_install_message}</p>}
      {install.targets?.length ? (
        <div className="install-target-list">
          <strong>{t('detail.install_targets')}</strong>
          <ul>
            {install.targets.map((target, i) => (
              <li key={i}>
                <span>{target.client}</span>
                <code>{target.destination}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export default function PackageDetailPage() {
  const params = useParams();
  const router = useRouter();
  const name = decodeURIComponent(params.name as string);
  const { t, i18n } = useTranslation();
  const tt: Translate = (key, options) => String(t(key, options));
  const dateLocale = i18n.language === 'zh' ? 'zh-CN' : 'en-US';
  const permissionSummaryText = (item: PermissionSummaryItem) =>
    tt(
      item.valueKey,
      item.valueKey === 'detail.permission_summary.filesystem_access'
        ? {
            ...item.values,
            deleteAllowed: item.values.deleteAllowed
              ? tt('detail.permissions.allowed')
              : tt('detail.permissions.not_allowed'),
          }
        : item.values,
    );

  const { user, token } = useAuth();

  const [pkg, setPkg] = useState<Package | null | undefined>(undefined);
  const [versionDetail, setVersionDetail] = useState<VersionDetail | null>(null);
  const [versions, setVersions] = useState<VersionSummary[]>([]);
  const [trustHistory, setTrustHistory] = useState<TrustHistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedClient, setSelectedClient] = useState('claude-code');

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
          &larr; {tt('detail.back')}
        </button>
        <DetailSkeleton />
      </div>
    );
  }

  if (!pkg) {
    return (
      <div className="detail-page">
        <button className="link-btn detail-back" onClick={() => router.push('/')}>
          &larr; {tt('detail.back')}
        </button>
        <div className="empty-state">
          <div className="empty-state-icon">{tt('detail.package_label')}</div>
          <h3>{tt('detail.not_found')}</h3>
          <p>{tt('detail.not_found_hint', { name })}</p>
        </div>
      </div>
    );
  }

  const source = versionDetail?.source;
  const install = versionDetail?.installation;
  const integrity = versionDetail?.integrity;
  const perms = versionDetail?.permissions;
  const deps = versionDetail?.dependencies;
  const entry = versionDetail?.entry_points;
  const compat = versionDetail?.compatibility ?? [];
  const selectableClients = getSelectableClients(pkg.type, compat);
  const effectiveClient = selectableClients.includes(selectedClient)
    ? selectedClient
    : (selectableClients[0] ?? 'claude-code');
  const trustScore = versionDetail?.trust_score;
  const gradeClass = getGradeClass(pkg.grade);
  const riskLabel = tt(getRiskLabelKey(pkg.risk_level), { defaultValue: pkg.risk_level ?? tt('detail.unknown') });
  const typeLabel = tt(getTypeLabelKey(pkg.type), { defaultValue: pkg.type });
  const trustAdvice = tt(getTrustAdvice(pkg.grade));
  const permissionSummary = getPermissionSummary(perms);
  const feedbackSummary = getFeedbackSummary(pkg.feedback_counts);
  const installCommand = buildInstallCommand(pkg.name, selectableClients, install?.method, effectiveClient);
  const sourceLabel = source?.repository_url
    ? source.repository_url.replace(/^https?:\/\//, '')
    : pkg.homepage?.replace(/^https?:\/\//, '') ?? tt('detail.source_unavailable');
  const clientLabel = (client: string) => tt(`detail.client.${client}`, { defaultValue: getClientLabel(client) });

  return (
    <motion.div className="detail-page" variants={pageStagger} initial="hidden" animate="visible">
      <button className="link-btn detail-back" onClick={() => router.push('/')}>
        &larr; {tt('detail.back')}
      </button>

      <motion.section className="detail-hero" variants={softPanel}>
        <PackageIcon type={pkg.type} iconUrl={pkg.icon_url} label={pkg.name} />
        <div className="detail-hero-copy">
          <div className="detail-title-row">
            <h1 className="detail-name">{pkg.name}</h1>
            <TypeBadge type={pkg.type} />
            <StatusBadge status={pkg.status} />
          </div>
          <p className="detail-source-line">
            {sourceLabel}
            {pkg.owner && (
              <>
                <span aria-hidden="true"> / </span>
                <strong>{tt('detail.by_owner', { owner: pkg.owner.display_name })}</strong>
              </>
            )}
          </p>
          <p className="detail-description">{pkg.description}</p>
          <div className="detail-badge-row">
            <span className={`detail-risk-chip ${gradeClass}`}>
              {tt('detail.grade_risk', { grade: pkg.grade ?? '--', risk: riskLabel })}
            </span>
            {selectableClients.length > 0 && (
              <span className="detail-client-chip">
                {selectableClients.map(clientLabel).join(', ')}
              </span>
            )}
            {source?.verified_owner && <span className="detail-verified-chip">{tt('detail.verified_source')}</span>}
          </div>
          <div className="detail-meta-grid">
            <div className="detail-meta-item">
              <span className="detail-meta-label">{tt('detail.meta.version')}</span>
              <span className="detail-meta-value">v{pkg.latest_version}</span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">{tt('detail.meta.license')}</span>
              <span className="detail-meta-value">{pkg.license}</span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">{tt('detail.meta.type')}</span>
              <span className="detail-meta-value">{typeLabel}</span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">{tt('detail.meta.installs')}</span>
              <span className="detail-meta-value">{pkg.install_count.toLocaleString()}</span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">{tt('detail.meta.feedback')}</span>
              <span className="detail-meta-value">{tt(feedbackSummary.key, feedbackSummary.values)}</span>
            </div>
          </div>
        </div>
      </motion.section>

      <motion.div className="detail-shell" variants={pageStagger}>
        <motion.main className="detail-main" variants={pageStagger}>
          <DetailSection id="overview" title={tt('detail.nav.overview')} kicker={tt('detail.section.overview_kicker')}>
            <SourceSummary source={source} homepage={pkg.homepage} t={tt} />
            {compat.length > 0 && (
              <div className="detail-subsection">
                <h3>{tt('detail.compatible_clients')}</h3>
                <div className="keyword-list">
                  {compat.map((c) => <span key={c} className="keyword-tag">{clientLabel(c)}</span>)}
                </div>
              </div>
            )}
            {pkg.keywords.length > 0 && (
              <div className="detail-subsection">
                <h3>{tt('detail.keywords')}</h3>
                <div className="keyword-list">
                  {pkg.keywords.map((kw) => <span key={kw} className="keyword-tag">{kw}</span>)}
                </div>
              </div>
            )}
          </DetailSection>

          <DetailSection id="trust" title={tt('detail.trust_score')} kicker={riskLabel}>
            <div className={`trust-level ${gradeClass}`}>
              <ScoreBadge grade={pkg.grade} size="lg" />
              <div>
                <span className="trust-label">{riskLabel}</span>
                <p>{trustAdvice}</p>
              </div>
            </div>
            {trustScore ? (
              <div className="detail-trust-panel">
                <TrustScoreDetail
                  trustScore={trustScore}
                  effectiveGrade={versionDetail?.effective_grade}
                  autoGrade={versionDetail?.auto_grade}
                  manualGrade={versionDetail?.manual_grade}
                  manualGradeReason={versionDetail?.manual_grade_reason}
                />
              </div>
            ) : (
              <p className="detail-muted">{tt('detail.empty.trust_score')}</p>
            )}
            {trustHistory.length > 0 && (
              <div className="detail-subsection">
                <h3>{tt('detail.section.trust_history')}</h3>
                <div className="detail-table-wrap">
                  <table className="detail-table">
                    <thead>
                      <tr>
                        <th>{tt('detail.meta.version')}</th>
                        <th>{tt('trust_score.table_header.score')}</th>
                        <th>{tt('scanner.grade')}</th>
                        <th>{tt('detail.calculated')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {trustHistory.map((point) => (
                        <tr key={point.version}>
                          <td><strong>v{point.version}</strong></td>
                          <td>{point.score !== null && point.score !== undefined ? point.score.toFixed(1) : '-'}</td>
                          <td>{point.grade ?? '-'}</td>
                          <td>
                            {point.calculated_at
                              ? new Date(point.calculated_at).toLocaleDateString(dateLocale, {
                                  year: 'numeric',
                                  month: 'short',
                                  day: 'numeric',
                                })
                              : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </DetailSection>

          {versionDetail?.scan_report?.findings?.length ? (
            <DetailSection
              id="scan-findings"
              title={`${tt('detail.scan_findings')} (${versionDetail.scan_report.findings.length})`}
              kicker={
                versionDetail.scan_report.summary?.pass_rate != null
                  ? `${tt('detail.pass_rate')} ${Math.round(Number(versionDetail.scan_report.summary.pass_rate))}%`
                  : undefined
              }
            >
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
                    {f.evidence && <div className="finding-evidence">{f.evidence}</div>}
                    {f.description && <p className="finding-desc">{f.description}</p>}
                    {f.remediation && <p className="finding-suggestion">{f.remediation}</p>}
                  </div>
                ))}
              </div>
            </DetailSection>
          ) : null}

          <DetailSection id="files" title={tt('detail.files.title')} kicker={tt('detail.files.kicker')}>
            <PackageFileBrowser fileContents={versionDetail?.scan_file_contents} />
          </DetailSection>

          <DetailSection id="integrity" title={tt('detail.integrity.title')} kicker={tt('detail.integrity.kicker')}>
            <PackageIntegrityPanel source={source} integrity={integrity} />
          </DetailSection>

          <DetailSection id="permissions" title={tt('detail.nav.permissions')} kicker={tt('detail.section.permissions_kicker')}>
            <div className="permission-summary-grid">
              {permissionSummary.map((item) => (
                <div className={`permission-summary-card ${item.tone}`} key={item.labelKey}>
                  <span>{tt(item.labelKey)}</span>
                  <strong>{permissionSummaryText(item)}</strong>
                </div>
              ))}
            </div>
            <PermissionDetails perms={perms} t={tt} />
          </DetailSection>

          <DetailSection id="dependencies" title={tt('detail.dependencies')} kicker={tt('detail.section.dependencies_kicker')}>
            <DependenciesDetails deps={deps} t={tt} />
          </DetailSection>

          <DetailSection id="entry-points" title={tt('detail.entry_points')} kicker={tt('detail.section.entry_points_kicker')}>
            <EntryPointDetails entry={entry} t={tt} />
          </DetailSection>

          <DetailSection id="installation" title={tt('detail.installation')} kicker={tt('detail.section.installation_kicker')}>
            <InstallationDetails install={install} deps={deps} t={tt} />
          </DetailSection>

          <div id="feedback">
            <FeedbackSection packageName={pkg.name} user={user} token={token} />
          </div>

          <DetailSection id="versions" title={tt('detail.versions')} kicker={tt('detail.section.versions_kicker')}>
            <motion.ul className="version-list" variants={listStagger} initial="hidden" whileInView="visible" viewport={{ once: true, amount: 0.2 }}>
              {(versions.length > 0 ? versions : [{
                id: pkg.id,
                version: pkg.latest_version,
                status: 'latest',
                submitted_at: pkg.created_at,
              }]).map((v) => (
                <motion.li key={v.id} variants={listItem}>
                  <strong>v{v.version}</strong>
                  {v.version === pkg.latest_version && <span>{tt('detail.latest')}</span>}
                  <em>{tt(`status_badge.${v.status}`, { defaultValue: v.status.replace(/_/g, ' ') })}</em>
                  {v.submitted_at && (
                    <time>
                      {new Date(v.submitted_at).toLocaleDateString(dateLocale, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })}
                    </time>
                  )}
                </motion.li>
              ))}
            </motion.ul>
          </DetailSection>
        </motion.main>

        <motion.aside className="detail-rail" aria-label={tt('detail.rail.trust_summary')} variants={listStagger}>
          <motion.nav className="rail-card rail-section-card" aria-label="Package detail sections" variants={softPanel}>
            <div className="rail-card-heading rail-section-heading">
              <strong>{tt('detail.rail.sections')}</strong>
            </div>
            <div className="rail-section-links">
              <a href="#overview">{tt('detail.nav.overview')}</a>
              <a href="#trust">{tt('detail.nav.trust')}</a>
              <a href="#files">{tt('detail.nav.files')}</a>
              <a href="#integrity">{tt('detail.nav.integrity')}</a>
              <a href="#permissions">{tt('detail.nav.permissions')}</a>
              <a href="#installation">{tt('detail.nav.installation')}</a>
              <a href="#versions">{tt('detail.nav.versions')}</a>
              <a href="#feedback">{tt('detail.nav.feedback')}</a>
            </div>
          </motion.nav>

          <motion.div className="rail-card rail-install-card" variants={softPanel}>
            <div className="rail-card-heading">
              <span>{tt('detail.rail.install')}</span>
              <strong>{clientLabel(effectiveClient)}</strong>
            </div>
            {selectableClients.length > 1 && (
              <label className="rail-select-label">
                {tt('detail.install.target_client')}
                <select
                  value={effectiveClient}
                  onChange={(e) => setSelectedClient(e.target.value)}
                  aria-label={tt('detail.install.target_client')}
                >
                  {selectableClients.map((c) => (
                    <option key={c} value={c}>
                      {clientLabel(c)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <InstallCommandBlock command={installCommand} packageName={pkg.name} />
            <div className="rail-target-path">
              <span>{tt('detail.install.target_path')}</span>
              <code>{getClientTargetPath(install?.targets, effectiveClient, pkg.name)}</code>
            </div>
          </motion.div>

          <motion.div className={`rail-card rail-trust-card ${gradeClass}`} variants={softPanel}>
            <div className="rail-card-heading">
              <span>{tt('detail.rail.trust_summary')}</span>
              <ScoreBadge grade={pkg.grade} />
            </div>
            <p className="rail-trust-advice">{trustAdvice}</p>
            <div className="rail-permission-list">
              {permissionSummary.map((item) => (
                <div className={`rail-permission-item ${item.tone}`} key={item.labelKey}>
                  <span>{tt(item.labelKey)}</span>
                  <strong>{permissionSummaryText(item)}</strong>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div className="rail-card rail-source-card" variants={softPanel}>
            <div className="rail-card-heading">
              <span>{tt('detail.rail.source')}</span>
              {source?.verified_owner ? <strong className="detail-safe-text">{tt('detail.verified_source')}</strong> : <strong>{tt('detail.rail.review')}</strong>}
            </div>
            <p>{sourceLabel}</p>
            {source?.repository_url && <ExternalLink href={source.repository_url}>{tt('detail.source.open_repository')}</ExternalLink>}
            {pkg.homepage && <ExternalLink href={pkg.homepage}>{tt('detail.source.open_homepage')}</ExternalLink>}
          </motion.div>
        </motion.aside>
      </motion.div>
    </motion.div>
  );
}
