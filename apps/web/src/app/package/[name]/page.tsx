'use client';

import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchPackage, fetchPackageVersion, fetchPackageVersions } from '@/data/packages';
import type {
  Package,
  PublicInstallation,
  PublicVersionDetail,
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
import PackageIcon from './PackageIcon';
import PackageReadingNav, { type ReadingNavItem } from './PackageReadingNav';
import {
  getFeedbackSummary,
  getGradeClass,
  getPublicPermissionSummary,
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
        <aside className="detail-reading-rail skeleton">
          <div className="skeleton-bar detail-skeleton-meta" />
          <div className="skeleton-block" />
        </aside>
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

function InstallationDetails({
  install,
  t,
}: {
  install?: PublicInstallation | null;
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
  const [versionDetail, setVersionDetail] = useState<PublicVersionDetail | null>(null);
  const [versions, setVersions] = useState<VersionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedClient, setSelectedClient] = useState('claude-code');

  useEffect(() => {
    setLoading(true);
    setPkg(undefined);
    setVersionDetail(null);
    setVersions([]);

    fetchPackage(name)
      .then(async (p) => {
        setPkg(p);
        if (p) {
          const [vDetail, vList] = await Promise.all([
            fetchPackageVersion(name, p.latest_version).catch(() => null),
            fetchPackageVersions(name).catch(() => []),
          ]);
          setVersionDetail(vDetail);
          setVersions(vList);
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

  const install = versionDetail?.installation;
  const compat = versionDetail?.compatibility ?? [];
  const selectableClients = getSelectableClients(pkg.type, compat);
  const effectiveClient = selectableClients.includes(selectedClient)
    ? selectedClient
    : (selectableClients[0] ?? 'claude-code');
  const effectiveGrade = versionDetail?.effective_grade ?? pkg.grade;
  const riskLevel = versionDetail?.risk_level ?? pkg.risk_level;
  const gradeClass = getGradeClass(effectiveGrade);
  const riskLabel = tt(getRiskLabelKey(riskLevel), { defaultValue: riskLevel ?? tt('detail.unknown') });
  const typeLabel = tt(getTypeLabelKey(pkg.type), { defaultValue: pkg.type });
  const trustAdvice = versionDetail?.install_recommendation
    ? tt(`trust_score.recommendation.${versionDetail.install_recommendation}`, {
        defaultValue: versionDetail.install_recommendation,
      })
    : tt(getTrustAdvice(effectiveGrade));
  const permissionSummary = getPublicPermissionSummary(versionDetail?.permission_summary);
  const feedbackSummary = getFeedbackSummary(pkg.feedback_counts);
  const installCommand = buildInstallCommand(pkg.name, selectableClients, install?.method, effectiveClient);
  const clientLabel = (client: string) => tt(`detail.client.${client}`, { defaultValue: getClientLabel(client) });
  const sectionNavItems: ReadingNavItem[] = [
    { id: 'overview', label: tt('detail.nav.overview') },
    { id: 'trust', label: tt('detail.nav.trust') },
    { id: 'permissions', label: tt('detail.nav.permissions') },
    { id: 'installation', label: tt('detail.nav.installation') },
    { id: 'feedback', label: tt('detail.nav.feedback') },
    { id: 'versions', label: tt('detail.nav.versions') },
  ];

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
          {pkg.owner && (
            <p className="detail-source-line">
              <strong>{tt('detail.by_owner', { owner: pkg.owner.display_name })}</strong>
            </p>
          )}
          <p className="detail-description">{pkg.description}</p>
          <div className="detail-badge-row">
            <span className={`detail-risk-chip ${gradeClass}`}>
              {tt('detail.grade_risk', { grade: effectiveGrade ?? '--', risk: riskLabel })}
            </span>
            {selectableClients.length > 0 && (
              <span className="detail-client-chip">
                {tt('detail.compatible_clients_label', {
                  clients: selectableClients.map(clientLabel).join(', '),
                })}
              </span>
            )}
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
        <motion.aside className="detail-reading-rail" variants={softPanel}>
          <PackageReadingNav items={sectionNavItems} title={tt('detail.rail.sections')} />
        </motion.aside>

        <motion.main className="detail-main" variants={pageStagger}>
          <DetailSection id="overview" title={tt('detail.nav.overview')} kicker={tt('detail.section.overview_kicker')}>
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

          <DetailSection id="trust" title={tt('detail.trust_conclusion')} kicker={riskLabel}>
            <div className="detail-trust-panel">
              <TrustScoreDetail
                mode="public"
                effectiveGrade={effectiveGrade}
                publicRiskLevel={riskLevel}
                publicInstallRecommendation={versionDetail?.install_recommendation}
              />
            </div>
          </DetailSection>

          <DetailSection id="permissions" title={tt('detail.nav.permissions')} kicker={tt('detail.section.permissions_kicker')}>
            {permissionSummary.length > 0 ? (
              <div className="permission-summary-grid">
                {permissionSummary.map((item) => (
                  <div className={`permission-summary-card ${item.tone}`} key={item.labelKey}>
                    <span>{tt(item.labelKey)}</span>
                    <strong>{permissionSummaryText(item)}</strong>
                  </div>
                ))}
              </div>
            ) : (
              <p className="detail-muted">{tt('detail.empty.permissions')}</p>
            )}
          </DetailSection>

          <DetailSection id="installation" title={tt('detail.installation')} kicker={tt('detail.section.installation_kicker')}>
            <InstallationDetails install={install} t={tt} />
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
            <InstallCommandBlock command={installCommand} packageName={pkg.name} client={effectiveClient} />
            <div className="rail-target-path">
              <span>{tt('detail.install.target_path')}</span>
              <code>{getClientTargetPath(install?.targets, effectiveClient, pkg.name)}</code>
            </div>
          </motion.div>

          <motion.div className={`rail-card rail-trust-card ${gradeClass}`} variants={softPanel}>
            <div className="rail-card-heading">
              <span>{tt('detail.rail.trust_summary')}</span>
              <ScoreBadge grade={effectiveGrade} />
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
        </motion.aside>
      </motion.div>
    </motion.div>
  );
}
