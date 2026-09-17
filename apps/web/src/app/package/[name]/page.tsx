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
import TypeBadge from '@/components/TypeBadge';
import StatusBadge from '@/components/StatusBadge';
import TrustScoreDetail from '@/components/TrustScoreDetail';
import CapabilityRadar from '@/components/CapabilityRadar';
import FeedbackSection from '@/components/FeedbackSection';
import { fadeUp, listItem, listStagger, motion, pageStagger, softPanel } from '@/components/Motion';
import { useAuth } from '@/lib/auth';
import InstallCommandBlock from './InstallCommandBlock';
import PackageIcon from './PackageIcon';
import PackageReadingNav, { type ReadingNavItem } from './PackageReadingNav';
import {
  getBoundaryRows,
  getBoundaryVerdict,
  getCapabilityAxes,
  getCapabilityHighlights,
  getFeedbackSummary,
  hasDeclaredCapability,
  type CapabilityHighlight,
} from './detail-view-model';

type Translate = (key: string, options?: Record<string, unknown>) => string;

function DetailSkeleton() {
  return (
    <div className="detail-page">
      <div className="skeleton detail-back-skeleton">
        <div className="skeleton-bar" />
      </div>
      <section className="detail-hero skeleton">
        <div className="detail-hero-top">
          <div className="detail-identity-mark" />
          <div className="detail-hero-copy">
            <div className="skeleton-bar detail-skeleton-title" />
            <div className="skeleton-bar detail-skeleton-line" />
            <div className="skeleton-bar detail-skeleton-wide" />
          </div>
        </div>
        <div className="detail-meta-grid">
          {Array.from({ length: 5 }).map((_, i) => (
            <div className="detail-meta-item" key={i}>
              <div className="skeleton-bar detail-skeleton-meta" />
              <div className="skeleton-bar detail-skeleton-value" />
            </div>
          ))}
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
  clientLabel,
}: {
  install?: PublicInstallation | null;
  t: Translate;
  clientLabel: (client: string) => string;
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
                <span>{target.client ? clientLabel(target.client) : '—'}</span>
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
  const highlightBody = (highlight: CapabilityHighlight) => {
    const values = { ...highlight.bodyValues };
    if (typeof values.scopeKey === 'string') {
      values.scope = tt(values.scopeKey);
      delete values.scopeKey;
    }
    return tt(highlight.bodyKey, values);
  };

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
  const capabilityAxes = getCapabilityAxes(versionDetail?.permission_summary);
  const boundaryRows = getBoundaryRows(versionDetail?.permission_summary);
  const boundaryVerdict = getBoundaryVerdict(
    versionDetail?.permission_summary,
    versionDetail?.trust_boundary,
  );
  const declaredRows = boundaryRows.filter((row) => row.allowed);
  const highlights = getCapabilityHighlights(
    versionDetail?.capabilities,
    versionDetail?.trust_boundary,
    pkg.keywords,
    i18n.language === 'zh' ? '、' : ', ',
  );
  const feedbackSummary = getFeedbackSummary(pkg.feedback_counts);
  const installCommand = buildInstallCommand(pkg.name, selectableClients, install?.method, effectiveClient);
  const clientLabel = (client: string) => tt(`detail.client.${client}`, { defaultValue: getClientLabel(client) });
  const typeLabel = tt(`search.${pkg.type}`, { defaultValue: pkg.type });
  const hasPermissionManifest = Boolean(versionDetail?.permission_summary);
  const sectionNavItems: ReadingNavItem[] = [
    { id: 'capability', label: tt('detail.nav.capability') },
    { id: 'permissions', label: tt('detail.nav.boundary') },
    { id: 'installation', label: tt('detail.nav.installation') },
    { id: 'feedback', label: tt('detail.nav.feedback') },
    { id: 'versions', label: tt('detail.nav.versions') },
  ];

  return (
    <motion.div className="detail-page" variants={pageStagger} initial="hidden" animate="visible">
      <nav className="detail-breadcrumb" aria-label={tt('detail.breadcrumb.label')}>
        <button className="link-btn" onClick={() => router.push('/')}>
          &larr; {tt('detail.back')}
        </button>
        <span className="detail-breadcrumb-sep" aria-hidden="true">/</span>
        <span>{tt('detail.breadcrumb.detail')}</span>
      </nav>

      <motion.section className="detail-hero" variants={softPanel}>
        <div className="detail-hero-top">
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
          </div>
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
            <span className="detail-meta-label">{tt('detail.meta.installs')}</span>
            <span className="detail-meta-value">{pkg.install_count.toLocaleString()}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">{tt('detail.meta.feedback')}</span>
            <span className="detail-meta-value">{tt(feedbackSummary.key, feedbackSummary.values)}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">{tt('detail.compatible_clients')}</span>
            <span className="detail-meta-value">
              {compat.length > 0
                ? compat.map((client) => clientLabel(client)).join(' · ')
                : tt('detail.not_evaluated')}
            </span>
          </div>
        </div>
      </motion.section>

      <motion.div className="detail-shell" variants={pageStagger}>
        <motion.aside className="detail-reading-rail" variants={softPanel}>
          <PackageReadingNav items={sectionNavItems} title={tt('detail.rail.sections')} />
        </motion.aside>

        <motion.main className="detail-main" variants={pageStagger}>
          <DetailSection
            id="capability"
            title={tt('detail.capability.block_title', { type: typeLabel })}
            kicker={tt('detail.capability.block_kicker')}
          >
            <p className="detail-muted">
              {tt('detail.capability.block_summary', { name: pkg.name })}
            </p>
            <div className="capability-highlight-grid">
              {highlights.map((highlight) => (
                <motion.article
                  className={`capability-highlight ${highlight.tone}`}
                  key={highlight.key}
                  variants={fadeUp}
                >
                  <span>{tt(highlight.labelKey)}</span>
                  <strong>{highlightBody(highlight)}</strong>
                  {highlight.authorDeclared && (
                    <em className="capability-highlight-flag">
                      {tt('detail.capability.tile.author_declared')}
                    </em>
                  )}
                </motion.article>
              ))}
            </div>
          </DetailSection>

          <DetailSection
            id="permissions"
            title={tt('detail.boundary.title')}
            kicker={tt('detail.boundary.subtitle', { type: typeLabel })}
          >
            {hasPermissionManifest ? (
              <div className="boundary-layout">
                <div className="boundary-radar">
                  {hasDeclaredCapability(capabilityAxes) ? (
                    <CapabilityRadar axes={capabilityAxes} packageName={pkg.name} />
                  ) : (
                    <p className="detail-muted">{tt('detail.capability.empty')}</p>
                  )}
                </div>
                <div className="boundary-panel">
                  {(effectiveGrade || riskLevel || versionDetail?.install_recommendation) && (
                    <div className="boundary-grade">
                      <TrustScoreDetail
                        mode="public"
                        effectiveGrade={effectiveGrade}
                        publicRiskLevel={riskLevel}
                        publicInstallRecommendation={versionDetail?.install_recommendation}
                      />
                    </div>
                  )}
                  {!effectiveGrade && !riskLevel && !versionDetail?.install_recommendation && (
                    <p className="detail-muted">{tt('detail.empty.trust_score')}</p>
                  )}
                  <ul className="boundary-list">
                    {boundaryRows.map((row) => (
                      <li className={row.allowed ? row.tone : 'off'} key={row.key}>
                        <span>{tt(`detail.boundary.item.${row.key}`)}</span>
                        <strong>{tt(row.valueKey, row.values)}</strong>
                      </li>
                    ))}
                  </ul>
                  <p className={`boundary-verdict ${boundaryVerdict.tone}`}>
                    {tt(boundaryVerdict.key, boundaryVerdict.values)}
                  </p>
                </div>
              </div>
            ) : (
              <p className="detail-muted">{tt('detail.empty.permissions')}</p>
            )}
          </DetailSection>

          <DetailSection id="installation" title={tt('detail.installation')} kicker={tt('detail.section.installation_kicker')}>
            <InstallationDetails install={install} t={tt} clientLabel={clientLabel} />
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

        <motion.aside className="detail-rail" aria-label={tt('detail.rail.install')} variants={listStagger}>
          <motion.div className="rail-card rail-install-card" variants={softPanel}>
            <div className="rail-card-heading">
              <span>{tt('detail.rail.install')}</span>
              <strong>{clientLabel(effectiveClient)}</strong>
            </div>
            <p className="rail-card-note">{tt('detail.rail.install_hint')}</p>
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
            {!install?.targets?.length && (
              <div className="rail-target-path">
                <span>{tt('detail.install.target_path')}</span>
                <code>{getClientTargetPath(install?.targets, effectiveClient, pkg.name, pkg.type)}</code>
              </div>
            )}
          </motion.div>

          {hasPermissionManifest && (
            <motion.div className="rail-card rail-permission-card" variants={softPanel}>
              <div className="rail-card-heading">
                <span>{tt('detail.rail.permissions')}</span>
                <a className="rail-card-link" href="#permissions">
                  {tt('detail.rail.see_detail')}
                </a>
              </div>
              {declaredRows.length > 0 ? (
                <>
                  <p className="rail-card-note">
                    {tt('detail.rail.declared_count', {
                      declared: declaredRows.length,
                      total: boundaryRows.length,
                    })}
                  </p>
                  <div className="keyword-list">
                    {declaredRows.map((row) => (
                      <span className="keyword-tag" key={row.key}>
                        {tt(`detail.boundary.item.${row.key}`)}
                      </span>
                    ))}
                  </div>
                </>
              ) : (
                <p className="rail-card-note">{tt('detail.capability.empty')}</p>
              )}
            </motion.div>
          )}

          {pkg.keywords.length > 0 && (
            <motion.div className="rail-card" variants={softPanel}>
              <div className="rail-card-heading">
                <span>{tt('detail.keywords')}</span>
              </div>
              <div className="keyword-list">
                {pkg.keywords.map((kw) => <span key={kw} className="keyword-tag">{kw}</span>)}
              </div>
            </motion.div>
          )}

        </motion.aside>
      </motion.div>
    </motion.div>
  );
}
