'use client';

import { useTranslation } from 'react-i18next';

import type { DependencyScan } from '@/types';

interface DependencyCoverageSummaryProps {
  dependencyScan: DependencyScan | null | undefined;
}

function humanize(value: string): string {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function DependencyCoverageSummary({
  dependencyScan,
}: DependencyCoverageSummaryProps) {
  const { t } = useTranslation();
  const acquisition = dependencyScan?.artifact_acquisition;
  const integrity = dependencyScan?.integrity;
  const manifestLock = dependencyScan?.manifest_lock;
  const acquisitionReasons = Object.entries(acquisition?.unavailable_reasons || {});
  const integrityReasons = Object.entries(integrity?.unavailable_reasons || {});
  const collectionErrors = acquisition?.collection_errors || [];

  const showAcquisition = Boolean(
    acquisition
    && (
      acquisition.status !== 'not_applicable'
      || (acquisition.requested_count ?? 0) > 0
      || collectionErrors.length > 0
    ),
  );
  const showIntegrity = Boolean(
    integrity
    && (
      (integrity.claimed_count ?? 0) > 0
      || !['not_applicable', undefined].includes(integrity.status)
    ),
  );
  const showManifestLock = Boolean(
    manifestLock
    && (
      showAcquisition
      || showIntegrity
      || (manifestLock.checked_pairs ?? 0) > 0
      || (manifestLock.mismatch_count ?? 0) > 0
      || (manifestLock.unchecked_count ?? 0) > 0
    ),
  );

  if (!dependencyScan || (!showAcquisition && !showIntegrity && !showManifestLock)) {
    return null;
  }

  const hasGap = Boolean(
    dependencyScan.status === 'partial'
    || acquisition?.status === 'partial'
    || (acquisition?.unavailable_count ?? 0) > 0
    || collectionErrors.length > 0
    || ['partial', 'unsupported', 'mismatch', 'not_checked'].includes(integrity?.status || '')
    || (integrity?.unavailable_count ?? 0) > 0
    || (integrity?.unsupported_count ?? 0) > 0
    || ['partial', 'mismatch'].includes(manifestLock?.status || ''),
  );
  const statusLabel = (status: string | undefined) => (
    status
      ? t(`review.detail.dependency_coverage_status_${status}`, {
          defaultValue: humanize(status),
        })
      : '—'
  );
  const reasonLabel = (reason: string) => t(
    `review.detail.dependency_coverage_reason_${reason}`,
    { defaultValue: humanize(reason) },
  );
  const metric = (label: string, value: number | undefined) => (
    <div className="review-meta-field">
      <span className="review-meta-label">{label}</span>
      <span className="review-meta-value">
        {value === undefined ? '—' : value.toLocaleString()}
      </span>
    </div>
  );

  return (
    <section className="review-detail-section" data-testid="dependency-coverage">
      <h2 className="review-detail-section-title">
        {t('review.detail.dependency_coverage_title')}
      </h2>
      <p style={{ margin: '-0.4rem 0 0.8rem', color: 'var(--color-muted)', fontSize: '0.82rem', lineHeight: 1.5 }}>
        {t('review.detail.dependency_coverage_description')}
      </p>
      <details open={hasGap}>
        <summary style={{ cursor: 'pointer', fontWeight: 700 }}>
          {t('review.detail.dependency_coverage_overall_status')}: {statusLabel(dependencyScan.status)}
        </summary>

        {showAcquisition && acquisition && (
          <div style={{ marginTop: '0.9rem' }} data-testid="dependency-artifact-acquisition">
            <h3 className="review-meta-subtitle">
              {t('review.detail.dependency_coverage_acquisition_title')}
            </h3>
            <div className="review-meta-grid">
              <div className="review-meta-field">
                <span className="review-meta-label">{t('review.detail.dependency_coverage_status')}</span>
                <span className="review-meta-value">{statusLabel(acquisition.status)}</span>
              </div>
              {metric(t('review.detail.dependency_coverage_requested'), acquisition.requested_count)}
              {metric(t('review.detail.dependency_coverage_fetched'), acquisition.fetched_count)}
              {metric(t('review.detail.dependency_coverage_unavailable'), acquisition.unavailable_count)}
              {metric(t('review.detail.dependency_coverage_bytes'), acquisition.bytes_downloaded)}
            </div>
            {acquisitionReasons.length > 0 && (
              <div style={{ marginTop: '0.6rem', fontSize: '0.8rem' }}>
                <strong>{t('review.detail.dependency_coverage_unavailable_reasons')}</strong>
                <ul data-testid="dependency-acquisition-reasons">
                  {acquisitionReasons.map(([reason, count]) => (
                    <li key={reason}>{reasonLabel(reason)} ({reason}): {count}</li>
                  ))}
                </ul>
              </div>
            )}
            {collectionErrors.length > 0 && (
              <div style={{ marginTop: '0.6rem', fontSize: '0.8rem' }}>
                <strong>{t('review.detail.dependency_coverage_collection_errors')}</strong>
                <ul>
                  {collectionErrors.map((reason) => (
                    <li key={reason}>{reasonLabel(reason)} ({reason})</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {showIntegrity && integrity && (
          <div style={{ marginTop: '0.9rem' }} data-testid="dependency-integrity-coverage">
            <h3 className="review-meta-subtitle">
              {t('review.detail.dependency_coverage_integrity_title')}
            </h3>
            <div className="review-meta-grid">
              <div className="review-meta-field">
                <span className="review-meta-label">{t('review.detail.dependency_coverage_status')}</span>
                <span className="review-meta-value">{statusLabel(integrity.status)}</span>
              </div>
              {metric(t('review.detail.dependency_coverage_claimed'), integrity.claimed_count)}
              {metric(t('review.detail.dependency_coverage_verified'), integrity.verified_count)}
              {metric(t('review.detail.dependency_coverage_mismatched'), integrity.mismatch_count)}
              {metric(t('review.detail.dependency_coverage_unavailable'), integrity.unavailable_count)}
              {metric(t('review.detail.dependency_coverage_unsupported'), integrity.unsupported_count)}
            </div>
            {integrityReasons.length > 0 && (
              <div style={{ marginTop: '0.6rem', fontSize: '0.8rem' }}>
                <strong>{t('review.detail.dependency_coverage_unavailable_reasons')}</strong>
                <ul>
                  {integrityReasons.map(([reason, count]) => (
                    <li key={reason}>{reasonLabel(reason)} ({reason}): {count}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {showManifestLock && manifestLock && (
          <div style={{ marginTop: '0.9rem' }} data-testid="dependency-manifest-lock">
            <h3 className="review-meta-subtitle">
              {t('review.detail.dependency_coverage_manifest_lock_title')}
            </h3>
            <div className="review-meta-grid">
              <div className="review-meta-field">
                <span className="review-meta-label">{t('review.detail.dependency_coverage_status')}</span>
                <span className="review-meta-value">{statusLabel(manifestLock.status)}</span>
              </div>
              {metric(t('review.detail.dependency_coverage_checked_pairs'), manifestLock.checked_pairs)}
              {metric(t('review.detail.dependency_coverage_mismatched'), manifestLock.mismatch_count)}
              {metric(t('review.detail.dependency_coverage_unchecked'), manifestLock.unchecked_count)}
            </div>
          </div>
        )}
      </details>
    </section>
  );
}
