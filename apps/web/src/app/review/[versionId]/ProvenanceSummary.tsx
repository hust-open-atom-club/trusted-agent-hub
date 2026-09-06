'use client';

import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { ScanProvenance } from '@/types';

interface ProvenanceSummaryProps {
  provenance?: ScanProvenance | null;
}

interface MetaFieldProps {
  label: string;
  value: ReactNode;
  full?: boolean;
  code?: boolean;
}

interface ClaimDifference {
  section: 'source' | 'integrity';
  path: string;
  claimed: string;
  observed?: string;
}

function MetaField({ label, value, full = false, code = false }: MetaFieldProps) {
  return (
    <div className={`review-meta-field${full ? ' full' : ''}`}>
      <span className="review-meta-label">{label}</span>
      <span className="review-meta-value">
        {code ? <code style={{ wordBreak: 'break-all' }}>{value}</code> : value}
      </span>
    </div>
  );
}

function flattenEntries(value: unknown, prefix = ''): Array<[string, string]> {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    if (value.length === 0) return [];
    if (value.every((item) => item === null || ['string', 'number', 'boolean'].includes(typeof item))) {
      return [[prefix, value.map(String).join(', ')]];
    }
    return value.flatMap((item, index) => flattenEntries(item, `${prefix}[${index}]`));
  }
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
      flattenEntries(child, prefix ? `${prefix}.${key}` : key),
    );
  }
  if (typeof value === 'string' && !value.trim()) return [];
  return [[prefix, String(value)]];
}

function claimDifferences(
  section: ClaimDifference['section'],
  claims: Record<string, unknown> | undefined,
  facts: Record<string, unknown> | undefined,
): ClaimDifference[] {
  const observed = new Map(flattenEntries(facts ?? {}));
  return flattenEntries(claims ?? {}).flatMap(([path, claimed]) => {
    const fact = observed.get(path);
    return fact === claimed ? [] : [{ section, path, claimed, observed: fact }];
  });
}

export default function ProvenanceSummary({ provenance }: ProvenanceSummaryProps) {
  const { t } = useTranslation();

  if (!provenance) return null;

  const facts = provenance.acquisition_facts;
  const source = facts?.source;
  const integrity = facts?.integrity;
  const verification = facts?.verification;
  const capabilities = facts?.verification_capabilities;
  const refIsCommit = source?.ref_type === 'commit'
    || (!source?.ref_type && Boolean(source?.ref && /^[a-f0-9]{40}$/i.test(source.ref)));
  const refEqualsCommit = Boolean(
    refIsCommit
    && source.ref
    && source.commit_hash
    && source.ref.toLowerCase() === source.commit_hash.toLowerCase(),
  );
  const showRef = Boolean(source?.ref && !refEqualsCommit);

  const verificationItems = ([
    ['owner', 'review.detail.provenance_verification_owner'],
    ['signature', 'review.detail.provenance_verification_signature'],
    ['attestation', 'review.detail.provenance_verification_attestation'],
    ['sbom', 'review.detail.provenance_verification_sbom'],
  ] as const)
    .filter(([key]) => capabilities?.[key] === true || verification?.[key] === true)
    .map(([key, label]) => ({ key, label: t(label), verified: verification?.[key] === true }));
  const verifiedCount = verificationItems.filter((item) => item.verified).length;
  const failedCount = verificationItems.length - verifiedCount;

  const differences = [
    ...claimDifferences(
      'source',
      provenance.package_claims?.source,
      source as Record<string, unknown> | undefined,
    ),
    ...claimDifferences(
      'integrity',
      provenance.package_claims?.integrity,
      integrity as Record<string, unknown> | undefined,
    ),
  ];

  return (
    <div data-testid="provenance-summary">
      <div className="review-meta-grid">
        {source?.repository_url && (
          <MetaField
            label={t('review.detail.provenance_repository_url')}
            value={(
              <a href={source.repository_url} target="_blank" rel="noopener noreferrer">
                {source.repository_url}
              </a>
            )}
            full
          />
        )}
        {source?.owner && <MetaField label={t('review.detail.provenance_owner')} value={source.owner} />}
        {source?.repo && <MetaField label={t('review.detail.provenance_repo')} value={source.repo} />}
        {showRef && (
          <MetaField
            label={t('review.detail.provenance_ref')}
            value={`${source?.ref_type ? `${source.ref_type} ` : ''}${source?.ref}`}
          />
        )}
        {source?.commit_hash && (
          <MetaField
            label={t(showRef
              ? 'review.detail.provenance_resolved_commit'
              : 'review.detail.provenance_commit_hash')}
            value={source.commit_hash}
            code
            full={!showRef}
          />
        )}
        {source?.subdirectory && (
          <MetaField label={t('review.detail.provenance_subdirectory')} value={source.subdirectory} code />
        )}
        {facts?.acquisition_method && (
          <MetaField label={t('review.detail.provenance_acquisition_method')} value={facts.acquisition_method} />
        )}
        {integrity?.sha256 && (
          <MetaField label={t('review.detail.provenance_server_sha256')} value={integrity.sha256} code full />
        )}
        {integrity?.hash_scope && (
          <MetaField
            label={t('review.detail.provenance_hash_scope')}
            value={integrity.hash_scope === 'scanned_source'
              ? t('review.detail.provenance_hash_scope_scanned_source')
              : integrity.hash_scope}
          />
        )}
        {typeof integrity?.is_complete === 'boolean' && (
          <MetaField
            label={t('review.detail.provenance_completeness')}
            value={integrity.is_complete
              ? t('review.detail.provenance_is_complete')
              : t('review.detail.provenance_is_incomplete')}
          />
        )}
      </div>

      {verificationItems.length > 0 && (
        <details data-testid="supply-chain-verification" style={{ marginTop: '1rem' }}>
          <summary style={{ cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600 }}>
            {t('review.detail.provenance_supply_chain_status')}: {t(
              'review.detail.provenance_verification_summary',
              { verified: verifiedCount, failed: failedCount },
            )}
          </summary>
          <div className="review-meta-grid" style={{ marginTop: '0.65rem' }}>
            {verificationItems.map((item) => (
              <MetaField
                key={item.key}
                label={item.label}
                value={item.verified
                  ? t('review.detail.provenance_verified')
                  : t('review.detail.provenance_not_verified')}
              />
            ))}
          </div>
        </details>
      )}

      {differences.length > 0 && (
        <div data-testid="package-claim-differences" style={{ marginTop: '1rem' }}>
          <h3 className="review-meta-subtitle">{t('review.detail.provenance_claim_differences')}</h3>
          <div className="review-meta-grid">
            {differences.map((difference) => (
              <div className="review-meta-field full" key={`${difference.section}-${difference.path}`}>
                <span className="review-meta-label">
                  {t(`review.detail.provenance_package_${difference.section}`)} · <code>{difference.path}</code>
                </span>
                <span className="review-meta-value">
                  {t('review.detail.provenance_claimed_value')}: {difference.claimed}
                </span>
                <span className="review-meta-value">
                  {t('review.detail.provenance_observed_value')}: {difference.observed
                    ?? t('review.detail.provenance_observed_unavailable')}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
