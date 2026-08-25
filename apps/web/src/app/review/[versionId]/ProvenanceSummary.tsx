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

function MetaField({ label, value, full = false, code = false }: MetaFieldProps) {
  return (
    <div className={`review-meta-field${full ? ' full' : ''}`}>
      <span className="review-meta-label">{label}</span>
      <span className="review-meta-value">
        {code && value !== '—' ? <code>{value}</code> : value}
      </span>
    </div>
  );
}

function displayValue(value: string | null | undefined): string {
  return value || '—';
}

export default function ProvenanceSummary({ provenance }: ProvenanceSummaryProps) {
  const { t } = useTranslation();

  if (!provenance) return null;

  const facts = provenance.acquisition_facts;
  const source = facts?.source;
  const integrity = facts?.integrity;
  const verification = facts?.verification;
  const packageClaims = provenance.package_claims;

  const verificationLabel = (value: boolean | null | undefined): string =>
    String(t(
      value === true
        ? 'review.detail.provenance.verified'
        : value === false
          ? 'review.detail.provenance.not_verified'
          : 'review.detail.provenance.unknown',
    ));

  const hashScopeLabel = integrity?.hash_scope === 'scanned_source'
    ? String(t('review.detail.provenance.scope_scanned_source'))
    : String(t('review.detail.provenance.unknown'));

  const completenessLabel = integrity?.is_complete === true
    ? String(t('review.detail.provenance.complete'))
    : integrity?.is_complete === false
      ? String(t('review.detail.provenance.incomplete'))
      : String(t('review.detail.provenance.unknown'));

  const claimSummary: string[] = [];
  const sourceClaimCount = Object.keys(packageClaims?.source ?? {}).length;
  const integrityClaimCount = Object.keys(packageClaims?.integrity ?? {}).length;
  if (sourceClaimCount > 0) {
    claimSummary.push(String(t('review.detail.provenance.source_claims', { count: sourceClaimCount })));
  }
  if (integrityClaimCount > 0) {
    claimSummary.push(String(t('review.detail.provenance.integrity_claims', { count: integrityClaimCount })));
  }

  return (
    <div className="review-meta-grid" data-testid="provenance-summary">
      <MetaField
        label={String(t('review.detail.provenance.acquisition_method'))}
        value={displayValue(facts?.acquisition_method)}
        full
      />
      <MetaField
        label={String(t('review.detail.provenance.repository'))}
        value={source?.repository_url ? (
          <a href={source.repository_url} target="_blank" rel="noopener noreferrer">
            {source.repository_url}
          </a>
        ) : '—'}
        full
      />
      <MetaField
        label={String(t('review.detail.provenance.owner'))}
        value={displayValue(source?.owner)}
      />
      <MetaField
        label={String(t('review.detail.provenance.repo'))}
        value={displayValue(source?.repo)}
      />
      <MetaField
        label={String(t('review.detail.provenance.ref'))}
        value={source?.ref
          ? `${source.ref_type ? `${source.ref_type}: ` : ''}${source.ref}`
          : '—'}
      />
      <MetaField
        label={String(t('review.detail.provenance.commit'))}
        value={displayValue(source?.commit_hash)}
        code
        full
      />
      <MetaField
        label={String(t('review.detail.provenance.subdirectory'))}
        value={displayValue(source?.subdirectory)}
      />
      <MetaField
        label={String(t('review.detail.provenance.hash'))}
        value={displayValue(integrity?.sha256)}
        code
        full
      />
      <MetaField
        label={String(t('review.detail.provenance.hash_scope'))}
        value={hashScopeLabel}
      />
      <MetaField
        label={String(t('review.detail.provenance.hash_completeness'))}
        value={completenessLabel}
      />
      <MetaField
        label={String(t('review.detail.provenance.verification_repository'))}
        value={verificationLabel(verification?.repository)}
      />
      <MetaField
        label={String(t('review.detail.provenance.verification_owner'))}
        value={verificationLabel(verification?.owner)}
      />
      <MetaField
        label={String(t('review.detail.provenance.verification_signature'))}
        value={verificationLabel(verification?.signature)}
      />
      <MetaField
        label={String(t('review.detail.provenance.verification_attestation'))}
        value={verificationLabel(verification?.attestation)}
      />
      <MetaField
        label={String(t('review.detail.provenance.verification_sbom'))}
        value={verificationLabel(verification?.sbom)}
      />
      <MetaField
        label={String(t('review.detail.provenance.package_claims'))}
        value={claimSummary.length > 0
          ? claimSummary.join(' · ')
          : String(t('review.detail.provenance.no_claims'))}
        full
      />
    </div>
  );
}
