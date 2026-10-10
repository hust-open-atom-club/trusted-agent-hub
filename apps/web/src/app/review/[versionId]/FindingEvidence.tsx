'use client';

import { useTranslation } from 'react-i18next';
import type { EvidenceReference, Finding, FindingLocation } from '@/types';
import { contextMessage } from './contextMessages';

type EvidenceRecord = Pick<Finding,
  'evidence_type' | 'evidence_missing_reason' | 'llm_context_reasons' |
  'llm_review_state' | 'llm_context_audit' | 'credential_evidence' | 'requires_manual_review'
> & { location?: FindingLocation | null };

export function EvidenceReferenceOmission({ reference }: { reference: EvidenceReference }) {
  const { t } = useTranslation();
  if (!reference.source_ref_sha256) return null;
  return (
    <div>
      {reference.missing_reason === 'sensitive_identifier'
        ? t('review.finding.evidence_reference_redacted')
        : t('review.finding.evidence_reference_omitted', { count: reference.source_ref_length })}
      {' · '}<code>SHA-256: {reference.source_ref_sha256}</code>
    </div>
  );
}

export function findingLocations(finding: Finding): {
  count: number;
  items: FindingLocation[];
  truncated: boolean;
} {
  if (finding.occurrences) {
    const { count, items, truncated } = finding.occurrences;
    return {
      // Empty, untruncated lists in older reports may still claim count=1.
      count: truncated ? Math.max(count, items.length) : items.length,
      items,
      truncated,
    };
  }
  if (finding.location?.file) {
    return { count: 1, items: [finding.location], truncated: false };
  }
  return { count: 0, items: [], truncated: false };
}

export function formatEvidenceLocation(location: FindingLocation): string {
  let line = location.line ? `:${location.line}` : '';
  if (location.line && location.column) line += `:${location.column}`;
  if (location.line && location.end_line && (location.end_line !== location.line || location.end_column !== location.column)) {
    line += `-${location.end_line}${location.end_column ? `:${location.end_column}` : ''}`;
  }
  return `${location.file || ''}${line}${location.source_ref ? ` ${location.source_ref}` : ''}`;
}

export default function FindingEvidence({ finding, versionId }: { finding: EvidenceRecord; versionId: string }) {
  const { t } = useTranslation();
  const location = finding.location;
  const credential = finding.credential_evidence;
  const missingReason = finding.evidence_missing_reason || location?.missing_reason;
  const sourceAvailable = !!location?.file
    && !['source_missing', 'sensitive_identifier'].includes(missingReason || '');
  const reasons = new Set(finding.llm_context_reasons || []);
  if (finding.llm_review_state === 'unavailable') reasons.add('provider_failure');
  const sourceLink = (line?: number | null) => `/review/files?${new URLSearchParams({
    versionId, path: location?.file || '', ...(line ? { line: String(line) } : {}),
  })}`;

  return (
    <div className="finding-evidence-line">
      {finding.evidence_type && <span>{t(`review.finding.evidence_type_${finding.evidence_type}`)} · </span>}
      {location?.file && (sourceAvailable
        ? <a href={sourceLink(location.line)} target="_blank" rel="noopener noreferrer">
            <code>{formatEvidenceLocation(location)}</code>
          </a>
        : <code>{formatEvidenceLocation(location)}</code>)}
      {missingReason && (
        <span>
          {' · '}{t('review.finding.evidence_missing')}: {t(
            `review.finding.evidence_reason_${missingReason}`,
            t('review.finding.evidence_reason_unavailable'),
          )}
        </span>
      )}
      {location && <EvidenceReferenceOmission reference={location} />}
      {credential && <section aria-label={t('review.finding.credential.title')}>
        <div>{t(`review.finding.credential.${credential.classification}`)} · {t('review.finding.credential.confidence', { value: Math.round(credential.confidence * 100) })}</div>
        <div>{t('review.finding.credential.types')}: {credential.types.map(type => t(`review.finding.credential.type_${type}`)).join(', ')}</div>
        <div>{t('review.finding.credential.rules')}: <code>{credential.rules.join(', ')}</code></div>
        <div>{t('review.finding.credential.fingerprint')}: <code>{credential.fingerprint}</code></div>
        <div>{credential.reasons.map(reason => t(`review.finding.credential.reason_${reason}`)).join(' · ')}</div>
        {finding.requires_manual_review && <p>{t('review.finding.credential.manual_review')}</p>}
        <details>
          <summary>{t('review.finding.credential.locations')}</summary>
          <ul>{credential.matches.map((match, index) => <li key={index}>
            <a href={`/review/files?${new URLSearchParams({ versionId, path: match.file, line: String(match.line) })}`} target="_blank" rel="noopener noreferrer">
              <code>{formatEvidenceLocation(match)}</code>
            </a>
            {' · '}{t('review.finding.credential.field')}: <code>{match.field}</code>
            {' · '}{match.usage.map(usage => t(`review.finding.credential.usage_${usage}`)).join(', ')}
            <pre>{match.snippet}</pre>
          </li>)}</ul>
        </details>
        {credential.truncated && <p>{t('review.finding.credential.truncated')}</p>}
      </section>}
      {location?.dependency_name && <div>{location.dependency_name}{location.version ? `@${location.version}` : ''}</div>}
      {location?.field_locations && <details>
        <summary>{t('review.finding.structured_fields')}</summary>
        <ul>
          {Object.entries(location.field_locations).map(([field, span]) => <li key={field}>
            {field}: {span.missing_reason
              ? <span>{span.missing_reason === 'field_missing'
                  ? t('review.finding.field_missing')
                  : t(`review.finding.evidence_reason_${span.missing_reason}`, t('review.finding.evidence_reason_unavailable'))}
                  {' '}<code>{span.source_ref}</code>
                </span>
              : sourceAvailable
                ? <a href={sourceLink(span.line)} target="_blank" rel="noopener noreferrer">
                    <code>{formatEvidenceLocation({ ...span, file: location.file })}</code>
                  </a>
                : <code>{span.source_ref}</code>}
            <EvidenceReferenceOmission reference={span} />
          </li>)}
        </ul>
      </details>}
      {Array.from(reasons).map(reason => <div key={reason}>{contextMessage(reason, t)}</div>)}
      {!!finding.llm_context_audit?.reasons?.length && <details>
        <summary>{t('review.finding.context_details')}</summary>
        <ul>{finding.llm_context_audit.reasons.map(reason => <li key={reason}>{contextMessage(reason, t)}</li>)}</ul>
      </details>}
    </div>
  );
}
