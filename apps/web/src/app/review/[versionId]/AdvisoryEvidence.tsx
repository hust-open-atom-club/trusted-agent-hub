'use client';

import { useTranslation } from 'react-i18next';
import type { ReviewAdvisory } from '@/types';
import FindingEvidence from './FindingEvidence';

export default function AdvisoryEvidence({ advisory, versionId }: {
  advisory: ReviewAdvisory;
  versionId: string;
}) {
  const { t } = useTranslation();
  const policy = advisory.registry_policy;
  return (
    <>
      <FindingEvidence finding={advisory} versionId={versionId} />
      {policy && (
        <details className="review-advisory-occurrences">
          <summary>
            {t('review.detail.advisory_occurrences', { count: policy.occurrence_count })}
          </summary>
          <code>{policy.registry_host}</code>
          <div className="review-advisory-occurrence-list">
            {policy.occurrences.map((occurrence, index) => (
              <div className="review-advisory-occurrence" key={index}>
                {!occurrence.dependency_name && (
                  <span>{t('review.detail.advisory_source_declaration')}</span>
                )}
                <FindingEvidence
                  finding={{ evidence_type: 'registry_policy', location: occurrence }}
                  versionId={versionId}
                />
                <span>{t('review.detail.advisory_scope')}: {t(
                  `review.detail.dependency_coverage_scope_${occurrence.scope}`,
                )}</span>
                <code>{occurrence.resolved_url}</code>
                {occurrence.integrity && <code>integrity: {occurrence.integrity}</code>}
              </div>
            ))}
          </div>
          {policy.truncated && (
            <p className="review-advisory-truncated">
              {t('review.detail.advisory_occurrences_omitted', {
                count: policy.occurrence_count - policy.occurrences.length,
              })}
            </p>
          )}
        </details>
      )}
    </>
  );
}
