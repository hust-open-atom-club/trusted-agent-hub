'use client';

import { useTranslation } from 'react-i18next';
import type { LLMContextCoverage } from '@/types';
import { contextMessage } from './contextMessages';

export default function ContextCoverageSummary({ coverage }: {
  coverage?: LLMContextCoverage | null;
}) {
  const { t } = useTranslation();
  if (!coverage) return null;
  const reasons = {
    source_missing: coverage.source_missing,
    location_unresolved: coverage.location_unresolved,
    evidence_limit: coverage.evidence_limit,
    context_budget: coverage.context_budget,
    delivery_missing: coverage.delivery_missing,
    ...coverage.reason_counts,
  };
  const files = Object.entries(coverage.top_finding_files || {});
  return (
    <section className="review-detail-section" aria-label={t('review.finding.coverage_title')}>
      <h2 className="review-detail-section-title">{t('review.finding.coverage_title')}</h2>
      <dl>
        {(['candidates', 'complete', 'partial', 'missing'] as const).map(key => (
          <div key={key}>
            <dt>{t(`review.finding.coverage_${key}`)}</dt>
            <dd>{coverage[key] ?? 0}</dd>
          </div>
        ))}
      </dl>
      <ul>
        {Object.entries(reasons).filter(([, count]) => typeof count === 'number').map(([reason, count]) => (
          <li key={reason}>{contextMessage(reason, t)} {t('review.finding.coverage_count', { count })}</li>
        ))}
      </ul>
      {files.length > 0 && <details>
        <summary>{t('review.finding.coverage_files')}</summary>
        <ul>{files.map(([file, count]) => <li key={file}>
          <code>{file}</code> · {t('review.finding.coverage_count', { count })}
        </li>)}</ul>
      </details>}
    </section>
  );
}
