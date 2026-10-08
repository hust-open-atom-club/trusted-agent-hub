'use client';

import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { DependencyQueryResult } from '@/types';

const QUERY_PAGE_SIZE = 50;

function QueryOccurrences({ result }: { result: DependencyQueryResult }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  return (
    <details onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary style={{ cursor: 'pointer' }}>
        {t('review.detail.dependency_coverage_occurrences', { count: result.occurrence_count })}
      </summary>
      {open && (
        <>
          <ul>
            {result.occurrences.map((occurrence, index) => (
              <li key={index} style={{ overflowWrap: 'anywhere' }}>
                <code>{occurrence.source_file}{occurrence.line ? `:${occurrence.line}` : ''}</code>
                {' · '}{t(`review.detail.dependency_coverage_scope_${occurrence.scope}`)}
                {' · '}{t(`review.detail.dependency_coverage_${occurrence.direct ? 'direct' : 'transitive'}`)}
                {occurrence.source_ref && <div><code>{occurrence.source_ref}</code></div>}
                {occurrence.registry && <div><code>{occurrence.registry}</code></div>}
              </li>
            ))}
          </ul>
          {result.occurrences_truncated && (
            <p>{t('review.detail.dependency_coverage_occurrences_truncated')}</p>
          )}
        </>
      )}
    </details>
  );
}

export default function DependencyQueryResults({
  results,
  truncated,
  omitted,
}: {
  results: DependencyQueryResult[];
  truncated?: boolean;
  omitted?: number;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const pageCount = Math.ceil(results.length / QUERY_PAGE_SIZE);
  const page = Math.min(pageIndex, Math.max(0, pageCount - 1));
  const visibleResults = results.slice(page * QUERY_PAGE_SIZE, (page + 1) * QUERY_PAGE_SIZE);
  const label = (name: string) => t(`review.detail.dependency_coverage_${name}`);

  if (results.length === 0 && !truncated) return null;

  return (
    <div style={{ marginTop: '0.8rem', fontSize: '0.8rem' }} data-testid="dependency-query-results">
      {truncated && (
        <p role="note">
          {t('review.detail.dependency_coverage_queries_truncated', { count: results.length })}
          {omitted !== undefined && <> {t('review.detail.dependency_coverage_queries_omitted', { count: omitted })}</>}
        </p>
      )}
      <details onToggle={(event) => setOpen(event.currentTarget.open)}>
        <summary style={{ cursor: 'pointer', fontWeight: 700 }}>
          {t('review.detail.dependency_coverage_query_results', { count: results.length })}
        </summary>
        {open && (
          <div className="review-table-wrapper" style={{ marginTop: '0.6rem', overflowX: 'auto' }}>
            {pageCount > 1 && (
              <nav aria-label={label('query_pagination')} style={{ display: 'flex', gap: '0.8rem', alignItems: 'center' }}>
                <button type="button" disabled={page === 0} onClick={() => setPageIndex(page - 1)}>
                  {label('query_previous')}
                </button>
                <span role="status">{t('review.detail.dependency_coverage_query_page', { page: page + 1, total: pageCount })}</span>
                <button type="button" disabled={page + 1 >= pageCount} onClick={() => setPageIndex(page + 1)}>
                  {label('query_next')}
                </button>
              </nav>
            )}
            <table className="review-table">
              <thead>
                <tr>
                  {['coordinate', 'status', 'failure_reasons', 'response', 'cache', 'sources'].map((name) => (
                    <th key={name} scope="col">{label(name)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleResults.map((result) => (
                  <tr
                    key={JSON.stringify([result.ecosystem, result.package_name, result.version])}
                    className="review-row"
                    style={{ cursor: 'default', overflowWrap: 'anywhere' }}
                  >
                    <td data-label={label('coordinate')} style={{ overflowWrap: 'anywhere' }}>
                      <code>{result.package_name}@{result.version ?? '—'}</code>
                      <div>{result.ecosystem}</div>
                    </td>
                    <td data-label={label('status')}>
                      {label(`status_${result.status}`)}
                      {result.status === 'succeeded' && (
                        <div>{label('known_vulnerabilities')}: {result.vulnerability_count}</div>
                      )}
                    </td>
                    <td data-label={label('failure_reasons')}>
                      {result.failure_reason
                        ? t(`review.detail.dependency_coverage_reason_${result.failure_reason}`, {
                            defaultValue: result.failure_reason.replace(/_/g, ' '),
                          })
                        : '—'}
                      {result.failure_reason && <div><code>{result.failure_reason}</code></div>}
                    </td>
                    <td data-label={label('response')}>
                      {result.data_source} · {result.response_status ?? '—'}
                      <div>{label('attempts')}: {result.attempts}</div>
                      {result.queried_at && <time dateTime={result.queried_at}>{result.queried_at}</time>}
                    </td>
                    <td data-label={label('cache')}>
                      {result.from_cache
                        ? label(result.cache_source ? `cache_${result.cache_source}` : 'cache_hits')
                        : '—'}
                      {result.cache_age_seconds !== undefined && (
                        <div>{t('review.detail.dependency_coverage_cache_age', { seconds: result.cache_age_seconds })}</div>
                      )}
                    </td>
                    <td data-label={label('sources')}><QueryOccurrences result={result} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </details>
    </div>
  );
}
