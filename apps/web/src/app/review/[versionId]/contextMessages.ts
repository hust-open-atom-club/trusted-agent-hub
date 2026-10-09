import type { TFunction } from 'i18next';
import systemMessages from '../../../../../../packages/schema/llm-context-messages.json';

const categories: Record<string, string> = {
  source_missing: 'source_missing',
  missing_location: 'source_missing',
  missing_source_location: 'source_missing',
  missing_source_file: 'source_missing',
  source_file_not_scanned: 'source_missing',
  source_file_not_text: 'source_missing',
  source_cache_conflict: 'source_missing',
  field_missing: 'source_missing',
  invalid_path: 'source_missing',
  invalid_source_path: 'source_missing',
  location_unresolved: 'location_unresolved',
  source_span_missing: 'location_unresolved',
  invalid_source_line: 'location_unresolved',
  source_line_out_of_range: 'location_unresolved',
  source_context_empty: 'location_unresolved',
  missing_line: 'location_unresolved',
  invalid_span: 'location_unresolved',
  line_out_of_range: 'location_unresolved',
  evidence_limit: 'evidence_limit',
  source_ref_too_long: 'evidence_limit',
  sensitive_identifier: 'evidence_redacted',
  evidence_redacted: 'evidence_redacted',
  context_budget: 'context_budget',
  per_finding_byte_limit: 'context_budget',
  total_byte_limit: 'context_budget',
  line_limit: 'context_budget',
  location_limit: 'context_budget',
  delivery_missing: 'delivery_missing',
  candidate_location_not_delivered: 'delivery_missing',
  source_context_not_built: 'delivery_missing',
  source_location_not_in_context: 'delivery_missing',
  provider_failure: 'provider_failure',
};

export function contextMessage(reason: string, t: TFunction): string {
  const value = reason.replace(/^llm_candidate_skipped:/, '');
  const separator = value.indexOf(':');
  const code = separator < 0 ? value : value.slice(0, separator);
  const reference = separator < 0 ? '' : value.slice(separator + 1);
  if (Object.hasOwn(systemMessages, code)) {
    return t(systemMessages[code as keyof typeof systemMessages]);
  }
  const category = categories[code];
  if (category) {
    const explanation = t(
      `review.finding.context_detail_${code}`,
      t(`review.finding.context_reason_${category}`),
    );
    return reference ? `${explanation} (${reference})` : explanation;
  }
  // Keep provider-authored prose; unknown machine codes need a readable fallback.
  return /^[a-z][a-z0-9_]*(?::.*)?$/.test(value)
    ? t('review.finding.context_reason_unknown') : reason;
}
