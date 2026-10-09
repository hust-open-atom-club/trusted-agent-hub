import { createInstance } from 'i18next';
import { describe, expect, it } from 'vitest';
import en from '@/i18n/locales/en/common.json';
import zh from '@/i18n/locales/zh/common.json';
import { contextMessage } from './contextMessages';
import systemMessages from '../../../../../../packages/schema/llm-context-messages.json';

describe('contextMessage', () => {
  it.each(['en', 'zh'])('translates audit and historical skip codes in %s', async language => {
    const i18n = createInstance();
    await i18n.init({ lng: language, resources: { en: { translation: en }, zh: { translation: zh } } });
    const codes = [
      'source_missing:src/run.py', 'per_finding_byte_limit', 'total_byte_limit',
      'delivery_missing:src/run.py:10-20', 'source_span_missing:SKILL.md',
      'llm_candidate_skipped:invalid_source_line', 'future_internal_reason',
    ];
    for (const code of codes) {
      const message = contextMessage(code, i18n.t);
      expect(message).not.toContain(code.split(':')[0]);
      expect(message).not.toContain('review.finding.');
    }
    for (const [code, key] of Object.entries(systemMessages)) {
      expect(contextMessage(code, i18n.t)).toBe(i18n.t(key));
      expect(contextMessage(code, i18n.t)).not.toBe(i18n.t('review.finding.context_reason_unknown'));
      expect(contextMessage(code, i18n.t)).not.toContain('review.finding.');
    }
    expect(contextMessage('evidence_redacted', i18n.t)).toBe(i18n.t(
      'review.finding.context_reason_evidence_redacted',
    ));
    expect(contextMessage(codes[0], i18n.t)).toContain('src/run.py');
    expect(contextMessage(codes[3], i18n.t)).toContain('src/run.py:10-20');
    expect(contextMessage('Need the caller implementation.', i18n.t)).toBe('Need the caller implementation.');
  });
});
