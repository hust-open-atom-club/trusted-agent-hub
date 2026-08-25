import { describe, expect, it } from 'vitest';

import { getIntegrityRows } from './detail-view-model';

describe('getIntegrityRows', () => {
  it('shows hash scope and preserves an incomplete hash status', () => {
    const rows = getIntegrityRows(undefined, {
      sha256: 'a'.repeat(64),
      hash_scope: 'scanned_source',
      is_complete: false,
    });
    const values = Object.fromEntries(rows.map((row) => [row.labelKey, row.value]));

    expect(values['detail.integrity.hash_scope']).toBe('detail.integrity.scope_scanned_source');
    expect(values['detail.integrity.completeness']).toBe('detail.integrity.incomplete');
  });

  it('shows unknown status when integrity metadata is absent', () => {
    const rows = getIntegrityRows(undefined, null);
    const values = Object.fromEntries(rows.map((row) => [row.labelKey, row.value]));

    expect(values['detail.integrity.hash_scope']).toBe('detail.integrity.unknown');
    expect(values['detail.integrity.completeness']).toBe('detail.integrity.unknown');
  });
});
