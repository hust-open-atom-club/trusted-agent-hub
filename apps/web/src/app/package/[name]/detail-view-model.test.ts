import { describe, expect, it } from 'vitest';

import type { PublicPermissionSummary } from '@/types';

import {
  getCapabilityAxes,
  getIntegrityRows,
  hasDeclaredCapability,
} from './detail-view-model';

function permissionSummary(
  overrides: Partial<PublicPermissionSummary> = {},
): PublicPermissionSummary {
  return {
    filesystem_read_count: 0,
    filesystem_write_count: 0,
    filesystem_delete: false,
    shell_allowed: false,
    network_allowed: false,
    environment_read_count: 0,
    environment_write_count: 0,
    credentials_access_count: 0,
    database_declared: false,
    browser_declared: false,
    external_services_count: 0,
    ...overrides,
  };
}

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

describe('getCapabilityAxes', () => {
  it('keeps every axis on the inner ring when nothing is declared', () => {
    const axes = getCapabilityAxes(permissionSummary());

    expect(axes.map((axis) => axis.key)).toEqual([
      'filesystem_read',
      'filesystem_write',
      'filesystem_delete',
      'shell',
      'network',
      'environment',
      'credentials_external',
    ]);
    expect(axes.every((axis) => axis.value === 0)).toBe(true);
    expect(axes.every((axis) => axis.detailKey === 'detail.capability.level.none')).toBe(true);
    expect(hasDeclaredCapability(axes)).toBe(false);
  });

  it('treats declared paths as a scoped capability and delete as unbounded', () => {
    const axes = getCapabilityAxes(
      permissionSummary({ filesystem_read_count: 2, filesystem_delete: true }),
    );
    const byKey = Object.fromEntries(axes.map((axis) => [axis.key, axis]));

    expect(byKey.filesystem_read.scope).toBe('limited');
    expect(byKey.filesystem_read.value).toBe(0.5);
    expect(byKey.filesystem_read.detailValues).toEqual({ count: 2 });
    expect(byKey.filesystem_delete.scope).toBe('unrestricted');
    expect(byKey.filesystem_delete.value).toBe(1);
    expect(byKey.filesystem_delete.tone).toBe('danger');
    expect(hasDeclaredCapability(axes)).toBe(true);
  });

  it('cannot express a shell allowlist, so it stays at the widest reading', () => {
    const axes = getCapabilityAxes(permissionSummary({ shell_allowed: true }));
    const shell = axes.find((axis) => axis.key === 'shell');

    expect(shell?.scope).toBe('unrestricted');
    expect(shell?.detailKey).toBe('detail.capability.value.shell');
  });

  it('ranks environment writes above read-only variables', () => {
    const readOnly = getCapabilityAxes(permissionSummary({ environment_read_count: 4 }));
    const writable = getCapabilityAxes(
      permissionSummary({ environment_read_count: 4, environment_write_count: 1 }),
    );

    expect(readOnly.find((axis) => axis.key === 'environment')?.scope).toBe('limited');
    expect(writable.find((axis) => axis.key === 'environment')?.scope).toBe('unrestricted');
  });

  it('folds credentials, database, browser and external services into one axis', () => {
    const declaredExternally = getCapabilityAxes(
      permissionSummary({ database_declared: true, external_services_count: 2 }),
    );
    const withCredentials = getCapabilityAxes(permissionSummary({ credentials_access_count: 1 }));

    expect(
      declaredExternally.find((axis) => axis.key === 'credentials_external')?.scope,
    ).toBe('limited');
    expect(withCredentials.find((axis) => axis.key === 'credentials_external')?.tone).toBe('danger');
  });

  it('degrades to an empty scope when the public summary is missing', () => {
    expect(hasDeclaredCapability(getCapabilityAxes(null))).toBe(false);
    expect(hasDeclaredCapability(getCapabilityAxes(undefined))).toBe(false);
  });
});
