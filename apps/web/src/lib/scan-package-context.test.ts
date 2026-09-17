import { beforeEach, describe, expect, it } from 'vitest';

import {
  forgetScanPackageContext,
  readScanPackageContext,
  rememberScanPackageContext,
  SCAN_PACKAGE_CONTEXT_KEY,
} from './scan-package-context';

describe('scan package context', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('round-trips a scan to package mapping', () => {
    rememberScanPackageContext('scan-current', 'package-1');

    expect(readScanPackageContext('scan-current')).toBe('package-1');
  });

  it('returns null for scans without a recorded package', () => {
    expect(readScanPackageContext('scan-unknown')).toBeNull();
  });

  it('forgets a single mapping without touching the others', () => {
    rememberScanPackageContext('scan-a', 'package-a');
    rememberScanPackageContext('scan-b', 'package-b');

    forgetScanPackageContext('scan-a');

    expect(readScanPackageContext('scan-a')).toBeNull();
    expect(readScanPackageContext('scan-b')).toBe('package-b');
  });

  it('keeps the mapping usable when storage holds malformed data', () => {
    window.localStorage.setItem(SCAN_PACKAGE_CONTEXT_KEY, 'not-json');
    expect(readScanPackageContext('scan-x')).toBeNull();

    rememberScanPackageContext('scan-x', 'package-x');

    expect(readScanPackageContext('scan-x')).toBe('package-x');
  });

  it('drops non-string values and array payloads', () => {
    window.localStorage.setItem(
      SCAN_PACKAGE_CONTEXT_KEY,
      JSON.stringify({ 'scan-num': 42, 'scan-ok': 'package-ok' }),
    );
    expect(readScanPackageContext('scan-num')).toBeNull();

    window.localStorage.setItem(SCAN_PACKAGE_CONTEXT_KEY, JSON.stringify(['x']));
    expect(readScanPackageContext('scan-ok')).toBeNull();
  });

  it('keeps only the most recent entries', () => {
    for (let index = 0; index < 60; index += 1) {
      rememberScanPackageContext(`scan-${index}`, `package-${index}`);
    }

    expect(readScanPackageContext('scan-0')).toBeNull();
    expect(readScanPackageContext('scan-59')).toBe('package-59');
  });
});
