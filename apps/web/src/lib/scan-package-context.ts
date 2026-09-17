export const SCAN_PACKAGE_CONTEXT_KEY = 'trusted-agent-hub:scan-package-context';

// The mapping is a resume hint for the scan list ("continue submission"), so a
// long-lived browser profile must not grow it without limit.
const MAX_SCAN_PACKAGE_CONTEXT_ENTRIES = 50;

type ScanPackageContextMap = Record<string, string>;

function parseScanPackageContext(raw: string): ScanPackageContextMap {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const map: ScanPackageContextMap = {};
    for (const [scanId, packageId] of Object.entries(
      parsed as Record<string, unknown>,
    )) {
      if (typeof packageId === 'string' && packageId) map[scanId] = packageId;
    }
    return map;
  } catch {
    return {};
  }
}

function readScanPackageContextMap(): ScanPackageContextMap {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(SCAN_PACKAGE_CONTEXT_KEY);
    return raw ? parseScanPackageContext(raw) : {};
  } catch {
    return {};
  }
}

function writeScanPackageContextMap(map: ScanPackageContextMap): void {
  if (typeof window === 'undefined') return;
  try {
    const entries = Object.entries(map);
    const bounded = entries.slice(
      Math.max(0, entries.length - MAX_SCAN_PACKAGE_CONTEXT_ENTRIES),
    );
    window.localStorage.setItem(
      SCAN_PACKAGE_CONTEXT_KEY,
      JSON.stringify(Object.fromEntries(bounded)),
    );
  } catch {
    // The context is an optional resume hint; losing it must never break the page.
  }
}

/** localStorage, not sessionStorage: the mapping must survive a browser restart. */
export function rememberScanPackageContext(
  scanId: string,
  packageId: string,
): void {
  if (!scanId || !packageId) return;
  const map = readScanPackageContextMap();
  // Re-insert so the entry counts as the most recent one when pruning.
  delete map[scanId];
  map[scanId] = packageId;
  writeScanPackageContextMap(map);
}

export function readScanPackageContext(scanId: string): string | null {
  if (!scanId) return null;
  return readScanPackageContextMap()[scanId] ?? null;
}

export function forgetScanPackageContext(scanId: string): void {
  if (!scanId) return;
  const map = readScanPackageContextMap();
  if (scanId in map) {
    delete map[scanId];
    writeScanPackageContextMap(map);
  }
}
