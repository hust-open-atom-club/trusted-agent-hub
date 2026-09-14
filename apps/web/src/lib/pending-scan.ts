export const PENDING_SCAN_STORAGE_KEY = 'trusted-agent-hub:pending-scan-id';

export interface PendingScanState {
  scanId: string | null;
  clientRequestId: string;
  repoUrl: string;
}

function legacyPendingScanState(raw: string): PendingScanState {
  return { scanId: raw, clientRequestId: '', repoUrl: '' };
}

function parsePendingScanState(raw: string): PendingScanState | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return legacyPendingScanState(raw);
  }
  if (!parsed || typeof parsed !== 'object') {
    return legacyPendingScanState(raw);
  }

  const candidate = parsed as Partial<PendingScanState>;
  const clientRequestId = typeof candidate.clientRequestId === 'string'
    ? candidate.clientRequestId
    : '';
  const repoUrl = typeof candidate.repoUrl === 'string' ? candidate.repoUrl : '';
  const scanId = typeof candidate.scanId === 'string' && candidate.scanId
    ? candidate.scanId
    : null;
  if (!clientRequestId && !scanId) return null;
  return { scanId, clientRequestId, repoUrl };
}

export function readPendingScanState(): PendingScanState | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(PENDING_SCAN_STORAGE_KEY);
    return raw ? parsePendingScanState(raw) : null;
  } catch {
    return null;
  }
}

export function writePendingScanState(state: PendingScanState): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(PENDING_SCAN_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // The current page can continue even when session storage is unavailable.
  }
}

export function clearPendingScanState(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.removeItem(PENDING_SCAN_STORAGE_KEY);
  } catch {
    // Session storage is optional.
  }
}

export function clearPendingScanIfMatches(scanId: string): void {
  if (readPendingScanState()?.scanId === scanId) {
    clearPendingScanState();
  }
}
