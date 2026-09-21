export const PENDING_SUBMIT_STORAGE_KEY = 'trusted-agent-hub:pending-submit-context';

export const PENDING_SUBMIT_TTL_MS = 6 * 60 * 60 * 1000;

export interface PendingSubmitContext {
  /** 新包流程要等 POST /packages 成功才知道；版本创建前可为 null。 */
  packageId: string | null;
  /** 恢复逻辑的查询锚点（GET /versions/{id}）。 */
  versionId: string | null;
  packageName: string;
  version: string;
  savedAt: number;
}

export function pendingSubmitMatchesTarget(
  context: PendingSubmitContext,
  targetPackageId: string | null,
): boolean {
  if (targetPackageId === null) return true;
  return context.packageId === targetPackageId;
}

export function pendingSubmitNeedsConfirmation(
  context: PendingSubmitContext,
  targetPackageId: string | null,
): boolean {
  return !pendingSubmitMatchesTarget(context, targetPackageId);
}

function parsePendingSubmitContext(raw: string): PendingSubmitContext | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const candidate = parsed as Partial<PendingSubmitContext>;
  if (
    typeof candidate.packageName !== 'string' || !candidate.packageName
    || typeof candidate.version !== 'string' || !candidate.version
    || typeof candidate.savedAt !== 'number'
  ) {
    return null;
  }
  return {
    packageId:
      typeof candidate.packageId === 'string' && candidate.packageId
        ? candidate.packageId
        : null,
    versionId:
      typeof candidate.versionId === 'string' && candidate.versionId
        ? candidate.versionId
        : null,
    packageName: candidate.packageName,
    version: candidate.version,
    savedAt: candidate.savedAt,
  };
}

export function readPendingSubmitContext(): PendingSubmitContext | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(PENDING_SUBMIT_STORAGE_KEY);
    if (!raw) return null;
    const context = parsePendingSubmitContext(raw);
    if (!context) return null;
    if (Date.now() - context.savedAt > PENDING_SUBMIT_TTL_MS) {
      window.localStorage.removeItem(PENDING_SUBMIT_STORAGE_KEY);
      return null;
    }
    return context;
  } catch {
    return null;
  }
}

export function writePendingSubmitContext(
  context: Omit<PendingSubmitContext, 'savedAt'>,
): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(
      PENDING_SUBMIT_STORAGE_KEY,
      JSON.stringify({ ...context, savedAt: Date.now() } satisfies PendingSubmitContext),
    );
  } catch {}
}

export function patchPendingSubmitContext(
  updates: Partial<Pick<PendingSubmitContext, 'packageId' | 'versionId'>>,
): void {
  const existing = readPendingSubmitContext();
  if (!existing) return;
  try {
    window.localStorage.setItem(
      PENDING_SUBMIT_STORAGE_KEY,
      JSON.stringify({
        ...existing,
        packageId: updates.packageId ?? existing.packageId,
        versionId: updates.versionId ?? existing.versionId,
      } satisfies PendingSubmitContext),
    );
  } catch {}
}

export function clearPendingSubmitContext(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(PENDING_SUBMIT_STORAGE_KEY);
  } catch {}
}
