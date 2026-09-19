export const PENDING_SUBMIT_STORAGE_KEY = 'trusted-agent-hub:pending-submit-context';

// 6h：覆盖"点完提交→刷新→当天晚些回来继续"的窗口；再久就该走全新提交流程。
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

/** 用 localStorage：关标签页/重启浏览器后仍要能提示"上次已提交"。 */
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
  } catch {
    // 存储失败只损失恢复提示，不阻断提交流程。
  }
}

/** 补写请求中途拿到的 id，不重置 savedAt；无存活上下文时为空操作。 */
export function patchPendingSubmitContext(
  updates: Partial<Pick<PendingSubmitContext, 'packageId' | 'versionId'>>,
): void {
  const existing = readPendingSubmitContext();
  if (!existing) return;
  writePendingSubmitContext({
    packageId: updates.packageId ?? existing.packageId,
    versionId: updates.versionId ?? existing.versionId,
    packageName: existing.packageName,
    version: existing.version,
  });
}

export function clearPendingSubmitContext(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(PENDING_SUBMIT_STORAGE_KEY);
  } catch {
    // 本来就无内容可清。
  }
}
