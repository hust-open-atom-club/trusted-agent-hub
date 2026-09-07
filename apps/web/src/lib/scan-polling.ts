export const SCAN_FRONTEND_WAIT_MS = 15 * 60 * 1000;

const EARLY_SCAN_POLL_MS = 2_500;
const EARLY_LLM_POLL_MS = 5_000;
const MID_LLM_POLL_MS = 10_000;
const LATE_LLM_POLL_MS = 15_000;

export interface LLMReviewProgress {
  status?: 'running' | 'completed' | 'degraded' | 'timeout' | string;
  phase?: 'judge_a' | 'judge_b' | 'arbitration' | 'complete' | string;
  attempt?: number;
  max_attempts?: number;
  findings_total?: number;
  findings_reviewed?: number;
  findings_pending?: number;
  started_at?: string;
  last_update_at?: string;
  deadline_at?: string;
  fallback?: string;
}

export interface ScanStatusPayload {
  scan_id: string;
  status: string;
  package_name?: string;
  trust_score?: {
    grade: string | null;
    level: string | null;
    recommendation: string | null;
  };
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  llm_review?: LLMReviewProgress | null;
  error?: string | null;
}

function timestampMs(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function scanPollIntervalMs(
  scan: Pick<ScanStatusPayload, 'status' | 'llm_review'>,
  nowMs = Date.now(),
): number {
  if (scan.status !== 'llm_review') return EARLY_SCAN_POLL_MS;

  const startedAt = timestampMs(scan.llm_review?.started_at) ?? nowMs;
  const elapsedMs = Math.max(0, nowMs - startedAt);
  if (elapsedMs < 2 * 60 * 1000) return EARLY_LLM_POLL_MS;
  if (elapsedMs < 5 * 60 * 1000) return MID_LLM_POLL_MS;
  return LATE_LLM_POLL_MS;
}

export function formatElapsed(startedAt: string | undefined, nowMs = Date.now()): string {
  const startMs = timestampMs(startedAt);
  if (startMs === null) return '0 秒';
  const totalSeconds = Math.max(0, Math.floor((nowMs - startMs) / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes} 分 ${seconds} 秒` : `${seconds} 秒`;
}

const PHASE_LABELS: Record<string, string> = {
  judge_a: 'Judge A',
  judge_b: 'Judge B',
  arbitration: '仲裁',
  complete: '已完成',
};

const SCAN_STATUS_LABELS: Record<string, string> = {
  pending: '扫描任务已排队',
  downloading: '正在下载仓库',
  scanning: '正在进行静态扫描',
  scoring: '正在计算信任评分',
  saving: '正在保存扫描报告',
};

export function formatScanStatusMessage(
  scan: Pick<ScanStatusPayload, 'status' | 'llm_review'>,
  nowMs = Date.now(),
): string {
  const progress = scan.llm_review;
  if (scan.status !== 'llm_review' || !progress) {
    return SCAN_STATUS_LABELS[scan.status] ?? `扫描中... (${scan.status})`;
  }

  const phase = PHASE_LABELS[progress.phase ?? ''] ?? progress.phase ?? '准备中';
  const attempt = Math.max(0, progress.attempt ?? 0);
  const maxAttempts = Math.max(1, progress.max_attempts ?? 3);
  const reviewed = Math.max(0, progress.findings_reviewed ?? 0);
  const total = Math.max(reviewed, progress.findings_total ?? 0);

  return [
    '正在进行 LLM 审查',
    `当前阶段：${phase}`,
    `当前尝试：第 ${attempt}/${maxAttempts} 次`,
    `已处理：${reviewed}/${total}`,
    `已等待：${formatElapsed(progress.started_at, nowMs)}`,
  ].join('\n');
}

