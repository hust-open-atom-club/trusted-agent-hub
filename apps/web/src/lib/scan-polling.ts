// Keep the page polling for the full backend execution budget. Terminal
// failures stop polling immediately and remain available from the scan list.
export const SCAN_TOTAL_TIMEOUT_MS = 30 * 60 * 1000;
export const SCAN_FRONTEND_WAIT_MS = SCAN_TOTAL_TIMEOUT_MS;
export const SCAN_TERMINAL_FAILURE_STATUSES = [
  'error',
  // Historical persisted tasks only. New LLM timeouts complete with a
  // partial report and never write this task-level status.
  'llm_timeout',
  'total_timeout',
] as const;

export function isScanTerminalFailure(status: string): boolean {
  return (SCAN_TERMINAL_FAILURE_STATUSES as readonly string[]).includes(status);
}

const EARLY_SCAN_POLL_MS = 2_500;
const EARLY_LLM_POLL_MS = 5_000;
const MID_LLM_POLL_MS = 10_000;
const LATE_LLM_POLL_MS = 15_000;
// Callback delivery retries use a small server-side backoff, so a fixed
// 5s client interval tracks it without hammering the API.
const CALLBACK_PENDING_POLL_MS = 5_000;

export interface LLMReviewProgress {
  status?: 'running' | 'completed' | 'degraded' | 'timeout' | string;
  phase?: 'not_started' | 'judge_a' | 'judge_b' | 'arbitration' | 'complete' | string;
  attempt?: number;
  max_attempts?: number;
  findings_total?: number;
  findings_reviewed?: number;
  findings_pending?: number;
  started_at?: string;
  last_update_at?: string;
  deadline_at?: string;
  fallback?: string;
  reason_code?: string;
}

export interface ScanStatusPayload {
  scan_id: string;
  status: string;
  package_name?: string;
  created_at?: string;
  updated_at?: string;
  finished_at?: string;
  expires_at?: string;
  client_request_id?: string;
  execution_deadline_at?: string;
  lifecycle?: string;
  auto_refresh?: boolean;
  delete_allowed?: boolean;
  source_ref?: string | null;
  source_subdirectory?: string | null;
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
  report_status?: 'complete' | 'partial' | 'failed' | 'report_unavailable' | null;
  scan_status?: {
    state: 'complete' | 'partial' | 'failed' | string;
    conclusion: 'risks_found' | 'no_risks_found' | 'inconclusive' | string;
    complete: boolean;
    reasons?: string[];
  } | null;
  error?: string | null;
}

function timestampMs(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function scanPollIntervalMs(
  scan: Pick<ScanStatusPayload, 'status' | 'lifecycle' | 'llm_review'>,
  nowMs = Date.now(),
): number {
  if (isScanTerminalFailure(scan.status)) return 0;
  if (scan.status === 'complete') {
    // The scan finished but its submission callback may still be in
    // flight (lifecycle=callback_pending). Poll at a fixed slow interval
    // until the callback settles; a hard 0 here would hammer the API.
    return scan.lifecycle === 'callback_pending' ? CALLBACK_PENDING_POLL_MS : 0;
  }
  if (scan.status !== 'llm_review') return EARLY_SCAN_POLL_MS;

  const startedAt = timestampMs(scan.llm_review?.started_at) ?? nowMs;
  const elapsedMs = Math.max(0, nowMs - startedAt);
  if (elapsedMs < 2 * 60 * 1000) return EARLY_LLM_POLL_MS;
  if (elapsedMs < 5 * 60 * 1000) return MID_LLM_POLL_MS;
  return LATE_LLM_POLL_MS;
}

// A 0ms interval means "stop polling" to callers, never "poll as fast as
// possible": a loop that fed it straight into setTimeout would hammer the
// API. The wait loop clamps the delay instead of trusting its callers to
// have short-circuited terminal states.
export const SCAN_MIN_POLL_MS = 1_000;

export function scanPollDelayMs(internalMs: number, remainingMs: number): number {
  return Math.max(SCAN_MIN_POLL_MS, Math.min(internalMs, remainingMs));
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
  not_started: '未启动',
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
  complete: '扫描流程已结束',
  llm_timeout: 'LLM 审查超时，扫描已结束',
  total_timeout: '扫描总时长超时，报告不可用',
  error: '扫描失败，扫描已结束',
};

export function formatLLMReviewPhase(phase: string | undefined): string {
  if (!phase) return '准备中';
  return PHASE_LABELS[phase] ?? phase;
}

export function formatScanStatusMessage(
  scan: Pick<ScanStatusPayload, 'status' | 'llm_review' | 'report_status'>,
  nowMs = Date.now(),
): string {
  const progress = scan.llm_review;
  if (scan.status !== 'llm_review' || !progress) {
    if (scan.status === 'complete' && scan.report_status === 'partial') {
      return '扫描流程已结束，报告不完整，需人工复核';
    }
    return SCAN_STATUS_LABELS[scan.status] ?? `扫描中... (${scan.status})`;
  }

  const phase = formatLLMReviewPhase(progress.phase);
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

