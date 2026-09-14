import { describe, expect, it } from 'vitest';

import {
  formatScanStatusMessage,
  isScanTerminalFailure,
  scanPollDelayMs,
  scanPollIntervalMs,
  SCAN_MIN_POLL_MS,
  SCAN_TOTAL_TIMEOUT_MS,
  SCAN_FRONTEND_WAIT_MS,
} from './scan-polling';

const startedAt = '2026-09-07T00:00:00.000Z';
const startMs = Date.parse(startedAt);

describe('scan polling policy', () => {
  it('uses the total scan timeout as the frontend wait budget', () => {
    expect(SCAN_TOTAL_TIMEOUT_MS).toBe(1_800_000);
    expect(SCAN_FRONTEND_WAIT_MS).toBe(SCAN_TOTAL_TIMEOUT_MS);
  });

  it('recognizes terminal failure states', () => {
    expect(isScanTerminalFailure('llm_timeout')).toBe(true);
    expect(isScanTerminalFailure('total_timeout')).toBe(true);
    expect(isScanTerminalFailure('scanning')).toBe(false);
  });

  it('polls acquisition and static scanning every 2.5 seconds', () => {
    expect(scanPollIntervalMs({ status: 'downloading' }, startMs)).toBe(2_500);
    expect(scanPollIntervalMs({ status: 'scanning' }, startMs)).toBe(2_500);
  });

  it('backs off LLM polling at two and five minutes', () => {
    const scan = { status: 'llm_review', llm_review: { started_at: startedAt } };
    expect(scanPollIntervalMs(scan, startMs + 119_999)).toBe(5_000);
    expect(scanPollIntervalMs(scan, startMs + 120_000)).toBe(10_000);
    expect(scanPollIntervalMs(scan, startMs + 300_000)).toBe(15_000);
  });

  it('formats safe LLM progress for the user', () => {
    expect(formatScanStatusMessage({
      status: 'llm_review',
      llm_review: {
        phase: 'judge_a',
        attempt: 2,
        max_attempts: 3,
        findings_reviewed: 0,
        findings_total: 3,
        started_at: startedAt,
      },
    }, startMs + 200_000)).toBe([
      '正在进行 LLM 审查',
      '当前阶段：Judge A',
      '当前尝试：第 2/3 次',
      '已处理：0/3',
      '已等待：3 分 20 秒',
    ].join('\n'));
  });

  it('never turns a stop-polling interval into a busy loop', () => {
    // 0 means "stop polling" (terminal state) to callers, not "poll now".
    expect(scanPollDelayMs(0, 600_000)).toBe(SCAN_MIN_POLL_MS);
    expect(scanPollDelayMs(0, 200)).toBe(SCAN_MIN_POLL_MS);
  });

  it('keeps normal intervals and shrinks them to the remaining budget', () => {
    expect(scanPollDelayMs(2_500, 600_000)).toBe(2_500);
    expect(scanPollDelayMs(15_000, 4_000)).toBe(4_000);
  });
});
