import { describe, expect, it } from 'vitest';

import {
  formatScanStatusMessage,
  scanPollIntervalMs,
  SCAN_FRONTEND_WAIT_MS,
} from './scan-polling';

const startedAt = '2026-09-07T00:00:00.000Z';
const startMs = Date.parse(startedAt);

describe('scan polling policy', () => {
  it('uses a 15 minute frontend wait budget', () => {
    expect(SCAN_FRONTEND_WAIT_MS).toBe(900_000);
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
});
