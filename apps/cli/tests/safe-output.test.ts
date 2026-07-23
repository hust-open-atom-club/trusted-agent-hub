/**
 * Tests for shared output sanitization (safe-output.ts).
 *
 * Run: npx tsx tests/safe-output.test.ts
 */

import * as assert from 'assert';
import { sanitizeOutput } from '../src/safe-output';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err: unknown) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.error(err instanceof Error ? err.stack || err.message : String(err));
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  console.log('CLI Safe Output Tests\n');

  // ── ANSI escape codes stripped ──────────────────────────────────────────

  runTest('ANSI CSI sequences stripped', () => {
    assert.strictEqual(sanitizeOutput('\x1b[31mRED\x1b[0m'), 'RED');
  });

  runTest('ANSI with multiple parameters stripped', () => {
    assert.strictEqual(sanitizeOutput('\x1b[1;31mBOLD RED\x1b[0m'), 'BOLD RED');
  });

  // ── OSC sequences stripped ──────────────────────────────────────────────

  runTest('OSC title sequences stripped', () => {
    assert.strictEqual(sanitizeOutput('\x1b]0;title\x07text'), 'text');
  });

  runTest('OSC with ST terminator stripped', () => {
    assert.strictEqual(sanitizeOutput('\x1b]0;title\x1b\\text'), 'text');
  });

  // ── C0/C1 control characters stripped ───────────────────────────────────

  runTest('C0 control chars stripped (\\n, \\r, \\t)', () => {
    assert.strictEqual(sanitizeOutput('a\nb\rc\td\x86e'), 'abcde');
  });

  runTest('NULL byte stripped', () => {
    assert.strictEqual(sanitizeOutput('a\x00b'), 'ab');
  });

  runTest('DEL stripped', () => {
    assert.strictEqual(sanitizeOutput('a\x7fb'), 'ab');
  });

  runTest('C1 control chars (0x80-0x9F) stripped', () => {
    assert.strictEqual(sanitizeOutput('a\x80b\x9fc'), 'abc');
  });

  // ── Truncation ──────────────────────────────────────────────────────────

  runTest('Truncates at 200 chars', () => {
    const long = 'x'.repeat(250);
    const result = sanitizeOutput(long);
    assert.strictEqual(result.length, 200);
    assert.strictEqual(result.endsWith('…'), true);
  });

  runTest('Short string not truncated', () => {
    const short = 'hello world';
    assert.strictEqual(sanitizeOutput(short), short);
  });

  runTest('Exactly 200 chars not truncated', () => {
    const exact = 'x'.repeat(200);
    const result = sanitizeOutput(exact);
    assert.strictEqual(result.length, 200);
    assert.strictEqual(result.endsWith('…'), false);
  });

  runTest('199 chars not truncated', () => {
    const s = 'x'.repeat(199);
    assert.strictEqual(sanitizeOutput(s), s);
  });

  // ── Combined ────────────────────────────────────────────────────────────

  runTest('Combined ANSI + control + truncation', () => {
    // 300 chars of 'x' with ANSI codes mixed in — after stripping ANSI
    // we get 300 'x' chars, which exceeds MAX_OUTPUT_LENGTH (200)
    const parts: string[] = [];
    for (let i = 0; i < 150; i++) {
      parts.push('\x1b[31m');
      parts.push('xx');
      parts.push('\x1b[0m');
    }
    const input = parts.join('');
    const result = sanitizeOutput(input);
    assert.strictEqual(result.length, 200);
    assert.strictEqual(result.endsWith('…'), true);
    // Must not contain any ANSI escape
    assert.ok(!result.includes('\x1b'));
  });

  // ── Empty input ────────────────────────────────────────────────────────

  runTest('Empty string unchanged', () => {
    assert.strictEqual(sanitizeOutput(''), '');
  });

  // ── Unicode preserved ───────────────────────────────────────────────────

  runTest('Unicode characters preserved', () => {
    assert.strictEqual(sanitizeOutput('中文テスト'), '中文テスト');
  });

  runTest('Emoji preserved', () => {
    assert.strictEqual(sanitizeOutput('🎉'), '🎉');
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main();
