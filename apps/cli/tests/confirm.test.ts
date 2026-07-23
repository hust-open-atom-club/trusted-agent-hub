/**
 * Tests for terminal confirmation (confirm.ts).
 *
 * Run: npx tsx tests/confirm.test.ts
 */

import * as assert from 'assert';
import { Writable, Readable } from 'stream';
import { createTerminalConfirm } from '../src/confirm';
import type { ConfirmSummary } from '../src/confirm';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err: unknown) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.error(err instanceof Error ? err.stack || err.message : String(err));
  }
}

function makeTtyInput(lines: string[]): Readable & { isTTY?: boolean } {
  let idx = 0;
  const readable = new Readable({
    read() {
      if (idx < lines.length) {
        this.push(lines[idx] + '\n');
        idx++;
      } else {
        this.push(null);
      }
    },
  });
  (readable as any).isTTY = true;
  return readable as Readable & { isTTY?: boolean };
}

function makeTtyOutput(): { output: Writable & { isTTY?: boolean }; getWritten(): string } {
  let buf = '';
  const writable = new Writable({
    write(chunk, _encoding, callback) {
      buf += chunk.toString();
      callback();
    },
  });
  (writable as any).isTTY = true;
  return { output: writable as Writable & { isTTY?: boolean }, getWritten: () => buf };
}

function makeNonTtyInput(): Readable & { isTTY?: boolean } {
  const readable = new Readable({ read() { this.push(null); } });
  (readable as any).isTTY = false;
  return readable as Readable & { isTTY?: boolean };
}

function makeNonTtyOutput(): Writable & { isTTY?: boolean } {
  const writable = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
  });
  (writable as any).isTTY = false;
  return writable as Writable & { isTTY?: boolean };
}

const summary: ConfirmSummary = {
  packageName: 'test-pkg',
  version: '1.0.0',
  client: 'claude-code',
  installPath: '/home/user/.claude/skills/test-pkg',
  contentState: 'clean',
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Confirm Tests\n');

  // ── TTY: yes (lowercase) ────────────────────────────────────────────────

  await runTest('TTY — "y" returns true', async () => {
    const input = makeTtyInput(['y']);
    const { output, getWritten } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm, 'confirm should be defined');
    const result = await confirm!(summary);
    assert.strictEqual(result, true);

    const written = getWritten();
    assert.ok(written.includes('test-pkg'), 'output must contain package name');
    assert.ok(written.includes('claude-code'), 'output must contain client');
    assert.ok(written.includes('clean'), 'output must contain content state');
  });

  // ── TTY: "yes" ──────────────────────────────────────────────────────────

  await runTest('TTY — "yes" returns true', async () => {
    const input = makeTtyInput(['yes']);
    const { output } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    const result = await confirm!(summary);
    assert.strictEqual(result, true);
  });

  // ── TTY: uppercase "Y" ──────────────────────────────────────────────────

  await runTest('TTY — "Y" returns true', async () => {
    const input = makeTtyInput(['Y']);
    const { output } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    const result = await confirm!(summary);
    assert.strictEqual(result, true);
  });

  // ── TTY: other input refuses ────────────────────────────────────────────

  await runTest('TTY — "n" returns false', async () => {
    const input = makeTtyInput(['n']);
    const { output } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    const result = await confirm!(summary);
    assert.strictEqual(result, false);
  });

  await runTest('TTY — empty string returns false', async () => {
    const input = makeTtyInput(['']);
    const { output } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    const result = await confirm!(summary);
    assert.strictEqual(result, false);
  });

  await runTest('TTY — random text returns false', async () => {
    const input = makeTtyInput(['maybe']);
    const { output } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    const result = await confirm!(summary);
    assert.strictEqual(result, false);
  });

  // ── Non-TTY ─────────────────────────────────────────────────────────────

  await runTest('Non-TTY input returns undefined', async () => {
    const input = makeNonTtyInput();
    const output = makeNonTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.strictEqual(confirm, undefined);
  });

  await runTest('Non-TTY output returns undefined', async () => {
    const input = makeTtyInput(['y']);
    const output = makeNonTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.strictEqual(confirm, undefined);
  });

  await runTest('Both non-TTY returns undefined', async () => {
    const input = makeNonTtyInput();
    const output = makeNonTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.strictEqual(confirm, undefined);
  });

  // ── Output sanitization ─────────────────────────────────────────────────

  await runTest('Summary output sanitizes ANSI in package name', async () => {
    const malicious: ConfirmSummary = {
      packageName: '\x1b[31mEVIL\x1b[0m',
      version: '1.0.0',
      client: 'claude-code',
      installPath: '/tmp',
      contentState: 'clean',
    };
    const input = makeTtyInput(['y']);
    const { output, getWritten } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    await confirm!(malicious);
    const written = getWritten();
    assert.ok(!written.includes('\x1b[31m'), 'ANSI escape must be stripped');
    assert.ok(written.includes('EVIL'), 'visible text preserved');
  });

  await runTest('Summary output sanitizes newlines in path', async () => {
    const malicious: ConfirmSummary = {
      packageName: 'pkg',
      version: '1.0.0',
      client: 'claude-code',
      installPath: '/tmp\nrm -rf /',
      contentState: 'clean',
    };
    const input = makeTtyInput(['y']);
    const { output, getWritten } = makeTtyOutput();
    const confirm = createTerminalConfirm({ input, output });
    assert.ok(confirm);
    await confirm!(malicious);
    const written = getWritten();
    // Newline (C0) should be stripped
    assert.ok(!written.includes('\nrm'), 'newline injection must be stripped');
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
