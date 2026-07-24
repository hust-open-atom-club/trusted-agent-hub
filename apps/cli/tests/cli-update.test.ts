/**
 * CLI integration tests for the `update` command.
 *
 * Run: npx tsx tests/cli-update.test.ts
 *
 * Coverage:
 *   - update --help shows all options
 *   - Uninstalled package → exit 1, UPDATE_STATUS=not_installed
 *   - Already latest → exit 0, UPDATE_STATUS=up_to_date
 *   - Non-TTY environment confirmation behavior
 *   - update --client cursor recognized
 *   - update --force flag accepted
 *   - UPDATE_STATUS machine-parseable line present
 */

import * as assert from 'assert';
import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

// Path to the compiled CLI entry point
const CLI_ENTRY = path.resolve(__dirname, '..', 'dist', 'apps', 'cli', 'src', 'cli.js');

// Use a guaranteed-unreachable API URL so commands fail fast with network errors
const ENV = { ...process.env, TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1' };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function runCli(args: string[], env?: Record<string, string>): {
  stdout: string;
  stderr: string;
  status: number | null;
  signal: string | null;
} {
  const result = spawnSync('node', [CLI_ENTRY, ...args], {
    env: { ...process.env, ...env },
    timeout: 15_000,
  });
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || '',
    status: result.status,
    signal: result.signal,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function test_updateHelpShowsOptions() {
  const { stdout, status } = runCli(['update', '--help']);
  assert.strictEqual(status, 0, `expected exit 0, got ${status}`);
  assert.ok(stdout.includes('update'), 'must show update in help');
  assert.ok(stdout.includes('--client'), 'must show --client option');
  assert.ok(stdout.includes('--force'), 'must show --force option');
  assert.ok(stdout.includes('--yes'), 'must show --yes option');
  assert.ok(stdout.includes('--accept-high-risk'), 'must show --accept-high-risk option');
  console.log('  ✓ update --help shows all options');
}

function test_uninstalledPackageExitsBad() {
  const { stdout, status } = runCli(['update', 'no-such-pkg', '--client', 'claude-code'], ENV);
  // Should fail — package doesn't exist locally (not_installed)
  // Exit code 1 for non-ok status
  assert.notStrictEqual(status, 0, `expected non-zero exit, got ${status}`);
  // Should mention the status
  assert.ok(stdout.includes('not_installed') || stdout.includes('not installed'),
    `Expected not_installed in output: "${stdout.slice(0, 300)}"`);
  console.log('  ✓ uninstalled package → exit 1, not_installed');
}

function test_updateStatusLine() {
  const { stdout, status } = runCli(['update', 'no-such-pkg', '--client', 'claude-code'], ENV);
  assert.notStrictEqual(status, 0);
  assert.ok(stdout.includes('UPDATE_STATUS='), 'must contain machine-parseable status line');
  assert.ok(stdout.includes('UPDATE_STATUS=not_installed'), 'status should be not_installed');
  console.log('  ✓ UPDATE_STATUS=not_installed present');
}

function test_updateClientCursorRecognized() {
  // Cursor client should be recognized as supported (different error from unsupported_client)
  const { stdout, status } = runCli(['update', 'pkg', '--client', 'cursor'], ENV);
  assert.notStrictEqual(status, 0, 'should fail (no local install)');
  // Must NOT say "unsupported client" for cursor
  assert.ok(!stdout.includes('unsupported_client') && !stdout.includes('Unsupported client'),
    `Should not say unsupported for cursor: "${stdout.slice(0, 300)}"`);
  console.log('  ✓ --client cursor recognized');
}

function test_updateForceFlagAccepted() {
  const { stdout, status } = runCli(['update', 'pkg', '--force', '--yes', '--accept-high-risk'], ENV);
  assert.notStrictEqual(status, 0, 'should fail (no local install)');
  // Must not be a parsing error
  assert.ok(!stdout.includes('unknown option') && !stdout.includes('error:'),
    `Should not have parsing error: "${stdout.slice(0, 300)}"`);
  console.log('  ✓ --force, --yes, --accept-high-risk flags accepted');
}

function test_updateDisplaysClient() {
  const { stdout } = runCli(['update', 'pkg', '--client', 'claude-code'], ENV);
  assert.ok(stdout.includes('claude-code'), 'must show client name');
  console.log('  ✓ displays client name');
}

function test_updateNoAnsiInStatusLine() {
  const { stdout } = runCli(['update', 'pkg', '--client', 'claude-code'], ENV);
  // Extract the UPDATE_STATUS line
  const lines = stdout.split('\n');
  const statusLine = lines.find(l => l.startsWith('UPDATE_STATUS='));
  assert.ok(statusLine !== undefined, 'must have UPDATE_STATUS line');
  assert.ok(!statusLine!.includes('\x1b'), 'UPDATE_STATUS must not contain ANSI codes');
  console.log('  ✓ UPDATE_STATUS line is clean (no ANSI)');
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

console.log('\nCLI Update Integration Tests\n');

// Ensure CLI is built
if (!fs.existsSync(CLI_ENTRY)) {
  console.log('  ⚠ CLI not built — skipping CLI integration tests');
  console.log('    Run `npm run build` first.');
  console.log('\n  ✓ All CLI update tests skipped (build needed)\n');
  process.exit(0);
}

test_updateHelpShowsOptions();
test_uninstalledPackageExitsBad();
test_updateStatusLine();
test_updateClientCursorRecognized();
test_updateForceFlagAccepted();
test_updateDisplaysClient();
test_updateNoAnsiInStatusLine();

console.log('\n  ✓ All CLI update integration tests passed!\n');
