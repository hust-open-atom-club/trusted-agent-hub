/**
 * CLI argument parsing regression tests.
 *
 * Run: npx tsx tests/cli-parsing.test.ts
 *
 * Verifies that Commander correctly routes options to subcommands:
 *   - Root --version outputs CLI version (0.1.0)
 *   - install --version <version> triggers the install action,
 *     NOT the root version command
 */

import * as assert from 'assert';
import { execSync, spawnSync } from 'child_process';
import * as path from 'path';

// Path to the compiled CLI entry point
const CLI_ENTRY = path.resolve(__dirname, '..', 'dist', 'apps', 'cli', 'src', 'cli.js');

// Use a guaranteed-unreachable API URL so the install command fails fast
// with a network error rather than hanging or succeeding.
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
    timeout: 10_000,
  });
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || '',
    status: result.status,
    signal: result.signal,
  };
}

function runCliSync(args: string[], env?: Record<string, string>): string {
  try {
    return execSync(`node "${CLI_ENTRY}" ${args.join(' ')}`, {
      env: { ...process.env, ...env },
      timeout: 10_000,
    }).toString();
  } catch (err: any) {
    // execSync throws on non-zero exit — return combined output
    return (err.stdout?.toString() || '') + (err.stderr?.toString() || '');
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function test_rootVersionOutputsCliVersion() {
  const { stdout, status } = runCli(['--version']);
  assert.strictEqual(status, 0, `expected exit 0, got ${status}`);
  assert.ok(stdout.includes('0.1.0'), `expected "0.1.0" in output, got: "${stdout}"`);
  console.log('  ✓ root --version outputs CLI version');
}

function test_rootVersionShortFlag() {
  const { stdout, status } = runCli(['-V']);
  assert.strictEqual(status, 0, `expected exit 0, got ${status}`);
  assert.ok(stdout.includes('0.1.0'), `expected "0.1.0" in output, got: "${stdout}"`);
  console.log('  ✓ root -V (short flag) outputs CLI version');
}

function test_installVersionOptionDoesNotPrintCliVersion() {
  // install --version 1.0.0 must NOT output "0.1.0" — it should trigger
  // the install action (which fails with a network error since no API).
  const { stdout, stderr, status } = runCli(
    ['install', 'test-pkg', '--version', '1.0.0', '--client', 'claude-code'],
    ENV,
  );
  assert.notStrictEqual(status, 0, 'install should fail (no API), not exit 0');
  const combined = stdout + stderr;
  assert.ok(!combined.includes('0.1.0'),
    `install --version 1.0.0 must NOT print CLI version 0.1.0. Got: "${combined.slice(0, 200)}"`);
  // Should show it's trying to install (the spinner or error message)
  assert.ok(
    combined.includes('install') || combined.includes('Install') ||
    combined.includes('manifest') || combined.includes('Fetching') ||
    combined.includes('fetch') || combined.includes('API') ||
    combined.includes('Cannot reach'),
    `Expected install-related output, got: "${combined.slice(0, 200)}"`,
  );
  console.log('  ✓ install --version 1.0.0 does NOT print CLI version');
}

function test_installVersionOptionOrderSwapped() {
  // --version after the package name should also route to install
  const { stdout, stderr, status } = runCli(
    ['install', 'test-pkg', '--client', 'claude-code', '--version', '2.0.0'],
    ENV,
  );
  assert.notStrictEqual(status, 0, 'install should fail (no API)');
  const combined = stdout + stderr;
  assert.ok(!combined.includes('0.1.0'),
    `version after other options must not print CLI version. Got: "${combined.slice(0, 200)}"`);
  console.log('  ✓ install with --version after --client also works');
}

function test_installWithoutVersionStillWorks() {
  const { stdout, stderr, status } = runCli(
    ['install', 'test-pkg', '--client', 'claude-code'],
    ENV,
  );
  assert.notStrictEqual(status, 0, 'install should fail (no API)');
  const combined = stdout + stderr;
  assert.ok(!combined.includes('0.1.0'),
    `install without --version must not print CLI version. Got: "${combined.slice(0, 200)}"`);
  console.log('  ✓ install without --version still enters install action');
}

function test_installHelpShowsVersionOption() {
  const { stdout, status } = runCli(['install', '--help']);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('--version'), 'install help must show --version option');
  assert.ok(stdout.includes('version'), 'install help must mention version');
  console.log('  ✓ install --help shows --version option');
}

function test_verifyHelpShowsOptions() {
  const { stdout, status } = runCli(['verify', '--help']);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('verify'), 'verify help must show verify');
  assert.ok(stdout.includes('--client'), 'verify help must show --client option');
  console.log('  ✓ verify --help shows options');
}

function test_uninstallHelpShowsOptions() {
  const { stdout, status } = runCli(['uninstall', '--help']);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('uninstall'), 'uninstall help must show uninstall');
  assert.ok(stdout.includes('--client'), 'uninstall help must show --client');
  assert.ok(stdout.includes('--yes'), 'uninstall help must show --yes');
  assert.ok(stdout.includes('--force'), 'uninstall help must show --force');
  console.log('  ✓ uninstall --help shows options');
}

function test_uninstallClientOptionWorks() {
  // uninstall --client should route to the uninstall action
  const { stdout, status } = runCli(['uninstall', 'pkg', '--client', 'cursor', '--yes']);
  // Should fail with not_installed (not a real package) but NOT print CLI version
  assert.notStrictEqual(status, 0, 'uninstall should fail (no record)');
  assert.ok(!stdout.includes('0.1.0'),
    'uninstall --client must NOT print CLI version');
  assert.ok(stdout.includes('cursor'), 'must show cursor client');
  console.log('  ✓ uninstall --client cursor works');
}

function test_uninstallForceOptionWorks() {
  const { stdout, status } = runCli(['uninstall', 'pkg', '--force', '--yes']);
  assert.notStrictEqual(status, 0, 'uninstall should fail (no record)');
  assert.ok(!stdout.includes('0.1.0'),
    'uninstall --force must NOT print CLI version');
  console.log('  ✓ uninstall --force works');
}

function test_installOptionsStillWorkAfterUninstallRegistered() {
  // Regression: install --version <version> must still work
  const { stdout, stderr, status } = runCli(
    ['install', 'test-pkg', '--version', '1.0.0', '--client', 'claude-code'],
    ENV,
  );
  assert.notStrictEqual(status, 0, 'install should fail (no API)');
  const combined = stdout + stderr;
  assert.ok(!combined.includes('0.1.0'),
    `install --version after uninstall registration must not print CLI version. Got: "${combined.slice(0, 200)}"`);
  console.log('  ✓ install --version still works after uninstall registered');
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

console.log('\nCLI Parsing Regression Tests\n');

test_rootVersionOutputsCliVersion();
test_rootVersionShortFlag();
test_installVersionOptionDoesNotPrintCliVersion();
test_installVersionOptionOrderSwapped();
test_installWithoutVersionStillWorks();
test_installHelpShowsVersionOption();
test_verifyHelpShowsOptions();
test_uninstallHelpShowsOptions();
test_uninstallClientOptionWorks();
test_uninstallForceOptionWorks();
test_installOptionsStillWorkAfterUninstallRegistered();

console.log('\n  ✓ All CLI parsing tests passed!\n');
