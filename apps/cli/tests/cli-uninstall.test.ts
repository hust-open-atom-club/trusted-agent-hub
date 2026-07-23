/**
 * CLI uninstall command integration tests.
 *
 * Run: npx tsx tests/cli-uninstall.test.ts
 *
 * Verifies the compiled CLI entry point handles uninstall correctly,
 * including end-to-end flows against a real temp HOME with install
 * records and actual directories on disk.
 *
 * Every test callback is awaited — async failures are never silently
 * swallowed.
 */

import * as assert from 'assert';
import { spawnSync } from 'child_process';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import * as crypto from 'crypto';

// Path to the compiled CLI entry point
const CLI_ENTRY = path.resolve(__dirname, '..', 'dist', 'apps', 'cli', 'src', 'cli.js');

function runCli(args: string[], envExtra?: Record<string, string>): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  const result = spawnSync('node', [CLI_ENTRY, ...args], {
    env: { ...process.env, ...envExtra },
    timeout: 15_000,
  });
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || '',
    status: result.status,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

/**
 * Run a single test.  Accepts both sync and async callbacks — the returned
 * Promise is always awaited so that async assertion failures are correctly
 * caught and counted.
 */
async function runTest(name: string, fn: () => void | Promise<void>): Promise<void> {
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

/** Create a temp HOME with a real install record and target directory,
 *  compute the actual content digest, and return paths + cleanup. */
async function setupRealEnv(pkgName: string, contentFiles?: Record<string, string>) {
  const homeDir = path.join(os.tmpdir(), 'tah-cli-e2e-' + crypto.randomBytes(4).toString('hex'));
  const clientRoot = path.resolve(homeDir, '.claude', 'skills');
  const targetDir = path.resolve(clientRoot, pkgName);
  const storeDir = path.resolve(homeDir, '.trusted-agent-hub');
  const recordPath = path.join(storeDir, 'installs.json');

  fs.mkdirSync(targetDir, { recursive: true });
  if (contentFiles) {
    for (const [name, content] of Object.entries(contentFiles)) {
      const fp = path.join(targetDir, name);
      fs.mkdirSync(path.dirname(fp), { recursive: true });
      fs.writeFileSync(fp, content);
    }
  } else {
    fs.writeFileSync(path.join(targetDir, 'README.md'), '# ' + pkgName);
  }

  // Compute actual digest
  const { computeDirectoryDigest } = await import('../src/content-integrity');
  const digest = await computeDirectoryDigest(targetDir);

  // Write install record
  const record = {
    package_name: pkgName,
    version: '1.0.0',
    client: 'claude-code',
    install_path: targetDir,
    sha256: 'a'.repeat(64),
    integrity_verified: true,
    installed_at: '2026-07-22T00:00:00.000Z',
    manifest_version: '1.0',
    content_hash_algorithm: 'sha256-tree-v1',
    content_sha256: digest.digest,
  };
  fs.mkdirSync(storeDir, { recursive: true });
  fs.writeFileSync(recordPath, JSON.stringify([record], null, 2), 'utf-8');

  const envVars: Record<string, string> = { HOME: homeDir };
  if (process.platform === 'win32') envVars.USERPROFILE = homeDir;

  const cleanup = () => {
    try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };

  return { homeDir, clientRoot, targetDir, recordPath, envVars, cleanup };
}

/** Write a record file directly (without validation via the store). */
function writeRecordFile(
  homeDir: string,
  records: Record<string, unknown>[],
): string {
  const storeDir = path.resolve(homeDir, '.trusted-agent-hub');
  const recordPath = path.join(storeDir, 'installs.json');
  fs.mkdirSync(storeDir, { recursive: true });
  fs.writeFileSync(recordPath, JSON.stringify(records, null, 2), 'utf-8');
  return recordPath;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Uninstall Integration Tests\n');

  // ── --help ──────────────────────────────────────────────────────────────

  await runTest('uninstall --help shows options', () => {
    const { stdout, status } = runCli(['uninstall', '--help']);
    assert.strictEqual(status, 0);
    assert.ok(stdout.includes('uninstall'), 'help must show uninstall');
    assert.ok(stdout.includes('--client'), 'help must show --client');
    assert.ok(stdout.includes('--yes'), 'help must show --yes');
    assert.ok(stdout.includes('--force'), 'help must show --force');
  });

  await runTest('uninstall -h works', () => {
    const { stdout, status } = runCli(['uninstall', '-h']);
    assert.strictEqual(status, 0);
    assert.ok(stdout.includes('uninstall'));
  });

  // ── Clean uninstall --yes (successful) ──────────────────────────────────

  await runTest('clean --yes → exit 0, dir gone, record gone', async () => {
    const env = await setupRealEnv('pkg-clean');
    try {
      assert.ok(fs.existsSync(env.targetDir), 'target dir must exist before');
      assert.ok(fs.existsSync(env.recordPath), 'record file must exist before');

      const { stdout, status } = runCli(
        ['uninstall', 'pkg-clean', '--yes'],
        env.envVars,
      );
      assert.strictEqual(status, 0, `expected exit 0, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(stdout.includes('[uninstalled]'), 'must show uninstalled status');

      // Target directory must be gone
      assert.ok(!fs.existsSync(env.targetDir), 'target dir must be removed');
      // Client root must still exist
      assert.ok(fs.existsSync(env.clientRoot), 'client root must still exist');
      // Record file must either be gone or contain empty array
      if (fs.existsSync(env.recordPath)) {
        const remaining = JSON.parse(fs.readFileSync(env.recordPath, 'utf-8'));
        assert.strictEqual(remaining.length, 0, 'record must be removed');
      }
      // No quarantine or temp leftovers
      const entries = fs.readdirSync(env.clientRoot);
      assert.strictEqual(
        entries.filter(e => e.startsWith('.uninstall-') || e.includes('.tmp-')).length,
        0,
        'no leftovers',
      );
    } finally {
      env.cleanup();
    }
  });

  // ── Clean uninstall --client cursor ─────────────────────────────────────

  await runTest('clean --yes --client cursor → exit 0, dir gone, record gone', async () => {
    const homeDir = path.join(os.tmpdir(), 'tah-cli-e2e-' + crypto.randomBytes(4).toString('hex'));
    const cursorRoot = path.resolve(homeDir, '.cursor', 'skills');
    const targetDir = path.resolve(cursorRoot, 'pkg-cursor');
    const storeDir = path.resolve(homeDir, '.trusted-agent-hub');
    const recordPath = path.join(storeDir, 'installs.json');

    fs.mkdirSync(targetDir, { recursive: true });
    fs.writeFileSync(path.join(targetDir, 'README.md'), '# cursor pkg');

    const { computeDirectoryDigest } = await import('../src/content-integrity');
    const digest = await computeDirectoryDigest(targetDir);

    fs.mkdirSync(storeDir, { recursive: true });
    fs.writeFileSync(recordPath, JSON.stringify([{
      package_name: 'pkg-cursor',
      version: '1.0.0',
      client: 'cursor',
      install_path: targetDir,
      sha256: 'a'.repeat(64),
      integrity_verified: true,
      installed_at: '2026-07-22T00:00:00.000Z',
      manifest_version: '1.0',
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: digest.digest,
    }], null, 2), 'utf-8');

    const envVars: Record<string, string> = { HOME: homeDir };
    if (process.platform === 'win32') envVars.USERPROFILE = homeDir;

    try {
      const { stdout, status } = runCli(
        ['uninstall', 'pkg-cursor', '--client', 'cursor', '--yes'],
        envVars,
      );
      assert.strictEqual(status, 0, `expected exit 0, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(stdout.includes('[uninstalled]'), 'must show uninstalled');

      // Target dir must be gone
      assert.ok(!fs.existsSync(targetDir), 'cursor target dir must be removed');
      // Client root must still exist
      assert.ok(fs.existsSync(cursorRoot), 'cursor client root must still exist');
      // Record must be removed
      if (fs.existsSync(recordPath)) {
        const remaining = JSON.parse(fs.readFileSync(recordPath, 'utf-8'));
        assert.strictEqual(remaining.length, 0, 'record must be removed');
      }
      // No leftovers
      const entries = fs.readdirSync(cursorRoot);
      assert.strictEqual(
        entries.filter(e => e.startsWith('.uninstall-') || e.includes('.tmp-')).length,
        0,
        'no leftovers',
      );
    } finally {
      try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  // ── Stale record (target missing) ──────────────────────────────────────

  await runTest('stale (target missing) → exit 0, record removed', async () => {
    const homeDir = path.join(os.tmpdir(), 'tah-cli-e2e-' + crypto.randomBytes(4).toString('hex'));
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    // Create client root but NOT the target dir
    fs.mkdirSync(clientRoot, { recursive: true });
    const targetDir = path.resolve(clientRoot, 'pkg-stale');

    writeRecordFile(homeDir, [{
      package_name: 'pkg-stale',
      version: '1.0.0',
      client: 'claude-code',
      install_path: targetDir,
      sha256: 'a'.repeat(64),
      integrity_verified: true,
      installed_at: '2026-07-22T00:00:00.000Z',
      manifest_version: '1.0',
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    }]);

    const envVars: Record<string, string> = { HOME: homeDir };
    if (process.platform === 'win32') envVars.USERPROFILE = homeDir;

    try {
      const { stdout, status } = runCli(
        ['uninstall', 'pkg-stale', '--yes'],
        envVars,
      );
      assert.strictEqual(status, 0, `expected exit 0, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(stdout.includes('[stale_record_removed]'), 'must show stale_record_removed');

      // Record must be removed
      const recordPath = path.join(homeDir, '.trusted-agent-hub', 'installs.json');
      if (fs.existsSync(recordPath)) {
        const remaining = JSON.parse(fs.readFileSync(recordPath, 'utf-8'));
        assert.strictEqual(remaining.length, 0, 'record must be removed');
      }
    } finally {
      try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  // ── Modified without --force → exit 1, dir + record kept ───────────────

  await runTest('modified without --force → exit 1, dir kept, record kept', async () => {
    const env = await setupRealEnv('pkg-mod', { 'README.md': '# Original' });
    try {
      // Tamper with the content
      fs.writeFileSync(path.join(env.targetDir, 'extra.txt'), 'tampered');

      const { stdout, status } = runCli(
        ['uninstall', 'pkg-mod', '--yes'],
        env.envVars,
      );
      assert.strictEqual(status, 1, `expected exit 1, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(stdout.includes('[modified]'), 'must show modified status');

      // Target dir must still exist
      assert.ok(fs.existsSync(env.targetDir), 'target dir must still exist');
      // Record must still exist
      assert.ok(fs.existsSync(env.recordPath), 'record must still exist');
    } finally {
      env.cleanup();
    }
  });

  // ── Modified with --force --yes → exit 0 ────────────────────────────────

  await runTest('modified --force --yes → exit 0, dir gone, record gone', async () => {
    const env = await setupRealEnv('pkg-mod-force', { 'README.md': '# Original' });
    try {
      fs.writeFileSync(path.join(env.targetDir, 'extra.txt'), 'tampered');

      const { stdout, status } = runCli(
        ['uninstall', 'pkg-mod-force', '--force', '--yes'],
        env.envVars,
      );
      assert.strictEqual(status, 0, `expected exit 0, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(stdout.includes('[uninstalled]'), 'must show uninstalled status');

      // Target dir must be gone
      assert.ok(!fs.existsSync(env.targetDir), 'target dir must be removed');
      // Client root must still exist
      assert.ok(fs.existsSync(env.clientRoot), 'client root must still exist');
      // Record must be removed
      if (fs.existsSync(env.recordPath)) {
        const remaining = JSON.parse(fs.readFileSync(env.recordPath, 'utf-8'));
        assert.strictEqual(remaining.length, 0, 'record must be removed');
      }
      // No leftovers
      const entries = fs.readdirSync(env.clientRoot);
      assert.strictEqual(
        entries.filter(e => e.startsWith('.uninstall-') || e.includes('.tmp-')).length,
        0,
        'no leftovers',
      );
    } finally {
      env.cleanup();
    }
  });

  // ── Non-TTY without --yes on a valid install → confirmation_required ────

  await runTest('non-TTY without --yes → confirmation_required, exit 1', async () => {
    const env = await setupRealEnv('pkg-confirm', { 'README.md': '# Needs confirm' });
    try {
      // spawnSync creates a non-TTY environment by default
      const { stdout, status } = runCli(
        ['uninstall', 'pkg-confirm'],  // no --yes
        env.envVars,
      );
      assert.strictEqual(status, 1, `expected exit 1, got ${status}. stdout: ${stdout.slice(0, 300)}`);
      assert.ok(
        stdout.includes('[confirmation_required]'),
        `must show confirmation_required, got: ${stdout.slice(0, 300)}`,
      );

      // Target dir and record must still exist
      assert.ok(fs.existsSync(env.targetDir), 'target dir must still exist');
      assert.ok(fs.existsSync(env.recordPath), 'record must still exist');
    } finally {
      env.cleanup();
    }
  });

  // ── not_installed → exit 1 ──────────────────────────────────────────────

  await runTest('not_installed → exit 1', () => {
    const homeDir = path.join(os.tmpdir(), 'tah-cli-e2e-' + crypto.randomBytes(4).toString('hex'));
    const envVars: Record<string, string> = { HOME: homeDir };
    if (process.platform === 'win32') envVars.USERPROFILE = homeDir;

    try {
      const { stdout, status } = runCli(
        ['uninstall', 'nonexistent-pkg', '--yes'],
        envVars,
      );
      assert.strictEqual(status, 1, `expected exit 1, got ${status}`);
      assert.ok(stdout.includes('[not_installed]'), 'must show not_installed');
    } finally {
      try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  // ── record_invalid (corrupt JSON) → exit 1 ──────────────────────────────

  await runTest('corrupt installs.json → record_invalid, exit 1', () => {
    const homeDir = path.join(os.tmpdir(), 'tah-cli-e2e-' + crypto.randomBytes(4).toString('hex'));
    const storeDir = path.join(homeDir, '.trusted-agent-hub');
    fs.mkdirSync(storeDir, { recursive: true });
    fs.writeFileSync(path.join(storeDir, 'installs.json'), '{corrupt', 'utf-8');

    const envVars: Record<string, string> = { HOME: homeDir };
    if (process.platform === 'win32') envVars.USERPROFILE = homeDir;

    try {
      const { stdout, status } = runCli(['uninstall', 'pkg', '--yes'], envVars);
      assert.strictEqual(status, 1, `expected exit 1, got ${status}`);
      assert.ok(
        stdout.includes('record_invalid'),
        `must show record_invalid, got: ${stdout.slice(0, 300)}`,
      );
    } finally {
      try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });

  // ── Unknown flag ────────────────────────────────────────────────────────

  await runTest('unknown flag → exit non-zero', () => {
    const { stderr, status } = runCli(['uninstall', 'pkg', '--unknown-flag']);
    assert.notStrictEqual(status, 0, 'unknown flag should error');
    assert.ok(
      stderr.includes('unknown') || stderr.includes('Unknown') || stderr.includes('error'),
      'must report unknown option',
    );
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
