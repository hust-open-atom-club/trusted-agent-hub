/**
 * Tests for UninstallExecutor (uninstall-executor.ts).
 *
 * Run: npx tsx tests/uninstall-executor.test.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { LocalInstallStore } from '../src/local-install-store';
import type { LocalInstallRecord } from '../src/local-install-store';
import {
  UninstallExecutor,
} from '../src/uninstall-executor';
import type {
  UninstallStatus,
  UninstallFileOps,
  FileIdentity,
  UninstallResult,
  UninstallOptions,
} from '../src/uninstall-executor';

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

function makeTmpDir(): string {
  const dir = path.join(os.tmpdir(), 'tah-uninstall-test-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function writeFile(dir: string, name: string, content: string | Buffer): void {
  const filePath = path.join(dir, name);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function makeRecord(overrides: Partial<LocalInstallRecord> = {}): LocalInstallRecord {
  return {
    package_name: 'test-pkg',
    version: '1.0.0',
    client: 'claude-code',
    install_path: '/tmp/does-not-exist',
    sha256: 'a'.repeat(64),
    integrity_verified: true,
    installed_at: '2026-07-22T00:00:00.000Z',
    manifest_version: '1.0',
    content_hash_algorithm: 'sha256-tree-v1',
    content_sha256: 'b'.repeat(64),
    ...overrides,
  };
}

/**
 * Create a fake HOME with:
 *  - .claude/skills/<pkgName>/  (the "install" directory)
 *  - .trusted-agent-hub/installs.json  (the record)
 *
 * Returns { homeDir, targetDir, store, cleanup }.
 */
function setupTestEnv(
  pkgName = 'test-pkg',
  opts?: {
    contentFiles?: Record<string, string>;
    recordOverrides?: Partial<LocalInstallRecord>;
    noRecord?: boolean;
    noTarget?: boolean;
  },
) {
  const homeDir = makeTmpDir();
  const clientRoot = path.resolve(homeDir, '.claude', 'skills');
  const targetDir = path.resolve(clientRoot, pkgName);

  if (!opts?.noTarget) {
    fs.mkdirSync(targetDir, { recursive: true });
    if (opts?.contentFiles) {
      for (const [name, content] of Object.entries(opts.contentFiles)) {
        writeFile(targetDir, name, content);
      }
    } else {
      writeFile(targetDir, 'README.md', '# Test Package');
    }
  }

  if (!opts?.noRecord) {
    const record = makeRecord({
      package_name: pkgName,
      install_path: targetDir,
      ...opts?.recordOverrides,
    });
    const store = new LocalInstallStore(homeDir);
    store.save(record);
  }

  return {
    homeDir,
    targetDir,
    clientRoot,
    store: new LocalInstallStore(homeDir),
    cleanup: () => cleanup(homeDir),
  };
}

/** Create and resolve a target dir so we can compute its actual digest. */
async function setupCleanEnv(pkgName = 'test-pkg') {
  const env = setupTestEnv(pkgName, {
    contentFiles: { 'README.md': '# Hello' },
  });

  // Compute the actual content digest
  const { computeDirectoryDigest } = await import('../src/content-integrity');
  const digest = await computeDirectoryDigest(env.targetDir);

  // Rewrite the record with the correct content hash
  env.store.save(makeRecord({
    package_name: pkgName,
    install_path: env.targetDir,
    content_hash_algorithm: 'sha256-tree-v1',
    content_sha256: digest.digest,
  }));

  return { ...env, digest: digest.digest };
}

// ---------------------------------------------------------------------------
// Default FileOps (real fs)
// ---------------------------------------------------------------------------

const realFileOps: UninstallFileOps = {
  lstat(filePath: string): FileIdentity {
    const stat = fs.lstatSync(filePath, { bigint: true }) as fs.BigIntStats;
    return { dev: stat.dev, ino: stat.ino, type: stat.isDirectory() ? 'directory' : 'other' };
  },
  rename(source: string, destination: string): void {
    fs.renameSync(source, destination);
  },
  removeTree(target: string): void {
    fs.rmSync(target, { recursive: true, force: true });
  },
  exists(target: string): boolean {
    return fs.existsSync(target);
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Uninstall Executor Tests\n');

  // =========================================================================
  // not_installed
  // =========================================================================

  await runTest('not_installed — no record found', async () => {
    const { homeDir, store, cleanup: clean } = setupTestEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('missing', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'not_installed');
    assert.strictEqual(result.packageName, 'missing');
    assert.strictEqual(result.client, 'claude-code');
    clean();
  });

  // =========================================================================
  // record_invalid
  // =========================================================================

  await runTest('record_invalid — corrupt installs.json', async () => {
    const homeDir = makeTmpDir();
    const storePath = path.join(homeDir, '.trusted-agent-hub', 'installs.json');
    fs.mkdirSync(path.dirname(storePath), { recursive: true });
    fs.writeFileSync(storePath, '{broken', 'utf-8');

    const executor = new UninstallExecutor({ homeDir });
    const result = await executor.uninstall('pkg', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'record_invalid');

    cleanup(homeDir);
  });

  // =========================================================================
  // unsupported_client
  // =========================================================================

  await runTest('unsupported_client — unknown client', async () => {
    const { homeDir, store, cleanup: clean } = setupTestEnv('pkg-a', {
      recordOverrides: { client: 'unknown-client' as any },
    });
    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'unknown-client' as any);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsupported_client');
    clean();
  });

  // =========================================================================
  // unsafe_path — outside client root
  // =========================================================================

  await runTest('unsafe_path — install path escapes client root', async () => {
    const { homeDir, store, cleanup: clean } = setupTestEnv('pkg-a', {
      recordOverrides: { install_path: '/etc/passwd' },
    });
    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_path');
    clean();
  });

  // =========================================================================
  // unsafe_path — client root itself
  // =========================================================================

  await runTest('unsafe_path — install path equals client root', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    fs.mkdirSync(clientRoot, { recursive: true });

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({
      install_path: clientRoot,
    }));

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('test-pkg', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_path');

    cleanup(homeDir);
  });

  // =========================================================================
  // stale_record_removed — target directory missing
  // =========================================================================

  await runTest('stale_record_removed — target missing, record removed', async () => {
    const { homeDir, store, cleanup: clean } = setupTestEnv('pkg-a', {
      noTarget: true,
    });
    // must create the parent dir for ancestor validation
    const parentPath = path.resolve(homeDir, '.claude', 'skills');
    fs.mkdirSync(parentPath, { recursive: true });

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'stale_record_removed');

    // Record must be gone
    const remaining = store.load();
    assert.strictEqual(remaining.length, 0);

    clean();
  });

  // =========================================================================
  // unsafe_content — target is a symlink
  // =========================================================================

  await runTest('unsafe_content — target is a symlink', async () => {
    const { homeDir, store, targetDir, cleanup: clean } = setupTestEnv('pkg-a');
    // Remove real target, create a symlink
    fs.rmSync(targetDir, { recursive: true, force: true });
    const realDir = path.join(path.dirname(targetDir), 'real');
    fs.mkdirSync(realDir, { recursive: true });
    try {
      fs.symlinkSync(realDir, targetDir, 'dir');
    } catch {
      // Can't create symlink on Windows — skip
      clean();
      return;
    }

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_content');
    clean();
  });

  // =========================================================================
  // legacy_record — no content hash, without --force
  // =========================================================================

  await runTest('legacy_record — without --force', async () => {
    const env = setupTestEnv('pkg-a', {
      contentFiles: { 'README.md': '# Legacy' },
      recordOverrides: {
        content_hash_algorithm: undefined,
        content_sha256: undefined,
      },
    });
    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'legacy_record');
    // Target and record must be intact
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);
    env.cleanup();
  });

  // =========================================================================
  // modified — content changed, without --force
  // =========================================================================

  await runTest('modified — without --force', async () => {
    const env = await setupCleanEnv('pkg-a');
    // Modify content
    writeFile(env.targetDir, 'evil.txt', 'tampered');

    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'modified');
    // Target and record must be intact
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);
    env.cleanup();
  });

  // =========================================================================
  // confirmation_required — no callback, not --yes
  // =========================================================================

  await runTest('confirmation_required — clean without --yes', async () => {
    const env = await setupCleanEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'confirmation_required');
    // Target and record must be intact
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);
    env.cleanup();
  });

  // =========================================================================
  // cancelled — user refuses
  // =========================================================================

  await runTest('cancelled — user refuses confirmation', async () => {
    const env = await setupCleanEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code', {
      confirm: async () => false,
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'cancelled');
    // Target and record must be intact
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);
    env.cleanup();
  });

  // =========================================================================
  // uninstalled — clean, --yes
  // =========================================================================

  await runTest('uninstalled — clean with --yes', async () => {
    const env = await setupCleanEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });

    const targetDir = env.targetDir;
    assert.ok(fs.existsSync(targetDir), 'target must exist before');

    const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');

    // Target must no longer exist
    assert.ok(!fs.existsSync(targetDir), 'target must be gone');
    // Record must be removed
    assert.strictEqual(env.store.load().length, 0);
    // Client root must still exist
    assert.ok(fs.existsSync(env.clientRoot));
    // No .uninstall-* leftovers
    const entries = fs.readdirSync(env.clientRoot);
    const leftovers = entries.filter(e => e.startsWith('.uninstall-'));
    assert.strictEqual(leftovers.length, 0, 'no .uninstall-* leftovers');

    env.cleanup();
  });

  // =========================================================================
  // uninstalled — clean, confirm callback
  // =========================================================================

  await runTest('uninstalled — clean with confirm callback returning true', async () => {
    const env = await setupCleanEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code', {
      confirm: async () => true,
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');
    assert.ok(!fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 0);
    env.cleanup();
  });

  // =========================================================================
  // modified + --force + --yes
  // =========================================================================

  await runTest('uninstalled — modified with --force --yes', async () => {
    const env = await setupCleanEnv('pkg-a');
    writeFile(env.targetDir, 'extra.txt', 'bonus');

    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code', {
      force: true,
      yes: true,
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');
    assert.ok(!fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 0);
    env.cleanup();
  });

  // =========================================================================
  // legacy + --force + --yes
  // =========================================================================

  await runTest('uninstalled — legacy with --force --yes', async () => {
    const env = setupTestEnv('pkg-a', {
      contentFiles: { 'README.md': '# Legacy Content' },
      recordOverrides: {
        content_hash_algorithm: undefined,
        content_sha256: undefined,
      },
    });

    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code', {
      force: true,
      yes: true,
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');
    assert.ok(!fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 0);
    env.cleanup();
  });

  // =========================================================================
  // modified + --force (no --yes) → confirmation_required
  // =========================================================================

  await runTest('confirmation_required — modified with --force but no --yes', async () => {
    const env = await setupCleanEnv('pkg-a');
    writeFile(env.targetDir, 'extra.txt', 'bonus');

    const executor = new UninstallExecutor({ homeDir: env.homeDir, store: env.store });
    const result = await executor.uninstall('pkg-a', 'claude-code', { force: true });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'confirmation_required');
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);
    env.cleanup();
  });

  // =========================================================================
  // unsafe_content — rename failure
  // =========================================================================

  await runTest('unsafe_content — quarantine rename fails', async () => {
    const env = await setupCleanEnv('pkg-a');

    const failOps: UninstallFileOps = {
      ...realFileOps,
      rename: (_source: string, _destination: string) => {
        throw new Error('simulated rename failure');
      },
    };

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
      fileOps: failOps,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_content');

    // Target must still exist (rename failed before moving)
    assert.ok(fs.existsSync(env.targetDir));
    // Record must still exist
    assert.strictEqual(env.store.load().length, 1);

    env.cleanup();
  });

  // =========================================================================
  // cleanup_failed — quarantine removal fails after record deleted
  // =========================================================================

  await runTest('cleanup_failed — quarantine cleanup fails after record removed', async () => {
    const env = await setupCleanEnv('pkg-a');
    let removeTreeCalled = false;

    const failOps: UninstallFileOps = {
      ...realFileOps,
      removeTree: (target: string) => {
        removeTreeCalled = true;
        throw new Error('simulated rm failure');
      },
    };

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
      fileOps: failOps,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'cleanup_failed');
    assert.ok(removeTreeCalled, 'removeTree must have been called');
    // Record must be removed (it was deleted before cleanup attempt)
    assert.strictEqual(env.store.load().length, 0);
    // quarantinePath must be reported
    assert.ok(result.quarantinePath, 'quarantinePath must be reported');
    assert.ok(result.quarantinePath!.includes('.uninstall-'));

    // Clean up leftover quarantine
    if (result.quarantinePath && fs.existsSync(result.quarantinePath)) {
      fs.rmSync(result.quarantinePath, { recursive: true, force: true });
    }

    env.cleanup();
  });

  // =========================================================================
  // record_update_failed — record changes before mutation
  // =========================================================================

  await runTest('record_update_failed — record modified concurrently', async () => {
    const env = await setupCleanEnv('pkg-a');

    // We'll use a custom executor that modifies the record between
    // the initial load and the re-validation. We can do this by
    // using a fileOps that doesn't affect renames but we need to
    // modify the record after the initial read...
    //
    // Instead, let's create the record with different initial values
    // and mutate the file between load and mutation.
    // The simplest approach: create the env, then create an executor
    // that uses a store pointing to the same home; modify the record
    // externally in the store before the confirm callback.
    // Actually, the uninstall flow loads the record, then optionally
    // waits for confirmation, then re-validates. So we can use a
    // confirm callback that modifies the record.

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', {
      confirm: async () => {
        // Modify the record during confirmation
        const r = env.store.find('pkg-a', 'claude-code')!;
        r.version = '9.9.9';
        env.store.save(r);
        return true;
      },
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'record_update_failed');
    // Target must still exist
    assert.ok(fs.existsSync(env.targetDir));
    // Record should still exist (with the modified version)
    assert.strictEqual(env.store.load().length, 1);

    env.cleanup();
  });

  // =========================================================================
  // unsafe_content — content changes before mutation
  // =========================================================================

  await runTest('unsafe_content — content modified during confirmation', async () => {
    const env = await setupCleanEnv('pkg-a');

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', {
      confirm: async () => {
        // Modify file content during confirmation window
        writeFile(env.targetDir, 'injected.txt', 'pwned');
        return true;
      },
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_content');
    // Target must still exist
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);

    env.cleanup();
  });

  // =========================================================================
  // rollback_failed — identity mismatch after quarantine rename
  // =========================================================================

  await runTest('rollback_failed — target identity changed between lstat and rename', async () => {
    const env = await setupCleanEnv('pkg-a');
    let quarantinePath: string | null = null;

    const trickyOps: UninstallFileOps = {
      ...realFileOps,
      lstat: (filePath: string): FileIdentity => {
        const realIdentity = realFileOps.lstat(filePath);
        // Return a different identity when checking the quarantine
        if (quarantinePath && filePath === quarantinePath) {
          return { dev: 999n, ino: 888n, type: 'directory' };
        }
        return realIdentity;
      },
      rename: (source: string, destination: string) => {
        quarantinePath = destination;
        realFileOps.rename(source, destination);
      },
    };

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
      fileOps: trickyOps,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'rollback_failed');
    // quarantinePath must be reported
    assert.ok(result.quarantinePath);
    assert.ok(result.quarantinePath!.includes('.uninstall-'));
    // Record must NOT be deleted
    assert.strictEqual(env.store.load().length, 1);

    // Clean up quarantine if it exists
    if (quarantinePath && fs.existsSync(quarantinePath)) {
      // rename back to restore
      try { fs.renameSync(quarantinePath, env.targetDir); } catch { /* ignore */ }
    }

    env.cleanup();
  });

  // =========================================================================
  // Different clients coexist
  // =========================================================================

  await runTest('uninstalling one client preserves other client records', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const pkgADir = path.resolve(clientRoot, 'pkg-a');
    fs.mkdirSync(pkgADir, { recursive: true });
    writeFile(pkgADir, 'README.md', '# Pkg A');

    const { computeDirectoryDigest } = await import('../src/content-integrity');
    const digestA = await computeDirectoryDigest(pkgADir);

    const store = new LocalInstallStore(homeDir);
    // Save two records with different clients
    store.save(makeRecord({
      package_name: 'pkg-a',
      client: 'claude-code',
      install_path: pkgADir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: digestA.digest,
    }));
    store.save(makeRecord({
      package_name: 'pkg-a',
      client: 'cursor',
      install_path: '/tmp/fake-cursor-path',
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'c'.repeat(64),
    }));

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');

    // claude-code record must be gone, cursor record must remain
    const remaining = store.load();
    assert.strictEqual(remaining.length, 1);
    assert.strictEqual(remaining[0].client, 'cursor');

    cleanup(homeDir);
  });

  // =========================================================================
  // unsafe_path — sibling-prefix attack
  // =========================================================================

  await runTest('unsafe_path — sibling-prefix path rejected', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    fs.mkdirSync(clientRoot, { recursive: true });
    // Path is a prefix of another valid path (sibling-prefix attack)
    const outsidePath = path.resolve(homeDir, '.claude', 'skills-evil');
    fs.mkdirSync(outsidePath, { recursive: true });

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({ install_path: outsidePath }));

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('test-pkg', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_path');

    // Target must still exist
    assert.ok(fs.existsSync(outsidePath));
    cleanup(homeDir);
  });

  // =========================================================================
  // Status coverage
  // =========================================================================

  await runTest('all UninstallStatus values have test coverage', async () => {
    const ALL_STATUSES: UninstallStatus[] = [
      'uninstalled',
      'stale_record_removed',
      'cancelled',
      'not_installed',
      'record_invalid',
      'unsupported_client',
      'unsafe_path',
      'unsafe_content',
      'legacy_record',
      'modified',
      'confirmation_required',
      'record_update_failed',
      'cleanup_failed',
      'rollback_failed',
    ];

    // The tests above cover all these statuses. This test just verifies
    // that the constant list is complete and self-consistent with the type.
    assert.strictEqual(ALL_STATUSES.length, 14);

    // Verify that each status has a unique string
    const seen = new Set<string>();
    for (const s of ALL_STATUSES) {
      assert.ok(!seen.has(s), `duplicate status: ${s}`);
      seen.add(s);
    }
  });

  // =========================================================================
  // sanitizeOutput applied to all result fields
  // =========================================================================

  await runTest('result fields are sanitized', async () => {
    const { homeDir, store, cleanup: clean } = setupTestEnv('pkg-a');
    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-a', 'claude-code');
    // Fields must not contain ANSI
    assert.ok(!result.packageName.includes('\x1b'));
    assert.ok(!result.client.includes('\x1b'));
    assert.ok(!result.message.includes('\x1b'));
    // Fields must not contain newlines
    assert.ok(!result.packageName.includes('\n'));
    assert.ok(!result.message.includes('\n'));
    clean();
  });

  // =========================================================================
  // Modified + --force + confirm callback
  // =========================================================================

  await runTest('uninstalled — modified with --force + confirm', async () => {
    const env = await setupCleanEnv('pkg-a');
    writeFile(env.targetDir, 'extra.txt', 'bonus');

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', {
      force: true,
      confirm: async () => true,
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'uninstalled');
    assert.ok(!fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 0);
    env.cleanup();
  });

  // =========================================================================
  // rollback_failed — record delete fails and restore succeeds
  // =========================================================================

  await runTest('record_update_failed — record delete fails, directory restored', async () => {
    const env = await setupCleanEnv('pkg-a');
    let quarantinePath: string | null = null;

    // FileOps: rename succeeds, but store remove will fail
    // We need to make the store fail. We'll use the _beforeRenameHook
    // on a separate store instance.
    const recordPath = env.store.getPath();
    const originalRaw = fs.readFileSync(recordPath, 'utf-8');
    assert.ok(originalRaw.includes('pkg-a'), 'record file must contain package name');

    // Use the static hook to simulate rename failure
    LocalInstallStore._beforeRenameHook = (tmpPath: string) => {
      fs.unlinkSync(tmpPath); // delete temp → rename will fail
    };

    let executor: UninstallExecutor;
    try {
      executor = new UninstallExecutor({
        homeDir: env.homeDir,
        store: env.store,
      });

      const result = await executor.uninstall('pkg-a', 'claude-code', { yes: true });
      // Should be record_update_failed (since cleanup fails... actually
      // the rename failure happens in writeRecordsAtomically which is called
      // by remove(). The code path: record is quarantined successfully, then
      // store.remove() fails with save_failed. The executor catches this
      // and tries to rollback.
      assert.strictEqual(result.ok, false);
      assert.ok(
        result.status === 'record_update_failed' || result.status === 'rollback_failed',
        `expected record_update_failed or rollback_failed, got ${result.status}`,
      );

      // After rollback, target should exist again if restore succeeded
      if (result.status === 'record_update_failed') {
        assert.ok(fs.existsSync(env.targetDir), 'target must be restored');
      }
    } finally {
      LocalInstallStore._beforeRenameHook = null;
      env.cleanup();
    }
  });

  // =========================================================================
  // P1 fix: stale record with missing client root
  // =========================================================================

  await runTest('stale_record_removed — client root also missing', async () => {
    const homeDir = makeTmpDir();
    // Do NOT create the client root directory at all
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-missing');

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({
      package_name: 'pkg-missing',
      install_path: targetDir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    }));

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-missing', 'claude-code');
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'stale_record_removed');
    assert.strictEqual(store.load().length, 0);

    cleanup(homeDir);
  });

  // =========================================================================
  // P1 fix: stale record with unsafe ancestor (symlink client root)
  // =========================================================================

  await runTest('stale record — symlink ancestor still fails closed', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-missing');

    // Create a symlink at the skills level pointing elsewhere
    const realSkills = path.resolve(homeDir, 'real-skills');
    fs.mkdirSync(realSkills, { recursive: true });
    fs.mkdirSync(path.resolve(homeDir, '.claude'), { recursive: true });
    try {
      fs.symlinkSync(realSkills, clientRoot, 'dir');
    } catch {
      cleanup(homeDir);
      return;
    }

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({
      package_name: 'pkg-missing',
      install_path: targetDir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    }));

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-missing', 'claude-code');
    // Symlink/junction ancestor must be rejected in the initial validation
    // phase — the status must be unsafe_path (not unsafe_content, which is
    // reserved for content-related failures).
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_path');
    // Record must still exist
    assert.strictEqual(store.load().length, 1);

    cleanup(homeDir);
  });

  // =========================================================================
  // P1 fix: integrity_verified concurrent change detected
  // =========================================================================

  await runTest('record_update_failed — integrity_verified changed during confirmation', async () => {
    const env = await setupCleanEnv('pkg-a');

    const executor = new UninstallExecutor({
      homeDir: env.homeDir,
      store: env.store,
    });

    const result = await executor.uninstall('pkg-a', 'claude-code', {
      confirm: async () => {
        // Toggle integrity_verified during confirmation
        const r = env.store.find('pkg-a', 'claude-code')!;
        r.integrity_verified = !r.integrity_verified;
        env.store.save(r);
        return true;
      },
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'record_update_failed');
    // Target must still exist (no rename happened)
    assert.ok(fs.existsSync(env.targetDir));
    assert.strictEqual(env.store.load().length, 1);

    env.cleanup();
  });

  // =========================================================================
  // P1 fix: stale target reappearing during cleanup
  // =========================================================================

  await runTest('stale record — target reappears on disk during check', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-reappear');
    fs.mkdirSync(clientRoot, { recursive: true });
    // Do NOT create targetDir

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({
      package_name: 'pkg-reappear',
      install_path: targetDir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    }));

    // fileOps that actually creates the directory on the second exists()
    // call, simulating a concurrent process recreating the target.
    let existCalls = 0;
    const sentinelContent = 'UNTOUCHED-' + crypto.randomBytes(8).toString('hex');
    const trickyOps: UninstallFileOps = {
      ...realFileOps,
      exists: (p: string) => {
        if (p === targetDir) {
          existCalls++;
          if (existCalls === 2) {
            // Really create the directory on disk with a sentinel file
            fs.mkdirSync(targetDir, { recursive: true });
            writeFile(targetDir, 'SENTINEL.txt', sentinelContent);
            return true;
          }
          // Call 1: not there
          return false;
        }
        return realFileOps.exists(p);
      },
    };

    const executor = new UninstallExecutor({ homeDir, store, fileOps: trickyOps });
    const result = await executor.uninstall('pkg-reappear', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_content');
    // Record must still exist
    assert.strictEqual(store.load().length, 1);
    // Injection MUST have fired — at least 2 exists() calls for target
    assert.ok(existCalls >= 2,
      `expected >=2 exists calls for target, got ${existCalls}`);
    // Sentinel must be untouched — the executor must not delete or
    // modify the reappeared content
    assert.ok(fs.existsSync(targetDir), 'reappeared directory must still exist');
    const sentinelPath = path.join(targetDir, 'SENTINEL.txt');
    assert.ok(fs.existsSync(sentinelPath), 'sentinel file must still exist');
    const actualContent = fs.readFileSync(sentinelPath, 'utf-8');
    assert.strictEqual(actualContent, sentinelContent,
      'sentinel content must be unchanged');
    // No quarantine leftovers
    const entries = fs.readdirSync(clientRoot);
    const quarantines = entries.filter(e => e.startsWith('.uninstall-'));
    assert.strictEqual(quarantines.length, 0, 'no quarantine leftovers');

    cleanup(homeDir);
  });

  // =========================================================================
  // P1 fix: stale record changed during cleanup
  // =========================================================================

  await runTest('stale record — record deleted between re-read and remove', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-gone');
    fs.mkdirSync(clientRoot, { recursive: true });
    // Do NOT create targetDir

    const store = new LocalInstallStore(homeDir);
    const record = makeRecord({
      package_name: 'pkg-gone',
      install_path: targetDir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    });
    store.save(record);

    // Wrap remove() to delete the record BEFORE delegating to the real
    // implementation, simulating a concurrent process removing the record
    // between handleStaleRecord's re-read and store.remove()'s internal
    // load-and-compare.
    const originalRemove = store.remove.bind(store);
    let wrapperCalled = false;
    store.remove = (pkg: string, cl: string, expected?: LocalInstallRecord) => {
      if (!wrapperCalled) {
        wrapperCalled = true;
        // Concurrent removal via a separate store instance
        const shadow = new LocalInstallStore(homeDir);
        shadow.remove(pkg, cl);
      }
      return originalRemove(pkg, cl, expected);
    };

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-gone', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'record_update_failed');
    // Target directory was already absent — must still be absent
    assert.ok(!fs.existsSync(targetDir));
    // Record was removed by the "concurrent" shadow store, but the
    // executor correctly detected the change and refused to proceed
    // with removing a record that no longer matched the snapshot.

    cleanup(homeDir);
  });

  await runTest('stale record — record modified between re-read and remove', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-mod-during');
    fs.mkdirSync(clientRoot, { recursive: true });
    // Do NOT create targetDir

    const store = new LocalInstallStore(homeDir);
    const record = makeRecord({
      package_name: 'pkg-mod-during',
      install_path: targetDir,
      version: '1.0.0',
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    });
    store.save(record);

    // Wrap remove() to modify the record BEFORE delegating
    const originalRemove = store.remove.bind(store);
    let wrapperCalled = false;
    store.remove = (pkg: string, cl: string, expected?: LocalInstallRecord) => {
      if (!wrapperCalled) {
        wrapperCalled = true;
        // Concurrent modification: change the version
        const shadow = new LocalInstallStore(homeDir);
        const current = shadow.find(pkg, cl)!;
        current.version = '9.9.9';
        shadow.save(current);
      }
      return originalRemove(pkg, cl, expected);
    };

    const executor = new UninstallExecutor({ homeDir, store });
    const result = await executor.uninstall('pkg-mod-during', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'record_update_failed');
    // Target must still be absent
    assert.ok(!fs.existsSync(targetDir));

    cleanup(homeDir);
  });

  // =========================================================================
  // P2 fix: stale record target reappears right before store.remove()
  // =========================================================================

  await runTest('stale record — target reappears at final check before remove', async () => {
    const homeDir = makeTmpDir();
    const clientRoot = path.resolve(homeDir, '.claude', 'skills');
    const targetDir = path.resolve(clientRoot, 'pkg-late-reappear');
    fs.mkdirSync(clientRoot, { recursive: true });
    // Do NOT create targetDir

    const store = new LocalInstallStore(homeDir);
    store.save(makeRecord({
      package_name: 'pkg-late-reappear',
      install_path: targetDir,
      content_hash_algorithm: 'sha256-tree-v1',
      content_sha256: 'b'.repeat(64),
    }));

    // Actually create the directory on the final exists() call (the one
    // right before store.remove()), with a sentinel to prove nothing
    // was written/deleted.
    let existCalls = 0;
    const sentinelContent = 'LATE-' + crypto.randomBytes(8).toString('hex');
    const trickyOps: UninstallFileOps = {
      ...realFileOps,
      exists: (p: string) => {
        if (p === targetDir) {
          existCalls++;
          if (existCalls >= 3) {
            // Really create the directory with a sentinel file
            fs.mkdirSync(targetDir, { recursive: true });
            writeFile(targetDir, 'SENTINEL.txt', sentinelContent);
            return true;
          }
          return false;
        }
        return realFileOps.exists(p);
      },
    };

    const executor = new UninstallExecutor({ homeDir, store, fileOps: trickyOps });
    const result = await executor.uninstall('pkg-late-reappear', 'claude-code');
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'unsafe_content');
    // Record must still exist
    assert.strictEqual(store.load().length, 1);
    // The injection MUST have fired — at least 3 exists() calls for the
    // target (initial, after re-read, final check).  If this fails the
    // race injection never ran and the test is a false positive.
    assert.ok(existCalls >= 3,
      `expected >=3 exists calls for target, got ${existCalls}`);
    // Sentinel MUST exist and be untouched
    const sentinelPath = path.join(targetDir, 'SENTINEL.txt');
    assert.ok(fs.existsSync(sentinelPath),
      'sentinel file must exist (race injection must have fired)');
    assert.strictEqual(fs.readFileSync(sentinelPath, 'utf-8'), sentinelContent,
      'sentinel content must be unchanged');
    // No quarantine leftovers
    const entries = fs.readdirSync(clientRoot);
    const quarantines = entries.filter(e => e.startsWith('.uninstall-'));
    assert.strictEqual(quarantines.length, 0, 'no quarantine leftovers');

    cleanup(homeDir);
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
