/**
 * Tests for VerifyExecutor — read-only package integrity verification.
 *
 * Run: npx tsx tests/verify-executor.test.ts
 *
 * Coverage: every VerifyStatus, read-only safety, error mapping.
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { VerifyExecutor } from '../src/verify-executor';
import type { VerifyResult } from '../src/verify-executor';
import { LocalInstallStore } from '../src/local-install-store';
import type { LocalInstallRecord } from '../src/local-install-store';
import { computeDirectoryDigest } from '../src/content-integrity';
import { createApiClient, ApiError } from '../src/api-client';
import type { FetchFn } from '../src/api-client';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => Promise<void>) {
  return fn().then(
    () => { passed++; console.log(`  ✓ ${name}`); },
    (err: unknown) => {
      failed++;
      console.log(`  ✗ ${name}`);
      console.error(err instanceof Error ? err.stack || err.message : String(err));
    },
  );
}

function makeTmpDir(): string {
  const dir = path.join(os.tmpdir(), 'tah-verify-test-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function sha256(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Build a minimal valid install manifest for verification.
 */
function makeManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    manifest_version: '1.0',
    name: 'test-pkg',
    version: '1.0.0',
    type: 'skill',
    description: 'Test package',
    source: {
      type: 'github',
      repository_url: 'https://github.com/example/repo',
      download_url: 'https://example.com/test.zip',
      ref: 'v1.0.0',
      commit_hash: 'a'.repeat(40),
    },
    integrity: {
      sha256: 'b'.repeat(64),
      download_size_bytes: 1000,
    },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/test.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: 'b'.repeat(64) },
        { action: 'extract', archive: 'test.zip' },
        { action: 'copy', source: 'src/', destination: '~/.claude/skills/test-pkg/' },
      ],
    },
    permissions: {},
    risk_summary: {
      level: 'low',
      grade: 'A',
      install_recommendation: 'safe',
    },
    compatibility: ['claude-code'],
    dependencies: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Verify Executor Tests\n');

  // -----------------------------------------------------------------------
  // valid
  // -----------------------------------------------------------------------

  await runTest('valid — correctly installed package', async () => {
    const home = makeTmpDir();
    try {
      // Create the install directory with content
      const skillsRoot = path.join(home, '.claude/skills');
      fs.mkdirSync(skillsRoot, { recursive: true });
      const installDir = path.join(skillsRoot, 'test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test Package');

      // Compute its content digest
      const digest = await computeDirectoryDigest(installDir);

      // Create a valid install record
      const store = new LocalInstallStore(home);
      const record: LocalInstallRecord = {
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      };
      store.save(record);

      // Create a mock API client that returns a matching manifest
      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async (url: string) => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.status, 'valid');
      assert.strictEqual(result.packageName, 'test-pkg');
      assert.strictEqual(result.version, '1.0.0');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // not_installed
  // -----------------------------------------------------------------------

  await runTest('not_installed — no record found', async () => {
    const home = makeTmpDir();
    try {
      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('no-such-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'not_installed');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // record_invalid — corrupt installs.json
  // -----------------------------------------------------------------------

  await runTest('record_invalid — corrupt installs.json', async () => {
    const home = makeTmpDir();
    try {
      // Write corrupt JSON
      const recordsDir = path.join(home, '.trusted-agent-hub');
      fs.mkdirSync(recordsDir, { recursive: true });
      fs.writeFileSync(path.join(recordsDir, 'installs.json'), '{broken');

      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'record_invalid');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // legacy_record — no content hash
  // -----------------------------------------------------------------------

  await runTest('legacy_record — missing content hash', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        // NO content_hash fields — legacy record
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'legacy_record');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // unsupported_client
  // -----------------------------------------------------------------------

  await runTest('unsupported_client — unknown client type', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.unknown/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'unknown-client',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'unknown-client');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'unsupported_client');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // unsafe_path — install path outside client root
  // -----------------------------------------------------------------------

  await runTest('unsafe_path — install path escapes client root', async () => {
    const home = makeTmpDir();
    try {
      // Path outside client root (e.g., in .ssh)
      const installDir = path.join(home, '.ssh');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Escaped');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'unsafe_path');
      // Sentinel file must not be read or modified
      // (the path exists but verify should reject it before computing digest)
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // missing — target directory doesn't exist
  // -----------------------------------------------------------------------

  await runTest('missing — target directory deleted', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: 'c'.repeat(64),
      });

      // Directory does NOT exist

      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'missing');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // modified — content digest mismatch
  // -----------------------------------------------------------------------

  await runTest('modified — file content changed', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), 'original');

      const originalDigest = (await computeDirectoryDigest(installDir)).digest;

      // Now modify the file
      fs.writeFileSync(path.join(installDir, 'README.md'), 'modified');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: originalDigest, // the ORIGINAL digest
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'modified');
      assert.notStrictEqual(result.actualContentSha256, undefined);
      assert.notStrictEqual(result.expectedContentSha256, undefined);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // modified — file added
  // -----------------------------------------------------------------------

  await runTest('modified — file added to install directory', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), 'hello');

      const originalDigest = (await computeDirectoryDigest(installDir)).digest;

      // Add a new file
      fs.writeFileSync(path.join(installDir, 'extra.txt'), 'bonus');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: originalDigest,
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'modified');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — name differs
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — manifest name differs from record', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Manifest with DIFFERENT name
      const manifest = makeManifest({
        name: 'different-pkg',
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — version 409 from server
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — server returns 409', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Server returns 409
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify({ error: { message: 'unavailable' } }), { status: 409 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // remote_unavailable — network error
  // -----------------------------------------------------------------------

  await runTest('remote_unavailable — network error', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Simulate network error
      const apiClient = createApiClient((async () => {
        throw new Error('fetch failed');
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'remote_unavailable');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // remote_unavailable — 5xx error
  // -----------------------------------------------------------------------

  await runTest('remote_unavailable — server 500', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const apiClient = createApiClient((async () => {
        return new Response('Internal error', { status: 500 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'remote_unavailable');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — invalid manifest JSON
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — invalid manifest from server', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Return something that isn't a valid manifest (missing required fields)
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify({ manifest_version: '1.0' }), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Read-only: verify does not modify installs.json or content
  // -----------------------------------------------------------------------

  await runTest('read-only — verify does not modify installs.json or content', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Take snapshots before verify
      const recordsBefore = fs.readFileSync(store.getPath(), 'utf-8');
      const contentDigestBefore = (await computeDirectoryDigest(installDir)).digest;
      const fileStatBefore = fs.statSync(path.join(installDir, 'README.md'));

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const requestMethods: string[] = [];
      const apiClient = createApiClient((async (_input: string | URL | Request, init?: RequestInit) => {
        requestMethods.push(init?.method || 'GET');
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.status, 'valid');

      // Verify nothing changed
      const recordsAfter = fs.readFileSync(store.getPath(), 'utf-8');
      assert.strictEqual(recordsAfter, recordsBefore);

      const contentDigestAfter = (await computeDirectoryDigest(installDir)).digest;
      assert.strictEqual(contentDigestAfter, contentDigestBefore);

      const fileStatAfter = fs.statSync(path.join(installDir, 'README.md'));
      assert.strictEqual(fileStatAfter.mtimeMs, fileStatBefore.mtimeMs);
      assert.deepStrictEqual(requestMethods, ['GET'], 'verify must never call recordInstall or another write endpoint');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — artifact SHA differs
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — artifact SHA mismatch', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Manifest with DIFFERENT integrity.sha256
      const manifest = makeManifest({
        integrity: { sha256: 'd'.repeat(64), download_size_bytes: 1000 },
        installation: {
          method: 'copy_directory',
          target_client: 'claude-code',
          steps: [
            { action: 'download', url: 'https://example.com/test.zip' },
            { action: 'verify', algorithm: 'sha256', checksum: 'd'.repeat(64) },
            { action: 'extract', archive: 'test.zip' },
            { action: 'copy', source: 'src/', destination: '~/.claude/skills/test-pkg/' },
          ],
        },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // HTTP 429 → remote_unavailable
  // -----------------------------------------------------------------------

  await runTest('remote_unavailable — HTTP 429 rate limit', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const apiClient = createApiClient((async () => {
        return new Response('Too Many Requests', { status: 429 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'remote_unavailable');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — npm_install method rejected
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — non-copy_directory method rejected', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
        installation: {
          method: 'npm_install',
          target_client: 'claude-code',
          steps: [{ action: 'download', url: 'https://example.com/test.zip' }],
        },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // record_invalid — integrity_verified=false
  // -----------------------------------------------------------------------

  await runTest('record_invalid — integrity_verified=false', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: false,  // NOT verified
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'record_invalid');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // record_invalid — mismatched content hash fields (algo without hash)
  // -----------------------------------------------------------------------

  await runTest('record_invalid — content_hash_algorithm without content_sha256', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const store = new LocalInstallStore(home);
      // Bypass the store's validation by writing directly to the file
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      const badRecord = {
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        // content_sha256 intentionally missing
      };
      fs.writeFileSync(filePath, JSON.stringify([badRecord]), 'utf-8');

      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      // The store's load() should catch this as record_invalid
      assert.ok(
        result.status === 'record_invalid',
        `expected record_invalid, got ${result.status}`,
      );
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // manifest_mismatch — [null] steps crashes safely
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch — null steps array element', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
        installation: {
          method: 'copy_directory',
          target_client: 'claude-code',
          steps: [
            null,
            { action: 'download', url: 'https://example.com/test.zip' },
          ],
        },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // unsafe_content — directory contains a symlink
  // -----------------------------------------------------------------------

  await runTest('unsafe_content — symlink inside install directory', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      // Step 1: Compute digest while directory is clean (no symlink)
      const cleanDigest = await computeDirectoryDigest(installDir);

      // Step 2: Save the record with the clean digest
      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: cleanDigest.digest,
      });

      // Step 3: Create an unsafe entry — symlink on POSIX, junction on Windows.
      // Junctions don't require admin on Windows and are detected by lstat.
      const linkPath = path.join(installDir, 'link.md');
      if (process.platform === 'win32') {
        // Use junction (directory symlink) on Windows — no admin required
        const junctionTarget = path.join(installDir, 'subdir');
        fs.mkdirSync(junctionTarget);
        fs.writeFileSync(path.join(junctionTarget, 'f.txt'), 'x');
        fs.symlinkSync(junctionTarget, linkPath, 'junction');
      } else {
        fs.symlinkSync(path.join(installDir, 'README.md'), linkPath);
      }

      // Step 4: Verify — digest should detect the unsafe entry via lstat
      //         and return unsafe_content (not modified, not valid)
      const manifest = makeManifest({
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'unsafe_content',
        `expected unsafe_content, got ${result.status}: ${result.message}`);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // maxFiles limit passed through to computeDirectoryDigest
  // -----------------------------------------------------------------------

  await runTest('maxFiles limit enforced during verify', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      // Create 15 files
      for (let i = 0; i < 15; i++) {
        fs.writeFileSync(path.join(installDir, `f${i}.txt`), 'content');
      }

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Set maxFiles to 10 — the digest will fail because there are 15 files
      const apiClient = createApiClient((async () => {
        return new Response('{}', { status: 200 });
      }) as FetchFn);
      const executor = new VerifyExecutor(apiClient, { homeDir: home, maxFiles: 10 });
      const result = await executor.verify('test-pkg', 'claude-code');

      // Should fail because digest exceeds file limit → ContentIntegrityError
      // with code 'too_many_files'.  The verifier maps unknown ContentIntegrityError
      // codes to 'modified'.
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'modified', `expected modified, got ${result.status}`);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // sanitizeOutput — filters ANSI, OSC, control chars, limits length
  // -----------------------------------------------------------------------

  await runTest('sanitizeOutput filters ANSI escape codes', async () => {
    const { sanitizeOutput } = await import('../src/verify-executor');
    const result = sanitizeOutput('\x1b[31mRED\x1b[0m');
    assert.strictEqual(result.includes('\x1b'), false);
    assert.ok(result.includes('RED'));
  });

  await runTest('sanitizeOutput filters OSC sequences', async () => {
    const { sanitizeOutput } = await import('../src/verify-executor');
    const result = sanitizeOutput('\x1b]0;title\x07text');
    assert.strictEqual(result.includes('\x1b]'), false);
    assert.ok(result.includes('text'));
  });

  await runTest('sanitizeOutput filters C0 control chars (\\n, \\r, \\t)', async () => {
    const { sanitizeOutput } = await import('../src/verify-executor');
    const result = sanitizeOutput('line1\nline2\rline3\tindent');
    assert.strictEqual(result.includes('\n'), false);
    assert.strictEqual(result.includes('\r'), false);
    assert.strictEqual(result.includes('\t'), false);
  });

  await runTest('sanitizeOutput filters C1 control chars (0x80-0x9F)', async () => {
    const { sanitizeOutput } = await import('../src/verify-executor');
    // U+0086 (START OF SELECTED AREA) — C1 control
    const result = sanitizeOutput('text\x86more');
    assert.strictEqual(result.includes('\x86'), false);
    assert.ok(result.includes('text'));
    assert.ok(result.includes('more'));
  });

  await runTest('sanitizeOutput truncates at 200 chars', async () => {
    const { sanitizeOutput } = await import('../src/verify-executor');
    const long = 'a'.repeat(300);
    const result = sanitizeOutput(long);
    assert.strictEqual(result.length, 200); // 199 + '…'
    assert.ok(result.endsWith('…'));
  });

  // -----------------------------------------------------------------------
  // VerifyResult → CLI output: all fields sanitized
  // -----------------------------------------------------------------------

  await runTest('CLI output cannot inject ANSI via packageName', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills', 'test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');
      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      // Package name with ANSI injection
      store.save({
        package_name: '\x1b[31mRED\x1b[0m',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const manifest = makeManifest({
        name: '\x1b[31mRED\x1b[0m',
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('\x1b[31mRED\x1b[0m', 'claude-code');

      // All user-facing fields must be free of ANSI
      assert.strictEqual(result.packageName.includes('\x1b'), false);
      assert.strictEqual(result.client.includes('\x1b'), false);
      assert.strictEqual(result.message.includes('\x1b'), false);
      if (result.version) assert.strictEqual(result.version.includes('\x1b'), false);
      if (result.installPath) assert.strictEqual(result.installPath.includes('\x1b'), false);
    } finally {
      cleanup(home);
    }
  });

  await runTest('CLI output cannot inject newlines via version', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills', 'test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');
      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0\n\rINJECTED',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      const manifest = makeManifest({
        version: '1.0\n\rINJECTED',
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      assert.strictEqual(result.version!.includes('\n'), false);
      assert.strictEqual(result.version!.includes('\r'), false);
      assert.strictEqual(result.packageName.includes('\n'), false);
      assert.strictEqual(result.message.includes('\n'), false);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Stable error messages — no raw manifest fields
  // -----------------------------------------------------------------------

  await runTest('manifest_mismatch does not leak raw server values', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');
      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg', version: '1.0.0', client: 'claude-code',
        install_path: installDir, sha256: 'b'.repeat(64),
        integrity_verified: true, installed_at: new Date().toISOString(),
        manifest_version: '1.0', content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Manifest with injected ANSI in name field
      const manifest = makeManifest({
        name: 'test-pkg',
        version: '\x1b[31mINJECTED\x1b[0m', // ANSI in version
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
      });
      const apiClient = createApiClient((async () => {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }) as FetchFn);

      const executor = new VerifyExecutor(apiClient, { homeDir: home });
      const result = await executor.verify('test-pkg', 'claude-code');

      // Must detect mismatch but NOT leak the ANSI version string
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, 'manifest_mismatch');
      assert.strictEqual(result.message.includes('\x1b'), false);
      assert.strictEqual(result.message.includes('INJECTED'), false);
    } finally {
      cleanup(home);
    }
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
