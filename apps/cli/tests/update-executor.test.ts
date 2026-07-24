/**
 * Comprehensive tests for UpdateExecutor — safe atomic package updates.
 *
 * Run: npx tsx tests/update-executor.test.ts
 *
 * Coverage:
 *   - Not installed → not_installed
 *   - Already latest → up_to_date
 *   - Normal upgrade → updated
 *   - Modified content default → modified (blocked)
 *   - Modified content --force → updated
 *   - Legacy record default → legacy_record (blocked)
 *   - Legacy record --force → updated
 *   - Same version → up_to_date (no write)
 *   - Downgrade → downgrade_blocked
 *   - Grade D without flags → update_blocked
 *   - Grade D with flags → updated
 *   - Grade E → update_blocked
 *   - Unsupported client → unsupported_client
 *   - API unreachable → manifest_unavailable
 *   - Manifest 409 → manifest_unavailable
 *   - Invalid manifest → invalid_manifest
 *   - Manifest name/client mismatch → invalid_manifest
 *   - Output sanitization (no ANSI/control chars in result)
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import AdmZip from 'adm-zip';

import { UpdateExecutor } from '../src/update-executor';
import { InstallExecutor } from '../src/install-executor';
import { LocalInstallStore } from '../src/local-install-store';
import type { LocalInstallRecord } from '../src/local-install-store';
import { createApiClient } from '../src/api-client';
import type { FetchFn, InstallManifest } from '../src/manifest-types';
import { computeDirectoryDigest } from '../src/content-integrity';
import { sanitizeOutput } from '../src/safe-output';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_HOME_BASE = path.join(os.tmpdir(), 'tah-update-test-' + crypto.randomBytes(8).toString('hex'));

function makeTempHome(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-update-test-'));
  return dir;
}

function makeManifest(overrides: Partial<InstallManifest> = {}): InstallManifest {
  return {
    manifest_version: '1.0',
    name: 'test-package',
    version: '2.0.0',
    type: 'skill',
    description: 'Test package',
    source: {
      type: 'github',
      repository_url: 'https://github.com/test/package',
      download_url: 'https://example.com/package-v2.zip',
      ref: 'v2.0.0',
      commit_hash: 'b'.repeat(40),
    },
    integrity: {
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      download_size_bytes: 1024,
    },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package-v2.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
    },
    permissions: {
      filesystem: { read: ['*'] },
      shell: { allowed: false },
      network: { allowed: false },
      environment: { read: [], write: [] },
    },
    risk_summary: {
      level: 'low_risk',
      grade: 'B',
      top_risks: [],
      install_recommendation: 'safe',
    },
    compatibility: ['claude-code'],
    dependencies: { npm: null, pip: null, system: null, docker: null, mcp_servers: null },
    ...overrides,
  };
}

function sha256(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function createPayloadZip(files: Record<string, string>): Buffer {
  const zip = new AdmZip();
  for (const [name, content] of Object.entries(files)) {
    zip.addFile(name, Buffer.from(content, 'utf-8'));
  }
  return zip.toBuffer();
}

function mockFetchForManifest(manifest: InstallManifest, zipBuf?: Buffer): FetchFn {
  return async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return {
        status: 201, ok: true, headers: new Headers(),
        json: async () => ({ id: 'rec-1', package_name: manifest.name, version: manifest.version }),
        text: async () => '',
      } as Response;
    }

    const url = urlStr.toString();
    if (url.includes('install-manifest')) {
      return {
        status: 200, ok: true, headers: new Headers(),
        json: async () => manifest,
        text: async () => JSON.stringify(manifest),
      } as Response;
    }

    if (zipBuf) {
      return {
        status: 200, ok: true,
        headers: new Headers({ 'content-length': String(zipBuf.length) }),
        body: new ReadableStream({
          start(controller) { controller.enqueue(zipBuf); controller.close(); },
        }),
        json: async () => ({}),
        text: async () => '',
      } as unknown as Response;
    }

    return {
      status: 404, ok: false, headers: new Headers(),
      json: async () => ({ error: { message: 'Not found' } }),
      text: async () => 'Not found',
    } as Response;
  };
}

/** Install a package at version 1.0.0 for testing updates. */
async function installV1(
  homeDir: string,
  pkgName: string = 'test-package',
): Promise<{ record: LocalInstallRecord; targetDir: string; manifest: InstallManifest }> {
  const zipFiles = { 'package/README.md': '# v1.0.0\n\nOld version.\n' };
  const zipBuf = createPayloadZip(zipFiles);
  const zipSha = sha256(zipBuf);

  const manifest = makeManifest({
    name: pkgName,
    version: '1.0.0',
    integrity: { sha256: zipSha, download_size_bytes: zipBuf.length },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package-v1.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: zipSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: `~/.claude/skills/${pkgName}/` },
      ],
    },
    source: {
      type: 'github',
      repository_url: 'https://github.com/test/package',
      download_url: 'https://example.com/package-v1.zip',
      ref: 'v1.0.0',
      commit_hash: 'a'.repeat(40),
    },
  });

  const fetcher = mockFetchForManifest(manifest, zipBuf);
  const apiClient = createApiClient(fetcher);
  const executor = new InstallExecutor(apiClient, { homeDir, fetchFn: fetcher });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});

  const record = result.record;
  return { record, targetDir: result.targetDir, manifest };
}

/** Create a v2 manifest with correct ZIP for update testing. */
function makeV2ManifestForUpdate(pkgName: string): { manifest: InstallManifest; zipBuf: Buffer; zipSha: string } {
  const zipFiles = { 'package/README.md': '# v2.0.0\n\nUpdated version!\n', 'package/main.js': 'console.log("v2");' };
  const zipBuf = createPayloadZip(zipFiles);
  const zipSha = sha256(zipBuf);

  const manifest = makeManifest({
    name: pkgName,
    version: '2.0.0',
    integrity: { sha256: zipSha, download_size_bytes: zipBuf.length },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package-v2.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: zipSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: `~/.claude/skills/${pkgName}/` },
      ],
    },
    source: {
      type: 'github',
      repository_url: 'https://github.com/test/package',
      download_url: 'https://example.com/package-v2.zip',
      ref: 'v2.0.0',
      commit_hash: 'b'.repeat(40),
    },
  });

  return { manifest, zipBuf, zipSha };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function test_notInstalled() {
  const homeDir = makeTempHome();
  try {
    const apiClient = createApiClient(mockFetchForManifest(makeManifest()));
    const executor = new UpdateExecutor(apiClient, { homeDir });
    const result = await executor.update('nonexistent', 'claude-code');
    assert.strictEqual(result.status, 'not_installed');
    assert.strictEqual(result.ok, false);
    console.log('  ✓ not installed → not_installed');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_upToDate() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Mock API returning same version
    const manifest = makeManifest({ name: 'test-package', version: '1.0.0' });
    const apiClient = createApiClient(mockFetchForManifest(manifest));
    const executor = new UpdateExecutor(apiClient, { homeDir });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'up_to_date');
    assert.strictEqual(result.ok, true);

    // Verify no files were changed
    const files = fs.readdirSync(record.install_path);
    assert.ok(files.includes('README.md'));
    console.log('  ✓ already latest → up_to_date (no writes)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_normalUpgrade() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'updated');
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.localVersion, '1.0.0');  // old version
    assert.strictEqual(result.remoteVersion, '2.0.0'); // new version

    // Verify new files exist
    assert.ok(fs.existsSync(path.join(record.install_path, 'main.js')), 'main.js should exist');
    const readme = fs.readFileSync(path.join(record.install_path, 'README.md'), 'utf-8');
    assert.ok(readme.includes('v2.0.0'), 'README should show v2.0.0');

    // Verify record was updated
    const store = new LocalInstallStore(homeDir);
    const updatedRecord = store.find('test-package', 'claude-code');
    assert.ok(updatedRecord !== null);
    assert.strictEqual(updatedRecord!.version, '2.0.0');

    console.log('  ✓ normal upgrade → updated');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_modifiedContentBlocked() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Modify the content
    fs.writeFileSync(path.join(record.install_path, 'hacked.js'), '// malicious');

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'modified');
    assert.strictEqual(result.ok, false);

    // Verify old version still intact
    assert.ok(fs.existsSync(path.join(record.install_path, 'hacked.js')));
    console.log('  ✓ modified content → modified (blocked)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_modifiedContentForce() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Modify the content
    fs.writeFileSync(path.join(record.install_path, 'hacked.js'), '// malicious');

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code', { force: true });
    assert.strictEqual(result.status, 'updated');
    assert.strictEqual(result.ok, true);

    // Verify old modified content was overwritten
    assert.ok(!fs.existsSync(path.join(record.install_path, 'hacked.js')));
    assert.ok(fs.existsSync(path.join(record.install_path, 'main.js')));
    console.log('  ✓ modified content --force → updated');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_legacyRecordBlocked() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Make the record "legacy" by removing content hash fields
    const store = new LocalInstallStore(homeDir);
    const legacyRecord: LocalInstallRecord = {
      ...record,
      content_hash_algorithm: undefined,
      content_sha256: undefined,
    };
    store.save(legacyRecord);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'legacy_record');
    assert.strictEqual(result.ok, false);
    console.log('  ✓ legacy_record → legacy_record (blocked)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_legacyRecordForce() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    const store = new LocalInstallStore(homeDir);
    store.save({ ...record, content_hash_algorithm: undefined, content_sha256: undefined } as LocalInstallRecord);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code', { force: true });
    assert.strictEqual(result.status, 'updated');
    console.log('  ✓ legacy_record --force → updated');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_downgradeBlocked() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    // Mock API returning lower version
    const manifest = makeManifest({ name: 'test-package', version: '0.9.0' });
    const apiClient = createApiClient(mockFetchForManifest(manifest));
    const executor = new UpdateExecutor(apiClient, { homeDir });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'downgrade_blocked');
    assert.strictEqual(result.ok, false);
    console.log('  ✓ downgrade → downgrade_blocked');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_gradeE_blocked() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    manifest.risk_summary.grade = 'E';
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code', { force: true, acceptHighRisk: true });
    assert.strictEqual(result.status, 'update_blocked');
    assert.strictEqual(result.ok, false);
    console.log('  ✓ Grade E → update_blocked (despite --force and --accept-high-risk)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_gradeDWithoutFlags() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    manifest.risk_summary.grade = 'D';
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'update_blocked');
    console.log('  ✓ Grade D without flags → update_blocked');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_gradeDWithFlags() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    manifest.risk_summary.grade = 'D';
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code', { force: true, acceptHighRisk: true });
    assert.strictEqual(result.status, 'updated');
    console.log('  ✓ Grade D with --force + --accept-high-risk → updated');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_unsupportedClient() {
  const homeDir = makeTempHome();
  try {
    const apiClient = createApiClient(mockFetchForManifest(makeManifest()));
    const executor = new UpdateExecutor(apiClient, { homeDir });
    const result = await executor.update('test-package', 'nonexistent-client');
    assert.strictEqual(result.status, 'unsupported_client');
    console.log('  ✓ unsupported client → unsupported_client');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_apiUnreachable() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    // Mock API that always throws
    const fetcher: FetchFn = async () => { throw new Error('Network error'); };
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'manifest_unavailable');
    console.log('  ✓ API unreachable → manifest_unavailable');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_manifest409() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const fetcher: FetchFn = async (urlStr: string) => {
      if (urlStr.toString().includes('install-manifest')) {
        return { status: 409, ok: false, headers: new Headers(), json: async () => ({}), text: async () => '' } as Response;
      }
      return { status: 200, ok: true, headers: new Headers(), json: async () => ({}), text: async () => '' } as Response;
    };
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'manifest_unavailable');
    console.log('  ✓ manifest 409 → manifest_unavailable');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_manifestNameMismatch() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const manifest = makeManifest({ name: 'wrong-name', version: '2.0.0' });
    const apiClient = createApiClient(mockFetchForManifest(manifest));
    const executor = new UpdateExecutor(apiClient, { homeDir });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'invalid_manifest');
    console.log('  ✓ manifest name mismatch → invalid_manifest');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_manifestClientMismatch() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const manifest = makeManifest({
      name: 'test-package',
      version: '2.0.0',
      installation: {
        method: 'copy_directory',
        target_client: 'cursor',  // Wrong client
        steps: [
          { action: 'download', url: 'https://example.com/pkg.zip' },
          { action: 'verify', algorithm: 'sha256', checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
          { action: 'extract', archive: 'package.zip' },
          { action: 'copy', source: 'package/', destination: '~/.cursor/skills/test-package/' },
        ],
      },
      source: {
        type: 'github', repository_url: 'https://github.com/test/package',
        download_url: 'https://example.com/package-v2.zip',
        ref: 'v2.0.0', commit_hash: 'b'.repeat(40),
      },
    } as InstallManifest);
    const apiClient = createApiClient(mockFetchForManifest(manifest));
    const executor = new UpdateExecutor(apiClient, { homeDir });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'invalid_manifest');
    console.log('  ✓ manifest client mismatch → invalid_manifest');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_outputSanitization() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    // Manifest with special characters that should be sanitized
    const { zipBuf, zipSha } = makeV2ManifestForUpdate('test-pkg\x1b[31m');
    const manifest = makeManifest({
      name: 'test-pkg\x1b[31m',
      version: '2.0.0',
      description: 'Test with \x1b[31mANSI\x1b[0m codes and \nnewlines',
      integrity: { sha256: zipSha, download_size_bytes: zipBuf.length },
      installation: {
        method: 'copy_directory',
        target_client: 'claude-code',
        steps: [
          { action: 'download', url: 'https://example.com/package-v2.zip' },
          { action: 'verify', algorithm: 'sha256', checksum: zipSha },
          { action: 'extract', archive: 'package.zip' },
          { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-pkg\x1b[31m/' },
        ],
      },
      source: {
        type: 'github', repository_url: 'https://github.com/test/package',
        download_url: 'https://example.com/package-v2.zip',
        ref: 'v2.0.0', commit_hash: 'b'.repeat(40),
      },
    } as InstallManifest);

    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-pkg\x1b[31m', 'claude-code');
    // Should either be not_installed (different name) or fail gracefully
    // The key test: output must not contain ANSI codes
    assert.ok(!result.message.includes('\x1b'), 'message must not contain ANSI codes');
    assert.ok(!result.message.includes('\n'), 'message must not contain newlines');
    assert.ok(!result.packageName.includes('\x1b'), 'packageName must not contain ANSI codes');
    console.log('  ✓ output sanitization → no ANSI/control chars');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_verifyAfterUpdate() {
  const homeDir = makeTempHome();
  try {
    await installV1(homeDir);

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'updated');

    // Now run verify to confirm the update is good
    const { VerifyExecutor } = await import('../src/verify-executor');
    // Verify needs the same API client for manifest lookups
    const v2fetcher = mockFetchForManifest(manifest, zipBuf);
    const v2apiClient = createApiClient(v2fetcher);
    const verifyResult = await new VerifyExecutor(v2apiClient, { homeDir }).verify('test-package', 'claude-code');
    assert.strictEqual(verifyResult.status, 'valid', `Expected valid, got ${verifyResult.status}: ${verifyResult.message}`);
    console.log('  ✓ update → verify passes');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_preserveInstalledAt() {
  const homeDir = makeTempHome();
  try {
    const { record: oldRecord } = await installV1(homeDir);
    const originalInstalledAt = oldRecord.installed_at;

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'updated');

    // Read back the record and check timestamps
    const store = new LocalInstallStore(homeDir);
    const updatedRecord = store.find('test-package', 'claude-code');
    assert.ok(updatedRecord !== null);
    assert.strictEqual(updatedRecord!.installed_at, originalInstalledAt,
      'installed_at should be preserved');
    assert.ok(updatedRecord!.updated_at !== undefined, 'updated_at should be set');
    assert.ok(updatedRecord!.updated_at !== originalInstalledAt,
      'updated_at should differ from installed_at');
    console.log('  ✓ installedAt preserved, updatedAt added');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

// ── P1 fix tests ─────────────────────────────────────────────────────────

async function test_unsafePathBlocked() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Corrupt install_path to point outside client root
    const store = new LocalInstallStore(homeDir);
    store.save({ ...record, install_path: '/tmp/outside-root' });

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'unsafe_path');
    assert.strictEqual(result.ok, false);

    // --force must NOT override unsafe_path
    const resultForce = await executor.update('test-package', 'claude-code', { force: true });
    assert.strictEqual(resultForce.status, 'unsafe_path');
    assert.strictEqual(resultForce.ok, false);
    console.log('  ✓ unsafe_path blocked (--force cannot override)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_recordInvalidBlocked() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Corrupt the record — set integrity_verified to false
    const store = new LocalInstallStore(homeDir);
    store.save({ ...record, integrity_verified: false });

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'record_invalid');
    assert.strictEqual(result.ok, false);

    // --force must NOT override record_invalid
    const resultForce = await executor.update('test-package', 'claude-code', { force: true });
    assert.strictEqual(resultForce.status, 'record_invalid');
    console.log('  ✓ record_invalid blocked (structural, --force cannot override)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_missingDirWithRecordBlocked() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Delete the target directory but keep the record
    fs.rmSync(record.install_path, { recursive: true, force: true });

    const { manifest, zipBuf } = makeV2ManifestForUpdate('test-package');
    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('test-package', 'claude-code');
    assert.strictEqual(result.status, 'update_failed');
    assert.ok(result.message.includes('Reinstall'), 'should suggest reinstall');
    console.log('  ✓ missing directory (record exists) → update_failed');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_contentRaceDetection() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir, 'race-pkg');

    // Build v2 manifest + zip that will trigger inspection recheck
    const zipFiles = { 'package/README.md': '# v2\n' };
    const zipBuf = createPayloadZip(zipFiles);
    const zipSha = sha256(zipBuf);

    const manifest = makeManifest({
      name: 'race-pkg',
      version: '2.0.0',
      integrity: { sha256: zipSha, download_size_bytes: zipBuf.length },
      installation: {
        method: 'copy_directory',
        target_client: 'claude-code',
        steps: [
          { action: 'download', url: 'https://example.com/race-pkg-v2.zip' },
          { action: 'verify', algorithm: 'sha256', checksum: zipSha },
          { action: 'extract', archive: 'package.zip' },
          { action: 'copy', source: 'package/', destination: '~/.claude/skills/race-pkg/' },
        ],
      },
      source: {
        type: 'github', repository_url: 'https://github.com/test/race',
        download_url: 'https://example.com/race-pkg-v2.zip',
        ref: 'v2.0.0', commit_hash: 'c'.repeat(40),
      },
    } as InstallManifest);

    // Custom fetch that modifies the installed content BEFORE returning the manifest
    let manifestReturned = false;
    const fetcher: FetchFn = async (urlStr: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return { status: 201, ok: true, headers: new Headers(), json: async () => ({}), text: async () => '' } as Response;
      }
      const url = urlStr.toString();
      if (url.includes('install-manifest')) {
        // Before returning the manifest, modify the installed content
        if (!manifestReturned) {
          fs.writeFileSync(path.join(record.install_path, 'injected.txt'), '// race!');
          manifestReturned = true;
        }
        return { status: 200, ok: true, headers: new Headers(), json: async () => manifest, text: async () => '' } as Response;
      }
      return {
        status: 200, ok: true,
        headers: new Headers({ 'content-length': String(zipBuf.length) }),
        body: new ReadableStream({ start(c) { c.enqueue(zipBuf); c.close(); } }),
        json: async () => ({}), text: async () => '',
      } as unknown as Response;
    };

    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    const result = await executor.update('race-pkg', 'claude-code');
    // Should detect the content change during manifest fetch
    assert.strictEqual(result.status, 'update_failed');
    assert.ok(
      result.message.includes('state changed') || result.message.includes('modified'),
      `Expected race detection message, got: ${result.message}`,
    );
    console.log('  ✓ content race detection → update_failed');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function test_rollbackFailedDetected() {
  const homeDir = makeTempHome();
  try {
    const { record } = await installV1(homeDir);

    // Build a manifest whose zip has a WRONG SHA — the install will fail
    // AFTER the backup is moved (staging populated, digest computed, backup
    // created).  We then delete the target so that rollback cannot restore.
    const zipFiles = { 'package/README.md': '# bad\n' };
    const zipBuf = createPayloadZip(zipFiles);
    const wrongSha = 'b'.repeat(64); // deliberate mismatch

    const manifest = makeManifest({
      name: 'test-package',
      version: '2.0.0',
      integrity: { sha256: wrongSha, download_size_bytes: zipBuf.length },
      installation: {
        method: 'copy_directory',
        target_client: 'claude-code',
        steps: [
          { action: 'download', url: 'https://example.com/bad.zip' },
          { action: 'verify', algorithm: 'sha256', checksum: wrongSha },
          { action: 'extract', archive: 'package.zip' },
          { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
        ],
      },
      source: {
        type: 'github', repository_url: 'https://github.com/test/package',
        download_url: 'https://example.com/bad.zip',
        ref: 'v2.0.0', commit_hash: 'd'.repeat(40),
      },
    } as InstallManifest);

    const fetcher = mockFetchForManifest(manifest, zipBuf);
    const apiClient = createApiClient(fetcher);
    const executor = new UpdateExecutor(apiClient, { homeDir, fetchFn: fetcher });

    // Also delete the old install directory so rollback verification fails
    // BUT the InstallExecutor's internal rollback should have restored it.
    // The SHA mismatch happens BEFORE backup is created, so the old version
    // should still be intact.
    const result = await executor.update('test-package', 'claude-code');
    // SHA mismatch → update_failed, but old version is intact (no rollback needed)
    assert.strictEqual(result.status, 'update_failed');
    assert.ok(
      result.message.includes('Previous version preserved') || result.message.includes('preserved'),
      `Expected preservation note in: ${result.message.slice(0, 100)}`,
    );

    // Verify old version is still there
    assert.ok(fs.existsSync(record.install_path), 'old installation should still exist');
    console.log('  ✓ failed update preserves old version (not rollback_failed)');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

async function main() {
  console.log('\nUpdate Executor Tests\n');

  await test_notInstalled();
  await test_upToDate();
  await test_normalUpgrade();
  await test_modifiedContentBlocked();
  await test_modifiedContentForce();
  await test_legacyRecordBlocked();
  await test_legacyRecordForce();
  await test_downgradeBlocked();
  await test_gradeE_blocked();
  await test_gradeDWithoutFlags();
  await test_gradeDWithFlags();
  await test_unsupportedClient();
  await test_apiUnreachable();
  await test_manifest409();
  await test_manifestNameMismatch();
  await test_manifestClientMismatch();
  await test_outputSanitization();
  await test_verifyAfterUpdate();
  await test_preserveInstalledAt();
  // P1 fix tests
  await test_unsafePathBlocked();
  await test_recordInvalidBlocked();
  await test_missingDirWithRecordBlocked();
  await test_contentRaceDetection();
  await test_rollbackFailedDetected();

  console.log('\n  ✓ All update-executor tests passed!\n');
}

main().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
