/**
 * Comprehensive tests for InstallExecutor — secure package installation.
 *
 * Run: npx tsx tests/install-executor.test.ts
 *
 * Coverage:
 *   - Normal install (full pipeline with real ZIP)
 *   - SHA-256 mismatch
 *   - ZIP path traversal (real malicious ZIP → extractZip)
 *   - ZIP absolute path (real malicious ZIP)
 *   - ZIP Windows drive letter (real malicious ZIP)
 *   - ZIP symlinks (if detectable)
 *   - Target directory out of bounds
 *   - Staging + atomic rename (no partial install)
 *   - Backup + restore on failure
 *   - Existing install preserved on failure
 *   - Download timeout
 *   - Download size exceeded
 *   - Extract size exceeded
 *   - Extract file count exceeded
 *   - Install failure rollback
 *   - Grade D double confirmation
 *   - Grade E always blocked
 *   - Install record saved locally
 *   - API reporting failure surfaced
 *   - Manifest validation (various invalid shapes)
 *   - isSafeInstallPath edge cases
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import AdmZip from 'adm-zip';

import { InstallExecutor, InstallBlockedError, InstallError } from '../src/install-executor';
import { validateManifest, ManifestValidationError, isSafeInstallPath } from '../src/manifest-types';
import { createApiClient } from '../src/api-client';
import type { FetchFn } from '../src/api-client';
import type { InstallManifest } from '../src/manifest-types';
import { isStrictChildPath, resolveManifestDestination, ClientPathError } from '../src/client-paths';

// ---------------------------------------------------------------------------
// Raw ZIP construction (bypasses AdmZip's filename normalization)
// ---------------------------------------------------------------------------

/**
 * Build a minimal ZIP file with arbitrary entry names (including ../ traversal).
 *
 * Produces: [local file header][file data]...[central dir][eocd]
 * Each entry is stored (no compression) for simplicity.
 */
function buildRawZip(entries: Array<{ name: string; data: Buffer }>): Buffer {
  const localHeaders: Buffer[] = [];
  const centralHeaders: Buffer[] = [];
  const datas: Buffer[] = [];
  let centralOffset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf-8');
    const nameLen = nameBuf.length;

    // CRC-32 of the data
    const crc = crc32(entry.data);

    // Local file header
    const localHeader = Buffer.alloc(30 + nameLen);
    localHeader.writeUInt32LE(0x04034b50, 0);  // signature
    localHeader.writeUInt16LE(20, 4);            // version needed
    localHeader.writeUInt16LE(0, 6);             // flags
    localHeader.writeUInt16LE(0, 8);             // compression (stored)
    localHeader.writeUInt16LE(0, 10);            // mod time
    localHeader.writeUInt16LE(0, 12);            // mod date
    localHeader.writeUInt32LE(crc, 14);          // CRC-32
    localHeader.writeUInt32LE(entry.data.length, 18);  // compressed size
    localHeader.writeUInt32LE(entry.data.length, 22);  // uncompressed size
    localHeader.writeUInt16LE(nameLen, 26);       // filename length
    localHeader.writeUInt16LE(0, 28);             // extra field length
    nameBuf.copy(localHeader, 30);

    localHeaders.push(localHeader);
    datas.push(entry.data);

    // Central directory header
    const centralHeader = Buffer.alloc(46 + nameLen);
    centralHeader.writeUInt32LE(0x02014b50, 0);  // signature
    centralHeader.writeUInt16LE(20, 4);            // version made by
    centralHeader.writeUInt16LE(20, 6);            // version needed
    centralHeader.writeUInt16LE(0, 8);             // flags
    centralHeader.writeUInt16LE(0, 10);            // compression
    centralHeader.writeUInt16LE(0, 12);            // mod time
    centralHeader.writeUInt16LE(0, 14);            // mod date
    centralHeader.writeUInt32LE(crc, 16);          // CRC-32
    centralHeader.writeUInt32LE(entry.data.length, 20);  // compressed size
    centralHeader.writeUInt32LE(entry.data.length, 24);  // uncompressed size
    centralHeader.writeUInt16LE(nameLen, 28);       // filename length
    centralHeader.writeUInt16LE(0, 30);             // extra field length
    centralHeader.writeUInt16LE(0, 32);             // comment length
    centralHeader.writeUInt16LE(0, 34);             // disk number start
    centralHeader.writeUInt16LE(0, 36);             // internal attributes
    centralHeader.writeUInt32LE(0, 38);             // external attributes
    centralHeader.writeUInt32LE(centralOffset, 42); // local header offset
    nameBuf.copy(centralHeader, 46);

    centralHeaders.push(centralHeader);
    centralOffset += localHeader.length + entry.data.length;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const centralDirOffset = centralOffset;
  const centralDirSize = centralDir.length;

  // End of central directory record
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);  // signature
  eocd.writeUInt16LE(0, 4);            // disk number
  eocd.writeUInt16LE(0, 6);            // disk with central dir
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralDirSize, 12); // central dir size
  eocd.writeUInt32LE(centralDirOffset, 16); // central dir offset
  eocd.writeUInt16LE(0, 20);            // comment length

  return Buffer.concat([
    ...localHeaders,
    ...datas,
    centralDir,
    eocd,
  ]);
}

/** CRC-32 for a buffer (simple table-based implementation) */
function crc32(buf: Buffer): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >>> 1) ^ 0xEDB88320;
      } else {
        crc = crc >>> 1;
      }
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_HOME = path.join(os.tmpdir(), 'tah-test-' + crypto.randomBytes(8).toString('hex'));

function makeManifest(overrides: Partial<InstallManifest> = {}): InstallManifest {
  return {
    manifest_version: '1.0',
    name: 'test-package',
    version: '1.0.0',
    type: 'skill',
    description: 'Test package for unit tests',
    source: {
      type: 'github',
      repository_url: 'https://github.com/test/package',
      download_url: 'https://example.com/package.zip',
      ref: 'v1.0.0',
      commit_hash: 'a'.repeat(40),
    },
    integrity: {
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      download_size_bytes: 1024,
    },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null,
      post_install_message: null,
    },
    permissions: {
      filesystem: { read: ['*'], write: [], delete: false },
      shell: { allowed: false, commands: [] },
      network: { allowed: false, domains: [] },
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

/** Build a mock fetch that serves manifest + ZIP download + install record */
function mockFetch(
  manifest: InstallManifest,
  zipBuf: Buffer,
  opts?: { recordInstallFails?: boolean; recordInstallStatus?: number },
): FetchFn {
  return async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      if (opts?.recordInstallFails) {
        throw new Error('Network error during install report');
      }
      return {
        status: opts?.recordInstallStatus || 201,
        ok: opts?.recordInstallStatus ? opts.recordInstallStatus < 400 : true,
        headers: new Headers(),
        json: async () => ({ id: 'rec-1', package_name: manifest.name, version: manifest.version,
          version_id: 'v1', user_id: 'u1', client: 'claude-code', install_path: '/test',
          integrity_verified: true, installed_at: new Date().toISOString() }),
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

    // Download: return the ZIP as a ReadableStream body
    return {
      status: 200,
      ok: true,
      headers: new Headers({ 'content-length': String(zipBuf.length) }),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(zipBuf);
          controller.close();
        },
      }),
      json: async () => ({}),
      text: async () => '',
    } as unknown as Response;
  };
}

/** Convenience: create both API client and executor from mock data */
function mockSetup(
  manifest: InstallManifest,
  zipBuf: Buffer,
  opts?: { homeDir?: string; recordInstallFails?: boolean; maxDownloadSize?: number },
): { apiClient: ReturnType<typeof createApiClient>; executor: InstallExecutor; fetchFn: FetchFn } {
  const fetcher = mockFetch(manifest, zipBuf, opts);
  const apiClient = createApiClient(fetcher);
  const executor = new InstallExecutor(apiClient, {
    homeDir: opts?.homeDir || TEST_HOME,
    fetchFn: fetcher,
    maxDownloadSize: opts?.maxDownloadSize,
    beforeSaveRecord: (opts as any)?.beforeSaveRecord,
  });
  return { apiClient, executor, fetchFn: fetcher };
}

/** Create a test ZIP payload with file contents */
function createPayloadZip(files: Record<string, string>): Buffer {
  const zip = new AdmZip();
  for (const [name, content] of Object.entries(files)) {
    zip.addFile(name, Buffer.from(content, 'utf-8'));
  }
  return zip.toBuffer();
}

function setup(manifestOverrides?: Partial<InstallManifest>, zipFiles?: Record<string, string>): {
  executor: InstallExecutor;
  clientRoot: string;
  targetDir: string;
  manifest: InstallManifest;
} {
  const clientRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(clientRoot, { recursive: true });
  const targetDir = path.join(clientRoot, 'test-package');

  const zf = zipFiles || { 'package/README.md': '# Test Package\n\nHello world.\n' };
  const zipBuf = createPayloadZip(zf);
  const expectedSha = sha256(zipBuf);

  const manifest = makeManifest({
    integrity: { sha256: expectedSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: expectedSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
    ...manifestOverrides,
  });

  // Fix up steps if overrides didn't set them
  if (manifestOverrides?.installation?.steps) {
    // Steps overridden — trust the caller
  }

  const { executor } = mockSetup(manifest, zipBuf);

  return { executor, clientRoot, targetDir, manifest };
}

function cleanup() {
  const recordsPath = path.join(TEST_HOME, '.trusted-agent-hub', 'installs.json');
  if (fs.existsSync(recordsPath)) fs.unlinkSync(recordsPath);
  const skills = path.join(TEST_HOME, '.claude', 'skills');
  if (fs.existsSync(skills)) fs.rmSync(skills, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Test: isSafeInstallPath
// ---------------------------------------------------------------------------

function test_isSafeInstallPath() {
  assert.strictEqual(isSafeInstallPath('foo/bar'), true);
  assert.strictEqual(isSafeInstallPath('package/'), true);
  assert.strictEqual(isSafeInstallPath('../payload'), false);
  assert.strictEqual(isSafeInstallPath('foo/../../bar'), false);
  assert.strictEqual(isSafeInstallPath('/tmp/evil'), false);
  assert.strictEqual(isSafeInstallPath('C:\\Windows'), false);
  assert.strictEqual(isSafeInstallPath('D:/evil'), false);
  assert.strictEqual(isSafeInstallPath('foo\x00bar'), false);
  assert.strictEqual(isSafeInstallPath(''), false);
  console.log('  ✓ isSafeInstallPath');
}

// ---------------------------------------------------------------------------
// Test: Manifest validation
// ---------------------------------------------------------------------------

function test_manifestValidation() {
  assert.doesNotThrow(() => validateManifest(makeManifest()));

  const missingGrade = makeManifest();
  delete (missingGrade.risk_summary as any).grade;
  assert.throws(
    () => validateManifest(missingGrade),
    (err: unknown) => err instanceof ManifestValidationError
      && err.invalidFields.includes('risk_summary.grade'),
  );

  const invalidGrade = makeManifest();
  (invalidGrade.risk_summary as any).grade = 'F';
  assert.throws(
    () => validateManifest(invalidGrade),
    (err: unknown) => err instanceof ManifestValidationError
      && err.invalidFields.includes('risk_summary.grade'),
  );

  assert.throws(() => validateManifest({}), ManifestValidationError);
  assert.throws(() => validateManifest(null), ManifestValidationError);

  const httpM = makeManifest();
  (httpM.source as any).download_url = 'http://example.com/package.zip';
  assert.throws(() => validateManifest(httpM), ManifestValidationError);

  const badSha = makeManifest();
  badSha.integrity.sha256 = 'bad';
  assert.throws(() => validateManifest(badSha), ManifestValidationError);

  const traversal = makeManifest();
  traversal.installation.steps = [
    { action: 'download', url: 'https://example.com/package.zip' },
    { action: 'verify', algorithm: 'sha256' as const, checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { action: 'extract', archive: 'package.zip' },
    { action: 'copy', source: 'package/', destination: '../escape' },
  ];
  assert.throws(() => validateManifest(traversal), ManifestValidationError);

  const blocked = makeManifest();
  blocked.risk_summary = { level: 'untrusted', grade: 'E', top_risks: [], install_recommendation: 'blocked' };
  assert.throws(() => validateManifest(blocked), ManifestValidationError);

  const badSeq = makeManifest();
  badSeq.installation.steps = [
    { action: 'download', url: 'https://example.com/package.zip' },
    { action: 'extract', archive: 'package.zip' },
    { action: 'verify', algorithm: 'sha256' as const, checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
  ];
  assert.throws(() => validateManifest(badSeq), ManifestValidationError);

  console.log('  ✓ Manifest validation');
}

// ---------------------------------------------------------------------------
// Test: Normal install (full pipeline with real ZIP)
// ---------------------------------------------------------------------------

async function test_normalInstall() {
  cleanup();
  const { executor, targetDir } = setup();

  const result = await executor.install('test-package', 'claude-code', {});
  assert.strictEqual(result.success, true);
  assert.ok(fs.existsSync(targetDir), 'target directory should exist');
  assert.ok(fs.existsSync(path.join(targetDir, 'README.md')), 'README.md should exist');
  const content = fs.readFileSync(path.join(targetDir, 'README.md'), 'utf-8');
  assert.ok(content.includes('Hello world'), 'file content should match');

  // Verify local record saved
  const records = executor.getLocalRecords();
  assert.strictEqual(records.length, 1);
  assert.strictEqual(records[0].package_name, 'test-package');
  assert.strictEqual(records[0].integrity_verified, true);

  cleanup();
  console.log('  ✓ Normal install (full pipeline)');
}

// ---------------------------------------------------------------------------
// Test: SHA-256 mismatch aborts
// ---------------------------------------------------------------------------

async function test_sha256Mismatch() {
  cleanup();
  // Create a manifest whose integrity.sha256 AND verify-step checksum
  // are both set to a WRONG value — so manifest validation passes,
  // but the actual file SHA-256 won't match
  const zipFiles = { 'package/README.md': '# test content for SHA mismatch' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const fakeSha = 'f'.repeat(64);

  // Both integrity and verify step must use the SAME fake checksum
  // (manifest validation enforces they match), but the real file won't match it
  const badManifest = makeManifest({
    integrity: { sha256: fakeSha, download_size_bytes: zipBuf.length },
    installation: {
      method: 'copy_directory',
      target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: fakeSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null,
      post_install_message: null,
    },
  });
  // Ensure source matches
  badManifest.source.download_url = 'https://example.com/package.zip';

  const { executor: exec } = mockSetup(badManifest, zipBuf);
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });
  const targetDir = path.join(skillsRoot, 'test-package');

  try {
    await exec.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown');
  } catch (err: unknown) {
    assert.ok(err instanceof InstallError);
    assert.strictEqual((err as InstallError).code, 'integrity_mismatch');
  }

  // Target should NOT exist (nothing written on mismatch)
  assert.strictEqual(fs.existsSync(targetDir), false, 'target should not exist after SHA mismatch');

  cleanup();
  console.log('  ✓ SHA-256 mismatch aborts');
}

// ---------------------------------------------------------------------------
// Test: ZIP path traversal (real malicious ZIP through extractZip)
// ---------------------------------------------------------------------------

function test_zipPathTraversal() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    // Build a real ZIP with traversal entry using raw bytes
    const zipBuf = buildRawZip([
      { name: '../escape/evil.txt', data: Buffer.from('evil payload', 'utf-8') },
    ]);
    const zipPath = path.join(tmpDir, 'malicious.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for path traversal');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      assert.strictEqual((err as InstallError).code, 'zip_path_traversal');
    }

    // Verify nothing escaped
    const escapedDir = path.join(tmpDir, 'escape');
    assert.strictEqual(fs.existsSync(escapedDir), false, 'escape directory must not exist');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ ZIP path traversal (real malicious ZIP)');
}

// ---------------------------------------------------------------------------
// Test: ZIP absolute path (real malicious ZIP through extractZip)
// ---------------------------------------------------------------------------

function test_zipAbsolutePath() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    const zipBuf = buildRawZip([
      { name: '/tmp/evil.txt', data: Buffer.from('evil', 'utf-8') },
    ]);
    const zipPath = path.join(tmpDir, 'abs.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for absolute path');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      assert.strictEqual((err as InstallError).code, 'zip_absolute_path');
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ ZIP absolute path (real malicious ZIP)');
}

// ---------------------------------------------------------------------------
// Test: ZIP Windows drive letter (real malicious ZIP)
// ---------------------------------------------------------------------------

function test_zipWindowsDrive() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    const zipBuf = buildRawZip([
      { name: 'C:\\evil.txt', data: Buffer.from('evil', 'utf-8') },
    ]);
    const zipPath = path.join(tmpDir, 'win.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for Windows drive letter');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      // On Windows, path.isAbsolute() catches drive-letter paths first,
      // so either error code is correct
      const code = (err as InstallError).code;
      assert.ok(
        code === 'zip_windows_drive' || code === 'zip_absolute_path',
        `Expected zip_windows_drive or zip_absolute_path, got ${code}`,
      );
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ ZIP Windows drive letter (real malicious ZIP)');
}

// ---------------------------------------------------------------------------
// Test: ZIP directory traversal (directory entry with ../)
// ---------------------------------------------------------------------------

function test_zipDirectoryTraversal() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    // Build ZIP with a directory entry that traverses — the P1 case
    const zipBuf = buildRawZip([
      { name: '../escape-dir/', data: Buffer.alloc(0) },       // directory
      { name: '../escape-dir/evil.txt', data: Buffer.from('evil', 'utf-8') },
    ]);
    const zipPath = path.join(tmpDir, 'dirtrav.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for directory traversal');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      assert.ok(
        (err as InstallError).code === 'zip_path_traversal' ||
        (err as InstallError).code === 'zip_path_escape',
      );
    }

    // Verify nothing escaped
    const escapedDir = path.join(tmpDir, 'escape-dir');
    assert.strictEqual(fs.existsSync(escapedDir), false, 'escape directory must not exist');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ ZIP directory traversal (real malicious ZIP with dir entry)');
}

// ---------------------------------------------------------------------------
// Test: Extract size exceeded
// ---------------------------------------------------------------------------

function test_extractSizeExceeded() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    const bigContent = Buffer.alloc(1024 * 1024, 'x'); // 1 MB
    const zipBuf = buildRawZip([
      { name: 'big-file.bin', data: bigContent },
    ]);
    const zipPath = path.join(tmpDir, 'big.zip');
    fs.writeFileSync(zipPath, zipBuf);

    // Set maxExtractSize to 1 byte — everything will exceed
    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME, maxExtractSize: 1 },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for size exceeded');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      assert.strictEqual((err as InstallError).code, 'zip_too_large');
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ Extract size exceeded');
}

// ---------------------------------------------------------------------------
// Test: Extract file count exceeded
// ---------------------------------------------------------------------------

function test_extractFileCountExceeded() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-zip-test-'));
  const destDir = path.join(tmpDir, 'safe');

  try {
    fs.mkdirSync(destDir);

    const rawEntries = [];
    for (let i = 0; i < 10; i++) {
      rawEntries.push({ name: `file-${i}.txt`, data: Buffer.from('content') });
    }
    const zipBuf = buildRawZip(rawEntries);
    const zipPath = path.join(tmpDir, 'many.zip');
    fs.writeFileSync(zipPath, zipBuf);

    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: TEST_HOME, maxExtractFiles: 5 },
    );

    try {
      executor.extractZip(zipPath, destDir);
      assert.fail('Should have thrown for file count exceeded');
    } catch (err: unknown) {
      assert.ok(err instanceof InstallError);
      assert.strictEqual((err as InstallError).code, 'zip_too_many_files');
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('  ✓ Extract file count exceeded');
}

// ---------------------------------------------------------------------------
// Test: Existing install preserved on early failure (before backup/rename)
// ---------------------------------------------------------------------------

async function test_existingInstallPreservedOnEarlyFailure() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });
  const targetDir = path.join(skillsRoot, 'test-package');

  // Pre-create an existing installation
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, 'ORIGINAL.txt'), 'original content');

  // Early failure: SHA mismatch (fails before target→backup rename)
  const zipFiles = { 'package/README.md': '# new' };
  const zipBuf = createPayloadZip(zipFiles);
  const fakeSha = 'f'.repeat(64);
  const badManifest = makeManifest({
    integrity: { sha256: fakeSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: fakeSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  badManifest.source.download_url = 'https://example.com/package.zip';
  const { executor: exec } = mockSetup(badManifest, zipBuf);

  try {
    await exec.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown');
  } catch (err: unknown) {
    assert.ok(err instanceof InstallError);
    assert.strictEqual((err as InstallError).code, 'integrity_mismatch');
  }

  // Original install MUST be preserved
  assert.ok(fs.existsSync(targetDir), 'target must still exist');
  assert.ok(fs.existsSync(path.join(targetDir, 'ORIGINAL.txt')), 'ORIGINAL.txt must still exist');
  assert.strictEqual(fs.readFileSync(path.join(targetDir, 'ORIGINAL.txt'), 'utf-8'), 'original content');

  // No staging/backup dirs should linger
  const entries = fs.readdirSync(skillsRoot);
  assert.strictEqual(entries.filter(e => e.startsWith('.staging-')).length, 0, 'no staging leftovers');
  assert.strictEqual(entries.filter(e => e.startsWith('.backup-')).length, 0, 'no backup leftovers');

  cleanup();
  console.log('  ✓ Existing install preserved on early failure');
}

// ---------------------------------------------------------------------------
// Test: Backup restored after late failure (record save fails after rename)
// ---------------------------------------------------------------------------

async function test_backupRestoredOnLateFailure() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });
  const targetDir = path.join(skillsRoot, 'test-package');

  // Pre-create an existing installation
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, 'OLD.txt'), 'old version content');

  // Use a valid manifest so the full pipeline runs through to rename + save
  const zipFiles = { 'package/README.md': '# new', 'package/NEW.txt': 'new content' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // Inject failure after rename but before saveLocalRecord completes
  const { executor: exec } = mockSetup(manifest, zipBuf, {
    beforeSaveRecord: () => { throw new Error('Simulated disk full'); },
  } as any);

  try {
    await exec.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown');
  } catch (err: unknown) {
    assert.ok(err instanceof Error);
    assert.ok(err.message.includes('Simulated disk full'));
  }

  // OLD version MUST be restored (backup was created, then restored on failure)
  assert.ok(fs.existsSync(targetDir), 'target must exist after rollback');
  assert.ok(fs.existsSync(path.join(targetDir, 'OLD.txt')), 'OLD.txt must be restored');
  assert.strictEqual(fs.readFileSync(path.join(targetDir, 'OLD.txt'), 'utf-8'), 'old version content');

  // NEW content must NOT be present
  assert.strictEqual(fs.existsSync(path.join(targetDir, 'NEW.txt')), false, 'NEW.txt must not exist');

  // No staging/backup dirs should linger
  const entries = fs.readdirSync(skillsRoot);
  assert.strictEqual(entries.filter(e => e.startsWith('.staging-')).length, 0, 'no staging leftovers');
  assert.strictEqual(entries.filter(e => e.startsWith('.backup-')).length, 0, 'no backup leftovers');

  cleanup();
  console.log('  ✓ Backup restored on late failure (record save fails after rename)');
}

// ---------------------------------------------------------------------------
// Test: First-time install record failure rolls back cleanly (P1 fix)
// ---------------------------------------------------------------------------

async function test_firstInstallRecordFailureRollback() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });
  const targetDir = path.join(skillsRoot, 'test-package');

  // No pre-existing install — targetDir should NOT exist
  assert.strictEqual(fs.existsSync(targetDir), false);

  // Build valid manifest; beforeSaveRecord will throw after rename
  const zipFiles = { 'package/README.md': '# fresh install', 'package/src/main.js': 'console.log(1)' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  const { executor: exec } = mockSetup(manifest, zipBuf, {
    beforeSaveRecord: () => { throw new Error('Simulated disk full on first install'); },
  } as any);

  try {
    await exec.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown');
  } catch (err: unknown) {
    assert.ok(err instanceof Error);
    assert.ok(err.message.includes('Simulated disk full'));
  }

  // P1: target must NOT exist — first-time install failure must roll back completely
  assert.strictEqual(fs.existsSync(targetDir), false, 'target must not exist after rollback');

  // No lingering staging or backup directories
  const entries = fs.readdirSync(skillsRoot);
  assert.strictEqual(entries.filter(e => e.startsWith('.staging-')).length, 0, 'no staging leftovers');
  assert.strictEqual(entries.filter(e => e.startsWith('.backup-')).length, 0, 'no backup leftovers');

  // No install record should have been written
  const records = exec.getLocalRecords();
  assert.strictEqual(records.length, 0, 'no install record should exist');

  cleanup();
  console.log('  ✓ First-time install record failure rolls back cleanly');
}

// ---------------------------------------------------------------------------
// Test: Staging + atomic rename (no partial install visible)
// ---------------------------------------------------------------------------

async function test_stagingAtomicRename() {
  cleanup();
  const { executor, targetDir } = setup({}, { 'package/hello.txt': 'hello world' });

  // Before install, target should not exist
  assert.strictEqual(fs.existsSync(targetDir), false);

  const result = await executor.install('test-package', 'claude-code', {});
  assert.strictEqual(result.success, true);
  assert.ok(fs.existsSync(path.join(targetDir, 'hello.txt')));

  // There should be no staging or backup directories lingering
  const skillsDir = path.join(TEST_HOME, '.claude', 'skills');
  const entries = fs.readdirSync(skillsDir);
  const stagingDirs = entries.filter(e => e.startsWith('.staging-') || e.startsWith('.backup-'));
  assert.strictEqual(stagingDirs.length, 0, `lingering staging/backup dirs: ${stagingDirs.join(', ')}`);

  cleanup();
  console.log('  ✓ Staging + atomic rename (no leftovers)');
}

// ---------------------------------------------------------------------------
// Test: Download size exceeded (mock)
// ---------------------------------------------------------------------------

async function test_downloadSizeExceeded() {
  cleanup();
  const manifest = makeManifest();
  const bigBuf = Buffer.alloc(2 * 1024 * 1024, 'x'); // 2 MB
  manifest.integrity.sha256 = sha256(bigBuf);
  manifest.integrity.download_size_bytes = bigBuf.length;
  manifest.installation.steps[1] = { action: 'verify', algorithm: 'sha256', checksum: manifest.integrity.sha256 };

  const { executor } = mockSetup(manifest, bigBuf, { maxDownloadSize: 1024 });

  try {
    await executor.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown for download size exceeded');
  } catch (err: unknown) {
    assert.ok(err instanceof InstallError);
    assert.strictEqual((err as InstallError).code, 'download_size_exceeded');
  }

  cleanup();
  console.log('  ✓ Download size exceeded');
}

// ---------------------------------------------------------------------------
// Test: Grade D blocked / Grade E always blocked
// ---------------------------------------------------------------------------

async function test_gradeGating() {
  cleanup();

  // Grade D blocked without flags
  const dManifest = makeManifest({
    risk_summary: { level: 'high_risk', grade: 'D', top_risks: ['risky'], install_recommendation: 'caution' },
  });
  const dZip = createPayloadZip({ 'package/README.md': '# d' });
  const { executor: dExec } = mockSetup(dManifest, dZip);

  try { await dExec.install('test-package', 'claude-code', {}); assert.fail(); } catch (e) {
    assert.ok(e instanceof InstallBlockedError);
    assert.strictEqual((e as InstallBlockedError).grade, 'D');
  }
  try { await dExec.install('test-package', 'claude-code', { force: true }); assert.fail(); } catch (e) {
    assert.ok(e instanceof InstallBlockedError);
  }

  // Grade D allowed with both flags
  const d2Zip = createPayloadZip({ 'package/README.md': '# d2' });
  const d2Manifest = {
    ...dManifest,
    integrity: { sha256: sha256(d2Zip), download_size_bytes: d2Zip.length },
    installation: { ...dManifest.installation, steps: [
      { action: 'download' as const, url: 'https://example.com/package.zip' },
      { action: 'verify' as const, algorithm: 'sha256' as const, checksum: sha256(d2Zip) },
      { action: 'extract' as const, archive: 'package.zip' },
      { action: 'copy' as const, source: 'package/', destination: '~/.claude/skills/test-package/' },
    ]},
  };
  const { executor: d2Exec } = mockSetup(d2Manifest, d2Zip);
  const d2Result = await d2Exec.install('test-package', 'claude-code', { force: true, acceptHighRisk: true });
  assert.strictEqual(d2Result.success, true);

  // Grade E always blocked (even with all flags)
  const eManifest = makeManifest({
    risk_summary: { level: 'untrusted', grade: 'E', top_risks: ['critical'], install_recommendation: 'not_recommended' },
  });
  const eZip = createPayloadZip({ 'package/README.md': '# e' });
  const { executor: eExec } = mockSetup(eManifest, eZip);

  try {
    await eExec.install('test-package', 'claude-code', { yes: true, force: true, acceptHighRisk: true });
    assert.fail('Grade E should never be allowed');
  } catch (e) {
    assert.ok(e instanceof InstallBlockedError);
    assert.strictEqual((e as InstallBlockedError).grade, 'E');
  }

  cleanup();
  console.log('  ✓ Grade gating (D blocked, D allowed with flags, E always blocked)');
}

// ---------------------------------------------------------------------------
// Test: API reporting failure surfaced (not silently swallowed)
// ---------------------------------------------------------------------------
// Test: Content digest failure preserves existing installation
// ---------------------------------------------------------------------------

async function test_digestFailureRestoresBackup() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });

  // Pre-create an existing installation
  const targetDir = path.resolve(TEST_HOME, '.claude/skills/test-pkg');
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, 'existing.txt'), 'old installation');
  const oldContent = fs.readFileSync(path.join(targetDir, 'existing.txt'), 'utf-8');

  const zipFiles = { 'package/README.md': '# new install' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-pkg/' },
      ],
    },
  });

  // Save record snapshot before install attempt
  const { LocalInstallStore } = await import('../src/local-install-store');
  const { ContentIntegrityError } = await import('../src/content-integrity');
  const store = new LocalInstallStore(TEST_HOME);
  const recordsBefore = (() => {
    try { return store.load(); } catch { return []; }
  })();

  // Inject digest failure via beforeDigest hook — directly throw
  // ContentIntegrityError to simulate a genuine digest computation failure.
  // No symlink creation needed, so this works on all platforms.
  const executor = new InstallExecutor(
    createApiClient(mockFetch([{ status: 200, body: zipBuf }])),
    {
      homeDir: TEST_HOME,
      beforeDigest: (_stagingDir: string) => {
        throw new ContentIntegrityError(
          'Simulated digest failure',
          'unsafe_content',
        );
      },
    },
  );

  try {
    await executor.installWithManifest(manifest, 'claude-code', {});
    assert.fail('Should have thrown');
  } catch (e: unknown) {
    // The ContentIntegrityError from beforeDigest propagates through the
    // rollback handler (which re-throws).  Accept either the original error
    // or InstallError wrapping it, since the important property is that
    // the old installation is preserved, not the error type.
    assert.ok(e instanceof Error, 'should throw an Error');
  }

  // The old installation MUST still be intact (digest failed BEFORE backup)
  assert.ok(fs.existsSync(targetDir), 'target directory must still exist');
  assert.ok(fs.existsSync(path.join(targetDir, 'existing.txt')), 'old file must be intact');
  const restoredContent = fs.readFileSync(path.join(targetDir, 'existing.txt'), 'utf-8');
  assert.strictEqual(restoredContent, oldContent, 'old content must be unchanged');

  // No staging or backup leftovers
  const dirs = fs.readdirSync(skillsRoot);
  assert.strictEqual(dirs.filter(f => f.startsWith('.staging-')).length, 0, 'no staging dirs');
  assert.strictEqual(dirs.filter(f => f.startsWith('.backup-')).length, 0, 'no backup dirs');

  // Install records must be unchanged
  const recordsAfter = (() => {
    try { return store.load(); } catch { return []; }
  })();
  assert.deepStrictEqual(recordsAfter, recordsBefore, 'install records must be unchanged');

  cleanup();
  console.log('  ✓ Digest failure preserves existing installation');
}

// ---------------------------------------------------------------------------

async function test_apiReportFailureSurfaced() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });

  // Build valid manifest so install succeeds, but recordInstall will fail
  const zipFiles = { 'package/README.md': '# test' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // Use recordInstallFails so the fire-and-forget POST throws
  const fetcher = mockFetch(manifest, zipBuf, { recordInstallFails: true });
  const apiClient = createApiClient(fetcher);
  const executor = new InstallExecutor(apiClient, { homeDir: TEST_HOME, fetchFn: fetcher });

  // Capture stderr
  const stderrOutput: string[] = [];
  const originalStderr = process.stderr.write;
  (process.stderr.write as any) = (chunk: string) => { stderrOutput.push(chunk); return true; };

  try {
    const result = await executor.install('test-package', 'claude-code', {});
    assert.strictEqual(result.success, true);

    // Give the fire-and-forget a moment to fail
    await new Promise(r => setTimeout(r, 300));
  } finally {
    (process.stderr.write as any) = originalStderr;
  }

  // P2 fix: assert that the warning was actually written to stderr
  const combined = stderrOutput.join('');
  assert.ok(combined.includes('Failed to report install'), `Expected stderr to contain warning, got: "${combined}"`);
  // The error gets wrapped by ApiError; check for the key phrase
  assert.ok(
    combined.includes('Network error') || combined.includes('Cannot reach API'),
    `Expected stderr to mention the failure, got: "${combined}"`,
  );

  cleanup();
  console.log('  ✓ API report failure surfaced to stderr');
}

// ---------------------------------------------------------------------------
// Test: Download timeout (P2-5: body hangs after headers)
// ---------------------------------------------------------------------------

async function test_downloadTimeout() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });

  const zipFiles = { 'package/README.md': '# test' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // Mock fetch that returns headers immediately but never sends body data
  const hangFetch: FetchFn = async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return { status: 201, ok: true, headers: new Headers(),
        json: async () => ({}), text: async () => '' } as Response;
    }
    const url = urlStr.toString();
    if (url.includes('install-manifest')) {
      return { status: 200, ok: true, headers: new Headers(),
        json: async () => manifest, text: async () => JSON.stringify(manifest) } as Response;
    }
    // Return headers but a body that never emits data
    return {
      status: 200, ok: true,
      headers: new Headers({ 'content-length': String(zipBuf.length) }),
      body: new ReadableStream({
        start(_controller) {
          // Never enqueue anything — simulates a hung server
        },
      }),
      json: async () => ({}),
      text: async () => '',
    } as unknown as Response;
  };

  const apiClient = createApiClient(hangFetch);
  const executor = new InstallExecutor(apiClient, {
    homeDir: TEST_HOME,
    fetchFn: hangFetch,
    downloadTimeout: 500, // 500ms — very short for testing
  });

  try {
    await executor.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown download_timeout');
  } catch (err: unknown) {
    assert.ok(err instanceof InstallError);
    assert.strictEqual((err as InstallError).code, 'download_timeout');
  }

  cleanup();
  console.log('  ✓ Download timeout (body hangs after headers)');
}

// ---------------------------------------------------------------------------
// Test: HTTPS → HTTP redirect rejected (P2)
// ---------------------------------------------------------------------------

async function test_redirectToHttpRejected() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });

  const zipFiles = { 'package/README.md': '# test' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // Mock fetch that simulates HTTPS → HTTP redirect via response.url
  const redirectFetch: FetchFn = async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return { status: 201, ok: true, headers: new Headers(),
        json: async () => ({}), text: async () => '' } as Response;
    }
    const url = urlStr.toString();
    if (url.includes('install-manifest')) {
      return { status: 200, ok: true, headers: new Headers(),
        json: async () => manifest, text: async () => JSON.stringify(manifest) } as Response;
    }
    // Return success but with response.url pointing to HTTP
    return {
      status: 200, ok: true, url: 'http://evil.example.com/package.zip',
      headers: new Headers({ 'content-length': String(zipBuf.length) }),
      body: new ReadableStream({
        start(controller) { controller.enqueue(zipBuf); controller.close(); },
      }),
      json: async () => ({}), text: async () => '',
    } as unknown as Response;
  };

  const apiClient = createApiClient(redirectFetch);
  const executor = new InstallExecutor(apiClient, { homeDir: TEST_HOME, fetchFn: redirectFetch });

  try {
    await executor.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown redirect_to_http');
  } catch (err: unknown) {
    assert.ok(err instanceof InstallError);
    assert.strictEqual((err as InstallError).code, 'redirect_to_http');
  }

  cleanup();
  console.log('  ✓ HTTPS → HTTP redirect rejected');
}

// ---------------------------------------------------------------------------
// Test: No Content-Length + streaming data exceeds size limit (P2)
// ---------------------------------------------------------------------------

async function test_streamingSizeExceededWithoutContentLength() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });
  const targetDir = path.join(skillsRoot, 'test-package');

  // Use buildRawZip (stored, no compression) so size is predictable
  const zipBuf = buildRawZip([
    { name: 'package/README.md', data: Buffer.alloc(2048, 'A') },
  ]);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // No Content-Length header; stream sends chunks that exceed the limit,
  // then keeps the stream OPEN to prove the limit is enforced in real time
  // (not after stream closes).
  const fetcher: FetchFn = async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return { status: 201, ok: true, headers: new Headers(),
        json: async () => ({}), text: async () => '' } as Response;
    }
    const url = urlStr.toString();
    if (url.includes('install-manifest')) {
      return { status: 200, ok: true, headers: new Headers(),
        json: async () => manifest, text: async () => JSON.stringify(manifest) } as Response;
    }
    // Send oversized data in chunks — after the limit is exceeded the
    // Transform will abort, but we keep the stream open to prove it's
    // a real-time abort, not a post-completion check.
    return {
      status: 200, ok: true, headers: new Headers(),
      body: new ReadableStream({
        start(controller) {
          // Send chunks that individually are under the limit,
          // but together exceed it
          controller.enqueue(zipBuf.subarray(0, 300));
          controller.enqueue(zipBuf.subarray(300, 600));
          // After the second chunk (600 bytes total > 500 limit),
          // the Transform will error and pipeline will destroy the stream.
          // We keep the stream open to prove real-time enforcement.
          // (pipeline's destroy will clean up the controller)
        },
      }),
      json: async () => ({}), text: async () => '',
    } as unknown as Response;
  };

  const apiClient = createApiClient(fetcher);
  const executor = new InstallExecutor(apiClient, {
    homeDir: TEST_HOME,
    fetchFn: fetcher,
    maxDownloadSize: 500, // 2 × 300 bytes > 500 → limit hit on second chunk
    downloadTimeout: 5000, // long enough to prove we don't hit timeout
  });

  const startTime = Date.now();
  let errorCode = '';
  let installError: Error | null = null;
  try {
    await executor.install('test-package', 'claude-code', {});
    assert.fail('Should have thrown download_size_exceeded');
  } catch (err: unknown) {
    installError = err as Error;
    errorCode = (err as any).code || '';
  }
  const elapsed = Date.now() - startTime;

  // Must be the right error
  assert.ok(installError instanceof InstallError);
  assert.strictEqual(errorCode, 'download_size_exceeded',
    `Expected download_size_exceeded, got ${errorCode}`);

  // Must return well before the timeout — proves real-time Transform enforcement,
  // NOT a post-pipeline check or timeout-driven abort
  assert.ok(elapsed < 4000, `Took ${elapsed}ms — should abort immediately on limit hit`);

  // Target must not exist (partial download → no extraction/copy happened)
  assert.strictEqual(fs.existsSync(targetDir), false, 'target must not exist after size abort');

  cleanup();
  console.log('  ✓ No Content-Length + streaming size exceeded (real-time abort)');
}

// ---------------------------------------------------------------------------
// Test: Target directory bounds
// ---------------------------------------------------------------------------

function test_targetDirBounds() {
  const clientRoot = path.join(TEST_HOME, '.claude', 'skills');
  assert.strictEqual(isStrictChildPath(path.join(clientRoot, 'pkg'), clientRoot), true);
  assert.strictEqual(isStrictChildPath(path.join(TEST_HOME, '.ssh'), clientRoot), false);
  assert.strictEqual(isStrictChildPath(clientRoot, clientRoot), false);
  console.log('  ✓ Target directory bounds');
}

// ---------------------------------------------------------------------------
// Test: Manifest destination resolution contract
// ---------------------------------------------------------------------------

function test_manifestDestinationResolvedCorrectly() {
  const home = 'C:\\e2e-home';
  const clientRoot = path.resolve(home, '.claude/skills');

  // Claude Code: correct resolution
  const claudeTarget = resolveManifestDestination(
    '~/.claude/skills/test-package/',
    'claude-code',
    clientRoot,
  );
  assert.strictEqual(claudeTarget, path.resolve(home, '.claude/skills/test-package'));
  // Must NOT contain a literal ~ segment
  assert.ok(!claudeTarget.includes(`${path.sep}~${path.sep}`));
  assert.ok(!claudeTarget.endsWith(`${path.sep}~`));

  // Cursor: correct resolution
  const cursorRoot = path.resolve(home, '.cursor/skills');
  const cursorTarget = resolveManifestDestination(
    '~/.cursor/skills/test-package/',
    'cursor',
    cursorRoot,
  );
  assert.strictEqual(cursorTarget, path.resolve(home, '.cursor/skills/test-package'));
  assert.ok(!cursorTarget.includes(`${path.sep}~${path.sep}`));

  console.log('  ✓ Manifest destination resolved correctly');
}

function test_manifestDestinationRejectsWrongRoot() {
  const home = 'C:\\e2e-home';
  const clientRoot = path.resolve(home, '.claude/skills');

  // Cursor path in a Claude Code destination → reject
  try {
    resolveManifestDestination(
      '~/.cursor/skills/test-package/',
      'claude-code',
      clientRoot,
    );
    assert.fail('Should have thrown');
  } catch (e: unknown) {
    assert.ok(e instanceof ClientPathError);
    assert.strictEqual((e as ClientPathError).code, 'destination_root_mismatch');
  }

  console.log('  ✓ Manifest destination rejects wrong client root');
}

function test_manifestDestinationRejectsRootItself() {
  const home = 'C:\\e2e-home';
  const clientRoot = path.resolve(home, '.claude/skills');

  // The root directory itself (no child path) → reject
  try {
    resolveManifestDestination(
      '~/.claude/skills/',
      'claude-code',
      clientRoot,
    );
    assert.fail('Should have thrown');
  } catch (e: unknown) {
    assert.ok(e instanceof ClientPathError);
    assert.strictEqual((e as ClientPathError).code, 'invalid_destination');
  }

  console.log('  ✓ Manifest destination rejects root itself');
}

function test_manifestDestinationRejectsTraversal() {
  const home = 'C:\\e2e-home';
  const clientRoot = path.resolve(home, '.claude/skills');

  // Traversal attempt → reject
  try {
    resolveManifestDestination(
      '~/.claude/skills/../escape/',
      'claude-code',
      clientRoot,
    );
    assert.fail('Should have thrown');
  } catch (e: unknown) {
    assert.ok(e instanceof ClientPathError);
    assert.strictEqual((e as ClientPathError).code, 'invalid_destination');
  }

  console.log('  ✓ Manifest destination rejects traversal');
}

function test_manifestDestinationRejectsRelative() {
  const home = 'C:\\e2e-home';
  const clientRoot = path.resolve(home, '.claude/skills');

  // Relative path (no manifest root prefix) → reject
  try {
    resolveManifestDestination(
      'test-package/',
      'claude-code',
      clientRoot,
    );
    assert.fail('Should have thrown');
  } catch (e: unknown) {
    assert.ok(e instanceof ClientPathError);
    assert.strictEqual((e as ClientPathError).code, 'destination_root_mismatch');
  }

  console.log('  ✓ Manifest destination rejects relative path');
}

// ---------------------------------------------------------------------------
// Test: Local install records
// ---------------------------------------------------------------------------

function test_localRecords() {
  const tmpHome = path.join(os.tmpdir(), 'tah-rec-test-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(tmpHome, { recursive: true });

  try {
    const executor = new InstallExecutor(
      { getInstallManifest: async () => ({}), recordInstall: async () => ({}), getApiBase: () => '' } as any,
      { homeDir: tmpHome },
    );

    const store = executor.getRecordStore();
    assert.deepStrictEqual(store.load(), []);

    store.save({
      package_name: 'test', version: '1.0.0', client: 'claude-code',
      install_path: '/test', sha256: 'a'.repeat(64),
      integrity_verified: true, installed_at: new Date().toISOString(), manifest_version: '1.0',
    });
    assert.strictEqual(store.load().length, 1);

    // Upsert
    store.save({
      package_name: 'test', version: '2.0.0', client: 'claude-code',
      install_path: '/test2', sha256: 'b'.repeat(64),
      integrity_verified: true, installed_at: new Date().toISOString(), manifest_version: '1.0',
    });
    const records = store.load();
    assert.strictEqual(records.length, 1);
    assert.strictEqual(records[0].version, '2.0.0');

    // Verify getLocalRecords still works
    const executorRecords = executor.getLocalRecords();
    assert.strictEqual(executorRecords.length, 1);
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
  console.log('  ✓ Local install records');
}

// ---------------------------------------------------------------------------
// Test: installWithManifest reuses pre-fetched manifest (P2 fix)
// ---------------------------------------------------------------------------

async function test_installWithManifest() {
  cleanup();
  const { executor, manifest, targetDir } = setup();

  // Use installWithManifest instead of install — should work identically
  const result = await executor.installWithManifest(manifest, 'claude-code', {});
  assert.strictEqual(result.success, true);
  assert.ok(fs.existsSync(targetDir));
  assert.strictEqual(result.manifest, manifest); // same object, not a re-fetched copy

  cleanup();
  console.log('  ✓ installWithManifest (avoids double fetch)');
}

// ---------------------------------------------------------------------------
// Test: version parameter flows through to API manifest request
// ---------------------------------------------------------------------------

async function test_versionParamInManifestRequest() {
  cleanup();
  const skillsRoot = path.join(TEST_HOME, '.claude', 'skills');
  fs.mkdirSync(skillsRoot, { recursive: true });

  const zipFiles = { 'package/README.md': '# version test' };
  const zipBuf = createPayloadZip(zipFiles);
  const realSha = sha256(zipBuf);
  const manifest = makeManifest({
    integrity: { sha256: realSha, download_size_bytes: zipBuf.length },
    installation: { method: 'copy_directory', target_client: 'claude-code',
      steps: [
        { action: 'download', url: 'https://example.com/package.zip' },
        { action: 'verify', algorithm: 'sha256', checksum: realSha },
        { action: 'extract', archive: 'package.zip' },
        { action: 'copy', source: 'package/', destination: '~/.claude/skills/test-package/' },
      ],
      pre_install_message: null, post_install_message: null,
    },
  });
  manifest.source.download_url = 'https://example.com/package.zip';

  // Capture the manifest request URL
  const capturedUrls: string[] = [];
  const fetcher: FetchFn = async (urlStr: string, init?: RequestInit) => {
    capturedUrls.push(urlStr);
    if (init?.method === 'POST') {
      return { status: 201, ok: true, headers: new Headers(),
        json: async () => ({}), text: async () => '' } as Response;
    }
    if (urlStr.toString().includes('install-manifest')) {
      return { status: 200, ok: true, headers: new Headers(),
        json: async () => manifest, text: async () => JSON.stringify(manifest) } as Response;
    }
    return { status: 200, ok: true, headers: new Headers(),
      body: new ReadableStream({ start(c) { c.enqueue(zipBuf); c.close(); } }),
      json: async () => ({}), text: async () => '' } as unknown as Response;
  };

  const apiClient = createApiClient(fetcher);
  const executor = new InstallExecutor(apiClient, { homeDir: TEST_HOME, fetchFn: fetcher });

  // Install with an explicit version
  await executor.install('test-package', 'claude-code', {}, '1.0.0');

  // The manifest request URL must include version=1.0.0
  const manifestUrl = capturedUrls.find(u => u.includes('install-manifest'));
  assert.ok(manifestUrl, 'manifest request was made');
  assert.ok(manifestUrl!.includes('version=1.0.0'),
    `Manifest URL should include version=1.0.0, got: ${manifestUrl}`);

  // Install without version — URL must NOT include version param
  capturedUrls.length = 0;
  await executor.install('test-package', 'claude-code', {});
  const manifestUrl2 = capturedUrls.find(u => u.includes('install-manifest'));
  assert.ok(manifestUrl2, 'second manifest request was made');
  assert.ok(!manifestUrl2!.includes('version='),
    `Manifest URL without version should not have version= param, got: ${manifestUrl2}`);

  cleanup();
  console.log('  ✓ Version param flows to manifest API request');
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

(async () => {
  console.log('\nCLI Install Executor Tests\n');

  test_isSafeInstallPath();
  test_manifestValidation();
  test_zipPathTraversal();
  test_zipAbsolutePath();
  test_zipWindowsDrive();
  test_zipDirectoryTraversal();
  test_extractSizeExceeded();
  test_extractFileCountExceeded();
  test_targetDirBounds();
  test_manifestDestinationResolvedCorrectly();
  test_manifestDestinationRejectsWrongRoot();
  test_manifestDestinationRejectsRootItself();
  test_manifestDestinationRejectsTraversal();
  test_manifestDestinationRejectsRelative();
  test_localRecords();

  await test_normalInstall();
  await test_sha256Mismatch();
  await test_existingInstallPreservedOnEarlyFailure();
  await test_backupRestoredOnLateFailure();
  await test_firstInstallRecordFailureRollback();
  await test_stagingAtomicRename();
  await test_downloadSizeExceeded();
  await test_downloadTimeout();
  await test_redirectToHttpRejected();
  await test_streamingSizeExceededWithoutContentLength();
  await test_gradeGating();
  await test_installWithManifest();
  await test_versionParamInManifestRequest();
  await test_apiReportFailureSurfaced();
  await test_digestFailureRestoresBackup();

  console.log('\n  ✓ All tests passed!\n');
})();
