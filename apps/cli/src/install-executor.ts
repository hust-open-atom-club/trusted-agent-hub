/**
 * TrustedAgentHub Install Executor — secure, verifiable package installation.
 *
 * Implements the Install Manifest v1.0 pipeline:
 *   download → verify (SHA-256) → extract → copy
 *
 * Safety guarantees:
 *   - Grade gate checked BEFORE any download/write
 *   - HTTPS-only downloads (with explicit localhost exception for dev)
 *   - SHA-256 integrity verification; mismatch → abort
 *   - Path traversal prevention during extraction (ALL entries, including dirs)
 *   - Absolute path / Windows drive letter / symlink rejection
 *   - Extraction size and file count limits
 *   - Staging directory with atomic rename; backup/restore on failure
 *   - Download timeout covers full response body + file write
 *   - No shell command execution from manifest
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Readable, Transform } from 'stream';
import { pipeline } from 'stream';
import { promisify } from 'util';
import AdmZip from 'adm-zip';

import { validateManifest, ManifestValidationError } from './manifest-types';
import type { InstallManifest, DownloadStep, CopyStep } from './manifest-types';
import { checkInstall, resolveGrade } from './grade-gate';
import {
  CLIENT_INSTALL_ROOTS,
  isStrictChildPath,
  resolveManifestDestination,
  getClientRoot,
} from './client-paths';
import { computeDirectoryDigest } from './content-integrity';
import { LocalInstallStore } from './local-install-store';
import type { LocalInstallRecord } from './local-install-store';

const streamPipeline = promisify(pipeline);

// ---------------------------------------------------------------------------
// Safety limits
// ---------------------------------------------------------------------------

const DEFAULT_MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024;   // 100 MB
const DEFAULT_MAX_EXTRACT_SIZE = 500 * 1024 * 1024;     // 500 MB
const DEFAULT_MAX_EXTRACT_FILES = 10_000;
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000;             // 120 seconds
const LOCALHOST_ORIGINS = new Set(['localhost', '127.0.0.1', '[::1]']);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class InstallBlockedError extends Error {
  constructor(
    message: string,
    public grade: string,
  ) {
    super(message);
    this.name = 'InstallBlockedError';
  }
}

export class InstallError extends Error {
  constructor(
    message: string,
    public code: string,
    public cause?: unknown,
  ) {
    super(message);
    this.name = 'InstallError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type { LocalInstallRecord } from './local-install-store';

export interface InstallResult {
  success: true;
  manifest: InstallManifest;
  targetDir: string;
  sha256: string;
  record: LocalInstallRecord;
}

export interface InstallOptions {
  /** Override the home directory (for testing) */
  homeDir?: string;
  /** Maximum download size in bytes */
  maxDownloadSize?: number;
  /** Maximum total extracted size in bytes */
  maxExtractSize?: number;
  /** Maximum number of extracted files */
  maxExtractFiles?: number;
  /** Download timeout in milliseconds */
  downloadTimeout?: number;
  /** Custom fetch implementation (for testing) */
  fetchFn?: typeof fetch;
  /** Test hook: called before saving local record; can throw to simulate failure */
  beforeSaveRecord?: () => void;
  /** Test hook: called after copy to staging but before content digest; can throw or
   *  corrupt the staging directory to simulate digest failure */
  beforeDigest?: (stagingDir: string) => void;
}

// ---------------------------------------------------------------------------
// ZIP entry validation result — single pass, all entries
// ---------------------------------------------------------------------------

interface ValidatedZipEntry {
  entryName: string;
  isDirectory: boolean;
  getData: () => Buffer;
  uncompressedSize: number;
}

// ---------------------------------------------------------------------------
// Install Executor
// ---------------------------------------------------------------------------

export class InstallExecutor {
  private readonly homeDir: string;
  private readonly maxDownloadSize: number;
  private readonly maxExtractSize: number;
  private readonly maxExtractFiles: number;
  private readonly downloadTimeout: number;
  private readonly downloadFetch: typeof fetch;
  private readonly beforeSaveRecord?: () => void;
  private readonly beforeDigest?: (stagingDir: string) => void;
  private readonly recordStore: LocalInstallStore;

  constructor(
    private apiClient: ReturnType<typeof import('./api-client').createApiClient>,
    options: InstallOptions = {},
  ) {
    this.homeDir = options.homeDir || os.homedir();
    this.maxDownloadSize = options.maxDownloadSize || DEFAULT_MAX_DOWNLOAD_SIZE;
    this.maxExtractSize = options.maxExtractSize || DEFAULT_MAX_EXTRACT_SIZE;
    this.maxExtractFiles = options.maxExtractFiles || DEFAULT_MAX_EXTRACT_FILES;
    this.downloadTimeout = options.downloadTimeout || DEFAULT_DOWNLOAD_TIMEOUT_MS;
    this.downloadFetch = options.fetchFn || fetch;
    this.beforeSaveRecord = options.beforeSaveRecord;
    this.beforeDigest = options.beforeDigest;
    this.recordStore = new LocalInstallStore(this.homeDir);
  }

  // -----------------------------------------------------------------------
  // Public: install (fetches manifest, then delegates to installWithManifest)
  // -----------------------------------------------------------------------

  async install(
    packageName: string,
    clientType: string,
    gradeFlags: { yes?: boolean; force?: boolean; acceptHighRisk?: boolean },
    version?: string,
  ): Promise<InstallResult> {
    // Resolve client root
    const clientRootRel = CLIENT_INSTALL_ROOTS[clientType];
    if (!clientRootRel) {
      throw new InstallError(
        `Unsupported client: "${clientType}". Supported clients: ${Object.keys(CLIENT_INSTALL_ROOTS).join(', ')}`,
        'unsupported_client',
      );
    }

    // Fetch manifest
    let rawManifest: unknown;
    try {
      rawManifest = await this.apiClient.getInstallManifest(packageName, clientType, version);
    } catch (err: unknown) {
      throw new InstallError(
        `Failed to fetch install manifest: ${err instanceof Error ? err.message : String(err)}`,
        'manifest_fetch_failed',
        err,
      );
    }

    // Validate manifest structure
    let manifest: InstallManifest;
    try {
      manifest = validateManifest(rawManifest);
    } catch (err: unknown) {
      if (err instanceof ManifestValidationError) {
        throw new InstallError(
          `Invalid install manifest: ${err.message} (fields: ${err.invalidFields.join(', ')})`,
          'manifest_validation_failed',
          err,
        );
      }
      throw err;
    }

    return this.installWithManifest(manifest, clientType, gradeFlags);
  }

  // -----------------------------------------------------------------------
  // Public: install with pre-fetched & validated manifest (avoids double fetch)
  // -----------------------------------------------------------------------

  async installWithManifest(
    manifest: InstallManifest,
    clientType: string,
    gradeFlags: { yes?: boolean; force?: boolean; acceptHighRisk?: boolean },
  ): Promise<InstallResult> {
    // Resolve client root
    const clientRootRel = CLIENT_INSTALL_ROOTS[clientType];
    if (!clientRootRel) {
      throw new InstallError(
        `Unsupported client: "${clientType}". Supported clients: ${Object.keys(CLIENT_INSTALL_ROOTS).join(', ')}`,
        'unsupported_client',
      );
    }

    // P2 fix: verify manifest target_client matches the requested client
    if (manifest.installation.target_client !== clientType) {
      throw new InstallError(
        `Manifest target_client "${manifest.installation.target_client}" does not match requested client "${clientType}"`,
        'client_mismatch',
      );
    }

    // Grade gate check — MUST happen before any download or file write
    const grade = manifest.risk_summary.grade || resolveGrade({
      grade: manifest.risk_summary.grade,
      riskLevel: manifest.risk_summary.level,
    }) || 'unknown';

    const gateResult = checkInstall({ grade }, gradeFlags);
    if (!gateResult.allowed) {
      throw new InstallBlockedError(
        gateResult.reason || `Installation blocked by safety policy (Grade ${grade})`,
        grade,
      );
    }

    // Resolve target directory from the manifest's logical destination.
    // The server sends paths like `~/.claude/skills/<package>/` — we strip
    // the logical root prefix and join the remainder to the real HOME-based
    // client root.  The copy step is required for `copy_directory` manifests.
    const clientRoot = path.resolve(this.homeDir, clientRootRel);
    const copyStep = manifest.installation.steps.find(
      (s): s is CopyStep => s.action === 'copy',
    );
    if (!copyStep) {
      throw new InstallError(
        'Install manifest is missing the copy step',
        'missing_copy_step',
      );
    }

    const targetDir = resolveManifestDestination(
      copyStep.destination,
      clientType,
      clientRoot,
    );

    // Ensure client root exists
    fs.mkdirSync(clientRoot, { recursive: true });

    // Create temp workspace for download and extraction
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-install-'));
    // Staging directory — within clientRoot, not tmpdir
    const stagingDir = path.join(clientRoot, `.staging-${manifest.name}-${Date.now()}`);
    // Backup directory for existing installation
    const backupDir = path.join(clientRoot, `.backup-${manifest.name}-${Date.now()}`);

    let archivePath: string | null = null;
    let stagingPopulated = false;
    let backupCreated = false;
    let targetActivated = false; // P1: track whether staging→target rename succeeded

    try {
      // 1. Download
      const dlStep = manifest.installation.steps.find(
        (s): s is DownloadStep => s.action === 'download',
      );
      if (!dlStep) {
        throw new InstallError('No download step in manifest', 'missing_download_step');
      }
      archivePath = path.join(tempDir, 'package.zip');
      await this.downloadFile(dlStep.url, archivePath, manifest.integrity.download_size_bytes);

      // 2. Verify SHA-256
      const actualSha256 = await this.computeSha256(archivePath);
      const expectedSha256 = manifest.integrity.sha256;
      if (actualSha256 !== expectedSha256) {
        throw new InstallError(
          `SHA-256 mismatch.\n  Expected: ${expectedSha256}\n  Actual:   ${actualSha256}`,
          'integrity_mismatch',
        );
      }

      // 3. Extract to temp extract dir
      const extractDir = path.join(tempDir, 'extracted');
      fs.mkdirSync(extractDir);
      this.extractZip(archivePath, extractDir);

      // 4. Determine source directory within extracted content
      const sourceDir = copyStep
        ? path.resolve(extractDir, copyStep.source)
        : extractDir;
      if (!fs.existsSync(sourceDir)) {
        throw new InstallError(
          `Source directory does not exist after extraction: "${copyStep?.source || '(root)'}"`,
          'source_missing',
        );
      }

      // 5. Copy to staging directory (within clientRoot)
      this.copyDirSync(sourceDir, stagingDir, clientRoot);
      stagingPopulated = true;

      // 6. Test hook — can corrupt staging to simulate digest failure
      if (this.beforeDigest) this.beforeDigest(stagingDir);

      // 7. Compute content digest of staging directory BEFORE touching the
      //    live target.  If this fails the old target is still intact —
      //    no backup has been made yet.
      const contentDigest = await computeDirectoryDigest(stagingDir);

      // 8. Backup existing target if present (digest succeeded — staging is valid)
      if (fs.existsSync(targetDir)) {
        fs.renameSync(targetDir, backupDir);
        backupCreated = true;
      }

      // 9. Atomically rename staging → target
      fs.renameSync(stagingDir, targetDir);
      stagingPopulated = false; // staging is now the live target
      targetActivated = true;   // target now holds the new content

      // 10. Save local install record — MUST succeed before deleting backup.
      //    If this fails, we restore the backup and remove the new target.
      const record: LocalInstallRecord = {
        package_name: manifest.name,
        version: manifest.version,
        client: clientType,
        install_path: targetDir,
        sha256: actualSha256,
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: manifest.manifest_version,
        content_hash_algorithm: contentDigest.algorithm,
        content_sha256: contentDigest.digest,
      };
      // Allow test hooks to inject failure at this exact point
      if (this.beforeSaveRecord) this.beforeSaveRecord();
      this.recordStore.save(record);

      // 11. Only now is it safe to remove the old backup.
      //    P2: backup cleanup is non-fatal — failure here must not invalidate
      //    the already-committed install.
      if (backupCreated && fs.existsSync(backupDir)) {
        try {
          fs.rmSync(backupDir, { recursive: true, force: true });
          backupCreated = false;
        } catch {
          // Non-fatal: install is already committed; log a warning
          console.error(`  ⚠ Could not remove backup directory: ${backupDir}`);
        }
      }

      // 11. Report install to API (fire-and-forget)
      this.reportInstallAsync(manifest, clientType, targetDir, actualSha256);

      return {
        success: true,
        manifest,
        targetDir,
        sha256: actualSha256,
        record,
      };
    } catch (err: unknown) {
      // Rollback (reverse order of activation):
      //   a) Clean up staging if it still exists on disk
      //   b) If target was activated: delete new target
      //   c) Restore backup whenever one was created (regardless of targetActivated)
      if (fs.existsSync(stagingDir)) {
        try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch { /* best-effort */ }
      }
      if (targetActivated) {
        if (fs.existsSync(targetDir)) {
          try { fs.rmSync(targetDir, { recursive: true, force: true }); } catch { /* best-effort */ }
        }
      }
      // Restore backup whenever one was created — this covers:
      //   - Digest succeeded, backup created, but rename or record save failed
      //   - Any post-backup failure before the install fully committed
      if (backupCreated && fs.existsSync(backupDir)) {
        try { fs.renameSync(backupDir, targetDir); } catch { /* best-effort restore */ }
      }
      throw err;
    } finally {
      // Always cleanup temp dir (download + extract)
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  }

  // -----------------------------------------------------------------------
  // Private: Download (P1 fixes: timeout covers body + file write is awaited)
  // -----------------------------------------------------------------------

  private async downloadFile(url: string, destPath: string, _expectedSize: number): Promise<void> {
    // HTTPS enforcement — with explicit localhost exception for dev
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && !LOCALHOST_ORIGINS.has(parsed.hostname)) {
      throw new InstallError(
        `Download URL must use HTTPS (got: ${url}). Localhost is allowed for development only.`,
        'non_https_download',
      );
    }

    // AbortController for fetch headers phase
    const controller = new AbortController();
    const headerTimeoutId = setTimeout(() => controller.abort(), this.downloadTimeout);

    let nodeReadable: Readable | null = null;
    let destFile: ReturnType<typeof fs.createWriteStream> | null = null;
    let bodyTimer: ReturnType<typeof setTimeout> | null = null;

    try {
      const response = await this.downloadFetch(url, {
        signal: controller.signal,
        redirect: 'follow',
      });

      // Headers received — clear the fetch-header timer
      clearTimeout(headerTimeoutId);

      // P2: verify final URL after redirects is still HTTPS (or allowed localhost)
      //      Fail safe: unparseable final URL → reject the download
      if (response.url) {
        try {
          const finalUrl = new URL(response.url);
          if (finalUrl.protocol !== 'https:' && !LOCALHOST_ORIGINS.has(finalUrl.hostname)) {
            throw new InstallError(
              `Redirected to non-HTTPS URL: ${response.url}. Original: ${url}`,
              'redirect_to_http',
            );
          }
        } catch (err: unknown) {
          if (err instanceof InstallError) throw err;
          throw new InstallError(
            `Cannot validate final download URL after redirect: ${response.url}`,
            'redirect_invalid_url',
          );
        }
      }

      if (!response.ok) {
        throw new InstallError(
          `Download failed with HTTP ${response.status}`,
          'download_http_error',
        );
      }

      // Check Content-Length if available
      const contentLength = response.headers.get('content-length');
      if (contentLength) {
        const size = parseInt(contentLength, 10);
        if (size > this.maxDownloadSize) {
          throw new InstallError(
            `Download size ${size} exceeds maximum ${this.maxDownloadSize} bytes`,
            'download_size_exceeded',
          );
        }
      }

      if (!response.body) {
        throw new InstallError('Response body is empty', 'empty_response_body');
      }

      // Set up stream pipeline with a Transform that enforces the size limit
      // in real time.  When the limit is exceeded, the Transform calls
      // callback(err) which causes pipeline() to destroy both the source
      // and dest streams immediately — no more data is written to disk.
      destFile = fs.createWriteStream(destPath);
      nodeReadable = Readable.fromWeb(response.body as any);

      const maxSize = this.maxDownloadSize;
      let bytesWritten = 0;
      const limitTransform = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          bytesWritten += chunk.length;
          if (bytesWritten > maxSize) {
            callback(new InstallError(
              `Download exceeded maximum size of ${maxSize} bytes`,
              'download_size_exceeded',
            ));
            return;
          }
          callback(null, chunk);
        },
      });

      // P1 fix: timer covers body read (server can hang after headers)
      bodyTimer = setTimeout(() => {
        if (nodeReadable) nodeReadable.destroy(new Error('Download body read timed out'));
        if (destFile) destFile.destroy();
      }, this.downloadTimeout);

      await streamPipeline(nodeReadable, limitTransform, destFile);

      // Clear body timer — download completed within timeout
      if (bodyTimer) { clearTimeout(bodyTimer); bodyTimer = null; }

      // Defensive: final size check (should never trigger since the Transform
      // enforces the limit, but guards against edge cases)
      if (bytesWritten > this.maxDownloadSize) {
        throw new InstallError(
          `Download exceeded maximum size of ${this.maxDownloadSize} bytes`,
          'download_size_exceeded',
        );
      }
    } catch (err: unknown) {
      // Clean up partial file
      if (destFile) destFile.destroy();
      try { fs.unlinkSync(destPath); } catch { /* ignore */ }

      if (err instanceof InstallError) throw err;
      // Detect timeout (AbortError from fetch, or stream destroyed by body timer)
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Download body read timed out') ||
          (err instanceof Error && err.name === 'AbortError')) {
        throw new InstallError(
          `Download timed out after ${this.downloadTimeout / 1000}s`,
          'download_timeout',
        );
      }
      throw new InstallError(
        `Download failed: ${msg}`,
        'download_failed',
        err,
      );
    } finally {
      clearTimeout(headerTimeoutId);
      if (bodyTimer) clearTimeout(bodyTimer);
    }
  }

  // -----------------------------------------------------------------------
  // Private: SHA-256
  // -----------------------------------------------------------------------

  private computeSha256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk as string | Buffer));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  // -----------------------------------------------------------------------
  // Private: Extract ZIP
  // P1 fix: ALL entries (including directories) go through the same validation
  // -----------------------------------------------------------------------

  extractZip(archivePath: string, destDir: string): void {
    let zip: AdmZip;
    try {
      zip = new AdmZip(archivePath);
    } catch (err: unknown) {
      throw new InstallError(
        `Failed to open ZIP archive: ${err instanceof Error ? err.message : String(err)}`,
        'zip_open_failed',
        err,
      );
    }

    const entries = zip.getEntries();
    if (entries.length > this.maxExtractFiles) {
      throw new InstallError(
        `ZIP contains ${entries.length} files, exceeding maximum of ${this.maxExtractFiles}`,
        'zip_too_many_files',
      );
    }

    // ── Pass 1: validate ALL entries (including directories) ──
    const validated: ValidatedZipEntry[] = [];
    let totalUncompressedSize = 0;

    for (const entry of entries) {
      const entryName = entry.entryName;

      // ---- path safety checks (applies to directories AND files) ----

      // Path traversal check
      const normalized = path.normalize(entryName);
      if (normalized.startsWith('..') || normalized.includes('..' + path.sep)) {
        throw new InstallError(
          `Path traversal detected in ZIP: "${entryName}"`,
          'zip_path_traversal',
        );
      }

      // Absolute path check
      if (path.isAbsolute(entryName)) {
        throw new InstallError(
          `Absolute path in ZIP: "${entryName}"`,
          'zip_absolute_path',
        );
      }

      // Windows drive letter check
      if (/^[A-Za-z]:/.test(entryName)) {
        throw new InstallError(
          `Windows drive letter path in ZIP: "${entryName}"`,
          'zip_windows_drive',
        );
      }

      // Null byte check
      if (entryName.includes('\x00')) {
        throw new InstallError(
          `Null byte in ZIP entry: "${entryName}"`,
          'zip_null_byte',
        );
      }

      // Resolve full path and verify it's strictly within destDir
      const fullPath = path.resolve(destDir, entryName);
      if (!fullPath.startsWith(destDir + path.sep) && fullPath !== destDir) {
        throw new InstallError(
          `ZIP entry escapes destination: "${entryName}"`,
          'zip_path_escape',
        );
      }

      // Track size (files only)
      if (!entry.isDirectory) {
        totalUncompressedSize += entry.header.size;
        if (totalUncompressedSize > this.maxExtractSize) {
          throw new InstallError(
            `ZIP uncompressed size exceeds maximum of ${this.maxExtractSize} bytes`,
            'zip_too_large',
          );
        }
      }

      validated.push({
        entryName,
        isDirectory: entry.isDirectory,
        getData: () => entry.getData(),
        uncompressedSize: entry.header.size,
      });
    }

    // ── Pass 2: extract all validated entries ──
    for (const entry of validated) {
      const fullPath = path.resolve(destDir, entry.entryName);

      if (entry.isDirectory) {
        fs.mkdirSync(fullPath, { recursive: true });
      } else {
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, entry.getData());
      }
    }
  }

  // -----------------------------------------------------------------------
  // Private: Copy recursive (staging only — target handling is in installWithManifest)
  // -----------------------------------------------------------------------

  private copyDirSync(src: string, dest: string, clientRoot: string): void {
    // Safety check: dest must be within clientRoot
    if (!isStrictChildPath(dest, clientRoot)) {
      throw new InstallError(
        `Copy destination "${dest}" escapes client root "${clientRoot}"`,
        'copy_path_escape',
      );
    }

    fs.mkdirSync(dest, { recursive: true });

    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);

      // Verify destPath is still within clientRoot
      if (!isStrictChildPath(destPath, clientRoot)) {
        throw new InstallError(
          `Copy destination "${destPath}" escapes client root`,
          'copy_path_escape',
        );
      }

      if (entry.isDirectory()) {
        this.copyDirSync(srcPath, destPath, clientRoot);
      } else if (entry.isSymbolicLink()) {
        throw new InstallError(
          `Symbolic links are not allowed: "${entry.name}"`,
          'symlink_rejected',
        );
      } else if (entry.isFile()) {
        fs.copyFileSync(srcPath, destPath);
      }
      // Skip other types (sockets, devices, etc.)
    }
  }

  // -----------------------------------------------------------------------
  // Public: Local install records (delegates to LocalInstallStore)
  // -----------------------------------------------------------------------

  /** Get all locally installed packages (for verify/update/uninstall). */
  getLocalRecords(): LocalInstallRecord[] {
    return this.recordStore.load();
  }

  /** Expose the underlying store for verify executor. */
  getRecordStore(): LocalInstallStore {
    return this.recordStore;
  }

  // -----------------------------------------------------------------------
  // Private: API install reporting (fire-and-forget — with visible warning)
  // -----------------------------------------------------------------------

  private reportInstallAsync(
    manifest: InstallManifest,
    client: string,
    installPath: string,
    sha256: string,
  ): void {
    this.apiClient.recordInstall({
      package_name: manifest.name,
      version: manifest.version,
      client,
      install_path: installPath,
      integrity_verified: true,
    }).catch((err: unknown) => {
      // P1 fix: surface the failure so the user knows stats weren't reported
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ⚠ Failed to report install to registry: ${msg}`);
      console.error(`    Local install is complete but stats may not be recorded.`);
    });
  }

  // -----------------------------------------------------------------------
  // Static helpers
  // -----------------------------------------------------------------------

  // -----------------------------------------------------------------------
  // Static helpers
  // -----------------------------------------------------------------------

  /** Resolve the client-specific root directory (for use by CLI display). */
  static getClientRoot(clientType: string, homeDir?: string): string | null {
    try {
      return getClientRoot(clientType, homeDir);
    } catch {
      return null;
    }
  }
}
