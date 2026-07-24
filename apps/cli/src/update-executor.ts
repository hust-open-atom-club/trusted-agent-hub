/**
 * TrustedAgentHub Update Executor — safe, atomic package updates.
 *
 * Design principles:
 *   - Default fail-closed: ANY non-clean inspection state (modified, legacy,
 *     unsafe_path, unsafe_content, record_invalid) blocks the update unless
 *     --force is explicitly passed for recoverable states (modified, legacy).
 *   - Unsafe structural states (unsafe_path, unsafe_content, record_invalid)
 *     are ALWAYS blocked — --force cannot override filesystem integrity.
 *   - Staging → backup → atomic replace via InstallExecutor — never
 *     `uninstall + install` which could leave the user with no working version.
 *   - Any failure before the atomic commit preserves the old version.
 *   - Double race detection: both the JSON record AND the filesystem content
 *     are rechecked immediately before the install pipeline runs.
 *   - If the atomic commit succeeds, the update is committed even if
 *     follow-up steps (record patching, API reporting) fail — the new
 *     version is functional and the CLI warns about non-fatal issues.
 *
 * Flow:
 *   inspect → [fail-closed gate: block all non-clean states] →
 *   fetch latest manifest → validate → version compare → grade gate →
 *   [race check: record + content digest] →
 *   installWithManifest (download/verify/extract/staging/backup/
 *   atomic-replace/record-save) →
 *   [verify old version after failure → rollback_failed if needed] →
 *   patch record (preserve installed_at, add updated_at) →
 *   report API
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

import { LocalInstallInspector } from './local-install-inspector';
import type { InspectResult } from './local-install-inspector';
import type { LocalInstallRecord } from './local-install-store';
import { LocalInstallStore } from './local-install-store';
import { InstallExecutor, InstallBlockedError, InstallError } from './install-executor';
import { validateManifest, ManifestValidationError } from './manifest-types';
import type { InstallManifest } from './manifest-types';
import { checkInstall, resolveGrade } from './grade-gate';
import { compareVersions, isValidVersion } from './version-policy';
import { CLIENT_INSTALL_ROOTS } from './client-paths';
import { computeDirectoryDigest, ContentIntegrityError } from './content-integrity';
import { sanitizeOutput } from './safe-output';
import { ApiError } from './api-client';

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export type UpdateStatus =
  | 'updated'
  | 'up_to_date'
  | 'not_installed'
  | 'modified'
  | 'legacy_record'
  | 'record_invalid'
  | 'unsafe_path'
  | 'unsafe_content'
  | 'unsupported_client'
  | 'manifest_unavailable'
  | 'invalid_manifest'
  | 'downgrade_blocked'
  | 'update_blocked'
  | 'update_failed'
  | 'rollback_failed';

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface UpdateResult {
  ok: boolean;
  status: UpdateStatus;
  packageName: string;
  client: string;
  /** The version BEFORE the update (the installed version). */
  localVersion?: string;
  /** The version AFTER the update (the remote manifest version). */
  remoteVersion?: string;
  installPath?: string;
  artifactSha256?: string;
  message: string;
  /** Backup path for manual recovery when rollback itself fails. */
  backupPath?: string;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface UpdateOptions {
  force?: boolean;
  yes?: boolean;
  acceptHighRisk?: boolean;
  homeDir?: string;
  /** Custom fetch implementation (for testing). */
  fetchFn?: typeof fetch;
  /** Test hook: passed through to InstallExecutor.beforeSaveRecord. */
  _beforeInstallSaveRecord?: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUpdateResult(
  status: UpdateStatus,
  packageName: string,
  client: string,
  message: string,
  extras: Partial<Pick<UpdateResult, 'localVersion' | 'remoteVersion' | 'installPath' | 'artifactSha256' | 'backupPath'>> = {},
): UpdateResult {
  const ok = status === 'updated' || status === 'up_to_date';
  return {
    ok,
    status,
    packageName: sanitizeOutput(packageName),
    client: sanitizeOutput(client),
    message: sanitizeOutput(message),
    localVersion: extras.localVersion ? sanitizeOutput(extras.localVersion) : undefined,
    remoteVersion: extras.remoteVersion ? sanitizeOutput(extras.remoteVersion) : undefined,
    installPath: extras.installPath ? sanitizeOutput(extras.installPath) : undefined,
    artifactSha256: extras.artifactSha256,
    backupPath: extras.backupPath ? sanitizeOutput(extras.backupPath) : undefined,
  };
}

/**
 * Inspection states that are structural / integrity issues — always fail-closed,
 * even with --force.  These represent filesystem tampering, not user edits.
 */
const STRUCTURAL_FAIL_STATES = new Set<string>([
  'unsafe_path',
  'unsafe_content',
  'record_invalid',
]);

/**
 * Inspection states that are recoverable with --force (user edits).
 */
const RECOVERABLE_STATES = new Set<string>([
  'modified',
  'legacy_record',
]);

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

export class UpdateExecutor {
  private readonly homeDir: string;
  private readonly inspector: LocalInstallInspector;
  private readonly store: LocalInstallStore;
  private readonly fetchFn?: typeof fetch;
  private readonly beforeInstallSaveRecord?: () => void;

  constructor(
    private apiClient: ReturnType<typeof import('./api-client').createApiClient>,
    options: UpdateOptions = {},
  ) {
    this.homeDir = options.homeDir || os.homedir();
    this.inspector = new LocalInstallInspector({ homeDir: this.homeDir });
    this.store = new LocalInstallStore(this.homeDir);
    this.fetchFn = options.fetchFn;
    this.beforeInstallSaveRecord = options._beforeInstallSaveRecord;
  }

  // -----------------------------------------------------------------------
  // Public: update
  // -----------------------------------------------------------------------

  async update(
    packageName: string,
    clientType: string,
    options: UpdateOptions = {},
  ): Promise<UpdateResult> {
    // 1. Check client support
    const clientRootRel = CLIENT_INSTALL_ROOTS[clientType];
    if (!clientRootRel) {
      return makeUpdateResult(
        'unsupported_client',
        packageName,
        clientType,
        `Unsupported client: "${clientType}". Supported clients: ${Object.keys(CLIENT_INSTALL_ROOTS).join(', ')}`,
      );
    }

    // 2. Inspect local installation (read-only)
    const inspectResult = await this.inspector.inspect(packageName, clientType);

    if (inspectResult.contentState === 'missing' && inspectResult.record === null) {
      return makeUpdateResult(
        'not_installed',
        packageName,
        clientType,
        `Package "${packageName}" is not installed for client "${clientType}". Install it first with \`tah install ${packageName}\`.`,
      );
    }

    // No record at all → fail closed
    if (!inspectResult.record) {
      const statusMap: Record<string, UpdateStatus> = {
        record_invalid: 'update_failed',
        unsafe_path: 'unsafe_path',
        unsafe_content: 'unsafe_content',
        missing: 'not_installed',
      };
      const status = statusMap[inspectResult.contentState] || 'update_failed';
      return makeUpdateResult(status, packageName, clientType, inspectResult.message);
    }

    const record = inspectResult.record;

    // ── 3. Fail-closed gate: ALL non-clean states must be explicitly handled ──

    // Structural issues → ALWAYS blocked (--force cannot override)
    if (STRUCTURAL_FAIL_STATES.has(inspectResult.contentState)) {
      return makeUpdateResult(
        inspectResult.contentState as UpdateStatus,
        packageName,
        clientType,
        `Cannot update: ${inspectResult.message} Reinstall with \`tah install ${packageName}\` to repair.`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    // Missing directory but record exists → blocked
    if (inspectResult.contentState === 'missing') {
      return makeUpdateResult(
        'update_failed',
        packageName,
        clientType,
        `Installed directory no longer exists. Reinstall with \`tah install ${packageName}\`.`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    // Recoverable states (modified, legacy) → blocked unless --force
    if (RECOVERABLE_STATES.has(inspectResult.contentState) && !options.force) {
      const label = inspectResult.contentState === 'legacy_record' ? 'Legacy record' : 'Modified content';
      return makeUpdateResult(
        inspectResult.contentState as UpdateStatus,
        packageName,
        clientType,
        `${label} detected. Use --force to overwrite with the latest version.`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    // At this point, contentState MUST be 'clean' (or recoverable + --force).
    // Any unexpected state falls through to here — fail closed.
    if (inspectResult.contentState !== 'clean') {
      const allowed = new Set([...STRUCTURAL_FAIL_STATES, ...RECOVERABLE_STATES, 'missing', 'clean']);
      if (!allowed.has(inspectResult.contentState)) {
        return makeUpdateResult(
          'update_failed',
          packageName,
          clientType,
          `Unknown inspection state "${inspectResult.contentState}" — update blocked as a safety precaution.`,
          { localVersion: record.version, installPath: record.install_path },
        );
      }
    }

    // 4. Snapshot old record fields and content digest for race detection
    const oldRecordSnapshot: LocalInstallRecord = { ...record };
    const oldContentDigest = inspectResult.actualContentSha256;
    const oldExpectedDigest = inspectResult.expectedContentSha256;

    // 5. Fetch latest published install manifest
    let rawManifest: unknown;
    try {
      rawManifest = await this.apiClient.getInstallManifest(packageName, clientType);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.statusCode === 409) {
          return makeUpdateResult(
            'manifest_unavailable',
            packageName,
            clientType,
            `Install manifest unavailable for "${packageName}" with client "${clientType}".`,
            { localVersion: record.version, installPath: record.install_path },
          );
        }
        if (err.statusCode === 404) {
          return makeUpdateResult(
            'manifest_unavailable',
            packageName,
            clientType,
            `Package "${packageName}" not found on the registry.`,
            { localVersion: record.version, installPath: record.install_path },
          );
        }
      }
      return makeUpdateResult(
        'manifest_unavailable',
        packageName,
        clientType,
        `Failed to fetch manifest: ${err instanceof Error ? err.message : String(err)}`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    // 6. Validate manifest
    let manifest: InstallManifest;
    try {
      manifest = validateManifest(rawManifest);
    } catch (err: unknown) {
      if (err instanceof ManifestValidationError) {
        return makeUpdateResult(
          'invalid_manifest',
          packageName,
          clientType,
          `Invalid install manifest: ${err.message}`,
          { localVersion: record.version, installPath: record.install_path },
        );
      }
      throw err;
    }

    // 7. Cross-check manifest identity
    if (manifest.name !== packageName) {
      return makeUpdateResult(
        'invalid_manifest',
        packageName,
        clientType,
        `Manifest package name "${manifest.name}" does not match "${packageName}".`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    if (manifest.installation.target_client !== clientType) {
      return makeUpdateResult(
        'invalid_manifest',
        packageName,
        clientType,
        `Manifest target client "${manifest.installation.target_client}" does not match "${clientType}".`,
        { localVersion: record.version, installPath: record.install_path },
      );
    }

    const remoteVersion = manifest.version;

    // 8. Validate remote version is SemVer
    if (!isValidVersion(remoteVersion)) {
      return makeUpdateResult(
        'invalid_manifest',
        packageName,
        clientType,
        `Remote version "${remoteVersion}" is not valid SemVer.`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    // 9. Compare versions
    const versionCmp = compareVersions(record.version, remoteVersion);

    if (versionCmp.decision === 'invalid_version') {
      return makeUpdateResult(
        'update_failed',
        packageName,
        clientType,
        `Cannot compare versions: local="${record.version}", remote="${remoteVersion}".`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    if (versionCmp.decision === 'up_to_date') {
      return makeUpdateResult(
        'up_to_date',
        packageName,
        clientType,
        `Package "${packageName}" is already at the latest version (v${record.version}).`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    if (versionCmp.decision === 'downgrade_blocked') {
      return makeUpdateResult(
        'downgrade_blocked',
        packageName,
        clientType,
        `Remote version v${remoteVersion} is lower than installed v${record.version}. Downgrades are not supported.`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    // 10. Grade gate for the new version
    const grade = manifest.risk_summary.grade || resolveGrade({
      grade: manifest.risk_summary.grade,
      riskLevel: manifest.risk_summary.level,
    }) || 'unknown';

    if (grade === 'E') {
      return makeUpdateResult(
        'update_blocked',
        packageName,
        clientType,
        `Update blocked: Grade E packages cannot be installed.`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    const gateResult = checkInstall({ grade }, {
      yes: options.yes,
      force: options.force,
      acceptHighRisk: options.acceptHighRisk,
    });

    if (!gateResult.allowed) {
      return makeUpdateResult(
        'update_blocked',
        packageName,
        clientType,
        gateResult.reason || `Update blocked by safety policy (Grade ${grade}).`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    // 11. Dual race detection: re-check both the JSON record AND the
    //     filesystem content BEFORE calling the install pipeline.
    //     The manifest fetch + validation may have taken seconds; a user
    //     or another process could have modified the install in that window.

    // 11a. Record race check
    try {
      const currentRecord = this.store.find(packageName, clientType);
      if (!currentRecord) {
        return makeUpdateResult(
          'update_failed',
          packageName,
          clientType,
          'Record was removed concurrently — update aborted.',
          { localVersion: record.version, remoteVersion, installPath: record.install_path },
        );
      }

      const raceFields: (keyof LocalInstallRecord)[] = [
        'package_name', 'version', 'client', 'install_path',
        'sha256', 'integrity_verified', 'content_hash_algorithm', 'content_sha256',
      ];
      for (const field of raceFields) {
        if (currentRecord[field] !== oldRecordSnapshot[field]) {
          return makeUpdateResult(
            'update_failed',
            packageName,
            clientType,
            `Install record changed concurrently (field: ${field}) — update aborted.`,
            { localVersion: record.version, remoteVersion, installPath: record.install_path },
          );
        }
      }
    } catch (err: unknown) {
      return makeUpdateResult(
        'update_failed',
        packageName,
        clientType,
        `Cannot verify install records before update: ${err instanceof Error ? err.message : String(err)}`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    // 11b. Content race check moved to beforeActivate hook — see step 12.
    //      The hook fires inside InstallExecutor right before the target→backup
    //      rename, which is the latest possible moment before activation.

    // 12. Execute the update via InstallExecutor.installWithManifest().
    //     This handles the full pipeline: download → verify → extract →
    //     staging → backup old → atomic replace → save record → cleanup.
    //
    //     If it throws, the old version is preserved (InstallExecutor has
    //     internal rollback that restores the backup).  We verify that
    //     post-failure and report rollback_failed if it isn't.

    // 12. Final TOCTOU check: re-verify the live target directory identity and
    //     content digest right before the backup→rename activation.  This fires
    //     AFTER download/verify/extract/staging are complete — the latest
    //     possible moment before the old installation is moved aside.
    const capturedContentDigest = oldContentDigest;
    const capturedRecordPath = record.install_path;
    const beforeActivate = async (targetDir: string): Promise<void> => {
      // Guard: the new manifest must target the same directory as the
      // existing installation.  A manifest that redirects to a different
      // path would orphan the old directory and overwrite the record.
      if (path.resolve(targetDir) !== path.resolve(capturedRecordPath)) {
        throw new InstallError(
          `Manifest target path "${targetDir}" does not match installed path "${capturedRecordPath}". ` +
          'The update manifest must target the same directory.',
          'invalid_manifest',
        );
      }

      const recheck = await this.inspector.inspect(packageName, clientType);
      if (recheck.contentState !== inspectResult.contentState) {
        throw new InstallError(
          `Installation state changed during update (was: ${inspectResult.contentState}, now: ${recheck.contentState})`,
          'content_race',
        );
      }
      if (recheck.actualContentSha256 !== capturedContentDigest) {
        throw new InstallError(
          'Installed content was modified during the update — aborting to preserve changes.',
          'content_race',
        );
      }
    };

    let installResult: Awaited<ReturnType<InstallExecutor['installWithManifest']>>;
    try {
      const installExecutor = new InstallExecutor(this.apiClient, {
        homeDir: this.homeDir,
        fetchFn: this.fetchFn,
        beforeActivate,
        beforeSaveRecord: this.beforeInstallSaveRecord,
      });
      installResult = await installExecutor.installWithManifest(manifest, clientType, {
        yes: options.yes,
        force: options.force,
        acceptHighRisk: options.acceptHighRisk,
      });
    } catch (err: unknown) {
      // The InstallExecutor's internal rollback should have restored the
      // old version.  Verify that the old target still exists and is intact.
      // Use oldContentDigest (the actual digest at update start) not
      // oldExpectedDigest (from the install record).  For --force updates
      // on modified content, the record digest won't match the actual
      // content — we want to verify the actual content is preserved.
      const oldIntact = await this.verifyOldVersionIntact(oldRecordSnapshot, oldContentDigest);

      if (err instanceof InstallBlockedError) {
        return makeUpdateResult(
          'update_blocked',
          packageName,
          clientType,
          `Update blocked: ${err.message}`,
          { localVersion: record.version, remoteVersion, installPath: record.install_path },
        );
      }

      if (err instanceof InstallError) {
        // Hooks from beforeActivate
        if (err.code === 'invalid_manifest') {
          return makeUpdateResult(
            'invalid_manifest',
            packageName,
            clientType,
            err.message,
            { localVersion: record.version, remoteVersion, installPath: record.install_path },
          );
        }
        if (err.code === 'content_race') {
          return makeUpdateResult(
            'update_failed',
            packageName,
            clientType,
            `Installed content changed during update: ${err.message}`,
            { localVersion: record.version, remoteVersion, installPath: record.install_path },
          );
        }
        if (!oldIntact) {
          return makeUpdateResult(
            'rollback_failed',
            packageName,
            clientType,
            `Rollback failed after update error (${err.code}). ` +
            `Check install path: ${oldRecordSnapshot.install_path}`,
            {
              localVersion: record.version,
              remoteVersion,
              installPath: oldRecordSnapshot.install_path,
            },
          );
        }
        // Put "preserved" first so it survives sanitizeOutput truncation
        return makeUpdateResult(
          'update_failed',
          packageName,
          clientType,
          `Previous version preserved. Update failed (${err.code}): ${err.message}`,
          { localVersion: record.version, remoteVersion, installPath: record.install_path },
        );
      }

      if (!oldIntact) {
        return makeUpdateResult(
          'rollback_failed',
          packageName,
          clientType,
          `Unexpected error during update and the previous version could not be verified. ` +
          `Check the install path manually: ${oldRecordSnapshot.install_path}`,
          {
            localVersion: record.version,
            remoteVersion,
            installPath: oldRecordSnapshot.install_path,
          },
        );
      }

      return makeUpdateResult(
        'update_failed',
        packageName,
        clientType,
        `Unexpected error during update: ${err instanceof Error ? err.message : String(err)}`,
        { localVersion: record.version, remoteVersion, installPath: record.install_path },
      );
    }

    // 13. Patch the record: preserve original installed_at, add/update updated_at.
    //     installWithManifest wrote a fresh record with a new installed_at.
    //     We load it back, fix the timestamps, and re-save.
    try {
      const savedRecord = this.store.find(packageName, clientType);
      if (savedRecord) {
        const patchedRecord: LocalInstallRecord = {
          ...savedRecord,
          installed_at: oldRecordSnapshot.installed_at,
          updated_at: new Date().toISOString(),
        };
        this.store.save(patchedRecord);
      }
    } catch (err: unknown) {
      // Non-fatal: the new version is already live and the record is valid
      // (just has the wrong installed_at).  Warn but don't fail.
      console.error(`  ⚠ Could not preserve original install timestamp: ${err instanceof Error ? err.message : String(err)}`);
      console.error(`    The package is updated but \`installed_at\` reflects the update time.`);
    }

    // 14. Report updated install to API (fire-and-forget with warning)
    this.reportUpdateAsync(manifest, clientType, installResult.targetDir, installResult.sha256);

    return makeUpdateResult(
      'updated',
      packageName,
      clientType,
      `Updated "${packageName}" from v${oldRecordSnapshot.version} to v${manifest.version}.`,
      {
        localVersion: oldRecordSnapshot.version,
        remoteVersion: manifest.version,
        installPath: installResult.targetDir,
        artifactSha256: installResult.sha256,
      },
    );
  }

  // -----------------------------------------------------------------------
  // Private: verify old version is still intact after a failed install
  // -----------------------------------------------------------------------

  private async verifyOldVersionIntact(
    oldRecord: LocalInstallRecord,
    expectedContentDigest?: string,
  ): Promise<boolean> {
    try {
      // Check the old install path still exists and is a directory
      if (!fs.existsSync(oldRecord.install_path)) return false;
      const stat = fs.lstatSync(oldRecord.install_path);
      if (!stat.isDirectory() || stat.isSymbolicLink()) return false;

      // If we have an expected digest, verify content hasn't been corrupted
      if (expectedContentDigest) {
        const digest = await computeDirectoryDigest(oldRecord.install_path);
        if (digest.digest !== expectedContentDigest) return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // Private: API update reporting (fire-and-forget)
  // -----------------------------------------------------------------------

  private reportUpdateAsync(
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
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ⚠ Failed to report update to registry: ${msg}`);
      console.error(`    Local update is complete but stats may not be recorded.`);
    });
  }
}
