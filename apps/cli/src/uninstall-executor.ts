/**
 * TrustedAgentHub Uninstall Executor — safe, offline package removal.
 *
 * Orchestrates a security state machine that:
 *   1. Validates the local install record
 *   2. Checks path safety (client root, strict child, no symlinks/junctions)
 *   3. Computes a content digest and gates on clean/modified/legacy
 *   4. Requires confirmation (or `--yes`) before any mutation
 *   5. Quarantines the target directory via same-filesystem rename
 *   6. Verifies the quarantined identity before touching records
 *   7. Atomically removes the local install record
 *   8. Cleans up the quarantine directory
 *   9. Rolls back the quarantine on record-update failure
 *
 * Safety guarantees:
 *   - Fully local — no Manifest fetch, no API calls, no package commands
 *   - No symlink/junction following
 *   - No deletion outside the client root
 *   - Bigint dev/ino identity checks prevent TOCTOU substitution
 *   - Atomic record removal with expected-record snapshot verification
 *   - Stale record (missing directory) handled without confirmation
 *   - All result fields sanitized before return
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { LocalInstallStore, RECORD_COMPARE_FIELDS } from './local-install-store';
import type { LocalInstallRecord } from './local-install-store';
import { RecordStoreError } from './local-install-store';
import {
  computeDirectoryDigest,
  ContentIntegrityError,
  validateAncestorChain,
  validateExistingAncestorChain,
} from './content-integrity';
import {
  isStrictChildPath,
  getClientRoot,
  isSupportedClient,
} from './client-paths';
import { sanitizeOutput } from './safe-output';
import type { ConfirmCallback } from './confirm';

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export type UninstallStatus =
  | 'uninstalled'
  | 'stale_record_removed'
  | 'cancelled'
  | 'not_installed'
  | 'record_invalid'
  | 'unsupported_client'
  | 'unsafe_path'
  | 'unsafe_content'
  | 'legacy_record'
  | 'modified'
  | 'confirmation_required'
  | 'record_update_failed'
  | 'cleanup_failed'
  | 'rollback_failed';

const SUCCESS_STATUSES = new Set<UninstallStatus>([
  'uninstalled',
  'stale_record_removed',
  'cancelled',
]);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UninstallSummary {
  packageName: string;
  version: string;
  client: string;
  installPath: string;
  contentState: 'clean' | 'modified' | 'legacy';
}

export interface UninstallOptions {
  force?: boolean;
  yes?: boolean;
  confirm?: ConfirmCallback;
  homeDir?: string;
  maxFiles?: number;
  maxBytes?: number;
}

export interface UninstallResult {
  ok: boolean;
  status: UninstallStatus;
  packageName: string;
  client: string;
  version?: string;
  installPath?: string;
  quarantinePath?: string;
  message: string;
}

export interface FileIdentity {
  dev: bigint;
  ino: bigint;
  type: 'directory' | 'other';
}

export interface ObservedTargetState {
  identity: FileIdentity;
  actualContentSha256: string;
  contentState: 'clean' | 'modified' | 'legacy';
}

/**
 * Narrow filesystem operations adapter — allows unit tests to inject
 * deterministic failures at specific boundaries.
 */
export interface UninstallFileOps {
  lstat(filePath: string): FileIdentity;
  rename(source: string, destination: string): void;
  removeTree(target: string): void;
  exists(target: string): boolean;
}

export interface UninstallExecutorDependencies {
  homeDir?: string;
  store?: LocalInstallStore;
  fileOps?: UninstallFileOps;
  maxFiles?: number;
  maxBytes?: number;
}

// ---------------------------------------------------------------------------
// Default FileOps (Node fs)
// ---------------------------------------------------------------------------

const defaultFileOps: UninstallFileOps = {
  lstat(filePath: string): FileIdentity {
    const stat = fs.lstatSync(filePath, { bigint: true }) as fs.BigIntStats;
    return {
      dev: stat.dev,
      ino: stat.ino,
      type: stat.isDirectory() ? 'directory' : 'other',
    };
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
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compare two records field-by-field using the canonical field list from
 * {@link RECORD_COMPARE_FIELDS}.  Returns `true` when every listed field
 * is identical.
 */
function recordsFieldsMatch(a: LocalInstallRecord, b: LocalInstallRecord): boolean {
  for (const key of RECORD_COMPARE_FIELDS) {
    if (a[key] !== b[key]) return false;
  }
  return true;
}

function readDirectoryIdentity(fileOps: UninstallFileOps, target: string): FileIdentity {
  const identity = fileOps.lstat(target);
  if (identity.type !== 'directory') {
    throw new Error('unsafe_content');
  }
  return identity;
}

function sameDirectoryIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return (
    left.type === 'directory' &&
    right.type === 'directory' &&
    left.dev === right.dev &&
    left.ino === right.ino
  );
}

function createRandomQuarantinePath(clientRoot: string, fileOps: UninstallFileOps): string {
  for (let attempt = 0; attempt < 16; attempt++) {
    const candidate = path.join(
      clientRoot,
      `.uninstall-${crypto.randomBytes(16).toString('hex')}`,
    );
    if (isStrictChildPath(candidate, clientRoot) && !fileOps.exists(candidate)) {
      return candidate;
    }
  }
  throw new Error('unsafe_content');
}

// ---------------------------------------------------------------------------
// Result factory
// ---------------------------------------------------------------------------

interface ResultContext {
  packageName: string;
  client: string;
  message: string;
  version?: string;
  installPath?: string;
  quarantinePath?: string;
}

function makeResult(status: UninstallStatus, context: ResultContext): UninstallResult {
  return {
    ok: SUCCESS_STATUSES.has(status),
    status,
    packageName: sanitizeOutput(context.packageName),
    client: sanitizeOutput(context.client),
    version: context.version ? sanitizeOutput(context.version) : undefined,
    installPath: context.installPath ? sanitizeOutput(context.installPath) : undefined,
    quarantinePath: context.quarantinePath ? sanitizeOutput(context.quarantinePath) : undefined,
    message: sanitizeOutput(context.message),
  };
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

export class UninstallExecutor {
  private readonly homeDir: string;
  private readonly store: LocalInstallStore;
  private readonly fileOps: UninstallFileOps;
  private readonly maxFiles: number;
  private readonly maxBytes: number;

  constructor(dependencies: UninstallExecutorDependencies = {}) {
    this.homeDir = dependencies.homeDir || os.homedir();
    this.store = dependencies.store || new LocalInstallStore(this.homeDir);
    this.fileOps = dependencies.fileOps || defaultFileOps;
    this.maxFiles = dependencies.maxFiles ?? 10_000;
    this.maxBytes = dependencies.maxBytes ?? 500 * 1024 * 1024;
  }

  // -----------------------------------------------------------------------
  // Public: uninstall
  // -----------------------------------------------------------------------

  async uninstall(
    packageName: string,
    client: string,
    options: UninstallOptions = {},
  ): Promise<UninstallResult> {
    // 1. Strictly load records
    let records: LocalInstallRecord[];
    try {
      records = this.store.load();
    } catch {
      return makeResult('record_invalid', {
        packageName,
        client,
        message: 'The local install records file is corrupted.',
      });
    }

    const record = records.find(
      (r) => r.package_name === packageName && r.client === client,
    );

    if (!record) {
      return makeResult('not_installed', {
        packageName,
        client,
        message: 'Package is not installed for this client.',
      });
    }

    // 2. Check client support
    if (!isSupportedClient(record.client)) {
      return makeResult('unsupported_client', {
        packageName,
        client,
        version: record.version,
        message: `Client "${record.client}" is not supported.`,
      });
    }

    // 3. Resolve client root; install_path must be strict child
    let clientRoot: string;
    try {
      clientRoot = getClientRoot(record.client, this.homeDir);
    } catch {
      return makeResult('unsupported_client', {
        packageName,
        client,
        version: record.version,
        message: `Cannot resolve client root for "${record.client}".`,
      });
    }

    if (!isStrictChildPath(record.install_path, clientRoot)) {
      return makeResult('unsafe_path', {
        packageName,
        client,
        version: record.version,
        installPath: record.install_path,
        message: 'Install path is outside the client root.',
      });
    }

    // 4. Check whether the target still exists BEFORE deciding which
    //    ancestor-validation strategy to use.  A missing target (stale
    //    record) must still be removable even when the client root itself
    //    has been deleted — but any *existing* ancestor must still be a
    //    real directory (no symlink / junction / file).
    const targetExists = this.fileOps.exists(record.install_path);

    if (targetExists) {
      // Normal path: client root must exist and be safe
      try {
        validateAncestorChain(clientRoot);
      } catch (err: unknown) {
        if (err instanceof ContentIntegrityError) {
          return makeResult('unsafe_path', {
            packageName,
            client,
            version: record.version,
            installPath: record.install_path,
            message: `Client root ancestor is unsafe: ${err.message}`,
          });
        }
        throw err;
      }
    } else {
      // Stale path: client root may not exist, but any existing ancestor
      // must still be a real directory.
      try {
        validateExistingAncestorChain(clientRoot);
      } catch (err: unknown) {
        if (err instanceof ContentIntegrityError) {
          return makeResult('unsafe_path', {
            packageName,
            client,
            version: record.version,
            installPath: record.install_path,
            message: `Client root ancestor is unsafe: ${err.message}`,
          });
        }
        throw err;
      }
    }

    try {
      validateExistingAncestorChain(path.dirname(record.install_path));
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return makeResult('unsafe_path', {
          packageName,
          client,
          version: record.version,
          installPath: record.install_path,
          message: `Install parent ancestor is unsafe: ${err.message}`,
        });
      }
      throw err;
    }

    // 5. Branch: target missing → stale record cleanup
    if (!targetExists) {
      return this.handleStaleRecord(record, clientRoot);
    }

    // 6. Target must be a directory (not symlink)
    let targetIdentity: FileIdentity;
    try {
      targetIdentity = readDirectoryIdentity(this.fileOps, record.install_path);
    } catch {
      return makeResult('unsafe_content', {
        packageName,
        client,
        version: record.version,
        installPath: record.install_path,
        message: 'Install path is not a real directory.',
      });
    }

    // 7. Compute content digest; determine contentState
    let actualDigest: string;
    try {
      const digest = await computeDirectoryDigest(record.install_path, {
        maxFiles: this.maxFiles,
        maxBytes: this.maxBytes,
      });
      actualDigest = digest.digest;
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return makeResult('unsafe_content', {
          packageName,
          client,
          version: record.version,
          installPath: record.install_path,
          message: `Cannot verify content: ${err.message}`,
        });
      }
      throw err;
    }

    const isLegacy = !record.content_sha256;
    let contentState: 'clean' | 'modified' | 'legacy';

    if (isLegacy) {
      contentState = 'legacy';
    } else if (actualDigest !== record.content_sha256) {
      contentState = 'modified';
    } else {
      contentState = 'clean';
    }

    // Capture observed state BEFORE entering confirmation / consent logic
    const observedState: ObservedTargetState = {
      identity: targetIdentity,
      actualContentSha256: actualDigest,
      contentState,
    };

    // 8. Gate on content state
    if (contentState !== 'clean' && !options.force) {
      return makeResult(
        contentState === 'legacy' ? 'legacy_record' : 'modified',
        {
          packageName,
          client,
          version: record.version,
          installPath: record.install_path,
          message:
            contentState === 'legacy'
              ? 'Legacy record without content digest — use --force to continue.'
              : 'Installed content has been modified — use --force to continue.',
        },
      );
    }

    // 9. Confirmation / consent
    if (!options.yes) {
      if (!options.confirm) {
        return makeResult('confirmation_required', {
          packageName,
          client,
          version: record.version,
          installPath: record.install_path,
          message: 'Confirmation is required unless --yes is passed.',
        });
      }

      const summary: UninstallSummary = {
        packageName: record.package_name,
        version: record.version,
        client: record.client,
        installPath: record.install_path,
        contentState,
      };

      if (!(await options.confirm(summary))) {
        return makeResult('cancelled', {
          packageName,
          client,
          version: record.version,
          installPath: record.install_path,
          message: 'Uninstall cancelled.',
        });
      }
    }

    // 10. Execute the safe transaction
    return this.executeUninstallTransaction(
      record,
      observedState,
      clientRoot,
      options,
    );
  }

  // -----------------------------------------------------------------------
  // Stale record (target directory missing)
  // -----------------------------------------------------------------------

  private handleStaleRecord(
    record: LocalInstallRecord,
    clientRoot: string,
  ): UninstallResult {
    const context: ResultContext = {
      packageName: record.package_name,
      client: record.client,
      version: record.version,
      installPath: record.install_path,
      message: '',
    };

    // Re-validate ancestor chains (lenient — ancestors may not exist)
    try {
      validateExistingAncestorChain(clientRoot);
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Client root ancestor is unsafe; cannot safely remove stale record.',
      });
    }

    try {
      validateExistingAncestorChain(path.dirname(record.install_path));
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Ancestor chain changed; cannot safely remove stale record.',
      });
    }

    // Confirm target still missing
    if (this.fileOps.exists(record.install_path)) {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target directory reappeared; cannot remove as stale.',
      });
    }

    // Re-load and compare record (all fields including integrity_verified)
    let currentRecord: LocalInstallRecord | null;
    try {
      currentRecord = this.store.find(record.package_name, record.client);
    } catch {
      return makeResult('record_invalid', {
        ...context,
        message: 'Cannot re-read install records.',
      });
    }

    if (!currentRecord) {
      return makeResult('record_update_failed', {
        ...context,
        message: 'Record was removed concurrently.',
      });
    }

    if (!recordsFieldsMatch(currentRecord, record)) {
      return makeResult('record_update_failed', {
        ...context,
        message: 'Record changed; cannot safely remove stale record.',
      });
    }

    // Final check: target must still be absent right before record deletion
    if (this.fileOps.exists(record.install_path)) {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target directory reappeared during stale cleanup.',
      });
    }

    // Atomically remove the stale record (pass expected snapshot for
    // a final field-by-field comparison inside the store)
    try {
      this.store.remove(record.package_name, record.client, record);
    } catch (err: unknown) {
      if (err instanceof RecordStoreError && err.code === 'record_changed') {
        return makeResult('record_update_failed', {
          ...context,
          message: 'Record changed during removal.',
        });
      }
      return makeResult('record_update_failed', {
        ...context,
        message: `Failed to remove stale record: ${err instanceof Error ? err.message : String(err)}`,
      });
    }

    return makeResult('stale_record_removed', {
      ...context,
      message: 'Install record was removed; the directory was already gone.',
    });
  }

  // -----------------------------------------------------------------------
  // Safe uninstall transaction
  // -----------------------------------------------------------------------

  private async executeUninstallTransaction(
    record: LocalInstallRecord,
    observedState: ObservedTargetState,
    clientRoot: string,
    options: UninstallOptions,
  ): Promise<UninstallResult> {
    const context: ResultContext = {
      packageName: record.package_name,
      client: record.client,
      version: record.version,
      installPath: record.install_path,
      message: '',
    };

    // --- Revalidation (pre-mutation) ---------------------------------------

    // Re-load and compare record
    let currentRecord: LocalInstallRecord | null;
    try {
      currentRecord = this.store.find(record.package_name, record.client);
    } catch {
      return makeResult('record_update_failed', {
        ...context,
        message: 'Cannot re-read install records before uninstall.',
      });
    }

    if (!currentRecord) {
      return makeResult('record_update_failed', {
        ...context,
        message: 'Record was removed concurrently.',
      });
    }

    // Compare all fields (uses canonical field list including integrity_verified)
    if (!recordsFieldsMatch(currentRecord, record)) {
      return makeResult('record_update_failed', {
        ...context,
        message: 'Record changed before uninstall.',
      });
    }

    // Re-validate path safety
    try {
      validateAncestorChain(clientRoot);
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Client root ancestor changed before uninstall.',
      });
    }

    try {
      validateExistingAncestorChain(path.dirname(record.install_path));
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Install parent ancestor changed before uninstall.',
      });
    }

    // Confirm target still exists and is a directory
    if (!this.fileOps.exists(record.install_path)) {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target directory disappeared before uninstall.',
      });
    }

    let latestIdentity: FileIdentity;
    try {
      latestIdentity = readDirectoryIdentity(this.fileOps, record.install_path);
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target is no longer a real directory.',
      });
    }

    // Re-compute digest and verify identity/state consistency
    let latestDigest: string;
    try {
      const digest = await computeDirectoryDigest(record.install_path, {
        maxFiles: this.maxFiles,
        maxBytes: this.maxBytes,
      });
      latestDigest = digest.digest;
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return makeResult('unsafe_content', {
          ...context,
          message: `Content verification failed before uninstall: ${err.message}`,
        });
      }
      throw err;
    }

    // Verify identity (dev/ino/type) matches what we observed
    if (!sameDirectoryIdentity(latestIdentity, observedState.identity)) {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target directory identity changed before uninstall.',
      });
    }

    // Verify actual digest matches what we observed
    if (latestDigest !== observedState.actualContentSha256) {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Target content changed before uninstall.',
      });
    }

    // --- Quarantine via same-filesystem rename -----------------------------

    let quarantinePath: string;
    try {
      quarantinePath = createRandomQuarantinePath(clientRoot, this.fileOps);
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Cannot create a safe quarantine directory.',
      });
    }

    try {
      this.fileOps.rename(record.install_path, quarantinePath);
    } catch {
      return makeResult('unsafe_content', {
        ...context,
        message: 'Cannot safely isolate the installed directory.',
      });
    }

    context.quarantinePath = quarantinePath;

    // --- Quarantine identity verification ----------------------------------

    let quarantinedIdentity: FileIdentity;
    try {
      quarantinedIdentity = readDirectoryIdentity(this.fileOps, quarantinePath);
    } catch {
      return makeResult('rollback_failed', {
        ...context,
        message: 'Cannot verify the quarantined directory for recovery.',
      });
    }

    const originalPathReappeared = this.fileOps.exists(record.install_path);

    if (
      !sameDirectoryIdentity(latestIdentity, quarantinedIdentity) ||
      originalPathReappeared
    ) {
      return makeResult('rollback_failed', {
        ...context,
        message:
          'The filesystem changed during uninstall; manual recovery is required.',
      });
    }

    // --- Atomically remove record ------------------------------------------

    try {
      this.store.remove(record.package_name, record.client, record);
    } catch (err: unknown) {
      // Attempt rollback — restore quarantined directory to original path
      let canRestore = false;
      try {
        canRestore =
          sameDirectoryIdentity(
            latestIdentity,
            this.fileOps.lstat(quarantinePath),
          ) && !this.fileOps.exists(record.install_path);
      } catch {
        canRestore = false;
      }

      if (canRestore) {
        try {
          this.fileOps.rename(quarantinePath, record.install_path);
          return makeResult('record_update_failed', {
            ...context,
            message:
              'The install record could not be removed; the directory was restored.',
          });
        } catch {
          return makeResult('rollback_failed', {
            ...context,
            message:
              'The install record failed and the directory could not be restored.',
          });
        }
      }

      return makeResult('rollback_failed', {
        ...context,
        message:
          'The install record failed and automatic recovery is unsafe.',
      });
    }

    // --- Cleanup quarantine ------------------------------------------------

    try {
      this.fileOps.removeTree(quarantinePath);
      return makeResult('uninstalled', {
        ...context,
        quarantinePath: undefined,
        message: 'Package was uninstalled.',
      });
    } catch {
      return makeResult('cleanup_failed', {
        ...context,
        message:
          'The install record was removed, but quarantined files remain.',
      });
    }
  }
}
