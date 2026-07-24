/**
 * Read-only local install inspector — shared by verify, uninstall, and update.
 *
 * Extracts the common logic of:
 *   1. Looking up install records by name + client
 *   2. Validating client support
 *   3. Validating install path safety (client root, strict child, ancestor chain)
 *   4. Checking target directory existence and type (no symlinks)
 *   5. Recomputing content digest
 *   6. Classifying content state (clean / modified / missing / legacy / unsafe)
 *
 * All checks are **read-only** — no files are modified, no records are written,
 * and no external commands are executed.
 */

import * as fs from 'fs';
import * as os from 'os';

import { LocalInstallStore } from './local-install-store';
import type { LocalInstallRecord } from './local-install-store';
import {
  computeDirectoryDigest,
  ContentIntegrityError,
  validateAncestorChain,
} from './content-integrity';
import {
  isStrictChildPath,
  getClientRoot,
  isSupportedClient,
} from './client-paths';
import { sanitizeOutput } from './safe-output';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ContentState =
  | 'clean'
  | 'modified'
  | 'missing'
  | 'legacy_record'
  | 'unsafe_path'
  | 'unsafe_content'
  | 'record_invalid';

export interface InspectResult {
  /** Whether the inspection passed all checks with a clean bill of health. */
  ok: boolean;

  /** The matched install record (null if not found). */
  record: LocalInstallRecord | null;

  /** The content state classification. */
  contentState: ContentState;

  /** Human-readable message (sanitized). */
  message: string;

  /** Re-computed content digest (only when the target exists and is readable). */
  actualContentSha256?: string;

  /** Expected content digest from the record (may be absent for legacy records). */
  expectedContentSha256?: string;

  /** Resolved client root directory. */
  clientRoot?: string;
}

export interface InspectOptions {
  /** Override the home directory (for testing). */
  homeDir?: string;
  /** Maximum files for directory digest computation. */
  maxFiles?: number;
  /** Maximum bytes for directory digest computation. */
  maxBytes?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(
  record: LocalInstallRecord | null,
  contentState: ContentState,
  message: string,
  extras: Partial<Pick<InspectResult, 'actualContentSha256' | 'expectedContentSha256' | 'clientRoot'>> = {},
): InspectResult {
  return {
    ok: contentState === 'clean',
    record,
    contentState,
    message: sanitizeOutput(message),
    ...extras,
  };
}

// ---------------------------------------------------------------------------
// Inspector
// ---------------------------------------------------------------------------

export class LocalInstallInspector {
  private readonly store: LocalInstallStore;
  private readonly homeDir: string;
  private readonly maxFiles: number | undefined;
  private readonly maxBytes: number | undefined;

  constructor(options: InspectOptions = {}) {
    this.homeDir = options.homeDir || os.homedir();
    this.store = new LocalInstallStore(this.homeDir);
    this.maxFiles = options.maxFiles;
    this.maxBytes = options.maxBytes;
  }

  // -----------------------------------------------------------------------
  // Public: inspect
  // -----------------------------------------------------------------------

  /**
   * Perform a full read-only inspection of a package installed for a client.
   *
   * Returns an `InspectResult` describing the state of the installation.
   * This method never modifies files, records, or external state.
   */
  async inspect(packageName: string, client: string): Promise<InspectResult> {
    // 1. Load records and find by name+client
    let records: LocalInstallRecord[];
    try {
      records = this.store.load();
    } catch {
      return makeResult(
        null,
        'record_invalid',
        'The local install records file is corrupted.',
      );
    }

    const record = records.find(
      (r) => r.package_name === packageName && r.client === client,
    );

    if (!record) {
      return makeResult(
        null,
        'missing', // semantically "not installed"
        `Package "${packageName}" is not installed for client "${client}".`,
      );
    }

    // 2. Check client support
    if (!isSupportedClient(record.client)) {
      return makeResult(
        record,
        'unsafe_path',
        `Client "${record.client}" is not supported.`,
      );
    }

    // 3. Resolve client root; install_path must be strict child
    let clientRoot: string;
    try {
      clientRoot = getClientRoot(record.client, this.homeDir);
    } catch {
      return makeResult(
        record,
        'unsafe_path',
        `Cannot resolve client root for "${record.client}".`,
      );
    }

    if (!isStrictChildPath(record.install_path, clientRoot)) {
      return makeResult(
        record,
        'unsafe_path',
        `Install path "${record.install_path}" is outside the client root.`,
      );
    }

    // 4. Check target exists and is a directory (not symlink) BEFORE
    //    validating ancestor chains. A missing target must not be
    //    flagged as unsafe_path.
    let targetStat: fs.Stats;
    try {
      targetStat = fs.lstatSync(record.install_path);
    } catch {
      return makeResult(
        record,
        'missing',
        `Installed directory "${record.install_path}" no longer exists.`,
        { clientRoot },
      );
    }

    if (targetStat.isSymbolicLink()) {
      return makeResult(
        record,
        'unsafe_content',
        `Installed path "${record.install_path}" is a symbolic link.`,
        { clientRoot },
      );
    }

    if (!targetStat.isDirectory()) {
      return makeResult(
        record,
        'missing',
        `Installed path "${record.install_path}" is not a directory.`,
        { clientRoot },
      );
    }

    // 5. Validate ancestor chains
    try {
      validateAncestorChain(record.install_path);
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return makeResult(
          record,
          'unsafe_path',
          `Install path ancestor is unsafe: ${err.message}`,
          { clientRoot },
        );
      }
      throw err;
    }

    try {
      validateAncestorChain(clientRoot);
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return makeResult(
          record,
          'unsafe_path',
          `Client root ancestor is unsafe: ${err.message}`,
          { clientRoot },
        );
      }
      throw err;
    }

    // 6. Record integrity pre-checks (renumbered from 6)
    if (record.integrity_verified !== true) {
      return makeResult(
        record,
        'record_invalid',
        `Install record for "${packageName}" was not integrity-verified at install time.`,
        { clientRoot },
      );
    }

    // content_hash_algorithm and content_sha256: both present or both absent
    const hasAlgo = record.content_hash_algorithm !== undefined && record.content_hash_algorithm !== null;
    const hasHash = record.content_sha256 !== undefined && record.content_sha256 !== null;

    if (hasAlgo !== hasHash) {
      return makeResult(
        record,
        'record_invalid',
        `Install record for "${packageName}" has mismatched content hash fields.`,
        { clientRoot },
      );
    }

    // Validate SHA formats
    if (record.content_sha256 && !/^[a-f0-9]{64}$/.test(record.content_sha256)) {
      return makeResult(
        record,
        'record_invalid',
        `Install record for "${packageName}" has an invalid content digest format.`,
        { clientRoot },
      );
    }

    if (!/^[a-f0-9]{64}$/.test(record.sha256)) {
      return makeResult(
        record,
        'record_invalid',
        `Install record for "${packageName}" has an invalid artifact SHA format.`,
        { clientRoot },
      );
    }

    // 7. Legacy record check
    if (!hasHash) {
      return makeResult(
        record,
        'legacy_record',
        `Package "${packageName}" was installed with an older client that did not record a content digest.`,
        {
          clientRoot,
          expectedContentSha256: undefined,
          actualContentSha256: undefined,
        },
      );
    }

    const expectedContentSha256 = record.content_sha256!;

    // 8. Recompute content digest
    let actualDigest: string;
    try {
      const digest = await computeDirectoryDigest(record.install_path, {
        maxFiles: this.maxFiles,
        maxBytes: this.maxBytes,
      });
      actualDigest = digest.digest;
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        if (err.code === 'unsafe_content') {
          return makeResult(
            record,
            'unsafe_content',
            `Installed content contains unsafe file types: ${err.message}`,
            { clientRoot, expectedContentSha256 },
          );
        }
        if (err.code === 'missing') {
          return makeResult(
            record,
            'missing',
            `Cannot read installed directory: ${err.message}`,
            { clientRoot, expectedContentSha256 },
          );
        }
        return makeResult(
          record,
          'modified',
          `Cannot read installed content: ${err.message}`,
          { clientRoot, expectedContentSha256 },
        );
      }
      throw err;
    }

    // 9. Compare digest
    if (actualDigest !== expectedContentSha256) {
      return makeResult(
        record,
        'modified',
        `Installed content has been modified since installation. ` +
        `Expected: ${expectedContentSha256.slice(0, 16)}…, ` +
        `actual: ${actualDigest.slice(0, 16)}…`,
        { clientRoot, expectedContentSha256, actualContentSha256: actualDigest },
      );
    }

    // 10. All checks passed — clean
    return makeResult(
      record,
      'clean',
      `Package "${packageName}" is clean and verified.`,
      {
        clientRoot,
        expectedContentSha256,
        actualContentSha256: actualDigest,
      },
    );
  }

  // -----------------------------------------------------------------------
  // Public: convenience accessors
  // -----------------------------------------------------------------------

  /** Expose the underlying store. */
  getStore(): LocalInstallStore {
    return this.store;
  }

  /** Expose the home directory. */
  getHomeDir(): string {
    return this.homeDir;
  }
}
