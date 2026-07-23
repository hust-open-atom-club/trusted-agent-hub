/**
 * Local install record persistence.
 *
 * Stores a JSON array at `~/.trusted-agent-hub/installs.json` with strict
 * validation and atomic saves.  Used by the install, verify, and uninstall
 * paths.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INSTALL_RECORDS_DIR = '.trusted-agent-hub';
const INSTALL_RECORDS_FILE = 'installs.json';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class RecordStoreError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = 'RecordStoreError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LocalInstallRecord {
  package_name: string;
  version: string;
  client: string;
  install_path: string;
  sha256: string;            // artifact SHA-256
  integrity_verified: boolean;
  installed_at: string;       // ISO 8601
  manifest_version: string;
  content_hash_algorithm?: 'sha256-tree-v1';
  content_sha256?: string;      // installed content digest (may be absent for legacy records)
}

/** Canonical ordered list of every field in {@link LocalInstallRecord}.
 *  Shared between the store and the uninstall executor so that record
 *  comparison never silently diverges when a field is added. */
export const RECORD_COMPARE_FIELDS: readonly (keyof LocalInstallRecord)[] = [
  'package_name',
  'version',
  'client',
  'install_path',
  'sha256',
  'integrity_verified',
  'installed_at',
  'manifest_version',
  'content_hash_algorithm',
  'content_sha256',
];

/**
 * Narrow persistence adapter — allows tests to inject failures at specific
 * file-operation boundaries without mocking the entire `fs` module.
 *
 * The default implementation delegates to Node's real `fs` functions.
 */
export interface RecordStorePersistence {
  writeText(filePath: string, value: string): void;
  rename(source: string, destination: string): void;
  remove(filePath: string): void;
}

const defaultPersistence: RecordStorePersistence = {
  writeText(filePath, value) {
    fs.writeFileSync(filePath, value, 'utf-8');
  },
  rename(source, destination) {
    fs.renameSync(source, destination);
  },
  remove(filePath) {
    fs.unlinkSync(filePath);
  },
};

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

const REQUIRED_STRING_FIELDS = [
  'package_name',
  'version',
  'client',
  'install_path',
  'sha256',
  'installed_at',
  'manifest_version',
] as const;

function validateRecord(record: unknown, index: number): LocalInstallRecord {
  if (typeof record !== 'object' || record === null) {
    throw new RecordStoreError(
      `Record at index ${index} is not an object`,
      'record_invalid',
    );
  }

  const r = record as Record<string, unknown>;

  // ── Unknown field detection ──────────────────────────────────────────
  // Every key must be in the known set; extra fields are rejected so that
  // a save→remove round-trip never silently drops data from other records.
  // KNOWN_KEYS is derived from RECORD_COMPARE_FIELDS so that adding a field
  // to the type automatically updates both lists.
  const KNOWN_KEYS = new Set<string>(RECORD_COMPARE_FIELDS);
  for (const key of Object.keys(r)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new RecordStoreError(
        `Record at index ${index}: unknown field "${key}"`,
        'record_invalid',
      );
    }
  }

  // Required string fields
  for (const field of REQUIRED_STRING_FIELDS) {
    if (typeof r[field] !== 'string' || (r[field] as string).length === 0) {
      throw new RecordStoreError(
        `Record at index ${index}: "${field}" must be a non-empty string, got ${typeof r[field]}`,
        'record_invalid',
      );
    }
  }

  // integrity_verified must be boolean
  if (typeof r.integrity_verified !== 'boolean') {
    throw new RecordStoreError(
      `Record at index ${index}: "integrity_verified" must be a boolean`,
      'record_invalid',
    );
  }

  // Validate SHA-256 hex format for artifact hash
  if (!/^[a-f0-9]{64}$/.test(r.sha256 as string)) {
    throw new RecordStoreError(
      `Record at index ${index}: "sha256" must be a 64-char lowercase hex string`,
      'record_invalid',
    );
  }

  // Content hash fields — must be both present or both absent
  const hasAlgo = r.content_hash_algorithm !== undefined && r.content_hash_algorithm !== null;
  const hasHash = r.content_sha256 !== undefined && r.content_sha256 !== null;

  if (hasAlgo !== hasHash) {
    throw new RecordStoreError(
      `Record at index ${index}: "content_hash_algorithm" and "content_sha256" must both be present or both absent`,
      'record_invalid',
    );
  }

  let content_hash_algorithm: 'sha256-tree-v1' | undefined;
  let content_sha256: string | undefined;

  if (hasAlgo) {
    if (r.content_hash_algorithm !== 'sha256-tree-v1') {
      throw new RecordStoreError(
        `Record at index ${index}: "content_hash_algorithm" must be "sha256-tree-v1"`,
        'record_invalid',
      );
    }
    content_hash_algorithm = 'sha256-tree-v1';

    if (typeof r.content_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.content_sha256 as string)) {
      throw new RecordStoreError(
        `Record at index ${index}: "content_sha256" must be a 64-char lowercase hex string`,
        'record_invalid',
      );
    }
    content_sha256 = r.content_sha256 as string;
  }

  return {
    package_name: r.package_name as string,
    version: r.version as string,
    client: r.client as string,
    install_path: r.install_path as string,
    sha256: r.sha256 as string,
    integrity_verified: r.integrity_verified as boolean,
    installed_at: r.installed_at as string,
    manifest_version: r.manifest_version as string,
    content_hash_algorithm,
    content_sha256,
  };
}

/**
 * Compare two records field-by-field — used by `remove()` to ensure the
 * record hasn't changed since a caller last read it.
 */
function recordsMatch(a: LocalInstallRecord, b: LocalInstallRecord): boolean {
  for (const key of RECORD_COMPARE_FIELDS) {
    if (a[key] !== b[key]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export class LocalInstallStore {
  private readonly homeDir: string;
  private readonly persistence: RecordStorePersistence;

  /** Test-only hook invoked after temp-file write and before renameSync.
   *  Throw to simulate a rename failure while the original file is intact.
   *
   *  @deprecated Prefer injecting a custom {@link RecordStorePersistence}
   *  through the constructor for new tests; this static hook remains for
   *  backward compatibility with existing `save()` tests only.
   */
  static _beforeRenameHook: ((tmpPath: string, targetPath: string) => void) | null = null;

  constructor(homeDir?: string, persistence?: RecordStorePersistence) {
    this.homeDir = homeDir || os.homedir();
    this.persistence = persistence || defaultPersistence;
  }

  /** Filesystem path of the install records file. */
  getPath(): string {
    const dir = path.resolve(this.homeDir, INSTALL_RECORDS_DIR);
    return path.join(dir, INSTALL_RECORDS_FILE);
  }

  /**
   * Load and strictly validate all install records.
   *
   * Throws `RecordStoreError` with code `record_invalid` if the file exists
   * but is corrupt (bad JSON, missing fields, wrong types, duplicate entries).
   * Returns an empty array only when the file does not exist.
   */
  load(): LocalInstallRecord[] {
    const filePath = this.getPath();
    if (!fs.existsSync(filePath)) {
      return [];
    }

    let raw: unknown;
    try {
      const text = fs.readFileSync(filePath, 'utf-8');
      raw = JSON.parse(text);
    } catch (err: unknown) {
      throw new RecordStoreError(
        `Install records file is corrupted (invalid JSON): ${err instanceof Error ? err.message : String(err)}`,
        'record_invalid',
      );
    }

    if (!Array.isArray(raw)) {
      throw new RecordStoreError(
        'Install records file must contain a JSON array',
        'record_invalid',
      );
    }

    const records = raw.map((item, idx) => validateRecord(item, idx));

    // Check for duplicate name+client combinations
    const seen = new Set<string>();
    for (const r of records) {
      const key = `${r.package_name}\0${r.client}`;
      if (seen.has(key)) {
        throw new RecordStoreError(
          `Duplicate record for package "${r.package_name}" and client "${r.client}"`,
          'record_invalid',
        );
      }
      seen.add(key);
    }

    return records;
  }

  /** Find a record by package name and client. */
  find(packageName: string, client: string): LocalInstallRecord | null {
    const records = this.load();
    return records.find(
      (r) => r.package_name === packageName && r.client === client,
    ) || null;
  }

  // -----------------------------------------------------------------------
  // Atomic write helper
  // -----------------------------------------------------------------------

  /**
   * Write `records` to the install file atomically using a temp file and
   * rename.  Cleans up the temp file on any failure.
   */
  private writeRecordsAtomically(records: LocalInstallRecord[]): void {
    const filePath = this.getPath();
    const dir = path.dirname(filePath);

    // Ensure the directory exists
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Write to a temp file, then atomically rename
    const tmpPath = filePath + '.tmp-' + Date.now() + '-' +
      Math.random().toString(36).slice(2, 8);
    try {
      this.persistence.writeText(tmpPath, JSON.stringify(records, null, 2));
      // Backward-compatible static hook for existing tests
      if (LocalInstallStore._beforeRenameHook) {
        LocalInstallStore._beforeRenameHook(tmpPath, filePath);
      }
      this.persistence.rename(tmpPath, filePath);
    } catch (err: unknown) {
      // Clean up temp file on failure
      try { this.persistence.remove(tmpPath); } catch { /* ignore */ }
      throw new RecordStoreError(
        `Failed to save install records: ${err instanceof Error ? err.message : String(err)}`,
        'save_failed',
      );
    }
  }

  // -----------------------------------------------------------------------
  // Save
  // -----------------------------------------------------------------------

  /**
   * Save or update a record with atomic replacement.
   *
   * The incoming record is validated through {@link validateRecord} before
   * touching the file — invalid records (extra fields, wrong types, bad SHA
   * format, mismatched content-hash fields) are rejected without modifying
   * the existing file.
   *
   * Writes to a temporary file in the same directory, then renames it over
   * the target.  If the write or rename fails, the temporary file is cleaned
   * up and the original file is preserved.
   */
  save(record: LocalInstallRecord): void {
    // Validate BEFORE loading or touching the file.  This prevents
    // an invalid record from being persisted, which would make the
    // file unreadable on the next load().
    const validated = validateRecord(record, -1);

    const records = this.load();
    const idx = records.findIndex(
      (r) => r.package_name === validated.package_name && r.client === validated.client,
    );

    if (idx >= 0) {
      records[idx] = validated;
    } else {
      records.push(validated);
    }

    this.writeRecordsAtomically(records);
  }

  // -----------------------------------------------------------------------
  // Remove
  // -----------------------------------------------------------------------

  /**
   * Atomically remove a record by `package_name` + `client`.
   *
   * - Loads and validates the full array, removes the matching entry, and
   *   writes the remaining records atomically.
   * - Returns the removed record, or `null` if no match is found.
   * - When `expectedRecord` is supplied, the current record (before removal)
   *   is compared field-by-field against it.  If the record is absent or has
   *   changed, a {@link RecordStoreError} with code `record_changed` is
   *   thrown **without** writing to disk.
   */
  remove(
    packageName: string,
    client: string,
    expectedRecord?: LocalInstallRecord,
  ): LocalInstallRecord | null {
    // Must load the full array first to validate integrity
    const records = this.load();

    const idx = records.findIndex(
      (r) => r.package_name === packageName && r.client === client,
    );

    if (idx < 0) {
      // Not found
      if (expectedRecord) {
        throw new RecordStoreError(
          `Record for "${packageName}" (client: "${client}") not found — may have been removed concurrently.`,
          'record_changed',
        );
      }
      return null;
    }

    // If an expected snapshot was provided, verify the current record matches
    if (expectedRecord) {
      if (!recordsMatch(records[idx], expectedRecord)) {
        throw new RecordStoreError(
          `Record for "${packageName}" (client: "${client}") changed since last read.`,
          'record_changed',
        );
      }
    }

    const removed = records[idx];

    // Write back the remaining records atomically
    const remaining = [...records.slice(0, idx), ...records.slice(idx + 1)];
    this.writeRecordsAtomically(remaining);

    return removed;
  }
}
