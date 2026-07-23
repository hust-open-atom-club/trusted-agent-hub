/**
 * TrustedAgentHub Verify Executor — read-only package integrity verification.
 *
 * Validates installed content against both the local install record and the
 * server-side manifest, without downloading archives, executing commands, or
 * modifying local or remote state.
 *
 * Safety guarantees:
 *   - Read-only: no writes to install directory or installs.json
 *   - No symlink following
 *   - No reads outside the client root
 *   - No command execution
 *   - Only queries the exact version recorded at install time
 *   - Fails closed on any ambiguous state
 *   - Never leaks response bodies, tokens, or file content in error messages
 */

import * as fs from 'fs';
import * as os from 'os';

import { LocalInstallStore } from './local-install-store';
import type { LocalInstallRecord } from './local-install-store';
import { computeDirectoryDigest, ContentIntegrityError, validateAncestorChain } from './content-integrity';
import { isStrictChildPath, getClientRoot, isSupportedClient, resolveManifestDestination } from './client-paths';
import { validateManifest, ManifestValidationError } from './manifest-types';
import type { InstallManifest, CopyStep } from './manifest-types';
import { ApiError } from './api-client';

// ---------------------------------------------------------------------------
// Safe output: strips ANSI, OSC, CR, LF, C0/C1 control characters and
// truncates to a maximum length.  Prevents terminal injection via crafted
// package names, client identifiers, paths, or server responses.
// ---------------------------------------------------------------------------

const MAX_OUTPUT_LENGTH = 200;

// C0: U+0000–U+001F, C1: U+0080–U+009F, plus DEL (U+007F)
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f\x80-\x9f]/g;
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;
const OSC_RE = /\x1b\].*?(\x07|\x1b\\)/g;

export function sanitizeOutput(input: string): string {
  let out = input
    .replace(OSC_RE, '')
    .replace(ANSI_RE, '')
    .replace(CONTROL_RE, '')
    .replace(/[\r\n]/g, ' ');
  if (out.length > MAX_OUTPUT_LENGTH) {
    out = out.slice(0, MAX_OUTPUT_LENGTH - 1) + '…';
  }
  return out;
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export type VerifyStatus =
  | 'valid'
  | 'not_installed'
  | 'record_invalid'
  | 'legacy_record'
  | 'unsupported_client'
  | 'unsafe_path'
  | 'missing'
  | 'unsafe_content'
  | 'modified'
  | 'manifest_mismatch'
  | 'remote_unavailable';

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

export interface VerifyResult {
  ok: boolean;
  status: VerifyStatus;
  packageName: string;
  version?: string;
  client: string;
  installPath?: string;
  artifactSha256?: string;
  expectedContentSha256?: string;
  actualContentSha256?: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface VerifyOptions {
  homeDir?: string;
  maxFiles?: number;
  maxBytes?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function result(
  status: VerifyStatus,
  pkg: string,
  client: string,
  message: string,
  extras: Partial<Pick<VerifyResult, 'version' | 'installPath' | 'artifactSha256' | 'expectedContentSha256' | 'actualContentSha256'>> = {},
): VerifyResult {
  const { installPath: rawInstallPath, version: rawVersion, ...restExtras } = extras;
  const installPath = rawInstallPath ? sanitizeOutput(rawInstallPath) : undefined;
  const version = rawVersion ? sanitizeOutput(rawVersion) : undefined;
  return {
    ok: status === 'valid',
    status,
    packageName: sanitizeOutput(pkg),
    client: sanitizeOutput(client),
    version,
    message: sanitizeOutput(message),
    ...restExtras,
    installPath,
  };
}

/**
 * Classify a network / API error into either `manifest_mismatch` or
 * `remote_unavailable`.  Must never leak tokens, response bodies, or file
 * contents into the error message.
 */
function classifyRemoteError(err: unknown): { status: 'manifest_mismatch' | 'remote_unavailable'; message: string } {
  if (err instanceof ApiError) {
    // 404 → manifest_mismatch (version no longer exists)
    if (err.statusCode === 404) {
      return {
        status: 'manifest_mismatch',
        message: 'The installed version is no longer available on the registry (404).',
      };
    }
    // 409 → manifest_mismatch (manifest unavailable for this combination)
    if (err.statusCode === 409) {
      return {
        status: 'manifest_mismatch',
        message: 'The installed version does not have a valid manifest on the registry (409).',
      };
    }
    // 429 (rate limit) → remote_unavailable (transient)
    if (err.statusCode === 429) {
      return {
        status: 'remote_unavailable',
        message: 'Registry rate limit exceeded. Try again later.',
      };
    }
    // 4xx other than 404/409/429 → manifest_mismatch
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
      return {
        status: 'manifest_mismatch',
        message: `Registry rejected manifest request (HTTP ${err.statusCode}).`,
      };
    }
  }

  // Network errors, timeouts, 429, 5xx, unknown → remote_unavailable
  return {
    status: 'remote_unavailable',
    message: 'Cannot reach the registry to verify the manifest. Check your network connection.',
  };
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

export class VerifyExecutor {
  private readonly store: LocalInstallStore;
  private readonly homeDir: string;
  private readonly maxFiles: number | undefined;
  private readonly maxBytes: number | undefined;

  constructor(
    private apiClient: ReturnType<typeof import('./api-client').createApiClient>,
    options: VerifyOptions = {},
  ) {
    this.homeDir = options.homeDir || os.homedir();
    this.store = new LocalInstallStore(this.homeDir);
    this.maxFiles = options.maxFiles;
    this.maxBytes = options.maxBytes;
  }

  // -----------------------------------------------------------------------
  // Public: verify
  // -----------------------------------------------------------------------

  async verify(packageName: string, client: string): Promise<VerifyResult> {
    // 1. Strictly load records and find by name+client
    let records: LocalInstallRecord[];
    try {
      records = this.store.load();
    } catch {
      return result(
        'record_invalid',
        packageName,
        client,
        'The local install records file is corrupted. Reinstall the package to repair.',
      );
    }

    const record = records.find(
      (r) => r.package_name === packageName && r.client === client,
    );

    if (!record) {
      return result(
        'not_installed',
        packageName,
        client,
        `Package "${packageName}" is not installed for client "${client}".`,
      );
    }

    // 2. Check client support
    if (!isSupportedClient(record.client)) {
      return result(
        'unsupported_client',
        packageName,
        client,
        `Client "${record.client}" is not supported.`,
        { version: record.version },
      );
    }

    // 3. Check install_path is a strict child of the client root
    let clientRoot: string;
    try {
      clientRoot = getClientRoot(record.client, this.homeDir);
    } catch {
      return result(
        'unsupported_client',
        packageName,
        client,
        `Cannot resolve client root for "${record.client}".`,
        { version: record.version },
      );
    }

    if (!isStrictChildPath(record.install_path, clientRoot)) {
      return result(
        'unsafe_path',
        packageName,
        client,
        `Install path "${record.install_path}" is outside the client root. The record may have been tampered with.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // 4. Check target exists and is a regular directory
    let targetStat: fs.Stats;
    try {
      targetStat = fs.lstatSync(record.install_path);
    } catch {
      return result(
        'missing',
        packageName,
        client,
        `Installed directory "${record.install_path}" no longer exists.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    if (targetStat.isSymbolicLink()) {
      return result(
        'unsafe_content',
        packageName,
        client,
        `Installed path "${record.install_path}" is a symbolic link — must be a real directory.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    if (!targetStat.isDirectory()) {
      return result(
        'missing',
        packageName,
        client,
        `Installed path "${record.install_path}" is not a directory.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // 5. Record integrity pre-checks (before touching the filesystem or network)
    //
    // integrity_verified must be true — a record written without SHA-256
    // verification of the downloaded archive is untrustworthy.
    if (record.integrity_verified !== true) {
      return result(
        'record_invalid',
        packageName,
        client,
        `Install record for "${packageName}" was not integrity-verified at install time. Reinstall to repair.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // content_hash_algorithm and content_sha256 must be both present or both
    // absent.  One without the other is a corrupted record.
    const hasAlgo = record.content_hash_algorithm !== undefined && record.content_hash_algorithm !== null;
    const hasHash = record.content_sha256 !== undefined && record.content_sha256 !== null;

    if (hasAlgo !== hasHash) {
      return result(
        'record_invalid',
        packageName,
        client,
        `Install record for "${packageName}" has mismatched content hash fields. Reinstall to repair.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // Legacy record — both fields missing (installed by older CLI)
    if (!hasHash) {
      return result(
        'legacy_record',
        packageName,
        client,
        `Package "${packageName}" was installed with an older client version that did not record a content digest. ` +
        'Reinstall to enable content verification.',
        { version: record.version, installPath: record.install_path, artifactSha256: record.sha256 },
      );
    }

    // content_sha256 must be exactly 64 lowercase hex chars
    if (record.content_sha256 && !/^[a-f0-9]{64}$/.test(record.content_sha256)) {
      return result(
        'record_invalid',
        packageName,
        client,
        `Install record for "${packageName}" has an invalid content digest format. Reinstall to repair.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // artifact sha256 must be exactly 64 lowercase hex chars
    if (!/^[a-f0-9]{64}$/.test(record.sha256)) {
      return result(
        'record_invalid',
        packageName,
        client,
        `Install record for "${packageName}" has an invalid artifact SHA format. Reinstall to repair.`,
        { version: record.version, installPath: record.install_path },
      );
    }

    // 6. Validate ancestor chain — ensure no parent directory is a symlink or
    //    junction that could redirect the lexical path outside the client root.
    try {
      validateAncestorChain(record.install_path);
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return result(
          'unsafe_path',
          packageName,
          client,
          `Install path ancestor is unsafe: ${err.message}`,
          { version: record.version, installPath: record.install_path },
        );
      }
      throw err;
    }

    // Also validate the client root ancestor chain
    try {
      validateAncestorChain(clientRoot);
    } catch (err: unknown) {
      if (err instanceof ContentIntegrityError) {
        return result(
          'unsafe_path',
          packageName,
          client,
          `Client root ancestor is unsafe: ${err.message}`,
          { version: record.version, installPath: record.install_path },
        );
      }
      throw err;
    }

    // content_sha256 is guaranteed defined past this point (legacy check above)
    const expectedContentSha256 = record.content_sha256!;

    // 7. Recompute and compare directory digest
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
          return result(
            'unsafe_content',
            packageName,
            client,
            `Installed content contains unsafe file types: ${err.message}`,
            {
              version: record.version,
              installPath: record.install_path,
              artifactSha256: record.sha256,
              expectedContentSha256,
            },
          );
        }
        if (err.code === 'missing') {
          return result(
            'missing',
            packageName,
            client,
            `Cannot read installed directory: ${err.message}`,
            {
              version: record.version,
              installPath: record.install_path,
              artifactSha256: record.sha256,
              expectedContentSha256,
            },
          );
        }
        // read_error → treat as modified (unreadable content)
        return result(
          'modified',
          packageName,
          client,
          `Cannot read installed content: ${err.message}`,
          {
            version: record.version,
            installPath: record.install_path,
            artifactSha256: record.sha256,
            expectedContentSha256,
          },
        );
      }
      throw err;
    }

    if (actualDigest !== expectedContentSha256) {
      return result(
        'modified',
        packageName,
        client,
        `Installed content has been modified since installation. ` +
        `Expected digest: ${expectedContentSha256.slice(0, 16)}…, ` +
        `actual: ${actualDigest.slice(0, 16)}…`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // 8. Request the exact manifest by version from the server
    let rawManifest: unknown;
    try {
      rawManifest = await this.apiClient.getInstallManifest(
        packageName,
        record.client,
        record.version,
      );
    } catch (err: unknown) {
      const { status, message } = classifyRemoteError(err);
      return result(
        status,
        packageName,
        client,
        message,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // 9. Validate manifest structure.  Catch TypeError as well — malformed
    //    steps arrays (e.g. [null]) can cause crashes inside validateManifest.
    let manifest: InstallManifest;
    try {
      manifest = validateManifest(rawManifest);
    } catch (err: unknown) {
      if (err instanceof ManifestValidationError || err instanceof TypeError) {
        return result(
          'manifest_mismatch',
          packageName,
          client,
          `Registry manifest for the installed version failed structural validation. The manifest may have been modified server-side.`,
          {
            version: record.version,
            installPath: record.install_path,
            artifactSha256: record.sha256,
            expectedContentSha256,
            actualContentSha256: actualDigest,
          },
        );
      }
      throw err;
    }

    // 10. Verify manifest installation method — only copy_directory is
    //     supported by the current installer and verifier.
    if (manifest.installation.method !== 'copy_directory') {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest installation method is not supported. Only copy_directory is accepted.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // Require exactly one copy step
    const copySteps = manifest.installation.steps.filter(
      (s): s is CopyStep => s.action === 'copy',
    );
    if (copySteps.length !== 1) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest must contain exactly one copy step (found ${copySteps.length}).`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // 11. Compare manifest fields with record
    if (manifest.name !== record.package_name) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest package name does not match the install record.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    if (manifest.version !== record.version) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest version does not match the install record.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    if (manifest.installation.target_client !== record.client) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest target client does not match the install record.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    if (manifest.manifest_version !== record.manifest_version) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest format version does not match the install record.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // Compare artifact SHA-256
    if (manifest.integrity.sha256 !== record.sha256) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest artifact SHA-256 does not match the install record.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // 12. Resolve copy destination and compare with record.install_path
    const copyStep = copySteps[0];
    let expectedPath: string;
    try {
      expectedPath = resolveManifestDestination(
        copyStep.destination,
        record.client,
        clientRoot,
      );
    } catch {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        'Manifest copy destination could not be resolved.',
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    if (expectedPath !== record.install_path) {
      return result(
        'manifest_mismatch',
        packageName,
        client,
        `Manifest destination does not match the install record path.`,
        {
          version: record.version,
          installPath: record.install_path,
          artifactSha256: record.sha256,
          expectedContentSha256,
          actualContentSha256: actualDigest,
        },
      );
    }

    // 13. All checks passed — valid
    return result(
      'valid',
      packageName,
      client,
      `Package "${packageName}" v${record.version} is correctly installed for "${record.client}".`,
      {
        version: record.version,
        installPath: record.install_path,
        artifactSha256: record.sha256,
        expectedContentSha256,
        actualContentSha256: actualDigest,
      },
    );
  }
}
