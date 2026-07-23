/**
 * Shared client path validation rules.
 *
 * Extracted from install-executor so that both install and verify can
 * use the same path-resolution logic without duplication.
 */

import * as path from 'path';
import * as os from 'os';

// ---------------------------------------------------------------------------
// Client install root mappings (mirrors apps/api/src/services/install.py)
// ---------------------------------------------------------------------------

export const CLIENT_INSTALL_ROOTS: Record<string, string> = {
  'claude-code': '.claude/skills',
  cursor: '.cursor/skills',
} as const;

/**
 * Logical roots used in Manifest destination fields.
 * The server sends destinations like `~/.claude/skills/<package>/`.
 * The CLI strips this prefix and joins the remainder to the real HOME-based root.
 */
export const CLIENT_MANIFEST_ROOTS: Record<string, string> = {
  'claude-code': '~/.claude/skills/',
  cursor: '~/.cursor/skills/',
} as const;

// ---------------------------------------------------------------------------
// Supported clients (derived from CLIENT_INSTALL_ROOTS keys)
// ---------------------------------------------------------------------------

export const SUPPORTED_CLIENTS: readonly string[] =
  Object.keys(CLIENT_INSTALL_ROOTS);

export function isSupportedClient(client: string): boolean {
  return Object.prototype.hasOwnProperty.call(CLIENT_INSTALL_ROOTS, client);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ClientPathError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = 'ClientPathError';
  }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/** Resolve the client-specific root directory. */
export function getClientRoot(clientType: string, homeDir?: string): string {
  const rel = CLIENT_INSTALL_ROOTS[clientType];
  if (!rel) {
    throw new ClientPathError(
      `Unsupported client: "${clientType}". Supported clients: ${SUPPORTED_CLIENTS.join(', ')}`,
      'unsupported_client',
    );
  }
  return path.resolve(homeDir || os.homedir(), rel);
}

/**
 * Check that `child` is a strict descendant of `parent` (not equal, not outside).
 */
export function isStrictChildPath(child: string, parent: string): boolean {
  const normalizedChild = path.resolve(child);
  const normalizedParent = path.resolve(parent);
  return (
    normalizedChild !== normalizedParent &&
    normalizedChild.startsWith(normalizedParent + path.sep)
  );
}

/**
 * Resolve a server-supplied logical destination (e.g. `~/.claude/skills/pkg/`)
 * into a real filesystem path under the client root.
 *
 * The manifest root prefix is stripped, and the remainder is joined to the
 * platform-native clientRoot.  This prevents the CLI from creating a literal
 * `~` directory or double-nesting the logical root under the real root.
 */
export function resolveManifestDestination(
  destination: string,
  clientType: string,
  clientRoot: string,
): string {
  const manifestRoot = CLIENT_MANIFEST_ROOTS[clientType];
  if (!manifestRoot) {
    throw new ClientPathError(
      `Unsupported client: "${clientType}"`,
      'unsupported_client',
    );
  }

  if (!destination.startsWith(manifestRoot)) {
    throw new ClientPathError(
      `Manifest destination "${destination}" is outside the declared root "${manifestRoot}"`,
      'destination_root_mismatch',
    );
  }

  const relative = destination.slice(manifestRoot.length);

  // Must identify a child directory — at least one non-empty segment
  if (!relative || relative === '/') {
    throw new ClientPathError(
      `Manifest destination "${destination}" does not identify a safe child directory`,
      'invalid_destination',
    );
  }

  // Strip trailing slashes for segment analysis
  const cleanRelative = relative.endsWith('/') ? relative.slice(0, -1) : relative;

  // Security: reject traversal attempts in the relative portion
  const segments = cleanRelative.split('/');
  if (segments.includes('..') || segments.includes('.')) {
    throw new ClientPathError(
      `Manifest destination "${destination}" contains path traversal`,
      'invalid_destination',
    );
  }

  if (segments.some(s => s.length === 0)) {
    throw new ClientPathError(
      `Manifest destination "${destination}" contains an empty path segment`,
      'invalid_destination',
    );
  }

  // The Manifest uses POSIX `/` separators; split and re-join via platform
  // path.resolve so the result uses the correct native separators.
  const targetDir = path.resolve(
    clientRoot,
    ...segments,
  );

  if (!isStrictChildPath(targetDir, clientRoot)) {
    throw new ClientPathError(
      `Target directory "${destination}" escapes client root`,
      'path_escape',
    );
  }

  return targetDir;
}
