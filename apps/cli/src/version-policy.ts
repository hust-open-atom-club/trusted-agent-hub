/**
 * Strict SemVer comparison for CLI update flows.
 *
 * When comparing local versus remote versions:
 *   - Rejects illegal version strings (fail-closed).
 *   - Remote > local  → upgrade permitted.
 *   - Remote = local  → up-to-date, no write needed.
 *   - Remote < local  → downgrade blocked (downgrade_blocked).
 *
 * Uses the `semver` package for canonical comparison so pre-release tags,
 * build metadata, and coercion are handled consistently.
 */

import { valid, gt, lt, eq } from 'semver';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VersionComparison =
  | 'upgrade'
  | 'up_to_date'
  | 'downgrade_blocked'
  | 'invalid_version';

export interface VersionPolicyResult {
  decision: VersionComparison;
  localVersion: string;
  remoteVersion: string;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class VersionPolicyError extends Error {
  constructor(
    message: string,
    public code: string,
    public localVersion: string,
    public remoteVersion: string,
  ) {
    super(message);
    this.name = 'VersionPolicyError';
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compare a locally-installed version against a candidate remote version.
 *
 * Both versions are validated as strict SemVer strings before comparison.
 * Invalid versions result in `invalid_version`.
 */
export function compareVersions(
  localVersion: string,
  remoteVersion: string,
): VersionPolicyResult {
  // Validate both versions
  const localValid = valid(localVersion);
  const remoteValid = valid(remoteVersion);

  if (!localValid || !remoteValid) {
    const result: VersionPolicyResult = {
      decision: 'invalid_version',
      localVersion,
      remoteVersion,
    };
    return result;
  }

  if (gt(remoteVersion, localVersion)) {
    return { decision: 'upgrade', localVersion, remoteVersion };
  }

  if (eq(remoteVersion, localVersion)) {
    return { decision: 'up_to_date', localVersion, remoteVersion };
  }

  // remote < local
  return { decision: 'downgrade_blocked', localVersion, remoteVersion };
}

/**
 * Validate a version string is strict SemVer.
 */
export function isValidVersion(version: string): boolean {
  return valid(version) !== null;
}
