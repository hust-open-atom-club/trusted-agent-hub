/**
 * Pure grade-based install gating logic.
 *
 * All functions are pure data transforms — no I/O, no filesystem, no commander.
 * This lets us unit-test the safety invariants without mock data or runtime.
 */

import { GRADE_INSTALL_POLICY, RISK_LEVEL_TO_GRADE } from '../../../packages/schema/constants';
import type { Grade } from '../../../packages/schema/constants';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GradeInput {
  /** Backend-supplied grade (A-E) — preferred */
  grade?: string | null;
  /** Package-level risk_level (fallback) */
  riskLevel?: string | null;
  /** Version-level risk_summary.level (fallback) */
  versionLevel?: string | null;
}

export type GateResult =
  | { allowed: true; grade: string; policy: string }
  | { allowed: false; grade: string; reason: string };

// ---------------------------------------------------------------------------
// Grade resolution
// ---------------------------------------------------------------------------

/**
 * Resolve a grade from available inputs.
 *
 * Priority:
 *   1. Backend `grade` field (A-E)
 *   2. Package-level `risk_level` → grade mapping
 *   3. Version-level `risk_summary.level` → grade mapping
 *   4. null — unknown
 *
 * Invalid grades (non A-E) are treated as null for safety.
 */
export function resolveGrade(input: GradeInput): string | null {
  // 1. Backend grade
  if (input.grade && /^[A-E]$/.test(input.grade)) {
    return input.grade;
  }

  // 2. Package risk_level
  if (input.riskLevel && input.riskLevel in RISK_LEVEL_TO_GRADE) {
    return RISK_LEVEL_TO_GRADE[input.riskLevel];
  }

  // 3. Version risk_summary.level
  if (input.versionLevel && input.versionLevel in RISK_LEVEL_TO_GRADE) {
    return RISK_LEVEL_TO_GRADE[input.versionLevel];
  }

  return null;
}

// ---------------------------------------------------------------------------
// Install gating
// ---------------------------------------------------------------------------

/**
 * Grade → safety policy (from constants).
 * Invalid/unknown grades default to 'block' (safe).
 */
export function getPolicy(grade: string | null): 'allow' | 'warn' | 'confirm' | 'block' {
  if (!grade || !(grade in GRADE_INSTALL_POLICY)) {
    return 'block';  // unknown grade → block (safe default)
  }
  return GRADE_INSTALL_POLICY[grade as Grade];
}

/**
 * Check whether installation is allowed given grade, yes flag, force flag, and
 * accept-high-risk flag.
 *
 * Rules (matching the CLI spec):
 *   Grade A → allow
 *   Grade B → allow (warn, display permissions)
 *   Grade C → allow only with --yes
 *   Grade D → allow only with --force AND --accept-high-risk (double confirm)
 *   Grade E → always blocked (--yes and --force are ignored)
 *   null/unknown → blocked (safe default)
 */
export function checkInstall(
  input: GradeInput,
  flags: { yes?: boolean; force?: boolean; acceptHighRisk?: boolean },
): GateResult {
  const grade = resolveGrade(input);
  const policy = getPolicy(grade);

  // Grade E: always blocked
  if (grade === 'E') {
    return {
      allowed: false,
      grade: 'E',
      reason: 'Grade E (untrusted) packages cannot be installed. The --yes, --force, and --accept-high-risk flags are ignored.',
    };
  }

  // Unknown grade: blocked (safe)
  if (grade === null) {
    return {
      allowed: false,
      grade: 'unknown',
      reason: 'Unable to determine safety grade. Installation blocked as a safety precaution.' +
        ' Use `trusted-agent-hub info <name>` to inspect the package.',
    };
  }

  // Grade D: requires both --force AND --accept-high-risk (double confirmation)
  if (grade === 'D') {
    if (!flags.force) {
      return {
        allowed: false,
        grade: 'D',
        reason: 'Grade D (high risk) requires --force to proceed with installation.',
      };
    }
    if (!flags.acceptHighRisk) {
      return {
        allowed: false,
        grade: 'D',
        reason: 'Grade D (high risk) requires --accept-high-risk as a second explicit confirmation.' +
          ' Use both --force and --accept-high-risk to proceed.',
      };
    }
    return { allowed: true, grade: 'D', policy };
  }

  // Grade C: requires --yes
  if (grade === 'C') {
    if (!flags.yes && !flags.force) {
      return {
        allowed: false,
        grade: 'C',
        reason: 'Grade C (medium risk) requires --yes to confirm installation.' +
          ' Review with `trusted-agent-hub info <name>` first.',
      };
    }
    return { allowed: true, grade: 'C', policy };
  }

  // Grade A/B: allowed
  return { allowed: true, grade, policy };
}
