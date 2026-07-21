/**
 * Unit tests for CLI grade gating logic.
 *
 * Run: npx ts-node tests/grade-gate.test.ts
 *
 * These tests cover all safety invariants:
 *   - Grade E blocked regardless of flags
 *   - Grade D requires both --force AND --accept-high-risk
 *   - Grade C requires --yes
 *   - Grade A/B always allowed
 *   - Missing grade defaults blocked
 *   - Invalid grade blocked (safe)
 *   - risk_level fallback mapping
 */

import * as assert from 'assert';
import { resolveGrade, checkInstall, getPolicy } from '../src/grade-gate';
import type { GradeInput } from '../src/grade-gate';

// ---------------------------------------------------------------------------
// resolveGrade tests
// ---------------------------------------------------------------------------

function test_resolveGrade() {
  // Backend grade takes priority
  assert.strictEqual(resolveGrade({ grade: 'A', riskLevel: 'high_risk' }), 'A');
  assert.strictEqual(resolveGrade({ grade: 'E', riskLevel: 'trusted' }), 'E');

  // Fallback to package risk_level
  assert.strictEqual(resolveGrade({ riskLevel: 'trusted' }), 'A');
  assert.strictEqual(resolveGrade({ riskLevel: 'low_risk' }), 'B');
  assert.strictEqual(resolveGrade({ riskLevel: 'medium_risk' }), 'C');
  assert.strictEqual(resolveGrade({ riskLevel: 'high_risk' }), 'D');
  assert.strictEqual(resolveGrade({ riskLevel: 'untrusted' }), 'E');

  // Fallback to version level
  assert.strictEqual(resolveGrade({ versionLevel: 'trusted' }), 'A');
  assert.strictEqual(resolveGrade({ versionLevel: 'untrusted' }), 'E');

  // Priority: grade > riskLevel > versionLevel
  assert.strictEqual(resolveGrade({ grade: 'B', riskLevel: 'high_risk', versionLevel: 'untrusted' }), 'B');
  assert.strictEqual(resolveGrade({ riskLevel: 'medium_risk', versionLevel: 'trusted' }), 'C');

  // null for missing inputs
  assert.strictEqual(resolveGrade({}), null);

  // Invalid grades treated as null
  assert.strictEqual(resolveGrade({ grade: 'Z' }), null);
  assert.strictEqual(resolveGrade({ grade: 'F' }), null);
  assert.strictEqual(resolveGrade({ grade: '' }), null);

  console.log('  ✓ resolveGrade');
}

// ---------------------------------------------------------------------------
// getPolicy tests
// ---------------------------------------------------------------------------

function test_getPolicy() {
  assert.strictEqual(getPolicy('A'), 'allow');
  assert.strictEqual(getPolicy('B'), 'warn');
  assert.strictEqual(getPolicy('C'), 'confirm');
  assert.strictEqual(getPolicy('D'), 'confirm');
  assert.strictEqual(getPolicy('E'), 'block');

  // Safety: unknown → block
  assert.strictEqual(getPolicy(null), 'block');
  assert.strictEqual(getPolicy('Z'), 'block');
  assert.strictEqual(getPolicy(''), 'block');

  console.log('  ✓ getPolicy');
}

// ---------------------------------------------------------------------------
// checkInstall tests — Grade E (blocked)
// ---------------------------------------------------------------------------

function test_gradeE_alwaysBlocked() {
  const input: GradeInput = { grade: 'E' };

  // Blocked with no flags
  const r1 = checkInstall(input, {});
  assert.strictEqual(r1.allowed, false);
  assert.strictEqual(r1.grade, 'E');

  // Blocked even with --yes
  const r2 = checkInstall(input, { yes: true });
  assert.strictEqual(r2.allowed, false);

  // Blocked even with --force
  const r3 = checkInstall(input, { force: true });
  assert.strictEqual(r3.allowed, false);

  // Blocked even with --accept-high-risk
  const r4 = checkInstall(input, { acceptHighRisk: true });
  assert.strictEqual(r4.allowed, false);

  // Blocked even with ALL flags
  const r5 = checkInstall(input, { yes: true, force: true, acceptHighRisk: true });
  assert.strictEqual(r5.allowed, false);
  assert.ok(r5.reason.includes('ignored'));

  // Also blocked via risk_level → E
  const viaLevel: GradeInput = { riskLevel: 'untrusted' };
  const r6 = checkInstall(viaLevel, {});
  assert.strictEqual(r6.allowed, false);
  assert.strictEqual(r6.grade, 'E');

  console.log('  ✓ Grade E always blocked');
}

// ---------------------------------------------------------------------------
// checkInstall tests — Grade D (double confirmation)
// ---------------------------------------------------------------------------

function test_gradeD_doubleConfirm() {
  const input: GradeInput = { grade: 'D' };

  // Blocked with no flags
  const r1 = checkInstall(input, {});
  assert.strictEqual(r1.allowed, false);

  // Blocked with only --yes
  const r2 = checkInstall(input, { yes: true });
  assert.strictEqual(r2.allowed, false);

  // Blocked with only --force (needs second flag)
  const r3 = checkInstall(input, { force: true });
  assert.strictEqual(r3.allowed, false);

  // Blocked with only --accept-high-risk (needs --force)
  const r4 = checkInstall(input, { acceptHighRisk: true });
  assert.strictEqual(r4.allowed, false);

  // Allowed ONLY with BOTH --force AND --accept-high-risk
  const r5 = checkInstall(input, { force: true, acceptHighRisk: true });
  assert.strictEqual(r5.allowed, true);
  assert.strictEqual(r5.grade, 'D');

  // Also works with all three
  const r6 = checkInstall(input, { yes: true, force: true, acceptHighRisk: true });
  assert.strictEqual(r6.allowed, true);

  console.log('  ✓ Grade D double confirmation');
}

// ---------------------------------------------------------------------------
// checkInstall tests — Grade C (requires --yes)
// ---------------------------------------------------------------------------

function test_gradeC_requiresYes() {
  const input: GradeInput = { grade: 'C' };

  // Blocked without --yes
  const r1 = checkInstall(input, {});
  assert.strictEqual(r1.allowed, false);

  // Allowed with --yes
  const r2 = checkInstall(input, { yes: true });
  assert.strictEqual(r2.allowed, true);
  assert.strictEqual(r2.grade, 'C');

  // Allowed with --force (implies consent)
  const r3 = checkInstall(input, { force: true });
  assert.strictEqual(r3.allowed, true);

  console.log('  ✓ Grade C requires --yes');
}

// ---------------------------------------------------------------------------
// checkInstall tests — Grade A/B (always allowed)
// ---------------------------------------------------------------------------

function test_gradeAB_allowed() {
  // A: always allowed
  assert.strictEqual(checkInstall({ grade: 'A' }, {}).allowed, true);
  assert.strictEqual(checkInstall({ grade: 'A' }, { yes: true }).allowed, true);

  // B: always allowed
  assert.strictEqual(checkInstall({ grade: 'B' }, {}).allowed, true);
  assert.strictEqual(checkInstall({ grade: 'B' }, { yes: true }).allowed, true);

  console.log('  ✓ Grade A/B always allowed');
}

// ---------------------------------------------------------------------------
// checkInstall tests — null/unknown grade
// ---------------------------------------------------------------------------

function test_unknownGrade_blocked() {
  // Missing all inputs → blocked
  const r1 = checkInstall({}, {});
  assert.strictEqual(r1.allowed, false);

  // Even with flags → blocked
  const r2 = checkInstall({}, { yes: true, force: true, acceptHighRisk: true });
  assert.strictEqual(r2.allowed, false);

  // Invalid grade → blocked
  const r3 = checkInstall({ grade: 'Z' }, { force: true, acceptHighRisk: true });
  assert.strictEqual(r3.allowed, false);

  console.log('  ✓ Unknown grade blocked');
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

console.log('\nCLI Grade Gate Tests\n');

test_resolveGrade();
test_getPolicy();
test_gradeE_alwaysBlocked();
test_gradeD_doubleConfirm();
test_gradeC_requiresYes();
test_gradeAB_allowed();
test_unknownGrade_blocked();

console.log('\n  ✓ All tests passed!\n');
