/**
 * Tests for version-policy.ts — SemVer comparison logic for CLI update.
 *
 * Run: npx tsx tests/version-policy.test.ts
 */

import * as assert from 'assert';
import { compareVersions, isValidVersion } from '../src/version-policy';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function test_compareVersions_upgrade() {
  const result = compareVersions('1.0.0', '2.0.0');
  assert.strictEqual(result.decision, 'upgrade');
  assert.strictEqual(result.localVersion, '1.0.0');
  assert.strictEqual(result.remoteVersion, '2.0.0');
  console.log('  ✓ upgrade: 1.0.0 → 2.0.0');
}

function test_compareVersions_upgrade_minor() {
  const result = compareVersions('1.0.0', '1.1.0');
  assert.strictEqual(result.decision, 'upgrade');
  console.log('  ✓ upgrade: 1.0.0 → 1.1.0');
}

function test_compareVersions_upgrade_patch() {
  const result = compareVersions('1.0.0', '1.0.1');
  assert.strictEqual(result.decision, 'upgrade');
  console.log('  ✓ upgrade: 1.0.0 → 1.0.1');
}

function test_compareVersions_up_to_date() {
  const result = compareVersions('1.0.0', '1.0.0');
  assert.strictEqual(result.decision, 'up_to_date');
  console.log('  ✓ up_to_date: 1.0.0 = 1.0.0');
}

function test_compareVersions_up_to_date_with_v_prefix() {
  // semver treats "v1" as invalid — use the strict version
  const result = compareVersions('2.1.0', '2.1.0');
  assert.strictEqual(result.decision, 'up_to_date');
  console.log('  ✓ up_to_date: 2.1.0 = 2.1.0');
}

function test_compareVersions_downgrade_blocked() {
  const result = compareVersions('2.0.0', '1.0.0');
  assert.strictEqual(result.decision, 'downgrade_blocked');
  console.log('  ✓ downgrade_blocked: 2.0.0 → 1.0.0');
}

function test_compareVersions_downgrade_blocked_patch() {
  const result = compareVersions('2.0.1', '2.0.0');
  assert.strictEqual(result.decision, 'downgrade_blocked');
  console.log('  ✓ downgrade_blocked: 2.0.1 → 2.0.0');
}

function test_compareVersions_prelease_upgrade() {
  // 1.0.0-alpha.1 < 1.0.0 (pre-release is lower than release)
  const result = compareVersions('1.0.0-alpha.1', '1.0.0');
  assert.strictEqual(result.decision, 'upgrade');
  console.log('  ✓ upgrade: 1.0.0-alpha.1 → 1.0.0 (prerelease to release)');
}

function test_compareVersions_same_prerelease() {
  const result = compareVersions('1.0.0-beta.1', '1.0.0-beta.1');
  assert.strictEqual(result.decision, 'up_to_date');
  console.log('  ✓ up_to_date: same prerelease');
}

function test_compareVersions_invalid_local() {
  const result = compareVersions('not-a-version', '1.0.0');
  assert.strictEqual(result.decision, 'invalid_version');
  console.log('  ✓ invalid_version: invalid local');
}

function test_compareVersions_invalid_remote() {
  const result = compareVersions('1.0.0', 'latest');
  assert.strictEqual(result.decision, 'invalid_version');
  console.log('  ✓ invalid_version: invalid remote');
}

function test_compareVersions_both_invalid() {
  const result = compareVersions('abc', 'xyz');
  assert.strictEqual(result.decision, 'invalid_version');
  console.log('  ✓ invalid_version: both invalid');
}

function test_compareVersions_empty_strings() {
  const result = compareVersions('', '');
  assert.strictEqual(result.decision, 'invalid_version');
  console.log('  ✓ invalid_version: empty strings');
}

function test_isValidVersion_valid() {
  assert.strictEqual(isValidVersion('1.0.0'), true);
  assert.strictEqual(isValidVersion('0.0.1'), true);
  assert.strictEqual(isValidVersion('10.20.30'), true);
  assert.strictEqual(isValidVersion('1.0.0-alpha.1'), true);
  assert.strictEqual(isValidVersion('1.0.0+build.123'), true);
  console.log('  ✓ isValidVersion: valid versions');
}

function test_isValidVersion_invalid() {
  assert.strictEqual(isValidVersion(''), false);
  assert.strictEqual(isValidVersion('1.0'), false);
  assert.strictEqual(isValidVersion('latest'), false);
  assert.strictEqual(isValidVersion('not-semver'), false);
  console.log('  ✓ isValidVersion: invalid versions');
}

function test_isValidVersion_coerced() {
  // semver 7.x coerces 'v' prefix
  assert.strictEqual(isValidVersion('v1.0.0'), true);
  assert.strictEqual(isValidVersion('v2.1.3'), true);
  console.log('  ✓ isValidVersion: v-prefix coerced');
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

console.log('\nVersion Policy Tests\n');

test_compareVersions_upgrade();
test_compareVersions_upgrade_minor();
test_compareVersions_upgrade_patch();
test_compareVersions_up_to_date();
test_compareVersions_up_to_date_with_v_prefix();
test_compareVersions_downgrade_blocked();
test_compareVersions_downgrade_blocked_patch();
test_compareVersions_prelease_upgrade();
test_compareVersions_same_prerelease();
test_compareVersions_invalid_local();
test_compareVersions_invalid_remote();
test_compareVersions_both_invalid();
test_compareVersions_empty_strings();
test_isValidVersion_valid();
test_isValidVersion_invalid();
test_isValidVersion_coerced();

console.log('\n  ✓ All version-policy tests passed!\n');
