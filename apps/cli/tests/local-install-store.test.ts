/**
 * Tests for local install record persistence (local-install-store.ts).
 *
 * Run: npx tsx tests/local-install-store.test.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import {
  LocalInstallStore,
  RecordStoreError,
} from '../src/local-install-store';
import type { LocalInstallRecord } from '../src/local-install-store';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => void | Promise<void>) {
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.then(
        () => { passed++; console.log(`  ✓ ${name}`); },
        (err: unknown) => {
          failed++;
          console.log(`  ✗ ${name}`);
          console.error(err instanceof Error ? err.stack || err.message : String(err));
        },
      );
    }
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err: unknown) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.error(err instanceof Error ? err.stack || err.message : String(err));
  }
}

function makeRecord(overrides: Partial<LocalInstallRecord> = {}): LocalInstallRecord {
  return {
    package_name: 'test-pkg',
    version: '1.0.0',
    client: 'claude-code',
    install_path: '/home/user/.claude/skills/test-pkg',
    sha256: 'a'.repeat(64),
    integrity_verified: true,
    installed_at: '2026-07-22T00:00:00.000Z',
    manifest_version: '1.0',
    content_hash_algorithm: 'sha256-tree-v1',
    content_sha256: 'b'.repeat(64),
    ...overrides,
  };
}

function makeTmpDir(): string {
  const dir = path.join(os.tmpdir(), 'tah-store-test-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Local Install Store Tests\n');

  // -----------------------------------------------------------------------
  // File doesn't exist → empty array
  // -----------------------------------------------------------------------

  runTest('File does not exist returns empty array', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const records = store.load();
      assert.deepStrictEqual(records, []);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Save and load
  // -----------------------------------------------------------------------

  runTest('Save and load a record', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const record = makeRecord();
      store.save(record);

      const loaded = store.load();
      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].package_name, 'test-pkg');
      assert.strictEqual(loaded[0].content_hash_algorithm, 'sha256-tree-v1');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Find
  // -----------------------------------------------------------------------

  runTest('Find by name and client', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      store.save(makeRecord({ package_name: 'pkg-a', client: 'claude-code' }));
      store.save(makeRecord({ package_name: 'pkg-b', client: 'claude-code' }));
      store.save(makeRecord({ package_name: 'pkg-a', client: 'cursor' }));

      assert.notStrictEqual(store.find('pkg-a', 'claude-code'), null);
      assert.notStrictEqual(store.find('pkg-b', 'claude-code'), null);
      assert.notStrictEqual(store.find('pkg-a', 'cursor'), null);
      assert.strictEqual(store.find('pkg-c', 'claude-code'), null);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Corrupted JSON → throws record_invalid
  // -----------------------------------------------------------------------

  runTest('Corrupted JSON throws record_invalid', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, '{broken json!!!', 'utf-8');

      try {
        store.load();
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError);
        assert.strictEqual((e as RecordStoreError).code, 'record_invalid');
      }
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Root not array → throws record_invalid
  // -----------------------------------------------------------------------

  runTest('Root value not array throws record_invalid', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify({ not: 'an array' }), 'utf-8');

      try {
        store.load();
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError);
        assert.strictEqual((e as RecordStoreError).code, 'record_invalid');
      }
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Missing required field → throws record_invalid
  // -----------------------------------------------------------------------

  runTest('Missing required field throws record_invalid', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      // Missing package_name
      fs.writeFileSync(filePath, JSON.stringify([{ version: '1.0.0' }]), 'utf-8');

      try {
        store.load();
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError);
        assert.strictEqual((e as RecordStoreError).code, 'record_invalid');
      }
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Wrong field type → throws record_invalid
  // -----------------------------------------------------------------------

  runTest('Wrong field type throws record_invalid', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const rec = makeRecord();
      (rec as any).integrity_verified = 'yes'; // should be boolean

      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify([rec]), 'utf-8');

      try {
        store.load();
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError);
        assert.strictEqual((e as RecordStoreError).code, 'record_invalid');
      }
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Duplicate name+client → throws record_invalid
  // -----------------------------------------------------------------------

  runTest('Duplicate name+client throws record_invalid', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(
        filePath,
        JSON.stringify([
          makeRecord({ package_name: 'dup', client: 'claude-code', version: '1.0.0' }),
          makeRecord({ package_name: 'dup', client: 'claude-code', version: '2.0.0' }),
        ]),
        'utf-8',
      );

      try {
        store.load();
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError);
        assert.strictEqual((e as RecordStoreError).code, 'record_invalid');
      }
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Same name+client replaced on save
  // -----------------------------------------------------------------------

  runTest('Same name+client replaced on save', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      store.save(makeRecord({ version: '1.0.0' }));
      store.save(makeRecord({ version: '2.0.0' }));

      const records = store.load();
      assert.strictEqual(records.length, 1);
      assert.strictEqual(records[0].version, '2.0.0');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Different clients coexist
  // -----------------------------------------------------------------------

  runTest('Different clients coexist', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      store.save(makeRecord({ client: 'claude-code' }));
      store.save(makeRecord({ client: 'cursor' }));

      const records = store.load();
      assert.strictEqual(records.length, 2);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Legacy record without content_hash accepted
  // -----------------------------------------------------------------------

  runTest('Legacy record without content_hash accepted', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      // Manually write a legacy record without content fields
      const legacy = {
        package_name: 'legacy-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: '/home/user/.claude/skills/legacy-pkg',
        sha256: 'a'.repeat(64),
        integrity_verified: true,
        installed_at: '2026-07-01T00:00:00.000Z',
        manifest_version: '1.0',
      };
      const filePath = store.getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify([legacy]), 'utf-8');

      const records = store.load();
      assert.strictEqual(records.length, 1);
      assert.strictEqual(records[0].content_hash_algorithm, undefined);
      assert.strictEqual(records[0].content_sha256, undefined);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // getPath
  // -----------------------------------------------------------------------

  runTest('getPath returns correct path', () => {
    const store = new LocalInstallStore('/home/test');
    assert.ok(store.getPath().endsWith('installs.json'));
    assert.ok(store.getPath().includes('.trusted-agent-hub'));
  });

  // -----------------------------------------------------------------------
  // Atomic save — original preserved and temp cleaned on rename failure
  // -----------------------------------------------------------------------

  runTest('Atomic save preserves original on rename failure', () => {
    const home = makeTmpDir();
    try {
      const store = new LocalInstallStore(home);
      const original = makeRecord({ version: '1.0.0' });
      store.save(original);

      const filePath = store.getPath();
      const originalRaw = fs.readFileSync(filePath, 'utf-8');
      assert.ok(originalRaw.includes('1.0.0'), 'original record must contain v1.0.0');

      // Install the beforeRename hook: delete the temp file so the
      // subsequent renameSync(tmpPath, filePath) throws a real ENOENT.
      // This exercises the actual rename failure path, error wrapping,
      // original file preservation, and temp-file cleanup.
      LocalInstallStore._beforeRenameHook = (tmpPath: string) => {
        fs.unlinkSync(tmpPath);
      };

      try {
        store.save(makeRecord({ version: '2.0.0' }));
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof RecordStoreError,
          `expected RecordStoreError, got ${e?.constructor?.name}`);
        assert.strictEqual((e as RecordStoreError).code, 'save_failed');
      } finally {
        LocalInstallStore._beforeRenameHook = null;
      }

      // Original file must be intact — byte-for-byte identical
      const afterRaw = fs.readFileSync(filePath, 'utf-8');
      assert.strictEqual(afterRaw, originalRaw,
        'original file must be preserved byte-for-byte after failed save');

      // No temp file should be left behind
      const dir = path.dirname(filePath);
      const dirFiles = fs.readdirSync(dir);
      const tempFiles = dirFiles.filter(f => f.startsWith('installs.json.tmp-'));
      assert.strictEqual(tempFiles.length, 0, 'no temp file should remain');
    } finally {
      cleanup(home);
    }
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
