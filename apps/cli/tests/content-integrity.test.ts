/**
 * Tests for deterministic content digest (content-integrity.ts).
 *
 * Run: npx tsx tests/content-integrity.test.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { execFileSync } from 'child_process';

import {
  CONTENT_HASH_ALGORITHM,
  computeDirectoryDigest,
  ContentIntegrityError,
} from '../src/content-integrity';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpDir(): string {
  const dir = path.join(os.tmpdir(), 'tah-digest-test-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeFile(dir: string, name: string, content: string | Buffer): void {
  const filePath = path.join(dir, name);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => Promise<void>) {
  return fn().then(
    () => { passed++; console.log(`  ✓ ${name}`); },
    (err: unknown) => {
      failed++;
      console.log(`  ✗ ${name}`);
      console.error(err instanceof Error ? err.stack || err.message : String(err));
    },
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Content Integrity Tests\n');

  // -----------------------------------------------------------------------
  // Empty directory
  // -----------------------------------------------------------------------

  await runTest('Empty directory produces valid digest', async () => {
    const dir = makeTmpDir();
    try {
      const digest = await computeDirectoryDigest(dir);
      assert.strictEqual(digest.algorithm, CONTENT_HASH_ALGORITHM);
      assert.strictEqual(digest.fileCount, 0);
      assert.strictEqual(digest.totalBytes, 0);
      assert.strictEqual(digest.digest.length, 64);
      assert.ok(/^[a-f0-9]{64}$/.test(digest.digest));
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Stable across repeated computations
  // -----------------------------------------------------------------------

  await runTest('Repeated computation produces identical digest', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      writeFile(dir, 'sub/b.txt', 'world');

      const d1 = await computeDirectoryDigest(dir);
      const d2 = await computeDirectoryDigest(dir);
      assert.strictEqual(d1.digest, d2.digest);
      assert.strictEqual(d1.fileCount, d2.fileCount);
      assert.strictEqual(d1.totalBytes, d2.totalBytes);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Order-independent
  // -----------------------------------------------------------------------

  await runTest('Creation order does not affect digest', async () => {
    const dir1 = makeTmpDir();
    const dir2 = makeTmpDir();
    try {
      writeFile(dir1, 'c.txt', 'ccc');
      writeFile(dir1, 'a.txt', 'aaa');
      writeFile(dir1, 'b.txt', 'bbb');

      writeFile(dir2, 'b.txt', 'bbb');
      writeFile(dir2, 'c.txt', 'ccc');
      writeFile(dir2, 'a.txt', 'aaa');

      const d1 = await computeDirectoryDigest(dir1);
      const d2 = await computeDirectoryDigest(dir2);
      assert.strictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir1);
      cleanup(dir2);
    }
  });

  // -----------------------------------------------------------------------
  // Content change
  // -----------------------------------------------------------------------

  await runTest('Content change detected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      const d1 = await computeDirectoryDigest(dir);

      writeFile(dir, 'a.txt', 'world');
      const d2 = await computeDirectoryDigest(dir);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // File addition
  // -----------------------------------------------------------------------

  await runTest('File addition detected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      const d1 = await computeDirectoryDigest(dir);

      writeFile(dir, 'b.txt', 'world');
      const d2 = await computeDirectoryDigest(dir);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // File deletion
  // -----------------------------------------------------------------------

  await runTest('File deletion detected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      writeFile(dir, 'b.txt', 'world');
      const d1 = await computeDirectoryDigest(dir);

      fs.unlinkSync(path.join(dir, 'b.txt'));
      const d2 = await computeDirectoryDigest(dir);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // File rename
  // -----------------------------------------------------------------------

  await runTest('File rename detected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      const d1 = await computeDirectoryDigest(dir);

      fs.renameSync(path.join(dir, 'a.txt'), path.join(dir, 'b.txt'));
      const d2 = await computeDirectoryDigest(dir);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Nested directory change
  // -----------------------------------------------------------------------

  await runTest('Nested directory change detected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'sub/a.txt', 'hello');
      const d1 = await computeDirectoryDigest(dir);

      writeFile(dir, 'sub/a.txt', 'changed');
      const d2 = await computeDirectoryDigest(dir);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Symlink rejected
  // -----------------------------------------------------------------------

  await runTest('Symlink rejected', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'real.txt', 'content');

      // Try to create a symlink (may fail on Windows without privileges)
      try {
        fs.symlinkSync(path.join(dir, 'real.txt'), path.join(dir, 'link.txt'));
      } catch {
        // Cannot create symlink — skip validation, test passes
        return;
      }

      try {
        await computeDirectoryDigest(dir);
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'unsafe_content');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Root symlink rejected
  // -----------------------------------------------------------------------

  await runTest('Root symlink rejected', async () => {
    const dir = makeTmpDir();
    try {
      const realDir = path.join(dir, 'real');
      fs.mkdirSync(realDir);
      writeFile(realDir, 'a.txt', 'hello');

      try {
        fs.symlinkSync(realDir, path.join(dir, 'link'), 'dir');
      } catch {
        // Cannot create symlink — skip
        return;
      }

      try {
        await computeDirectoryDigest(path.join(dir, 'link'));
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'unsafe_content');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // POSIX special files
  // -----------------------------------------------------------------------

  await runTest('FIFO rejected on POSIX', async () => {
    if (process.platform === 'win32') return;
    const dir = makeTmpDir();
    try {
      execFileSync('mkfifo', [path.join(dir, 'unsafe.fifo')]);
      await assert.rejects(
        () => computeDirectoryDigest(dir),
        (error: unknown) => error instanceof ContentIntegrityError && error.code === 'unsafe_content',
      );
    } finally {
      cleanup(dir);
    }
  });

  await runTest('Unix socket rejected on POSIX', async () => {
    if (process.platform === 'win32') return;
    const dir = makeTmpDir();
    const socketPath = path.join(dir, 'unsafe.sock');
    const server = net.createServer();
    try {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, resolve);
      });
      await assert.rejects(
        () => computeDirectoryDigest(dir),
        (error: unknown) => error instanceof ContentIntegrityError && error.code === 'unsafe_content',
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      cleanup(dir);
    }
  });

  await runTest('Character device rejected in Linux CI', async () => {
    if (process.platform !== 'linux' || !process.env.CI) return;
    const dir = makeTmpDir();
    try {
      const devicePath = path.join(dir, 'unsafe-device');
      if (typeof process.getuid === 'function' && process.getuid() === 0) {
        execFileSync('mknod', [devicePath, 'c', '1', '3']);
      } else {
        execFileSync('sudo', ['-n', 'mknod', devicePath, 'c', '1', '3']);
      }
      await assert.rejects(
        () => computeDirectoryDigest(dir),
        (error: unknown) => error instanceof ContentIntegrityError && error.code === 'unsafe_content',
      );
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Non-existent path
  // -----------------------------------------------------------------------

  await runTest('Non-existent path rejected', async () => {
    try {
      await computeDirectoryDigest(path.join(os.tmpdir(), 'does-not-exist-' + crypto.randomBytes(8).toString('hex')));
      assert.fail('Should have thrown');
    } catch (e: unknown) {
      assert.ok(e instanceof ContentIntegrityError);
      assert.strictEqual((e as ContentIntegrityError).code, 'missing');
    }
  });

  // -----------------------------------------------------------------------
  // File instead of directory
  // -----------------------------------------------------------------------

  await runTest('File-instead-of-directory rejected', async () => {
    const dir = makeTmpDir();
    try {
      const filePath = path.join(dir, 'file.txt');
      fs.writeFileSync(filePath, 'hello');
      try {
        await computeDirectoryDigest(filePath);
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'missing');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Binary file content
  // -----------------------------------------------------------------------

  await runTest('Binary files digest correctly', async () => {
    const dir1 = makeTmpDir();
    const dir2 = makeTmpDir();
    try {
      const binaryContent = crypto.randomBytes(1024);
      writeFile(dir1, 'binary.bin', binaryContent);
      writeFile(dir2, 'binary.bin', binaryContent);

      const d1 = await computeDirectoryDigest(dir1);
      const d2 = await computeDirectoryDigest(dir2);
      assert.strictEqual(d1.digest, d2.digest);
      assert.strictEqual(d1.fileCount, 1);
      assert.strictEqual(d1.totalBytes, 1024);
    } finally {
      cleanup(dir1);
      cleanup(dir2);
    }
  });

  // -----------------------------------------------------------------------
  // Many files
  // -----------------------------------------------------------------------

  await runTest('Many files (100) computed correctly', async () => {
    const dir = makeTmpDir();
    try {
      for (let i = 0; i < 100; i++) {
        writeFile(dir, `file_${String(i).padStart(3, '0')}.txt`, `content ${i}`);
      }

      const d1 = await computeDirectoryDigest(dir);
      assert.strictEqual(d1.fileCount, 100);

      const d2 = await computeDirectoryDigest(dir);
      assert.strictEqual(d1.digest, d2.digest);

      // Modify one file
      writeFile(dir, 'file_050.txt', 'changed');
      const d3 = await computeDirectoryDigest(dir);
      assert.notStrictEqual(d1.digest, d3.digest);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // File count limit
  // -----------------------------------------------------------------------

  await runTest('File count limit exceeded', async () => {
    const dir = makeTmpDir();
    try {
      for (let i = 0; i < 15; i++) {
        writeFile(dir, `f${i}.txt`, 'x');
      }

      try {
        await computeDirectoryDigest(dir, { maxFiles: 10 });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'too_many_files');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Byte size limit
  // -----------------------------------------------------------------------

  await runTest('Byte size limit exceeded', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'big.txt', Buffer.alloc(5000, 'x'));
      try {
        await computeDirectoryDigest(dir, { maxBytes: 1000 });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'too_large');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Deep nesting
  // -----------------------------------------------------------------------

  await runTest('Deep nesting works', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a/b/c/d/e/f/g/h.txt', 'deep');
      const d = await computeDirectoryDigest(dir);
      assert.strictEqual(d.fileCount, 1);
      assert.strictEqual(d.digest.length, 64);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Digest format
  // -----------------------------------------------------------------------

  await runTest('Digest format is correct', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'test.txt', 'hello world');
      const d = await computeDirectoryDigest(dir);
      assert.strictEqual(d.algorithm, 'sha256-tree-v1');
      assert.strictEqual(d.digest.length, 64);
      assert.ok(/^[a-f0-9]{64}$/.test(d.digest));
      assert.strictEqual(d.fileCount, 1);
      assert.strictEqual(d.totalBytes, 11);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Empty subdirectories contribute to hash
  // -----------------------------------------------------------------------

  await runTest('Empty subdirectory changes digest', async () => {
    const dir1 = makeTmpDir();
    const dir2 = makeTmpDir();
    try {
      writeFile(dir1, 'a.txt', 'hello');
      writeFile(dir2, 'a.txt', 'hello');
      fs.mkdirSync(path.join(dir2, 'empty_sub'));

      const d1 = await computeDirectoryDigest(dir1);
      const d2 = await computeDirectoryDigest(dir2);

      assert.notStrictEqual(d1.digest, d2.digest);
    } finally {
      cleanup(dir1);
      cleanup(dir2);
    }
  });

  // -----------------------------------------------------------------------
  // Fixed test vector — ensures algorithm doesn't drift
  // -----------------------------------------------------------------------

  await runTest('Fixed test vector for sha256-tree-v1', async () => {
    // This known file tree MUST produce the same digest on all platforms
    // (Windows and Linux).  If this test fails the algorithm has drifted.
    const EXPECTED_DIGEST = '6c25f5c00a57e88da50bd24cca649d0a8e76bb404e78ffb5a53e2ac8e90d5bcc';

    const dir = makeTmpDir();
    try {
      writeFile(dir, 'README.md', 'Hello World');
      writeFile(dir, 'src/main.ts', 'export const x = 1;');

      const digest = await computeDirectoryDigest(dir);
      assert.strictEqual(digest.algorithm, 'sha256-tree-v1');
      assert.strictEqual(digest.fileCount, 2);
      assert.strictEqual(digest.digest, EXPECTED_DIGEST);

      // Recreate the same tree in a different directory — must produce same digest
      const dir2 = makeTmpDir();
      try {
        writeFile(dir2, 'README.md', 'Hello World');
        writeFile(dir2, 'src/main.ts', 'export const x = 1;');
        const digest2 = await computeDirectoryDigest(dir2);
        assert.strictEqual(digest2.digest, EXPECTED_DIGEST);
        assert.strictEqual(digest2.fileCount, 2);
      } finally {
        cleanup(dir2);
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // validateAncestorChain — normal directory
  // -----------------------------------------------------------------------

  await runTest('validateAncestorChain accepts normal directories', async () => {
    const { validateAncestorChain } = require('../src/content-integrity');
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      // Should not throw
      validateAncestorChain(dir);
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // validateAncestorChain — non-existent path
  // -----------------------------------------------------------------------

  await runTest('validateAncestorChain rejects non-existent path', async () => {
    const { validateAncestorChain } = require('../src/content-integrity');
    try {
      validateAncestorChain(path.join(os.tmpdir(), 'does-not-exist-xyz-12345'));
      assert.fail('Should have thrown');
    } catch (e: unknown) {
      assert.ok(e instanceof ContentIntegrityError);
      assert.strictEqual((e as ContentIntegrityError).code, 'unsafe_content');
    }
  });

  // -----------------------------------------------------------------------

  // -----------------------------------------------------------------------
  // Directory count limit exceeded
  // -----------------------------------------------------------------------

  await runTest('Directory count limit exceeded', async () => {
    const dir = makeTmpDir();
    try {
      // Create 15 directories (exceeds limit of 10)
      for (let i = 0; i < 15; i++) {
        fs.mkdirSync(path.join(dir, `dir_${i}`));
      }
      try {
        await computeDirectoryDigest(dir, { maxDirs: 10 });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'too_many_dirs');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Race: file added between scan and hash
  // -----------------------------------------------------------------------

  await runTest('Race detection: file added between scan and hash', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      try {
        await computeDirectoryDigest(dir, {
          _afterCollectHook: (root: string) => {
            writeFile(root, 'b.txt', 'injected');
          },
        });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'modified');
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Race: file deleted between scan and hash
  // (File is in collectEntries list but deleted before hashFileContent opens it)
  // -----------------------------------------------------------------------

  await runTest('Race detection: file deleted between scan and hash', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      writeFile(dir, 'b.txt', 'world');
      try {
        await computeDirectoryDigest(dir, {
          _afterCollectHook: (root: string) => {
            fs.unlinkSync(path.join(root, 'b.txt'));
          },
        });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        // hashFileContent fails to open deleted file → read_error, or
        // post-scan detects the missing entry → modified
        const code = (e as ContentIntegrityError).code;
        assert.ok(code === 'modified' || code === 'read_error',
          `expected modified or read_error, got ${code}`);
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Race: file renamed between scan and hash
  // -----------------------------------------------------------------------

  await runTest('Race detection: file renamed between scan and hash', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      try {
        await computeDirectoryDigest(dir, {
          _afterCollectHook: (root: string) => {
            fs.renameSync(path.join(root, 'a.txt'), path.join(root, 'renamed.txt'));
          },
        });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        const code = (e as ContentIntegrityError).code;
        assert.ok(code === 'modified' || code === 'read_error',
          `expected modified or read_error, got ${code}`);
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Race: root replaced between scan and hash
  // -----------------------------------------------------------------------

  await runTest('Race detection: root replaced between scan and hash', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'a.txt', 'hello');
      const backup = dir + '.bak';
      const replacement = makeTmpDir();
      writeFile(replacement, 'evil.txt', 'pwned');
      try {
        await computeDirectoryDigest(dir, {
          _afterCollectHook: (_root: string) => {
            fs.renameSync(dir, backup);
            fs.renameSync(replacement, dir);
          },
        });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        const code = (e as ContentIntegrityError).code;
        // Root dev/ino mismatch → unsafe_content, or entries mismatch → modified,
        // or file path changed → read_error
        assert.ok(
          code === 'unsafe_content' || code === 'modified' || code === 'read_error',
          `expected unsafe_content/modified/read_error, got ${code}`,
        );
        if (fs.existsSync(dir)) {
          fs.rmSync(dir, { recursive: true, force: true });
        }
        fs.renameSync(backup, dir);
      } finally {
        cleanup(backup);
        cleanup(replacement);
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Race: subdirectory replaced between scan and hash
  // -----------------------------------------------------------------------

  await runTest('Race detection: subdirectory replaced between scan and hash', async () => {
    const dir = makeTmpDir();
    try {
      writeFile(dir, 'sub/a.txt', 'hello');
      try {
        await computeDirectoryDigest(dir, {
          _afterCollectHook: (root: string) => {
            const subPath = path.join(root, 'sub');
            fs.rmSync(subPath, { recursive: true, force: true });
            fs.mkdirSync(subPath);
            writeFile(root, 'sub/b.txt', 'injected');
          },
        });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        const code = (e as ContentIntegrityError).code;
        assert.ok(
          code === 'modified' || code === 'unsafe_content' || code === 'read_error',
          `expected modified/unsafe_content/read_error, got ${code}`,
        );
      }
    } finally {
      cleanup(dir);
    }
  });

  // -----------------------------------------------------------------------
  // Unknown file type rejected (fail-closed)
  // -----------------------------------------------------------------------

  await runTest('Unknown file type rejected (fail-closed)', async () => {
    const { classifyEntryType, ContentIntegrityError } = await import('../src/content-integrity');
    // Mock stat where ALL isX() methods return false — simulates an
    // unrecognised platform-specific type (door, port, etc.).
    const unknownStat = {
      isSymbolicLink: () => false,
      isDirectory: () => false,
      isFile: () => false,
      isSocket: () => false,
      isFIFO: () => false,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
    };
    try {
      classifyEntryType(unknownStat, 'test-entry');
      assert.fail('Should have thrown');
    } catch (e: unknown) {
      assert.ok(e instanceof ContentIntegrityError);
      assert.strictEqual((e as ContentIntegrityError).code, 'unsafe_content');
      assert.ok((e as ContentIntegrityError).message.includes('Unsupported file type'));
    }

    // Verify that known types work
    assert.strictEqual(classifyEntryType({ ...unknownStat, isDirectory: () => true }, 'd'), 'dir');
    assert.strictEqual(classifyEntryType({ ...unknownStat, isFile: () => true }, 'f'), 'file');

    // Verify each unsafe type throws
    for (const [method, label] of [
      ['isSymbolicLink', 'Symbolic link'],
      ['isSocket', 'Socket'],
      ['isFIFO', 'FIFO'],
      ['isBlockDevice', 'Device file'],
      ['isCharacterDevice', 'Device file'],
    ] as const) {
      try {
        classifyEntryType({ ...unknownStat, [method]: () => true }, label);
        assert.fail(`Should have thrown for ${label}`);
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'unsafe_content');
      }
    }
  });

  // -----------------------------------------------------------------------
  // Max depth limit exceeded
  // -----------------------------------------------------------------------

  await runTest('Max depth limit exceeded', async () => {
    const dir = makeTmpDir();
    try {
      // Create deep nesting (> 5 levels)
      let current = dir;
      for (let i = 0; i < 10; i++) {
        current = path.join(current, `l${i}`);
        fs.mkdirSync(current);
      }
      try {
        await computeDirectoryDigest(dir, { maxDepth: 5 });
        assert.fail('Should have thrown');
      } catch (e: unknown) {
        assert.ok(e instanceof ContentIntegrityError);
        assert.strictEqual((e as ContentIntegrityError).code, 'too_deep');
      }
    } finally {
      cleanup(dir);
    }
  });

  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
