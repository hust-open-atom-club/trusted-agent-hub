/**
 * CLI integration tests for the `verify` command.
 *
 * Run: npx tsx tests/cli-verify.test.ts
 *
 * Uses a real subprocess with fresh HOME directories to validate the CLI →
 * executor pipeline.  Tests that require a live mock API server are covered by
 * the verify-executor unit tests and the Docker E2E acceptance suite.
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn, spawnSync } from 'child_process';

import { LocalInstallStore } from '../src/local-install-store';
import { computeDirectoryDigest } from '../src/content-integrity';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CLI_ENTRY = path.resolve(__dirname, '..', 'dist', 'apps', 'cli', 'src', 'cli.js');

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

function makeTmpDir(): string {
  const dir = path.join(os.tmpdir(), 'tah-cli-verify-' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function runCli(args: string[], env: Record<string, string>): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  const result = spawnSync('node', [CLI_ENTRY, ...args], {
    env: { ...process.env, ...env },
    timeout: 15_000,
  });
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || '',
    status: result.status,
  };
}

async function startManifestServer(manifest: unknown): Promise<{
  url: string;
  stop: () => Promise<{ method: string; url: string }[]>;
}> {
  const encodedManifest = Buffer.from(JSON.stringify(manifest), 'utf-8').toString('base64');
  const serverSource = `
    const http = require('http');
    const manifest = JSON.parse(Buffer.from(process.argv[1], 'base64').toString('utf8'));
    const requests = [];
    const server = http.createServer((req, response) => {
      // Write request info to stderr for parent assertion
      process.stderr.write('REQ:' + JSON.stringify({ method: req.method, url: req.url }) + '\\n');
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(manifest));
    });
    server.listen(0, '127.0.0.1', () => {
      process.stdout.write(String(server.address().port) + '\\n');
    });
    process.on('SIGTERM', () => server.close(() => process.exit(0)));
  `;

  const child = spawn(process.execPath, ['-e', serverSource, encodedManifest], {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  let stderrAccum = '';

  const port = await new Promise<number>((resolve, reject) => {
    let stdout = '';
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Timed out starting manifest server: ${stderrAccum}`));
    }, 5_000);

    child.stderr.on('data', (chunk: Buffer) => { stderrAccum += chunk.toString(); });
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
      const match = stdout.match(/^(\d+)\r?\n/);
      if (!match) return;
      clearTimeout(timeout);
      resolve(Number(match[1]));
    });
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', (code) => {
      if (stdout.match(/^(\d+)\r?\n/)) return;
      clearTimeout(timeout);
      reject(new Error(`Manifest server exited before ready (${code}): ${stderrAccum}`));
    });
  });

  // Parse already-received REQ lines from stderr accumulator
  function parseRequests(): { method: string; url: string }[] {
    const reqs: { method: string; url: string }[] = [];
    for (const line of stderrAccum.split('\n')) {
      if (line.startsWith('REQ:')) {
        try { reqs.push(JSON.parse(line.slice(4))); } catch { /* ignore */ }
      }
    }
    return reqs;
  }

  return {
    url: `http://127.0.0.1:${port}`,
    stop: () => new Promise<{ method: string; url: string }[]>((resolve) => {
      if (child.exitCode !== null) {
        resolve(parseRequests());
        return;
      }
      const timeout = setTimeout(() => {
        child.kill('SIGKILL');
        resolve(parseRequests());
      }, 3_000);
      child.once('exit', () => {
        clearTimeout(timeout);
        resolve(parseRequests());
      });
      child.kill('SIGTERM');
    }),
    getRequests: () => parseRequests(),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('CLI Verify Integration Tests\n');

  // -----------------------------------------------------------------------
  // verify --help
  // -----------------------------------------------------------------------

  await runTest('verify --help shows options', async () => {
    const home = makeTmpDir();
    try {
      const { stdout, status } = runCli(['verify', '--help'], {
        HOME: home,
        USERPROFILE: home,
        TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
      });
      assert.strictEqual(status, 0);
      assert.ok(stdout.includes('verify'), 'help must mention verify');
      assert.ok(stdout.includes('--client'), 'help must show --client');
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // not_installed → exit 1
  // -----------------------------------------------------------------------

  await runTest('not_installed → exit 1', async () => {
    const home = makeTmpDir();
    try {
      const { stdout, stderr, status } = runCli(
        ['verify', 'nonexistent', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 1, `expected exit 1, got ${status}: ${combined.slice(0, 300)}`);
      assert.ok(combined.includes('not_installed'), `expected not_installed: ${combined.slice(0, 300)}`);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // modified → exit 1
  // -----------------------------------------------------------------------

  await runTest('modified content → exit 1', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), 'original');

      const originalDigest = (await computeDirectoryDigest(installDir)).digest;

      // Now modify the file
      fs.writeFileSync(path.join(installDir, 'README.md'), 'modified');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: originalDigest,
      });

      const { stdout, stderr, status } = runCli(
        ['verify', 'test-pkg', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 1, `expected exit 1, got ${status}: ${combined.slice(0, 300)}`);
      assert.ok(combined.includes('modified'), `expected modified: ${combined.slice(0, 300)}`);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // missing → exit 1
  // -----------------------------------------------------------------------

  await runTest('missing directory → exit 1', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      // Directory does NOT exist

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: 'c'.repeat(64),
      });

      const { stdout, stderr, status } = runCli(
        ['verify', 'test-pkg', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 1, `expected exit 1, got ${status}`);
      assert.ok(combined.includes('missing'), `expected missing: ${combined.slice(0, 300)}`);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // remote_unavailable → exit 1 (API unreachable)
  // -----------------------------------------------------------------------

  await runTest('API unreachable → remote_unavailable → exit 1', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      // Use a closed port
      const { stdout, stderr, status } = runCli(
        ['verify', 'test-pkg', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:54321',
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 1, `expected exit 1, got ${status}`);
      assert.ok(
        combined.includes('remote_unavailable'),
        `expected remote_unavailable: ${combined.slice(0, 300)}`,
      );
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // valid → exit 0 through the real CLI subprocess
  // -----------------------------------------------------------------------

  await runTest('valid installation → exit 0', async () => {
    const home = makeTmpDir();
    let server: Awaited<ReturnType<typeof startManifestServer>> | undefined;
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');

      const digest = await computeDirectoryDigest(installDir);
      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest.digest,
      });

      server = await startManifestServer({
        manifest_version: '1.0',
        name: 'test-pkg',
        version: '1.0.0',
        type: 'skill',
        description: 'Test package',
        source: {
          type: 'github',
          repository_url: 'https://github.com/example/repo',
          download_url: 'https://example.com/test.zip',
          ref: 'v1.0.0',
          commit_hash: 'a'.repeat(40),
        },
        integrity: { sha256: 'b'.repeat(64), download_size_bytes: 1000 },
        installation: {
          method: 'copy_directory',
          target_client: 'claude-code',
          steps: [
            { action: 'download', url: 'https://example.com/test.zip' },
            { action: 'verify', algorithm: 'sha256', checksum: 'b'.repeat(64) },
            { action: 'extract', archive: 'test.zip' },
            { action: 'copy', source: 'src/', destination: '~/.claude/skills/test-pkg/' },
          ],
        },
        permissions: {},
        risk_summary: { level: 'low', grade: 'A', install_recommendation: 'safe' },
        compatibility: ['claude-code'],
        dependencies: {},
      });

      const { stdout, stderr, status } = runCli(
        ['verify', 'test-pkg', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: server.url,
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 0, `expected exit 0, got ${status}: ${combined.slice(0, 500)}`);
      assert.ok(combined.includes('[valid]'), `expected [valid]: ${combined.slice(0, 500)}`);

      // Assert the API request was correct — strict URL parsing
      const requests = await server.stop();
      assert.ok(requests.length >= 1, `expected at least 1 request, got ${requests.length}`);
      const req = requests[0];
      assert.strictEqual(req.method, 'GET', `expected GET, got ${req.method}`);

      // Parse URL and assert exact pathname + query params
      const reqUrl = new URL(req.url, 'http://localhost');
      assert.strictEqual(
        reqUrl.pathname,
        '/api/v0/packages/test-pkg/install-manifest',
        `pathname mismatch, got ${reqUrl.pathname}`,
      );
      assert.strictEqual(
        reqUrl.searchParams.get('client'), 'claude-code',
        `client param must be claude-code, got ${reqUrl.searchParams.get('client')}`,
      );
      assert.strictEqual(
        reqUrl.searchParams.get('version'), '1.0.0',
        `version param must be 1.0.0, got ${reqUrl.searchParams.get('version')}`,
      );
      // No unexpected params
      const expectedParams = new Set(['client', 'version']);
      for (const key of reqUrl.searchParams.keys()) {
        assert.ok(expectedParams.has(key), `unexpected query param: ${key}`);
      }
      server = undefined; // already stopped
    } finally {
      if (server) await server.stop();
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // CLI output sanitization: ANSI/control chars cannot reach stdout
  // -----------------------------------------------------------------------

  await runTest('CLI output strips ANSI and control chars', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills', 'test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), '# Test');
      const digest = (await computeDirectoryDigest(installDir)).digest;

      // Inject ANSI into package_name in the record
      const store = new LocalInstallStore(home);
      store.save({
        package_name: '\x1b[31mRED\x1b[0m',
        version: '1.0\r\nINJECTED',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: digest,
      });

      const { stdout, stderr, status } = runCli(
        ['verify', '\x1b[31mRED\x1b[0m', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
        },
      );
      const combined = stdout + stderr;
      // Injected ANSI escape sequences and CR must not survive sanitization.
      // (Visible text like "RED" may remain after ANSI codes are stripped —
      // that's expected. We check the raw escape bytes are gone.)
      assert.strictEqual(combined.includes('\x1b[31m'), false,
        'output must not contain injected ANSI sequence \\x1b[31m');
      assert.strictEqual(combined.includes('\rINJECTED'), false,
        'output must not contain \\r injected version');
      assert.strictEqual(combined.includes('\nINJECTED'), false,
        'output must not contain \\n injected version');
      assert.strictEqual(status, 1);
    } finally {
      cleanup(home);
    }
  });

  // -----------------------------------------------------------------------
  // Read-only: verify does not change files (modified case, no API needed)
  // -----------------------------------------------------------------------

  await runTest('read-only — files unchanged after verify (modified case)', async () => {
    const home = makeTmpDir();
    try {
      const installDir = path.join(home, '.claude/skills/test-pkg');
      fs.mkdirSync(installDir, { recursive: true });
      fs.writeFileSync(path.join(installDir, 'README.md'), 'original');

      const originalDigest = (await computeDirectoryDigest(installDir)).digest;
      fs.writeFileSync(path.join(installDir, 'README.md'), 'modified');

      const store = new LocalInstallStore(home);
      store.save({
        package_name: 'test-pkg',
        version: '1.0.0',
        client: 'claude-code',
        install_path: installDir,
        sha256: 'b'.repeat(64),
        integrity_verified: true,
        installed_at: new Date().toISOString(),
        manifest_version: '1.0',
        content_hash_algorithm: 'sha256-tree-v1',
        content_sha256: originalDigest,
      });

      // Snapshot before verify
      const recordsBefore = fs.readFileSync(store.getPath(), 'utf-8');
      const contentDigestBefore = (await computeDirectoryDigest(installDir)).digest;

      const { stdout, stderr, status } = runCli(
        ['verify', 'test-pkg', '--client', 'claude-code'],
        {
          HOME: home,
          USERPROFILE: home,
          TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1',
        },
      );
      const combined = stdout + stderr;
      assert.strictEqual(status, 1, `expected exit 1 for modified, got ${status}`);
      assert.ok(combined.includes('modified'));

      // Verify nothing changed
      const recordsAfter = fs.readFileSync(store.getPath(), 'utf-8');
      assert.strictEqual(recordsAfter, recordsBefore, 'installs.json must not change');

      const contentDigestAfter = (await computeDirectoryDigest(installDir)).digest;
      assert.strictEqual(contentDigestAfter, contentDigestBefore, 'content must not change');
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
