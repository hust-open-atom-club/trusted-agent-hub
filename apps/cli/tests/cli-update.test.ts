/**
 * CLI integration tests for the `update` command.
 *
 * Run: npx tsx tests/cli-update.test.ts
 *
 * Coverage:
 *   - update --help shows all options
 *   - Uninstalled package → exit 1, UPDATE_STATUS=not_installed
 *   - update --client cursor recognized
 *   - UPDATE_STATUS machine-parseable line present, no ANSI
 *   - E2E (in-process): install v1 → update v2 → verify → up_to_date
 *     (uses mock HTTP server + real executors; subprocess network
 *      unavailable in this environment)
 */

import * as assert from 'assert';
import { spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as http from 'http';
import AdmZip from 'adm-zip';
import { InstallExecutor } from '../src/install-executor';
import { UpdateExecutor } from '../src/update-executor';
import { VerifyExecutor } from '../src/verify-executor';
import { LocalInstallStore } from '../src/local-install-store';
import { createApiClient } from '../src/api-client';
import type { FetchFn, InstallManifest } from '../src/manifest-types';

const CLI_ENTRY = path.resolve(__dirname, '..', 'dist', 'apps', 'cli', 'src', 'cli.js');
const DEAD_ENV = { ...process.env, TRUSTED_AGENT_HUB_API_URL: 'http://127.0.0.1:1' };

function runCli(args: string[], env?: Record<string, string>, timeout = 15_000) {
  const result = spawnSync('node', [CLI_ENTRY, ...args], {
    env: { ...process.env, ...env },
    timeout,
  });
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || '',
    status: result.status,
    signal: result.signal,
  };
}

// ---------------------------------------------------------------------------
// CLI argument tests (no server needed)
// ---------------------------------------------------------------------------

function test_updateHelpShowsOptions() {
  const { stdout, status } = runCli(['update', '--help']);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('--client') && stdout.includes('--force') &&
    stdout.includes('--yes') && stdout.includes('--accept-high-risk'));
  console.log('  ✓ update --help shows all options');
}

function test_uninstalledPackageExitsBad() {
  const { stdout, status } = runCli(['update', 'no-such-pkg', '--client', 'claude-code'], DEAD_ENV);
  assert.notStrictEqual(status, 0);
  assert.ok(stdout.includes('not_installed') || stdout.includes('not installed'));
  console.log('  ✓ uninstalled package → exit 1, not_installed');
}

function test_updateStatusLineAndAnsi() {
  const { stdout, status } = runCli(['update', 'no-such-pkg'], DEAD_ENV);
  assert.notStrictEqual(status, 0);
  assert.ok(stdout.includes('UPDATE_STATUS=not_installed'));
  const statusLine = stdout.split('\n').find(l => l.startsWith('UPDATE_STATUS='))!;
  assert.ok(!statusLine.includes('\x1b'));
  console.log('  ✓ UPDATE_STATUS=not_installed, no ANSI');
}

function test_updateClientCursorRecognized() {
  const { stdout, status } = runCli(['update', 'pkg', '--client', 'cursor'], DEAD_ENV);
  assert.notStrictEqual(status, 0);
  assert.ok(!stdout.includes('unsupported_client') && !stdout.includes('Unsupported client'));
  console.log('  ✓ --client cursor recognized');
}

function test_updateForceYesHighRiskAccepted() {
  const { stdout, status } = runCli(['update', 'pkg', '--force', '--yes', '--accept-high-risk'], DEAD_ENV);
  assert.notStrictEqual(status, 0);
  assert.ok(!stdout.includes('unknown option'));
  console.log('  ✓ --force, --yes, --accept-high-risk flags accepted');
}

// ---------------------------------------------------------------------------
// In-process E2E: install v1 → update v2 → verify → up_to_date
// ---------------------------------------------------------------------------

function sha256(buf: Buffer): string { return crypto.createHash('sha256').update(buf).digest('hex'); }
function makeZip(files: Record<string, string>): Buffer {
  const zip = new AdmZip();
  for (const [k, v] of Object.entries(files)) zip.addFile(k, Buffer.from(v, 'utf-8'));
  return zip.toBuffer();
}

function buildManifest(name: string, version: string, client: string, dest: string,
  dlUrl: string, sha: string, size: number): InstallManifest {
  return {
    manifest_version: '1.0', name, version, type: 'skill', description: `v${version}`,
    source: { type: 'github', repository_url: 'https://github.com/t/r', download_url: dlUrl, ref: `v${version}`, commit_hash: 'a'.repeat(40) },
    integrity: { sha256: sha, download_size_bytes: size },
    installation: { method: 'copy_directory', target_client: client, steps: [
      { action: 'download', url: dlUrl }, { action: 'verify', algorithm: 'sha256', checksum: sha },
      { action: 'extract', archive: 'package.zip' }, { action: 'copy', source: 'package/', destination: dest },
    ]},
    permissions: { filesystem: { read: ['*'] }, shell: { allowed: false }, network: { allowed: false }, environment: { read: [], write: [] } },
    risk_summary: { level: 'low_risk', grade: 'B', top_risks: [], install_recommendation: 'safe' },
    compatibility: [client], dependencies: { npm: null, pip: null, system: null, docker: null, mcp_servers: null },
  } as InstallManifest;
}

async function startMock(
  manifests: Map<string, InstallManifest>,
  zips: Map<string, Buffer>,
): Promise<{ port: number; close: () => void }> {
  return new Promise(resolve => {
    const s = http.createServer((req, res) => {
      const u = new URL(req.url || '/', `http://localhost`);
      // POST install record
      if (req.method === 'POST' && u.pathname === '/api/v0/installs') {
        res.writeHead(201); res.end(JSON.stringify({ id: 'x' })); return;
      }
      // Manifest — support version param for specific version lookups
      const mm = u.pathname.match(/^\/api\/v0\/packages\/(.+)\/install-manifest$/);
      if (mm) {
        const pkgName = decodeURIComponent(mm[1]);
        const ver = u.searchParams.get('version');
        // Try version-specific manifest first, then generic
        const m = (ver ? manifests.get(`${pkgName}@${ver}`) : null) || manifests.get(pkgName);
        if (!m) { res.writeHead(404); res.end('{}'); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(m)); return;
      }
      // Version detail
      if (u.pathname.match(/^\/api\/v0\/packages\/.+\/versions\/.+$/)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'v', version: '1.0.0', status: 'published' })); return;
      }
      // Package info
      if (u.pathname.match(/^\/api\/v0\/packages\/.+$/)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'p', name: 'x', latest_version: '2.0.0', status: 'published' })); return;
      }
      // ZIP
      for (const [k, v] of zips) {
        if (req.url?.includes(k)) {
          res.writeHead(200, { 'Content-Length': String(v.length) }); res.end(v); return;
        }
      }
      res.writeHead(404); res.end('{}');
    });
    s.listen(0, () => { resolve({ port: (s.address() as any).port, close: () => s.close() }); });
  });
}

async function test_e2eInProcess() {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tah-e2e-'));
  const pkg = 'e2e-pkg';
  const client = 'claude-code';
  const dest = `~/.claude/skills/${pkg}/`;

  const v1Zip = makeZip({ 'package/README.md': '# v1\n', 'package/main.js': 'console.log("v1");' });
  const v2Zip = makeZip({ 'package/README.md': '# v2\n', 'package/main.js': 'console.log("v2");\n', 'package/utils.js': '// new' });
  const v1Sha = sha256(v1Zip); const v2Sha = sha256(v2Zip);

  const v1m = buildManifest(pkg, '1.0.0', client, dest, 'https://download.test/v1.zip', v1Sha, v1Zip.length);
  const v2m = buildManifest(pkg, '2.0.0', client, dest, 'https://download.test/v2.zip', v2Sha, v2Zip.length);

  const manifests = new Map<string, InstallManifest>([
    [pkg, v2m],                    // latest (no version param) → v2
    [`${pkg}@1.0.0`, v1m],         // version=1.0.0 → v1
    [`${pkg}@2.0.0`, v2m],         // version=2.0.0 → v2
  ]);
  const zips = new Map([['v1.zip', v1Zip], ['v2.zip', v2Zip]]);

  const { port, close } = await startMock(manifests, zips);

  const fetchFn: FetchFn = (urlStr, init) => {
    const parsed = new URL(urlStr.toString());
    parsed.protocol = 'http:'; parsed.hostname = 'localhost'; parsed.port = String(port);
    return fetch(parsed.toString(), init);
  };
  const apiClient = createApiClient(fetchFn);
  const installsJson = path.join(homeDir, '.trusted-agent-hub', 'installs.json');

  try {
    // ── Step 1: install v1 ──
    const installExec = new InstallExecutor(apiClient, { homeDir, fetchFn });
    // Rewrite all requests to http://localhost:${port}
    const rewriter = (urlStr: string, init?: RequestInit) => {
      const parsed = new URL(urlStr.toString());
      parsed.protocol = 'http:';
      parsed.hostname = 'localhost';
      parsed.port = String(port);
      return fetch(parsed.toString(), init);
    };
    const v1InstallExec = new InstallExecutor(createApiClient(rewriter), { homeDir, fetchFn: rewriter });
    const installResult = await v1InstallExec.install(pkg, client, { yes: true }, '1.0.0');
    assert.strictEqual(installResult.record.version, '1.0.0');
    const originalInstalledAt = installResult.record.installed_at;

    // Verify v1 files on disk
    assert.ok(fs.existsSync(path.join(installResult.targetDir, 'main.js')));
    const record1 = JSON.parse(fs.readFileSync(installsJson, 'utf-8'));
    assert.strictEqual(record1[0].version, '1.0.0');
    assert.strictEqual(record1[0].updated_at, undefined);
    console.log('  ✓ E2E step 1: install v1 OK');

    // ── Step 2: update to v2 ──
    const updateExec = new UpdateExecutor(apiClient, { homeDir, fetchFn });
    const updateResult = await updateExec.update(pkg, client, { yes: true });
    assert.strictEqual(updateResult.status, 'updated');
    assert.strictEqual(updateResult.localVersion, '1.0.0');
    assert.strictEqual(updateResult.remoteVersion, '2.0.0');
    console.log('  ✓ E2E step 2: update v1→v2 OK, status=updated');

    // ── Step 3: verify after update ──
    const verifyResult = await new VerifyExecutor(apiClient, { homeDir }).verify(pkg, client);
    assert.strictEqual(verifyResult.status, 'valid', `Expected valid, got ${verifyResult.status}: ${verifyResult.message}`);
    console.log('  ✓ E2E step 3: verify passes');

    // ── Step 4: check v2 files ──
    assert.ok(fs.existsSync(path.join(installResult.targetDir, 'utils.js')), 'v2 utils.js should exist');
    const readme = fs.readFileSync(path.join(installResult.targetDir, 'README.md'), 'utf-8');
    assert.ok(readme.includes('v2'), `README should contain v2: ${readme}`);
    console.log('  ✓ E2E step 4: v2 files on disk');

    // ── Step 5: check record ──
    const record2 = JSON.parse(fs.readFileSync(installsJson, 'utf-8'));
    assert.strictEqual(record2.length, 1);
    assert.strictEqual(record2[0].version, '2.0.0');
    assert.strictEqual(record2[0].installed_at, originalInstalledAt, 'installed_at preserved');
    assert.ok(record2[0].updated_at !== undefined, 'updated_at set');
    console.log('  ✓ E2E step 5: record updated, timestamps correct');

    // ── Step 6: up_to_date ──
    const update2 = await updateExec.update(pkg, client, { yes: true });
    assert.strictEqual(update2.status, 'up_to_date');
    assert.strictEqual(update2.ok, true);
    console.log('  ✓ E2E step 6: up_to_date, no writes');
  } finally {
    close();
    try { fs.rmSync(homeDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Run all
// ---------------------------------------------------------------------------

async function main() {
  console.log('\nCLI Update Integration + E2E Tests\n');

  if (!fs.existsSync(CLI_ENTRY)) {
    console.log('  ⚠ CLI not built — skipping CLI tests\n');
    process.exit(0);
  }

  // CLI arg tests (via subprocess — work without network)
  test_updateHelpShowsOptions();
  test_uninstalledPackageExitsBad();
  test_updateStatusLineAndAnsi();
  test_updateClientCursorRecognized();
  test_updateForceYesHighRiskAccepted();

  // In-process E2E
  console.log('\n  ── E2E: install → update → verify ──\n');
  await test_e2eInProcess();

  console.log('\n  ✓ All CLI update tests passed!\n');
}

main().catch(err => { console.error('Test suite failed:', err); process.exit(1); });
