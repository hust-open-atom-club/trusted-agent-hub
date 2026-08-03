/**
 * MCP client config write tests — config-writer unit tests plus install →
 * verify → uninstall closure for non-copy installs with mcp_servers.
 *
 * Run: npx tsx tests/mcp-config.test.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { InstallExecutor } from '../src/install-executor';
import { UninstallExecutor } from '../src/uninstall-executor';
import { VerifyExecutor } from '../src/verify-executor';
import { createApiClient } from '../src/api-client';
import type { FetchFn } from '../src/api-client';
import { validateManifest } from '../src/manifest-types';
import type { InstallManifest } from '../src/manifest-types';
import {
  describeMcpDiff,
  mcpServersFromManifest,
  readJsonConfig,
  removeMcpEntries,
  resolveMcpConfigPath,
  writeMergedMcpConfig,
} from '../src/config-writer';
import { LocalInstallStore } from '../src/local-install-store';

const TEST_HOME = path.join(
  os.tmpdir(),
  'tah-mcp-' + crypto.randomBytes(8).toString('hex'),
);

function makeNpmManifest(overrides: Partial<InstallManifest> = {}): InstallManifest {
  const manifest = {
    manifest_version: '1.0' as const,
    name: 'mcp-demo',
    version: '1.0.0',
    type: 'mcp_server',
    description: 'MCP demo',
    source: {
      type: 'npm' as const,
      repository_url: 'https://github.com/test/mcp-demo',
      download_url: null,
      ref: 'main',
      commit_hash: null,
    },
    integrity: null,
    installation: {
      method: 'npm_install' as const,
      target_client: 'claude-code',
      steps: [
        {
          action: 'npm_install' as const,
          package: 'mcp-demo',
          version: '1.0.0',
          registry: 'https://registry.npmjs.org',
        },
      ],
      pre_install_message: null,
      post_install_message: null,
    },
    permissions: {
      filesystem: { read: [], write: [], delete: false },
      shell: { allowed: false, commands: [] },
      network: { allowed: false, domains: [] },
      environment: { read: [], write: [] },
    },
    risk_summary: {
      level: 'low_risk',
      grade: 'B',
      top_risks: [],
      install_recommendation: 'safe',
    },
    compatibility: ['claude-code'],
    dependencies: {
      npm: null,
      pip: null,
      system: null,
      docker: null,
      mcp_servers: [
        {
          name: 'mcp-demo',
          command: 'node',
          args: ['server.js'],
          env: { API_KEY: 'demo' },
        },
      ],
    },
    ...overrides,
  };
  return validateManifest(manifest) as InstallManifest;
}

function mockFetch(manifest: InstallManifest): FetchFn {
  return async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return {
        status: 201,
        ok: true,
        headers: new Headers(),
        json: async () => ({
          id: 'rec-1',
          package_name: manifest.name,
          version: manifest.version,
          version_id: 'v1',
          user_id: 'u1',
          client: manifest.installation.target_client,
          install_path: '/managed',
          integrity_verified: true,
          installed_at: new Date().toISOString(),
        }),
        text: async () => '',
      } as Response;
    }
    if (String(urlStr).includes('install-manifest')) {
      return {
        status: 200,
        ok: true,
        headers: new Headers(),
        json: async () => manifest,
        text: async () => JSON.stringify(manifest),
      } as Response;
    }
    return {
      status: 404,
      ok: false,
      headers: new Headers(),
      json: async () => ({}),
      text: async () => '',
    } as Response;
  };
}

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => void | Promise<void>): void {
  Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  ✓ ${name}`);
    })
    .catch((err) => {
      failed++;
      console.error(`  ✗ ${name}`);
      console.error(err);
    });
}

// ---------------------------------------------------------------------------
// config-writer unit tests
// ---------------------------------------------------------------------------

runTest('writeMergedMcpConfig merges entries with backup', async () => {
  const home = path.join(TEST_HOME, 'unit-1');
  const configPath = resolveMcpConfigPath('claude-code', home)!;
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    JSON.stringify({ mcpServers: { existing: { command: 'a' } } }),
    'utf-8',
  );

  const result = await writeMergedMcpConfig(
    configPath,
    { 'mcp-demo': { command: 'node', args: ['x'] } },
    home,
  );
  assert.ok(result.backupPath);
  assert.ok(fs.existsSync(result.backupPath!));

  const config = await readJsonConfig(configPath);
  const servers = config.mcpServers as Record<string, unknown>;
  assert.ok('existing' in servers);
  assert.ok('mcp-demo' in servers);
});

runTest('writeMergedMcpConfig creates file when missing', async () => {
  const home = path.join(TEST_HOME, 'unit-2');
  const configPath = resolveMcpConfigPath('cursor', home)!;
  const result = await writeMergedMcpConfig(
    configPath,
    { demo: { url: 'http://127.0.0.1:9000' } },
    home,
  );
  assert.strictEqual(result.backupPath, null);
  const config = await readJsonConfig(configPath);
  assert.deepStrictEqual(
    (config.mcpServers as Record<string, unknown>).demo,
    { url: 'http://127.0.0.1:9000' },
  );
});

runTest('removeMcpEntries deletes only the given keys', async () => {
  const home = path.join(TEST_HOME, 'unit-3');
  const configPath = resolveMcpConfigPath('claude-code', home)!;
  await writeMergedMcpConfig(configPath, { a: { command: 'x' }, b: { command: 'y' } }, home);
  await removeMcpEntries(configPath, ['a']);
  const config = await readJsonConfig(configPath);
  const servers = config.mcpServers as Record<string, unknown>;
  assert.strictEqual('a' in servers, false);
  assert.ok('b' in servers);
});

runTest('mcpServersFromManifest extracts command entries', () => {
  const entries = mcpServersFromManifest(makeNpmManifest());
  assert.ok(entries);
  assert.deepStrictEqual(entries!['mcp-demo'].command, 'node');
  assert.deepStrictEqual(entries!['mcp-demo'].args, ['server.js']);
  assert.deepStrictEqual(entries!['mcp-demo'].env, { API_KEY: 'demo' });
});

runTest('describeMcpDiff marks add vs overwrite', () => {
  const diff = describeMcpDiff(
    { mcpServers: { old: { command: 'x' } } },
    { old: { command: 'y' }, fresh: { command: 'z' } },
  );
  assert.ok(diff.some((l) => l.includes('覆盖已有 MCP server: old')));
  assert.ok(diff.some((l) => l.includes('新增 MCP server: fresh')));
});

// ---------------------------------------------------------------------------
// Install → verify → uninstall closure with MCP config
// ---------------------------------------------------------------------------

runTest('install writes MCP config after confirmation', async () => {
  const home = path.join(TEST_HOME, 'e2e-1');
  const manifest = makeNpmManifest();
  const apiClient = createApiClient(mockFetch(manifest));
  const executor = new InstallExecutor(apiClient, {
    homeDir: home,
    confirmMcpWrite: async () => true,
    runCommand: async (cmd, args) => {
      const prefixIdx = args.indexOf('--prefix');
      if (prefixIdx >= 0) {
        fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
        fs.writeFileSync(path.join(args[prefixIdx + 1], 'package.json'), '{}', 'utf-8');
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });

  const result = await executor.installWithManifest(manifest, 'claude-code', {});
  assert.ok(result.record.config_file);
  assert.deepStrictEqual(result.record.config_entries, ['mcp-demo']);
  assert.strictEqual(result.record.backup_path, undefined);

  const config = await readJsonConfig(result.record.config_file!);
  assert.ok('mcp-demo' in (config.mcpServers as Record<string, unknown>));

  // verify → valid
  const verify = new VerifyExecutor(apiClient, { homeDir: home });
  const v1 = await verify.verify(manifest.name, 'claude-code');
  assert.strictEqual(v1.status, 'valid', v1.message);

  // 删除配置条目后 verify 应报 manifest_mismatch
  await removeMcpEntries(result.record.config_file!, ['mcp-demo']);
  const v2 = await verify.verify(manifest.name, 'claude-code');
  assert.strictEqual(v2.status, 'manifest_mismatch');
  // 恢复条目供 uninstall 清理
  await writeMergedMcpConfig(result.record.config_file!, { 'mcp-demo': { command: 'node' } }, home);

  // uninstall → 目录删除 + 配置条目移除 + 记录删除
  const uninstall = new UninstallExecutor({ homeDir: home });
  const u = await uninstall.uninstall(manifest.name, 'claude-code', {
    yes: true,
  });
  assert.strictEqual(u.status, 'uninstalled', u.message);
  assert.strictEqual(fs.existsSync(result.targetDir), false);
  const configAfter = await readJsonConfig(result.record.config_file!);
  assert.strictEqual(
    'mcp-demo' in (configAfter.mcpServers as Record<string, unknown>),
    false,
  );
  const store = new LocalInstallStore(home);
  assert.strictEqual(store.find(manifest.name, 'claude-code'), null);
});

runTest('install skips MCP write when confirmation is denied', async () => {
  const home = path.join(TEST_HOME, 'e2e-2');
  const manifest = makeNpmManifest();
  const apiClient = createApiClient(mockFetch(manifest));
  const executor = new InstallExecutor(apiClient, {
    homeDir: home,
    confirmMcpWrite: async () => false,
    runCommand: async (cmd, args) => {
      const prefixIdx = args.indexOf('--prefix');
      if (prefixIdx >= 0) {
        fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
        fs.writeFileSync(path.join(args[prefixIdx + 1], 'package.json'), '{}', 'utf-8');
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});
  assert.strictEqual(result.record.config_file, undefined);
  assert.strictEqual(fs.existsSync(resolveMcpConfigPath('claude-code', home)!), false);
});

// ---------------------------------------------------------------------------

setTimeout(() => {
  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}, 100);
