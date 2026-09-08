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
  expandHomePath,
  mcpServersFromManifest,
  readJsonConfig,
  removeMcpEntries,
  resolveMcpConfigPath,
  writeMergedMcpConfig,
} from '../src/config-writer';
import {
  hasCodexMcpSection,
  removeCodexMcpSections,
  resolveCodexConfigPath,
  writeCodexMcpSections,
} from '../src/codex-config-writer';
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

runTest('writeMergedMcpConfig expands ~ in command/args/env', async () => {
  const home = path.join(TEST_HOME, 'unit-home');
  const configPath = resolveMcpConfigPath('claude-code', home)!;
  await writeMergedMcpConfig(
    configPath,
    {
      filesystem: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '~'],
        env: { DATA_DIR: '~/data' },
      },
    },
    home,
  );
  const config = await readJsonConfig(configPath);
  const entry = (config.mcpServers as Record<string, any>).filesystem;
  assert.strictEqual(entry.args[2], home);
  assert.strictEqual(entry.env.DATA_DIR, path.join(home, 'data'));
});

runTest('expandHomePath handles ~, ~/x and plain values', () => {
  assert.strictEqual(expandHomePath('~', 'C:\\Users\\tester'), 'C:\\Users\\tester');
  assert.strictEqual(
    expandHomePath('~/data', 'C:\\Users\\tester'),
    path.join('C:\\Users\\tester', 'data'),
  );
  assert.strictEqual(expandHomePath('npx', 'C:\\Users\\tester'), 'npx');
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

runTest('writeCodexMcpSections writes and preserves unrelated TOML', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-1');
  const configPath = resolveCodexConfigPath(home);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    '# keep this comment\nmodel = "gpt-5"\n\n[mcp_servers.existing]\ncommand = "old"\n',
    'utf-8',
  );

  const result = await writeCodexMcpSections(
    configPath,
    {
      memory: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-memory'],
        env: { MEMORY_FILE_PATH: '/tmp/memory.json' },
      },
    },
    home,
  );

  assert.ok(result.backupPath);
  const text = fs.readFileSync(configPath, 'utf-8');
  assert.ok(text.includes('# keep this comment'));
  assert.ok(text.includes('model = "gpt-5"'));
  assert.ok(text.includes('[mcp_servers.existing]'));
  assert.ok(text.includes('[mcp_servers.memory]'));
  assert.ok(text.includes('MEMORY_FILE_PATH = "/tmp/memory.json"'));
});

runTest('removeCodexMcpSections removes only requested Codex servers', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-2');
  const configPath = resolveCodexConfigPath(home);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    '# top comment\n[mcp_servers.a]\ncommand = "a"\n\n[mcp_servers.b]\ncommand = "b"\n',
    'utf-8',
  );

  await removeCodexMcpSections(configPath, ['a']);
  const text = fs.readFileSync(configPath, 'utf-8');
  assert.ok(text.includes('# top comment'));
  assert.ok(!text.includes('[mcp_servers.a]'));
  assert.ok(text.includes('[mcp_servers.b]'));
});

runTest('hasCodexMcpSection detects Codex MCP sections', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-3');
  const configPath = resolveCodexConfigPath(home);
  await writeCodexMcpSections(
    configPath,
    { memory: { command: 'npx', args: ['-y', 'memory'] } },
    home,
  );

  assert.strictEqual(await hasCodexMcpSection(configPath, 'memory'), true);
  assert.strictEqual(await hasCodexMcpSection(configPath, 'missing'), false);
});

runTest('hasCodexMcpSection tolerates inline comments on table headers', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-4');
  const configPath = resolveCodexConfigPath(home);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    '[mcp_servers.memory] # managed by tah\ncommand = "node"\n',
    'utf-8',
  );
  assert.strictEqual(await hasCodexMcpSection(configPath, 'memory'), true);
});

runTest('Codex MCP section names are quoted when not bare TOML keys', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-5');
  const configPath = resolveCodexConfigPath(home);
  await writeCodexMcpSections(
    configPath,
    { 'bad.name': { command: 'node' } },
    home,
  );
  const text = fs.readFileSync(configPath, 'utf-8');
  assert.ok(text.startsWith('[mcp_servers."bad.name"]'));
  assert.ok(!text.includes('[mcp_servers.bad.name]'));
});

runTest('writeCodexMcpSections rejects malformed existing config', async () => {
  const home = path.join(TEST_HOME, 'codex-unit-6');
  const configPath = resolveCodexConfigPath(home);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, 'model = "unterminated\n', 'utf-8');

  await assert.rejects(
    writeCodexMcpSections(
      configPath,
      { memory: { command: 'npx' } },
      home,
    ),
    (err: unknown) =>
      err instanceof Error && err.message.includes('Cannot parse Codex config'),
  );
  assert.strictEqual(
    fs.readFileSync(configPath, 'utf-8'),
    'model = "unterminated\n',
  );
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
    confirmManagedInstall: async () => true,
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
    confirmManagedInstall: async () => true,
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

runTest('install writes Codex TOML config after confirmation', async () => {
  const home = path.join(TEST_HOME, 'e2e-codex-1');
  const manifest = makeNpmManifest({
    compatibility: ['codex'],
    installation: {
      method: 'npm_install',
      target_client: 'codex',
      steps: [
        {
          action: 'npm_install',
          package: 'mcp-demo',
          version: '1.0.0',
          registry: 'https://registry.npmjs.org',
        },
      ],
      pre_install_message: null,
      post_install_message: null,
    },
  });
  const apiClient = createApiClient(mockFetch(manifest));
  const executor = new InstallExecutor(apiClient, {
    homeDir: home,
    confirmManagedInstall: async () => true,
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

  const result = await executor.installWithManifest(manifest, 'codex', {});
  assert.strictEqual(result.record.client, 'codex');
  assert.strictEqual(result.record.config_file, resolveCodexConfigPath(home));
  assert.deepStrictEqual(result.record.config_entries, ['mcp-demo']);
  assert.strictEqual(
    await hasCodexMcpSection(result.record.config_file!, 'mcp-demo'),
    true,
  );
  const installedConfig = fs.readFileSync(result.record.config_file!, 'utf-8');
  assert.ok(
    installedConfig.includes(
      `cwd = ${JSON.stringify(result.record.install_path)}`,
    ),
  );

  const verify = new VerifyExecutor(apiClient, { homeDir: home });
  const v1 = await verify.verify(manifest.name, 'codex');
  assert.strictEqual(v1.status, 'valid', v1.message);

  await removeCodexMcpSections(result.record.config_file!, ['mcp-demo']);
  const v2 = await verify.verify(manifest.name, 'codex');
  assert.strictEqual(v2.status, 'manifest_mismatch');

  await writeCodexMcpSections(
    result.record.config_file!,
    { 'mcp-demo': { command: 'node', args: ['server.js'] } },
    home,
  );
  const uninstall = new UninstallExecutor({ homeDir: home });
  const u = await uninstall.uninstall(manifest.name, 'codex', { yes: true });
  assert.strictEqual(u.status, 'uninstalled', u.message);
  assert.strictEqual(
    await hasCodexMcpSection(result.record.config_file!, 'mcp-demo'),
    false,
  );
});

runTest('Codex save failure restores pre-existing config backup', async () => {
  const home = path.join(TEST_HOME, 'e2e-codex-2');
  const configPath = resolveCodexConfigPath(home);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  const original = '# keep me\n[mcp_servers.mcp-demo]\ncommand = "old"\n';
  fs.writeFileSync(configPath, original, 'utf-8');

  const manifest = makeNpmManifest({
    compatibility: ['codex'],
    installation: {
      method: 'npm_install',
      target_client: 'codex',
      steps: [
        {
          action: 'npm_install',
          package: 'mcp-demo',
          version: '1.0.0',
          registry: 'https://registry.npmjs.org',
        },
      ],
      pre_install_message: null,
      post_install_message: null,
    },
  });
  const apiClient = createApiClient(mockFetch(manifest));
  const executor = new InstallExecutor(apiClient, {
    homeDir: home,
    confirmManagedInstall: async () => true,
    confirmMcpWrite: async () => true,
    beforeSaveRecord: () => {
      throw new Error('simulated record save failure');
    },
    runCommand: async (cmd, args) => {
      const prefixIdx = args.indexOf('--prefix');
      if (prefixIdx >= 0) {
        fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
        fs.writeFileSync(path.join(args[prefixIdx + 1], 'package.json'), '{}', 'utf-8');
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });

  await assert.rejects(
    () => executor.installWithManifest(manifest, 'codex', {}),
    (err: unknown) => err instanceof Error && err.message.includes('simulated record save failure'),
  );
  assert.strictEqual(fs.readFileSync(configPath, 'utf-8'), original);
});

runTest('record-save failure rolls back written MCP entries', async () => {
  const home = path.join(TEST_HOME, 'e2e-3');
  const manifest = makeNpmManifest();
  const apiClient = createApiClient(mockFetch(manifest));
  const executor = new InstallExecutor(apiClient, {
    homeDir: home,
    confirmManagedInstall: async () => true,
    confirmMcpWrite: async () => true,
    beforeSaveRecord: () => {
      throw new Error('simulated record save failure');
    },
    runCommand: async (cmd, args) => {
      const prefixIdx = args.indexOf('--prefix');
      if (prefixIdx >= 0) {
        fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
        fs.writeFileSync(path.join(args[prefixIdx + 1], 'package.json'), '{}', 'utf-8');
      }
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });

  await assert.rejects(
    () => executor.installWithManifest(manifest, 'claude-code', {}),
    (err: unknown) => err instanceof Error && err.message.includes('simulated record save failure'),
  );
  // 安装失败后 MCP 配置条目应被回滚
  const config = await readJsonConfig(resolveMcpConfigPath('claude-code', home)!);
  assert.strictEqual(
    'mcp-demo' in (config.mcpServers as Record<string, unknown>),
    false,
  );
});

// ---------------------------------------------------------------------------

setTimeout(() => {
  console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
  if (failed) process.exit(1);
}, 100);
