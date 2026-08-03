/**
 * Tests for non-copy install methods (npm/pip/docker/manual) and the
 * extended Manifest v1.0 step validation.
 *
 * Run: npx tsx tests/install-methods.test.ts
 */

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { InstallExecutor, InstallError } from '../src/install-executor';
import { UpdateExecutor } from '../src/update-executor';
import { validateManifest, ManifestValidationError } from '../src/manifest-types';
import type { InstallManifest } from '../src/manifest-types';
import { createApiClient } from '../src/api-client';
import type { FetchFn } from '../src/api-client';
import { LocalInstallStore } from '../src/local-install-store';

const TEST_HOME = path.join(
  os.tmpdir(),
  'tah-methods-' + crypto.randomBytes(8).toString('hex'),
);

function makeMethodManifest(
  method: 'npm_install' | 'pip_install' | 'docker_run' | 'manual_steps',
  step: Record<string, unknown>,
  overrides: Partial<InstallManifest> = {},
): InstallManifest {
  const manifest = {
    manifest_version: '1.0' as const,
    name: 'demo-tool',
    version: '1.0.0',
    type: 'skill',
    description: 'Method test package',
    source: {
      type: 'github' as const,
      repository_url: 'https://github.com/test/demo',
      download_url: null,
      ref: 'main',
      commit_hash: null,
    },
    integrity: null,
    installation: {
      method,
      target_client: 'claude-code',
      steps: [step],
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
    dependencies: { npm: null, pip: null, system: null, docker: null, mcp_servers: null },
    ...overrides,
  };
  return validateManifest(manifest) as InstallManifest;
}

function mockApiFetch(): FetchFn {
  return async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return {
        status: 201,
        ok: true,
        headers: new Headers(),
        json: async () => ({
          id: 'rec-1',
          package_name: 'demo-tool',
          version: '1.0.0',
          version_id: 'v1',
          user_id: 'u1',
          client: 'claude-code',
          install_path: '/managed',
          integrity_verified: true,
          installed_at: new Date().toISOString(),
        }),
        text: async () => '',
      } as Response;
    }
    return {
      status: 200,
      ok: true,
      headers: new Headers(),
      json: async () => ({}),
      text: async () => '',
    } as Response;
  };
}

// ---------------------------------------------------------------------------
// Manifest step validation
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function runTest(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${name}`);
    console.error(err);
  }
}

runTest('npm manifest validates with registry', () => {
  const m = makeMethodManifest('npm_install', {
    action: 'npm_install',
    package: '@scope/demo',
    version: '1.2.3',
    registry: 'https://registry.npmjs.org',
  });
  assert.strictEqual(m.installation.steps[0].action, 'npm_install');
});

runTest('npm manifest rejects http registry', () => {
  assert.throws(
    () =>
      makeMethodManifest('npm_install', {
        action: 'npm_install',
        package: 'demo',
        version: '1.0.0',
        registry: 'http://registry.example.com',
      }),
    ManifestValidationError,
  );
});

runTest('npm manifest rejects local path package', () => {
  assert.throws(
    () =>
      makeMethodManifest('npm_install', {
        action: 'npm_install',
        package: '/tmp/evil',
        version: '1.0.0',
      }),
    ManifestValidationError,
  );
});

runTest('pip manifest validates with index_url', () => {
  const m = makeMethodManifest('pip_install', {
    action: 'pip_install',
    package: 'demo-pkg',
    version: '1.0.0',
    index_url: 'https://pypi.org/simple',
  });
  assert.strictEqual(m.installation.steps[0].action, 'pip_install');
});

runTest('pip manifest rejects http index_url', () => {
  assert.throws(
    () =>
      makeMethodManifest('pip_install', {
        action: 'pip_install',
        package: 'demo-pkg',
        version: '1.0.0',
        index_url: 'http://pypi.example.com/simple',
      }),
    ManifestValidationError,
  );
});

runTest('docker manifest validates with options', () => {
  const m = makeMethodManifest('docker_run', {
    action: 'docker_run',
    image: 'demo/app',
    tag: '1.0.0',
    ports: ['8080:80'],
    volumes: ['./data:/var/lib/app'],
    env: ['KEY=VALUE'],
  });
  const step = m.installation.steps[0] as { action: string; image: string };
  assert.strictEqual(step.image, 'demo/app');
});

runTest('docker manifest rejects image with spaces', () => {
  assert.throws(
    () =>
      makeMethodManifest('docker_run', {
        action: 'docker_run',
        image: 'evil image',
      }),
    ManifestValidationError,
  );
});

runTest('manual manifest validates with text', () => {
  const m = makeMethodManifest('manual_steps', {
    action: 'manual_steps',
    title: 'demo',
    text: '1. download\n2. install',
  });
  assert.strictEqual(m.installation.steps[0].action, 'manual_steps');
});

runTest('manual manifest rejects empty text', () => {
  assert.throws(
    () =>
      makeMethodManifest('manual_steps', {
        action: 'manual_steps',
        text: '',
      }),
    ManifestValidationError,
  );
});

runTest('npm method rejects copy steps', () => {
  assert.throws(
    () =>
      makeMethodManifest('npm_install', {
        action: 'copy',
        source: 'x/',
        destination: 'y/',
      }),
    ManifestValidationError,
  );
});

// ---------------------------------------------------------------------------
// Executor dispatch
// ---------------------------------------------------------------------------

async function makeExecutor(
  manifest: InstallManifest,
  runCommand?: (cmd: string, args: string[], opts?: { cwd?: string }) => Promise<{
    exitCode: number;
    stdout: string;
    stderr: string;
  }>,
): Promise<InstallExecutor> {
  const apiClient = createApiClient(mockApiFetch());
  const executor = new InstallExecutor(apiClient, {
    homeDir: TEST_HOME,
    confirmManagedInstall: async () => true,
    runCommand: runCommand || (async () => ({ exitCode: 0, stdout: '', stderr: '' })),
  });
  return executor;
}

runTest('npm install dispatches to npm executor with managed prefix', async () => {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const manifest = makeMethodManifest('npm_install', {
    action: 'npm_install',
    package: 'demo-tool',
    version: '1.0.0',
    registry: 'https://registry.npmjs.org',
  });
  const executor = await makeExecutor(manifest, async (cmd, args) => {
    calls.push({ cmd, args });
    // 模拟 npm 写入目标目录
    const prefixIdx = args.indexOf('--prefix');
    if (prefixIdx >= 0) {
      fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
      fs.writeFileSync(
        path.join(args[prefixIdx + 1], 'package.json'),
        '{"name":"demo-tool"}\n',
        'utf-8',
      );
    }
    return { exitCode: 0, stdout: 'ok', stderr: '' };
  });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});

  assert.strictEqual(result.sha256, null);
  assert.ok(result.targetDir.endsWith(path.join('installed', 'demo-tool-npm')));
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(
    calls[0].cmd,
    process.platform === 'win32' ? 'npm.cmd' : 'npm',
  );
  assert.ok(calls[0].args.includes('--prefix'));
  assert.ok(calls[0].args.includes('--registry'));
  assert.ok(calls[0].args.includes('demo-tool@1.0.0'));
  assert.strictEqual(result.record.method, 'npm_install');
  assert.ok(fs.existsSync(path.join(result.targetDir, 'package.json')));
});

runTest('pip install dispatches with --target and index', async () => {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const manifest = makeMethodManifest('pip_install', {
    action: 'pip_install',
    package: 'demo-pkg',
    version: '1.0.0',
    index_url: 'https://pypi.org/simple',
  });
  const executor = await makeExecutor(manifest, async (cmd, args) => {
    calls.push({ cmd, args });
    // 模拟 pip 写入目标目录
    const targetIdx = args.indexOf('--target');
    if (targetIdx >= 0) {
      fs.mkdirSync(args[targetIdx + 1], { recursive: true });
      fs.writeFileSync(path.join(args[targetIdx + 1], 'PKG-INFO'), 'demo\n', 'utf-8');
    }
    return { exitCode: 0, stdout: 'ok', stderr: '' };
  });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});

  assert.strictEqual(calls[0].cmd, 'python');
  assert.ok(calls[0].args.includes('--target'));
  assert.ok(calls[0].args.includes('--index-url'));
  assert.ok(calls[0].args.includes('demo-pkg==1.0.0'));
  assert.strictEqual(result.record.method, 'pip_install');
});

runTest('docker install pulls image and writes run config', async () => {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const manifest = makeMethodManifest('docker_run', {
    action: 'docker_run',
    image: 'demo/app',
    tag: '1.0.0',
    ports: ['8080:80'],
    volumes: [],
    env: ['KEY=VALUE'],
  });
  const executor = await makeExecutor(manifest, async (cmd, args) => {
    calls.push({ cmd, args });
    return { exitCode: 0, stdout: '', stderr: '' };
  });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});

  assert.deepStrictEqual(calls[0].args, ['pull', 'demo/app:1.0.0']);
  const config = JSON.parse(
    fs.readFileSync(path.join(result.targetDir, 'docker-run.json'), 'utf-8'),
  );
  assert.strictEqual(config.image, 'demo/app');
  assert.deepStrictEqual(config.ports, ['8080:80']);
  const runCmd = fs.readFileSync(
    path.join(result.targetDir, 'run-command.txt'),
    'utf-8',
  );
  assert.ok(runCmd.startsWith('docker run'));
  assert.strictEqual(result.record.method, 'docker_run');
});

runTest('manual install writes steps without executing commands', async () => {
  let ran = false;
  const manifest = makeMethodManifest('manual_steps', {
    action: 'manual_steps',
    title: 'demo-tool',
    text: '1. 下载安装包\n2. 按 README 执行',
  });
  const executor = await makeExecutor(manifest, async () => {
    ran = true;
    return { exitCode: 0, stdout: '', stderr: '' };
  });
  const result = await executor.installWithManifest(manifest, 'claude-code', {});

  assert.strictEqual(ran, false);
  const steps = fs.readFileSync(path.join(result.targetDir, 'steps.txt'), 'utf-8');
  assert.ok(steps.includes('按 README 执行'));
  assert.strictEqual(result.record.method, 'manual_steps');
});

runTest('command failure surfaces InstallError', async () => {
  const manifest = makeMethodManifest('npm_install', {
    action: 'npm_install',
    package: 'demo-tool',
    version: '1.0.0',
  });
  const executor = await makeExecutor(manifest, async () => ({
    exitCode: 1,
    stdout: '',
    stderr: 'E404 package not found',
  }));
  await assert.rejects(
    () => executor.installWithManifest(manifest, 'claude-code', {}),
    (err: unknown) =>
      err instanceof InstallError &&
      err.code === 'non_copy_install_failed' &&
      err.message.includes('E404'),
  );
});

runTest('grade E blocks non-copy installs before execution', async () => {
  let ran = false;
  const manifest = makeMethodManifest(
    'npm_install',
    { action: 'npm_install', package: 'demo', version: '1.0.0' },
    {
      risk_summary: {
        level: 'untrusted',
        grade: 'E',
        top_risks: [],
        install_recommendation: 'not_recommended',
      },
    },
  );
  const executor = await makeExecutor(manifest, async () => {
    ran = true;
    return { exitCode: 0, stdout: '', stderr: '' };
  });
  await assert.rejects(
    () => executor.installWithManifest(manifest, 'claude-code', {
      force: true,
      acceptHighRisk: true,
    }),
    (err: unknown) => (err as { name: string }).name === 'InstallBlockedError',
  );
  assert.strictEqual(ran, false);
});

runTest('managed install is fail-closed without confirmation callback', async () => {
  let ran = false;
  const manifest = makeMethodManifest('npm_install', {
    action: 'npm_install',
    package: 'demo',
    version: '1.0.0',
  });
  const apiClient = createApiClient(mockApiFetch());
  const executor = new InstallExecutor(apiClient, {
    homeDir: TEST_HOME,
    runCommand: async () => {
      ran = true;
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });
  await assert.rejects(
    () => executor.installWithManifest(manifest, 'claude-code', {}),
    (err: unknown) =>
      (err as { name: string }).name === 'InstallBlockedError',
  );
  assert.strictEqual(ran, false);
});

runTest('update works for npm installs with confirmation', async () => {
  const home = path.join(
    os.tmpdir(),
    'tah-methods-upd-' + crypto.randomBytes(4).toString('hex'),
  );
  const v1 = makeMethodManifest('npm_install', {
    action: 'npm_install',
    package: 'demo-tool',
    version: '1.0.0',
  });
  const v2 = validateManifest({
    ...v1,
    version: '2.0.0',
    installation: {
      ...v1.installation,
      steps: [
        {
          action: 'npm_install',
          package: 'demo-tool',
          version: '2.0.0',
          registry: 'https://registry.npmjs.org',
        },
      ],
    },
  }) as InstallManifest;

  const fetcher: FetchFn = async (urlStr: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      return {
        status: 201,
        ok: true,
        headers: new Headers(),
        json: async () => ({}),
        text: async () => '',
      } as Response;
    }
    if (String(urlStr).includes('install-manifest')) {
      return {
        status: 200,
        ok: true,
        headers: new Headers(),
        json: async () => v2,
        text: async () => JSON.stringify(v2),
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
  const api = createApiClient(fetcher);
  const runCommand = async (cmd: string, args: string[]) => {
    const prefixIdx = args.indexOf('--prefix');
    if (prefixIdx >= 0) {
      fs.mkdirSync(args[prefixIdx + 1], { recursive: true });
      fs.writeFileSync(
        path.join(args[prefixIdx + 1], 'package.json'),
        '{"name":"demo-tool"}\n',
        'utf-8',
      );
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  };

  const installer = new InstallExecutor(api, {
    homeDir: home,
    confirmManagedInstall: async () => true,
    runCommand,
  });
  await installer.installWithManifest(v1, 'claude-code', {});

  const updater = new UpdateExecutor(api, {
    homeDir: home,
    confirmManagedInstall: async () => true,
    runCommand,
  });
  const result = await updater.update('demo-tool', 'claude-code', {
    yes: true,
  });
  assert.strictEqual(result.status, 'updated', result.message);

  const store = new LocalInstallStore(home);
  const record = store.find('demo-tool', 'claude-code');
  assert.ok(record);
  assert.strictEqual(record!.version, '2.0.0');
  assert.strictEqual(record!.method, 'npm_install');
});

console.log(`\n  ✓ ${passed} passed` + (failed ? `  ✗ ${failed} failed` : '') + '\n');
if (failed) process.exit(1);
