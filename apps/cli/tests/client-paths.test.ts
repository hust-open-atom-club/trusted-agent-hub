/**
 * Tests for shared client path validation (client-paths.ts).
 *
 * Run: npx tsx tests/client-paths.test.ts
 */

import * as assert from 'assert';
import * as path from 'path';
import * as os from 'os';

import {
  CLIENT_INSTALL_ROOTS,
  CLIENT_MANIFEST_ROOTS,
  SUPPORTED_CLIENTS,
  isSupportedClient,
  getClientRoot,
  getRecordInstallRoot,
  isStrictChildPath,
  resolveManifestDestination,
  ClientPathError,
} from '../src/client-paths';

const home = os.homedir();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

console.log('CLI Client Path Tests\n');

// --- CLIENT_INSTALL_ROOTS ---
assert.deepStrictEqual(
  CLIENT_INSTALL_ROOTS['claude-code'],
  '.claude/skills',
);
assert.deepStrictEqual(
  CLIENT_INSTALL_ROOTS['claude-code-plugin'],
  '.claude/skills',
);
assert.deepStrictEqual(
  CLIENT_INSTALL_ROOTS['cursor'],
  '.cursor/skills',
);
assert.deepStrictEqual(
  CLIENT_INSTALL_ROOTS['codex'],
  '.codex/skills',
);
console.log('  ✓ CLIENT_INSTALL_ROOTS has expected keys');

// --- CLIENT_MANIFEST_ROOTS ---
assert.deepStrictEqual(
  CLIENT_MANIFEST_ROOTS['claude-code'],
  '~/.claude/skills/',
);
assert.deepStrictEqual(
  CLIENT_MANIFEST_ROOTS['claude-code-plugin'],
  '~/.claude/skills/',
);
assert.deepStrictEqual(
  CLIENT_MANIFEST_ROOTS['cursor'],
  '~/.cursor/skills/',
);
assert.deepStrictEqual(
  CLIENT_MANIFEST_ROOTS['codex'],
  '~/.codex/skills/',
);
console.log('  ✓ CLIENT_MANIFEST_ROOTS has expected keys');

// --- SUPPORTED_CLIENTS ---
assert.deepStrictEqual(SUPPORTED_CLIENTS, [
  'claude-code',
  'claude-code-plugin',
  'cursor',
  'codex',
]);
console.log('  ✓ SUPPORTED_CLIENTS');

// --- isSupportedClient ---
assert.strictEqual(isSupportedClient('claude-code'), true);
assert.strictEqual(isSupportedClient('cursor'), true);
assert.strictEqual(isSupportedClient('codex'), true);
assert.strictEqual(isSupportedClient('vscode'), false);
assert.strictEqual(isSupportedClient(''), false);
console.log('  ✓ isSupportedClient');

// ---------------------------------------------------------------------------
// getClientRoot
// ---------------------------------------------------------------------------

{
  const root = getClientRoot('claude-code', home);
  assert.strictEqual(root, path.resolve(home, '.claude/skills'));
  console.log('  ✓ getClientRoot claude-code');
}

{
  const root = getClientRoot('cursor', home);
  assert.strictEqual(root, path.resolve(home, '.cursor/skills'));
  console.log('  ✓ getClientRoot cursor');
}

{
  const root = getClientRoot('codex', home);
  assert.strictEqual(root, path.resolve(home, '.codex/skills'));
  console.log('  ✓ getClientRoot codex');

  const codexMcpRoot = getClientRoot('codex', home, 'mcp_server');
  assert.strictEqual(
    codexMcpRoot,
    path.resolve(home, '.trusted-agent-hub', 'installed'),
  );
  console.log('  ✓ getClientRoot codex mcp_server uses TAH managed directory');

  const previousCodexHome = process.env.CODEX_HOME;
  const customCodexHome = path.join(home, '.custom-codex');
  process.env.CODEX_HOME = customCodexHome;
  try {
    assert.strictEqual(
      getClientRoot('codex', home),
      path.resolve(customCodexHome, 'skills'),
    );
    assert.strictEqual(
      getClientRoot('codex', home, 'mcp_server'),
      path.resolve(home, '.trusted-agent-hub', 'installed'),
    );
  } finally {
    if (previousCodexHome === undefined) {
      delete process.env.CODEX_HOME;
    } else {
      process.env.CODEX_HOME = previousCodexHome;
    }
  }
  console.log('  ✓ getClientRoot codex honors CODEX_HOME for skills');

  assert.throws(
    () =>
      getRecordInstallRoot(
        {
          client: 'codex',
          package_type: 'mcp_server',
          install_root: path.resolve(home, '.evil'),
          method: 'copy_directory',
        },
        home,
      ),
    (err: unknown) =>
      err instanceof ClientPathError && err.code === 'unsafe_install_root',
  );
  console.log('  ✓ getRecordInstallRoot rejects mismatched install root');
}

{
  // claude-code-plugin shares the skills root so Claude Code auto-loads the
  // installed plugin as <name>@skills-dir.
  const root = getClientRoot('claude-code-plugin', home);
  assert.strictEqual(root, path.resolve(home, '.claude/skills'));
  console.log('  ✓ getClientRoot claude-code-plugin -> skills dir');
}

{
  assert.throws(
    () => getClientRoot('vscode', home),
    (err: unknown) =>
      err instanceof ClientPathError && err.code === 'unsupported_client',
  );
  console.log('  ✓ getClientRoot throws for unsupported client');
}

// ---------------------------------------------------------------------------
// isStrictChildPath
// ---------------------------------------------------------------------------

{
  const parent = path.resolve(home, '.claude/skills');
  const child = path.resolve(parent, 'example');
  assert.strictEqual(isStrictChildPath(child, parent), true);
  console.log('  ✓ isStrictChildPath true for child');
}

{
  const parent = path.resolve(home, '.claude/skills');
  assert.strictEqual(isStrictChildPath(parent, parent), false);
  console.log('  ✓ isStrictChildPath false for same path');
}

{
  const parent = path.resolve(home, '.claude/skills');
  const outside = path.resolve(home, '.cursor/skills');
  assert.strictEqual(isStrictChildPath(outside, parent), false);
  console.log('  ✓ isStrictChildPath false for outside path');
}

{
  const parent = path.resolve(home, '.claude/skills');
  const siblingPrefix = path.resolve(home, '.claude/skills-extra');
  assert.strictEqual(isStrictChildPath(siblingPrefix, parent), false);
  console.log('  ✓ isStrictChildPath false for sibling prefix');
}

// ---------------------------------------------------------------------------
// resolveManifestDestination
// ---------------------------------------------------------------------------

// Correct destination for claude-code
{
  const clientRoot = path.resolve(home, '.claude/skills');
  const result = resolveManifestDestination(
    '~/.claude/skills/example/',
    'claude-code',
    clientRoot,
  );
  assert.strictEqual(result, path.resolve(home, '.claude/skills/example'));
  console.log('  ✓ resolveManifestDestination claude-code correct');
}

// Correct destination for cursor
{
  const clientRoot = path.resolve(home, '.cursor/skills');
  const result = resolveManifestDestination(
    '~/.cursor/skills/example/',
    'cursor',
    clientRoot,
  );
  assert.strictEqual(result, path.resolve(home, '.cursor/skills/example'));
  console.log('  ✓ resolveManifestDestination cursor correct');
}

// Correct destination for claude-code-plugin (skills dir auto-load)
{
  const clientRoot = path.resolve(home, '.claude/skills');
  const result = resolveManifestDestination(
    '~/.claude/skills/example/',
    'claude-code-plugin',
    clientRoot,
  );
  assert.strictEqual(result, path.resolve(home, '.claude/skills/example'));
  console.log('  ✓ resolveManifestDestination claude-code-plugin correct');
}

// Correct destination for Codex Skills
{
  const clientRoot = path.resolve(home, '.codex/skills');
  const result = resolveManifestDestination(
    '~/.codex/skills/example/',
    'codex',
    clientRoot,
  );
  assert.strictEqual(result, path.resolve(home, '.codex/skills/example'));
  console.log('  ✓ resolveManifestDestination codex correct');

  const codexMcpRoot = path.resolve(home, '.trusted-agent-hub', 'installed');
  const codexMcpResult = resolveManifestDestination(
    '~/.trusted-agent-hub/installed/example/',
    'codex',
    codexMcpRoot,
    'mcp_server',
  );
  assert.strictEqual(
    codexMcpResult,
    path.resolve(home, '.trusted-agent-hub', 'installed', 'example'),
  );
  console.log('  ✓ resolveManifestDestination codex mcp_server correct');
}

// Rejects wrong client root (cursor destination with claude-code client)
{
  const clientRoot = path.resolve(home, '.claude/skills');
  assert.throws(
    () =>
      resolveManifestDestination(
        '~/.cursor/skills/example/',
        'claude-code',
        clientRoot,
      ),
    (err: unknown) =>
      err instanceof ClientPathError &&
      err.code === 'destination_root_mismatch',
  );
  console.log('  ✓ resolveManifestDestination rejects wrong client root');
}

// Rejects root itself (destination equals manifest root)
{
  const clientRoot = path.resolve(home, '.claude/skills');
  assert.throws(
    () =>
      resolveManifestDestination(
        '~/.claude/skills/',
        'claude-code',
        clientRoot,
      ),
    (err: unknown) =>
      err instanceof ClientPathError &&
      err.code === 'invalid_destination',
  );
  console.log('  ✓ resolveManifestDestination rejects root itself');
}

// Rejects traversal via ..
{
  const clientRoot = path.resolve(home, '.claude/skills');
  assert.throws(
    () =>
      resolveManifestDestination(
        '~/.claude/skills/../cursor/',
        'claude-code',
        clientRoot,
      ),
    (err: unknown) =>
      err instanceof ClientPathError &&
      err.code === 'invalid_destination',
  );
  console.log('  ✓ resolveManifestDestination rejects .. traversal');
}

// Rejects unsupported client
{
  const clientRoot = path.resolve(home, '.vscode/skills');
  assert.throws(
    () =>
      resolveManifestDestination(
        '~/.vscode/skills/example/',
        'vscode',
        clientRoot,
      ),
    (err: unknown) =>
      err instanceof ClientPathError &&
      err.code === 'unsupported_client',
  );
  console.log('  ✓ resolveManifestDestination rejects unsupported client');
}

// Deeply nested destination
{
  const clientRoot = path.resolve(home, '.claude/skills');
  const result = resolveManifestDestination(
    '~/.claude/skills/a/b/c/d/',
    'claude-code',
    clientRoot,
  );
  assert.strictEqual(
    result,
    path.resolve(home, '.claude/skills/a/b/c/d'),
  );
  console.log('  ✓ resolveManifestDestination handles deep nesting');
}

// --- isSupportedClient prototype safety ---
{
  assert.strictEqual(isSupportedClient('toString'), false);
  assert.strictEqual(isSupportedClient('__proto__'), false);
  assert.strictEqual(isSupportedClient('hasOwnProperty'), false);
  console.log('  ✓ isSupportedClient rejects prototype keys');
}

// --- resolveManifestDestination without trailing slash ---
{
  const clientRoot = path.resolve(home, '.claude/skills');
  const result = resolveManifestDestination(
    '~/.claude/skills/pkg',
    'claude-code',
    clientRoot,
  );
  assert.strictEqual(result, path.resolve(home, '.claude/skills/pkg'));
  console.log('  ✓ resolveManifestDestination without trailing slash');
}

console.log('\n  ✓ All client path tests passed!\n');
