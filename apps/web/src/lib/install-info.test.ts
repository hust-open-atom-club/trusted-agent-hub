import { describe, expect, it } from 'vitest';

import {
  buildInstallCommand,
  CLIENT_OPTIONS,
  getClientsForType,
  getClientLabel,
  getClientTargetPath,
  getInstallMethodInfo,
  getSelectableClients,
  isClientCompatible,
} from './install-info';

describe('getInstallMethodInfo', () => {
  it('maps copy_directory with label and no external command', () => {
    const info = getInstallMethodInfo('copy_directory');
    expect(info.label).toBe('目录复制');
    expect(info.requiresExternalCommand).toBe(false);
  });

  it.each(['npm_install', 'pip_install', 'docker_run'])(
    '%s requires explicit confirmation',
    (method) => {
      const info = getInstallMethodInfo(method);
      expect(info.requiresExternalCommand).toBe(true);
      expect(info.label).toBeTruthy();
    },
  );

  it('maps manual_steps without external command', () => {
    const info = getInstallMethodInfo('manual_steps');
    expect(info.label).toBe('人工步骤');
    expect(info.requiresExternalCommand).toBe(false);
  });

  it('falls back for unknown or missing method', () => {
    expect(getInstallMethodInfo(undefined).label).toBe('未知');
    expect(getInstallMethodInfo('weird').label).toBe('weird');
  });
});

describe('buildInstallCommand', () => {
  it('keeps default client without flags for copy_directory', () => {
    expect(buildInstallCommand('docx', ['claude-code'], 'copy_directory')).toBe(
      'tah install docx',
    );
  });

  it('adds --client for plugin-only packages', () => {
    expect(
      buildInstallCommand(
        'claude-skills-plugin',
        ['claude-code-plugin'],
        'copy_directory',
      ),
    ).toBe('tah install claude-skills-plugin --client claude-code-plugin');
  });

  it('adds --yes for external command methods', () => {
    expect(
      buildInstallCommand('npm-install-demo', ['claude-code'], 'npm_install'),
    ).toBe('tah install npm-install-demo --yes');
  });

  it('combines --client and --yes', () => {
    expect(
      buildInstallCommand('demo', ['cursor'], 'pip_install'),
    ).toBe('tah install demo --client cursor --yes');
  });

  it('uses explicitly selected client over default', () => {
    expect(
      buildInstallCommand('docx', ['claude-code', 'cursor'], 'copy_directory', 'cursor'),
    ).toBe('tah install docx --client cursor');
    expect(
      buildInstallCommand('docx', ['claude-code', 'cursor'], 'copy_directory', 'claude-code'),
    ).toBe('tah install docx');
  });
});

describe('getClientLabel', () => {
  it('maps known clients to labels', () => {
    expect(getClientLabel('claude-code')).toBe('Claude Code');
    expect(getClientLabel('claude-code-plugin')).toBe('Claude Code 插件');
    expect(getClientLabel('cursor')).toBe('Cursor');
    expect(getClientLabel('unknown')).toBe('unknown');
  });
});

describe('getClientTargetPath', () => {
  it('prefers declared targets', () => {
    expect(
      getClientTargetPath(
        [
          { client: 'claude-code', destination: '~/.claude/skills/docx/' },
          { client: 'cursor', destination: '~/.cursor/skills/docx/' },
        ],
        'cursor',
        'docx',
      ),
    ).toBe('~/.cursor/skills/docx/');
  });

  it('falls back to client root', () => {
    expect(getClientTargetPath(null, 'claude-code-plugin', 'demo')).toBe(
      '~/.claude/skills/demo/',
    );
    expect(getClientTargetPath(null, 'cursor', 'demo')).toBe(
      '~/.cursor/skills/demo/',
    );
  });
});

describe('CLIENT_OPTIONS / isClientCompatible', () => {
  it('lists all supported clients', () => {
    expect(CLIENT_OPTIONS.map((c) => c.id)).toEqual([
      'claude-code',
      'claude-code-plugin',
      'cursor',
    ]);
  });

  it('checks compatibility against declared clients', () => {
    expect(isClientCompatible('claude-code', ['claude-code', 'cursor'])).toBe(
      true,
    );
    expect(isClientCompatible('cursor', ['claude-code', 'cursor'])).toBe(true);
    expect(
      isClientCompatible('claude-code-plugin', ['claude-code', 'cursor']),
    ).toBe(false);
  });
});

describe('getClientsForType', () => {
  it('limits plugin packages to claude-code-plugin', () => {
    expect(getClientsForType('plugin')).toEqual(['claude-code-plugin']);
  });

  it('allows skills to target claude-code and cursor only', () => {
    expect(getClientsForType('skill')).toEqual(['claude-code', 'cursor']);
  });

  it('returns an empty list for unknown types', () => {
    expect(getClientsForType('unknown')).toEqual([]);
    expect(getClientsForType(null)).toEqual([]);
  });
});

describe('getSelectableClients', () => {
  it('removes plugin install from skills even if declared', () => {
    expect(
      getSelectableClients('skill', ['claude-code', 'claude-code-plugin']),
    ).toEqual(['claude-code']);
  });

  it('removes skill/cursor installs from plugins even if declared', () => {
    expect(
      getSelectableClients('plugin', ['claude-code', 'cursor', 'claude-code-plugin']),
    ).toEqual(['claude-code-plugin']);
  });

  it('falls back to type defaults when compatibility is missing', () => {
    expect(getSelectableClients('skill', null)).toEqual([
      'claude-code',
      'cursor',
    ]);
    expect(getSelectableClients('plugin', [])).toEqual(['claude-code-plugin']);
  });

  it('falls back to type defaults when declared clients are unsupported', () => {
    expect(getSelectableClients('skill', ['vscode', 'windsurf'])).toEqual([
      'claude-code',
      'cursor',
    ]);
  });

  it('keeps only declared clients that are supported and type-valid', () => {
    expect(
      getSelectableClients('skill', ['claude-code', 'cursor', 'vscode']),
    ).toEqual(['claude-code', 'cursor']);
  });
});
