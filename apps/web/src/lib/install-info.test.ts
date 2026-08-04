import { describe, expect, it } from 'vitest';

import { buildInstallCommand, getInstallMethodInfo } from './install-info';

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
});
