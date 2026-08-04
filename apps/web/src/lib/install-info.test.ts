import { describe, expect, it } from 'vitest';

import { getInstallMethodInfo } from './install-info';

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
