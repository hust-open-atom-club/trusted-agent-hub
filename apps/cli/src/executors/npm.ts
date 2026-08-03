/**
 * npm_install executor — installs an npm package into a managed directory
 * under `~/.trusted-agent-hub/installed/` so it never touches system paths.
 */

import * as fs from 'fs';

import { computeDirectoryDigest } from '../content-integrity';
import type { NpmInstallStep } from '../manifest-types';
import {
  buildRecord,
  managedInstallDir,
  type ExecutorContext,
  type ExecutorResult,
} from './types';

export async function runNpmInstall(
  ctx: ExecutorContext,
): Promise<ExecutorResult> {
  const step = ctx.manifest.installation.steps[0] as NpmInstallStep;
  if (step.action !== 'npm_install') {
    throw new Error('manifest installation step is not npm_install');
  }

  const targetDir = managedInstallDir(ctx.homeDir, ctx.manifest.name, 'npm');
  await fs.promises.mkdir(targetDir, { recursive: true });

  // Windows npm ships as npm.cmd (nvm/nvm4w shims put npm.ps1/npm.cmd on PATH);
  // execFile cannot spawn .cmd shims directly, so defaultRunCommand routes
  // them through cmd.exe.  Unix keeps the plain `npm` binary.
  const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const args = [
    'install',
    `${step.package}@${step.version}`,
    '--prefix',
    targetDir,
    '--no-audit',
    '--no-fund',
  ];
  if (step.registry) {
    args.push('--registry', step.registry);
  }

  const res = await ctx.runCommand(npmCommand, args);
  if (res.exitCode !== 0) {
    throw new Error(
      `npm install failed (exit ${res.exitCode}): ${
        res.stderr.trim() || res.stdout.trim() || 'unknown error'
      }`,
    );
  }

  const digest = await computeDirectoryDigest(targetDir).catch(() => null);
  const record = buildRecord(ctx, targetDir, {
    contentSha256: digest?.digest,
  });
  return { targetDir, sha256: null, record };
}
