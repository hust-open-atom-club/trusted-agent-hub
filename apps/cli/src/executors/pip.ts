/**
 * pip_install executor — installs a PyPI package into a managed directory
 * under `~/.trusted-agent-hub/installed/` using `pip install --target`.
 */

import * as fs from 'fs';

import { computeDirectoryDigest } from '../content-integrity';
import type { PipInstallStep } from '../manifest-types';
import {
  buildRecord,
  managedInstallDir,
  type ExecutorContext,
  type ExecutorResult,
} from './types';

export async function runPipInstall(
  ctx: ExecutorContext,
): Promise<ExecutorResult> {
  const step = ctx.manifest.installation.steps[0] as PipInstallStep;
  if (step.action !== 'pip_install') {
    throw new Error('manifest installation step is not pip_install');
  }

  const targetDir = managedInstallDir(ctx.homeDir, ctx.manifest.name, 'pip');
  await fs.promises.mkdir(targetDir, { recursive: true });

  const args = [
    '-m',
    'pip',
    'install',
    '--target',
    targetDir,
    '--no-input',
    '--disable-pip-version-check',
    `${step.package}${step.version ? `==${step.version}` : ''}`,
  ];
  if (step.index_url) {
    args.push('--index-url', step.index_url);
  }

  const res = await ctx.runCommand('python', args);
  if (res.exitCode !== 0) {
    throw new Error(
      `pip install failed (exit ${res.exitCode}): ${
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
