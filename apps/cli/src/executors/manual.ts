/**
 * manual_steps executor — records the manual installation steps without
 * executing anything, then writes a local install record for traceability.
 */

import * as fs from 'fs';
import * as path from 'path';

import { computeDirectoryDigest } from '../content-integrity';
import type { ManualStep } from '../manifest-types';
import {
  buildRecord,
  managedInstallDir,
  type ExecutorContext,
  type ExecutorResult,
} from './types';

export async function runManualInstall(
  ctx: ExecutorContext,
): Promise<ExecutorResult> {
  const step = ctx.manifest.installation.steps[0] as ManualStep;
  if (step.action !== 'manual_steps') {
    throw new Error('manifest installation step is not manual_steps');
  }

  const targetDir = managedInstallDir(
    ctx.homeDir,
    ctx.manifest.name,
    'manual',
  );
  await fs.promises.mkdir(targetDir, { recursive: true });

  const title = step.title ?? ctx.manifest.name;
  await fs.promises.writeFile(
    path.join(targetDir, 'steps.txt'),
    `${title}\n\n${step.text}\n`,
    'utf-8',
  );

  const digest = await computeDirectoryDigest(targetDir);
  const record = buildRecord(ctx, targetDir, {
    contentSha256: digest.digest,
  });
  return { targetDir, sha256: null, record };
}
