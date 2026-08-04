/**
 * docker_run executor — pulls the image (without running it) and writes a
 * run configuration under `~/.trusted-agent-hub/installed/`.  The container
 * is never started automatically; the user sees the generated run command.
 */

import * as fs from 'fs';
import * as path from 'path';

import { computeDirectoryDigest } from '../content-integrity';
import type { DockerRunStep } from '../manifest-types';
import {
  buildRecord,
  managedInstallDir,
  sanitizeSegment,
  type ExecutorContext,
  type ExecutorResult,
} from './types';

export async function runDockerInstall(
  ctx: ExecutorContext,
): Promise<ExecutorResult> {
  const step = ctx.manifest.installation.steps[0] as DockerRunStep;
  if (step.action !== 'docker_run') {
    throw new Error('manifest installation step is not docker_run');
  }

  const imageRef = step.tag ? `${step.image}:${step.tag}` : step.image;
  const res = await ctx.runCommand('docker', ['pull', imageRef]);
  if (res.exitCode !== 0) {
    throw new Error(
      `docker pull failed (exit ${res.exitCode}): ${
        res.stderr.trim() || res.stdout.trim() || 'unknown error'
      }`,
    );
  }

  const targetDir = managedInstallDir(
    ctx.homeDir,
    ctx.manifest.name,
    'docker',
  );
  await fs.promises.mkdir(targetDir, { recursive: true });

  const config = {
    image: step.image,
    tag: step.tag ?? null,
    ports: step.ports ?? [],
    volumes: step.volumes ?? [],
    env: step.env ?? [],
  };
  await fs.promises.writeFile(
    path.join(targetDir, 'docker-run.json'),
    JSON.stringify(config, null, 2) + '\n',
    'utf-8',
  );

  const runArgs = ['run', '--rm', '-d'];
  for (const port of config.ports) {
    runArgs.push('-p', port);
  }
  for (const volume of config.volumes) {
    runArgs.push('-v', volume);
  }
  for (const env of config.env) {
    runArgs.push('-e', env);
  }
  runArgs.push('--name', `${sanitizeSegment(ctx.manifest.name)}-${ctx.manifest.version.replace(/[^a-zA-Z0-9._-]/g, '-')}`);
  runArgs.push(imageRef);
  await fs.promises.writeFile(
    path.join(targetDir, 'run-command.txt'),
    `docker ${runArgs.join(' ')}\n`,
    'utf-8',
  );

  const digest = await computeDirectoryDigest(targetDir);
  const record = buildRecord(ctx, targetDir, {
    contentSha256: digest.digest,
  });
  return { targetDir, sha256: null, record };
}
