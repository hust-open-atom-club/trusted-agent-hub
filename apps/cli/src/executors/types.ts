/**
 * Shared types for non-copy_directory install executors.
 */

import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

import type { InstallManifest } from '../manifest-types';
import type { LocalInstallRecord } from '../local-install-store';

export interface RunCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type RunCommand = (
  cmd: string,
  args: string[],
  options?: { cwd?: string },
) => Promise<RunCommandResult>;

export interface ExecutorContext {
  homeDir: string;
  manifest: InstallManifest;
  clientType: string;
  runCommand: RunCommand;
}

export interface ExecutorResult {
  targetDir: string;
  sha256: string | null;
  record: LocalInstallRecord;
}

/** 非 ZIP 安装方式没有 artifact SHA-256，记录中使用全零占位。 */
export const NO_ARTIFACT_SHA256 = '0'.repeat(64);

export function sanitizeSegment(value: string): string {
  const cleaned = value.replace(/[^a-zA-Z0-9._-]/g, '-').replace(/^-+|-+$/g, '');
  return cleaned || 'pkg';
}

export function managedInstallDir(
  homeDir: string,
  name: string,
  method: string,
): string {
  return path.join(
    homeDir,
    '.trusted-agent-hub',
    'installed',
    `${sanitizeSegment(name)}-${method}`,
  );
}

export function buildRecord(
  ctx: ExecutorContext,
  targetDir: string,
  opts: { contentSha256?: string } = {},
): LocalInstallRecord {
  return {
    package_name: ctx.manifest.name,
    version: ctx.manifest.version,
    client: ctx.clientType,
    install_path: targetDir,
    sha256: NO_ARTIFACT_SHA256,
    integrity_verified: true,
    installed_at: new Date().toISOString(),
    manifest_version: ctx.manifest.manifest_version,
    method: ctx.manifest.installation.method,
    content_hash_algorithm: opts.contentSha256 ? 'sha256-tree-v1' : undefined,
    content_sha256: opts.contentSha256,
  };
}

const execFileP = promisify(execFile);

export async function defaultRunCommand(
  cmd: string,
  args: string[],
  options?: { cwd?: string },
): Promise<RunCommandResult> {
  try {
    const { stdout, stderr } = await execFileP(cmd, args, {
      cwd: options?.cwd,
      timeout: 300_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { exitCode: 0, stdout: stdout ?? '', stderr: stderr ?? '' };
  } catch (err) {
    const e = err as {
      code?: number;
      stdout?: string;
      stderr?: string;
    };
    return {
      exitCode: typeof e.code === 'number' ? e.code : 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? String(err),
    };
  }
}
