import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import type { CopyStep, InstallManifest } from './manifest-types';
import { CLIENT_INSTALL_ROOTS, resolveManifestDestination } from './client-paths';
import { managedInstallDir } from './executors/types';
import { LocalInstallStore } from './local-install-store';
import type { LocalInstallRecord } from './local-install-store';
import { computeDirectoryDigest } from './content-integrity';

const NON_COPY_METHOD_DIRS: Record<string, string> = {
  npm_install: 'npm',
  pip_install: 'pip',
  docker_run: 'docker',
  manual_steps: 'manual',
};

export interface InstallTargetIdentity {
  dev: bigint;
  ino: bigint;
}

export interface InstallTargetSnapshot {
  exists: boolean;
  identity: InstallTargetIdentity | null;
  digest: string | null;
}

export type InstallRecordSnapshot = LocalInstallRecord;

export interface InstallOverwriteConsent {
  targetDir: string;
  kind: 'record' | 'orphan';
  record: InstallRecordSnapshot | null;
  target: InstallTargetSnapshot;
}

export type PreflightBlockReason =
  | {
      code: 'record_path_mismatch';
      message: string;
      existingRecord: LocalInstallRecord;
      expectedPath: string;
      actualPath: string;
    }
  | {
      code: 'target_owned_by_other';
      message: string;
      ownerRecord: LocalInstallRecord;
      targetDir: string;
    };

export interface InstallPreflightResult {
  existingRecord: LocalInstallRecord | null;
  targetDir: string;
  targetExists: boolean;
  target: InstallTargetSnapshot;
  block: PreflightBlockReason | null;
}

export class PreflightError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = 'PreflightError';
  }
}

export function sameInstallPath(left: string, right: string): boolean {
  const l = path.resolve(left);
  const r = path.resolve(right);
  if (process.platform === 'win32') return l.toLowerCase() === r.toLowerCase();
  return l === r;
}

export function getInstallTargetDir(
  manifest: InstallManifest,
  clientType: string,
  homeDir: string = os.homedir(),
): string {
  const clientRootRel = CLIENT_INSTALL_ROOTS[clientType];
  if (!clientRootRel) {
    throw new PreflightError(`Unsupported client: "${clientType}"`, 'unsupported_client');
  }

  if (manifest.installation.method === 'copy_directory') {
    const copyStep = manifest.installation.steps.find(
      (step): step is CopyStep => step.action === 'copy',
    );
    if (!copyStep) {
      throw new PreflightError('Install manifest is missing the copy step', 'missing_copy_step');
    }
    const clientRoot = path.resolve(homeDir, clientRootRel);
    return resolveManifestDestination(copyStep.destination, clientType, clientRoot);
  }

  const methodDir = NON_COPY_METHOD_DIRS[manifest.installation.method];
  if (!methodDir) {
    throw new PreflightError(
      `Unsupported install method: "${manifest.installation.method}"`,
      'unsupported_method',
    );
  }
  return managedInstallDir(homeDir, manifest.name, methodDir);
}

export async function captureTargetSnapshot(
  targetDir: string,
): Promise<InstallTargetSnapshot> {
  let stat: fs.BigIntStats;
  try {
    stat = fs.lstatSync(targetDir, { bigint: true }) as fs.BigIntStats;
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { exists: false, identity: null, digest: null };
    }
    throw new PreflightError(
      `Cannot inspect target path: ${err instanceof Error ? err.message : String(err)}`,
      'target_inspect_failed',
    );
  }

  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new PreflightError(
      `Target path exists but is not a real directory: ${targetDir}`,
      'target_not_directory',
    );
  }

  const digest = await computeDirectoryDigest(targetDir);
  return {
    exists: true,
    identity: {
      dev: stat.dev,
      ino: stat.ino,
    },
    digest: digest.digest,
  };
}

function recordSnapshot(record: LocalInstallRecord): InstallRecordSnapshot {
  return { ...record };
}

export async function inspectExistingInstall(
  store: LocalInstallStore,
  manifest: InstallManifest,
  clientType: string,
  homeDir: string = os.homedir(),
): Promise<InstallPreflightResult> {
  const records = store.load();
  const targetDir = getInstallTargetDir(manifest, clientType, homeDir);
  const existingRecord =
    records.find(
      (record) =>
        record.package_name === manifest.name && record.client === clientType,
    ) || null;

  let block: PreflightBlockReason | null = null;
  if (existingRecord && !sameInstallPath(existingRecord.install_path, targetDir)) {
    block = {
      code: 'record_path_mismatch',
      message: 'Existing record path does not match the resolved install target.',
      existingRecord,
      expectedPath: targetDir,
      actualPath: existingRecord.install_path,
    };
  } else {
    const owner = records.find(
      (record) =>
        sameInstallPath(record.install_path, targetDir) &&
        (record.package_name !== manifest.name || record.client !== clientType),
    );
    if (owner) {
      block = {
        code: 'target_owned_by_other',
        message: 'Target directory is owned by another package record.',
        ownerRecord: owner,
        targetDir,
      };
    }
  }

  let target: InstallTargetSnapshot = {
    exists: false,
    identity: null,
    digest: null,
  };
  if (!block) {
    target = await captureTargetSnapshot(targetDir);
  }

  return {
    existingRecord,
    targetDir,
    targetExists: target.exists,
    target,
    block,
  };
}

export function makeOverwriteConsent(
  preflight: InstallPreflightResult,
  kind: 'record' | 'orphan',
): InstallOverwriteConsent {
  return {
    targetDir: preflight.targetDir,
    kind,
    record: preflight.existingRecord
      ? recordSnapshot(preflight.existingRecord)
      : null,
    target: preflight.target,
  };
}
