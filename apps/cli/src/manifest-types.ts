/**
 * Install Manifest v1.0 TypeScript types.
 *
 * Mirrors the Python models in apps/api/src/models/install.py.
 * Used by the install executor for runtime validation of manifest responses.
 */

// ---------------------------------------------------------------------------
// Manifest Source
// ---------------------------------------------------------------------------

export interface ManifestSource {
  type: 'github' | 'npm' | 'pypi' | 'docker' | 'local_upload';
  repository_url: string;
  download_url: string;
  ref: string;
  commit_hash: string; // 40-char hex
}

// ---------------------------------------------------------------------------
// Manifest Integrity
// ---------------------------------------------------------------------------

export interface ManifestIntegrity {
  sha256: string; // 64-char hex
  download_size_bytes: number;
}

// ---------------------------------------------------------------------------
// Installation Steps (discriminated union)
// ---------------------------------------------------------------------------

export interface DownloadStep {
  action: 'download';
  url: string;
}

export interface VerifyStep {
  action: 'verify';
  algorithm: 'sha256';
  checksum: string; // 64-char hex
}

export interface ExtractStep {
  action: 'extract';
  archive: string; // relative path within temp dir
}

export interface CopyStep {
  action: 'copy';
  source: string; // relative path within extract dir
  destination: string; // relative path within client root
}

export type InstallStep = DownloadStep | VerifyStep | ExtractStep | CopyStep;

// ---------------------------------------------------------------------------
// Manifest Installation
// ---------------------------------------------------------------------------

export interface ManifestInstallation {
  method: 'copy_directory' | 'npm_install' | 'pip_install' | 'docker_run' | 'manual_steps';
  target_client: string;
  steps: InstallStep[];
  pre_install_message?: string | null;
  post_install_message?: string | null;
}

// ---------------------------------------------------------------------------
// Permissions (subset — full model in packages.py)
// ---------------------------------------------------------------------------

export interface FilesystemPermissions {
  read?: string[];
  write?: string[];
  delete?: boolean;
}

export interface ShellPermissions {
  allowed?: boolean;
  commands?: string[];
  description?: string | null;
}

export interface NetworkPermissions {
  allowed?: boolean;
  domains?: string[];
  description?: string | null;
}

export interface EnvironmentPermissions {
  read?: string[];
  write?: string[];
}

export interface ManifestPermissions {
  filesystem?: FilesystemPermissions | null;
  shell?: ShellPermissions | null;
  network?: NetworkPermissions | null;
  environment?: EnvironmentPermissions | null;
}

// ---------------------------------------------------------------------------
// Risk Summary
// ---------------------------------------------------------------------------

export interface ManifestRiskSummary {
  level: string;
  grade?: string | null;
  top_risks?: string[];
  install_recommendation: string;
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface ManifestDependencies {
  npm?: Array<Record<string, string>> | null;
  pip?: Array<Record<string, string>> | null;
  system?: string[] | null;
  docker?: Array<Record<string, string>> | null;
  mcp_servers?: Array<Record<string, string>> | null;
}

// ---------------------------------------------------------------------------
// Full Install Manifest v1.0
// ---------------------------------------------------------------------------

export interface InstallManifest {
  manifest_version: '1.0';
  name: string;
  version: string; // semver
  type: string;
  description: string;
  source: ManifestSource;
  integrity: ManifestIntegrity;
  installation: ManifestInstallation;
  permissions: ManifestPermissions;
  risk_summary: ManifestRiskSummary;
  trust_score: number; // 0-100
  compatibility: string[];
  dependencies: ManifestDependencies;
}

// ---------------------------------------------------------------------------
// Runtime validators
// ---------------------------------------------------------------------------

const SHA256_RE = /^[a-f0-9]{64}$/;
const COMMIT_RE = /^[a-f0-9]{40}$/;

const VALID_ACTIONS = ['download', 'verify', 'extract', 'copy'] as const;
const VALID_STEP_ORDER_COPY_DIR: InstallStep['action'][] = ['download', 'verify', 'extract', 'copy'];

export class ManifestValidationError extends Error {
  constructor(
    message: string,
    public invalidFields: string[],
  ) {
    super(message);
    this.name = 'ManifestValidationError';
  }
}

function fail(field: string, msg: string): never {
  throw new ManifestValidationError(
    `Manifest validation failed: ${msg}`,
    [field],
  );
}

function check(cond: boolean, field: string, msg: string): void {
  if (!cond) fail(field, msg);
}

export function validateManifest(raw: unknown): InstallManifest {
  if (typeof raw !== 'object' || raw === null) {
    throw new ManifestValidationError('Manifest must be an object', ['(root)']);
  }
  const m = raw as Record<string, unknown>;

  // manifest_version
  check(m.manifest_version === '1.0', 'manifest_version', 'must be "1.0"');

  // name
  check(typeof m.name === 'string' && m.name.length > 0, 'name', 'must be a non-empty string');

  // version
  check(typeof m.version === 'string' && m.version.length > 0, 'version', 'must be a non-empty string');

  // type
  check(typeof m.type === 'string' && m.type.length > 0, 'type', 'must be a non-empty string');

  // description
  check(typeof m.description === 'string', 'description', 'must be a string');

  // trust_score
  check(
    typeof m.trust_score === 'number' && Number.isFinite(m.trust_score) && Number.isInteger(m.trust_score) && m.trust_score >= 0 && m.trust_score <= 100,
    'trust_score',
    'must be an integer 0-100',
  );

  // compatibility
  check(Array.isArray(m.compatibility), 'compatibility', 'must be an array');

  // --- source ---
  const src = m.source as Record<string, unknown> | undefined;
  check(src != null && typeof src === 'object', 'source', 'must be an object');
  const validSourceTypes = ['github', 'npm', 'pypi', 'docker', 'local_upload'];
  check(validSourceTypes.includes(src!.type as string), 'source.type', 'invalid source type');
  check(typeof src!.repository_url === 'string' && src!.repository_url.startsWith('https://'), 'source.repository_url', 'must be an HTTPS URL');
  check(typeof src!.download_url === 'string' && src!.download_url.startsWith('https://'), 'source.download_url', 'must be an HTTPS URL');
  check(typeof src!.ref === 'string' && src!.ref.length > 0, 'source.ref', 'must be a non-empty string');
  check(typeof src!.commit_hash === 'string' && COMMIT_RE.test(src!.commit_hash), 'source.commit_hash', 'must be a 40-char hex string');

  // --- integrity ---
  const integ = m.integrity as Record<string, unknown> | undefined;
  check(integ != null && typeof integ === 'object', 'integrity', 'must be an object');
  check(typeof integ!.sha256 === 'string' && SHA256_RE.test(integ!.sha256), 'integrity.sha256', 'must be a 64-char hex string');
  check(typeof integ!.download_size_bytes === 'number' && integ!.download_size_bytes >= 0, 'integrity.download_size_bytes', 'must be a non-negative integer');

  // --- installation ---
  const inst = m.installation as Record<string, unknown> | undefined;
  check(inst != null && typeof inst === 'object', 'installation', 'must be an object');
  const validMethods = ['copy_directory', 'npm_install', 'pip_install', 'docker_run', 'manual_steps'];
  check(validMethods.includes(inst!.method as string), 'installation.method', 'invalid install method');
  check(typeof inst!.target_client === 'string' && inst!.target_client.length > 0, 'installation.target_client', 'must be a non-empty string');
  const steps = inst!.steps;
  check(Array.isArray(steps) && steps.length > 0, 'installation.steps', 'must be a non-empty array');

  // Validate each step
  const validatedSteps: InstallStep[] = [];
  for (let i = 0; i < (steps as unknown[]).length; i++) {
    const step = (steps as unknown[])[i] as Record<string, unknown>;
    validatedSteps.push(validateStep(step, i));
  }

  // Validate step sequence for copy_directory
  if (inst!.method === 'copy_directory') {
    const actions = validatedSteps.map(s => s.action);
    const expected = VALID_STEP_ORDER_COPY_DIR;
    const match = actions.length === expected.length && actions.every((a, i) => a === expected[i]);
    check(match, 'installation.steps', `copy_directory requires exact step sequence: ${expected.join(' → ')}`);

    // Validate download URL matches source
    const dlStep = validatedSteps[0] as DownloadStep;
    check(dlStep.url === src!.download_url, 'installation.steps[0].url', 'download URL must match source.download_url');

    // Validate verify checksum matches integrity
    const vStep = validatedSteps[1] as VerifyStep;
    check(vStep.checksum === integ!.sha256, 'installation.steps[1].checksum', 'verify checksum must match integrity.sha256');

    // Validate copy destinations are safe
    for (const s of validatedSteps) {
      if (s.action === 'copy') {
        const cs = s as CopyStep;
        check(isSafeInstallPath(cs.source), `installation.steps.copy.source`, `unsafe path: "${cs.source}"`);
        check(isSafeInstallPath(cs.destination), `installation.steps.copy.destination`, `unsafe path: "${cs.destination}"`);
      }
      if (s.action === 'extract') {
        const es = s as ExtractStep;
        check(isSafeInstallPath(es.archive), `installation.steps.extract.archive`, `unsafe path: "${es.archive}"`);
      }
    }
  }

  // --- risk_summary ---
  const risk = m.risk_summary as Record<string, unknown> | undefined;
  check(risk != null && typeof risk === 'object', 'risk_summary', 'must be an object');
  check(typeof risk!.install_recommendation === 'string', 'risk_summary.install_recommendation', 'must be a string');
  // Blocked recommendation → reject manifest entirely
  check(risk!.install_recommendation !== 'blocked', 'risk_summary.install_recommendation', 'install is blocked by server');

  return m as unknown as InstallManifest;
}

function validateStep(step: Record<string, unknown>, index: number): InstallStep {
  const action = step.action;
  check(typeof action === 'string' && (VALID_ACTIONS as readonly string[]).includes(action), `steps[${index}].action`, `must be one of: ${VALID_ACTIONS.join(', ')}`);

  switch (action) {
    case 'download': {
      const url = step.url;
      check(typeof url === 'string' && url.startsWith('https://'), `steps[${index}].url`, 'must be an HTTPS URL');
      return { action: 'download', url: url as string };
    }
    case 'verify': {
      check(step.algorithm === 'sha256', `steps[${index}].algorithm`, 'must be "sha256"');
      const checksum = step.checksum;
      check(typeof checksum === 'string' && SHA256_RE.test(checksum), `steps[${index}].checksum`, 'must be a 64-char hex string');
      return { action: 'verify', algorithm: 'sha256', checksum: checksum as string };
    }
    case 'extract': {
      const archive = step.archive;
      check(typeof archive === 'string' && isSafeInstallPath(archive), `steps[${index}].archive`, 'unsafe archive path');
      return { action: 'extract', archive: archive as string };
    }
    case 'copy': {
      const source = step.source;
      const destination = step.destination;
      check(typeof source === 'string' && isSafeInstallPath(source), `steps[${index}].source`, 'unsafe source path');
      check(typeof destination === 'string' && isSafeInstallPath(destination), `steps[${index}].destination`, 'unsafe destination path');
      // No extra fields allowed on copy step
      const allowed = new Set(['action', 'source', 'destination']);
      for (const key of Object.keys(step)) {
        check(allowed.has(key), `steps[${index}].${key}`, 'unknown field');
      }
      return { action: 'copy', source: source as string, destination: destination as string };
    }
    default:
      fail(`steps[${index}].action`, `unknown action: ${action}`);
  }
}

/**
 * Check that a path does not contain traversal sequences, absolute paths,
 * Windows drive letters, backslashes, or null bytes.
 */
export function isSafeInstallPath(value: string): boolean {
  if (value.includes('\x00')) return false;
  if (value.includes('\\')) return false;
  if (value.startsWith('/')) return false;
  if (/^[A-Za-z]:/.test(value)) return false;
  // Check for .. as a path segment
  const segments = value.split('/');
  if (segments.includes('..')) return false;
  return value.length > 0;
}
