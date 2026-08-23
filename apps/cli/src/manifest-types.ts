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
  download_url: string | null;
  ref: string;
  subdirectory?: string | null;
  commit_hash: string | null; // 40-char hex
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

export interface NpmInstallStep {
  action: 'npm_install';
  package: string;
  version: string; // semver
  registry?: string | null;
}

export interface PipInstallStep {
  action: 'pip_install';
  package: string;
  version?: string | null;
  index_url?: string | null;
}

export interface DockerRunStep {
  action: 'docker_run';
  image: string;
  tag?: string | null;
  ports?: string[];
  volumes?: string[];
  env?: string[];
}

export interface ManualStep {
  action: 'manual_steps';
  title?: string | null;
  text: string;
}

export type InstallStep =
  | DownloadStep
  | VerifyStep
  | ExtractStep
  | CopyStep
  | NpmInstallStep
  | PipInstallStep
  | DockerRunStep
  | ManualStep;

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
  grade: 'A' | 'B' | 'C' | 'D' | 'E';
  top_risks?: string[];
  install_recommendation: string;
  requires_confirmation?: boolean;
  auto_grade?: 'A' | 'B' | 'C' | 'D' | 'E' | null;
  manual_grade?: 'A' | 'B' | 'C' | 'D' | 'E' | null;
  effective_grade?: 'A' | 'B' | 'C' | 'D' | 'E' | null;
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface ManifestDependencies {
  npm?: Array<Record<string, string>> | null;
  pip?: Array<Record<string, string>> | null;
  system?: string[] | null;
  docker?: Array<Record<string, string>> | null;
  mcp_servers?: Array<Record<string, unknown>> | null;
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
  integrity: ManifestIntegrity | null;
  installation: ManifestInstallation;
  permissions: ManifestPermissions;
  risk_summary: ManifestRiskSummary;
  compatibility: string[];
  dependencies: ManifestDependencies;
}

// ---------------------------------------------------------------------------
// Runtime validators
// ---------------------------------------------------------------------------

const SHA256_RE = /^[a-f0-9]{64}$/;
const COMMIT_RE = /^[a-f0-9]{40}$/;

const VALID_ACTIONS = [
  'download',
  'verify',
  'extract',
  'copy',
  'npm_install',
  'pip_install',
  'docker_run',
  'manual_steps',
] as const;
const VALID_STEP_ORDER_COPY_DIR: InstallStep['action'][] = ['download', 'verify', 'extract', 'copy'];

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const DOCKER_IMAGE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$/;
const NPM_PACKAGE_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

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

/** Allow HTTPS URLs and localhost HTTP (for dev). */
function isAllowedUrl(value: string): boolean {
  if (value.startsWith('https://')) return true;
  try {
    const u = new URL(value);
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

function isSafeSourceSubdirectory(value: string): boolean {
  if (value === '.') return true;
  if (
    value.trim().length === 0
    || value.includes('\x00')
    || value.includes('\\')
  ) return false;
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false;
  return value.split('/').every(
    segment => segment.length > 0 && segment !== '.' && segment !== '..',
  );
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

  // compatibility
  check(Array.isArray(m.compatibility), 'compatibility', 'must be an array');

  // --- source ---
  const src = m.source as Record<string, unknown> | undefined;
  check(src != null && typeof src === 'object', 'source', 'must be an object');
  const validSourceTypes = ['github', 'npm', 'pypi', 'docker', 'local_upload'];
  check(validSourceTypes.includes(src!.type as string), 'source.type', 'invalid source type');
  check(typeof src!.repository_url === 'string' && isAllowedUrl(src!.repository_url), 'source.repository_url', 'must be an HTTPS URL');
  check(typeof src!.ref === 'string' && src!.ref.length > 0, 'source.ref', 'must be a non-empty string');
  if (src!.subdirectory !== undefined && src!.subdirectory !== null) {
    check(
      typeof src!.subdirectory === 'string' && isSafeSourceSubdirectory(src!.subdirectory),
      'source.subdirectory',
      'must be a safe relative POSIX path',
    );
  }

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

  // Method-specific step sequence validation
  if (inst!.method === 'copy_directory') {
    // copy_directory 必须携带可下载制品与完整性摘要
    check(typeof src!.download_url === 'string' && isAllowedUrl(src!.download_url), 'source.download_url', 'must be an HTTPS URL (or localhost HTTP in dev)');
    check(typeof src!.commit_hash === 'string' && COMMIT_RE.test(src!.commit_hash), 'source.commit_hash', 'must be a 40-char hex string');
    const integ = m.integrity as Record<string, unknown> | undefined;
    check(integ != null && typeof integ === 'object', 'integrity', 'must be an object');
    check(typeof integ!.sha256 === 'string' && SHA256_RE.test(integ!.sha256), 'integrity.sha256', 'must be a 64-char hex string');
    check(typeof integ!.download_size_bytes === 'number' && integ!.download_size_bytes >= 0, 'integrity.download_size_bytes', 'must be a non-negative integer');

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

  if (inst!.method === 'npm_install') {
    check(validatedSteps.length === 1 && validatedSteps[0].action === 'npm_install', 'installation.steps', 'npm_install requires exactly one npm_install step');
  }
  if (inst!.method === 'pip_install') {
    check(validatedSteps.length === 1 && validatedSteps[0].action === 'pip_install', 'installation.steps', 'pip_install requires exactly one pip_install step');
  }
  if (inst!.method === 'docker_run') {
    check(validatedSteps.length === 1 && validatedSteps[0].action === 'docker_run', 'installation.steps', 'docker_run requires exactly one docker_run step');
  }
  if (inst!.method === 'manual_steps') {
    check(validatedSteps.length === 1 && validatedSteps[0].action === 'manual_steps', 'installation.steps', 'manual_steps requires exactly one manual_steps step');
  }

  // --- risk_summary ---
  const risk = m.risk_summary as Record<string, unknown> | undefined;
  check(risk != null && typeof risk === 'object', 'risk_summary', 'must be an object');
  check(
    typeof risk!.grade === 'string' && /^[A-E]$/.test(risk!.grade),
    'risk_summary.grade',
    'must be one of A, B, C, D, E',
  );
  check(typeof risk!.install_recommendation === 'string', 'risk_summary.install_recommendation', 'must be a string');
  // Blocked recommendation → reject manifest entirely
  check(risk!.install_recommendation !== 'blocked', 'risk_summary.install_recommendation', 'install is blocked by server');
  if ('requires_confirmation' in risk!) {
    check(typeof risk!.requires_confirmation === 'boolean', 'risk_summary.requires_confirmation', 'must be a boolean');
  }

  return m as unknown as InstallManifest;
}

function validateStep(step: Record<string, unknown>, index: number): InstallStep {
  const action = step.action;
  check(typeof action === 'string' && (VALID_ACTIONS as readonly string[]).includes(action), `steps[${index}].action`, `must be one of: ${VALID_ACTIONS.join(', ')}`);

  switch (action) {
    case 'download': {
      const url = step.url;
      check(typeof url === 'string' && isAllowedUrl(url), `steps[${index}].url`, 'must be an HTTPS URL');
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
    case 'npm_install': {
      const pkg = step.package;
      const version = step.version;
      check(typeof pkg === 'string' && NPM_PACKAGE_RE.test(pkg), `steps[${index}].package`, 'must be a valid npm package name');
      check(typeof version === 'string' && SEMVER_RE.test(version), `steps[${index}].version`, 'must be a valid semver version');
      if (step.registry !== undefined && step.registry !== null) {
        check(typeof step.registry === 'string' && isAllowedUrl(step.registry), `steps[${index}].registry`, 'must be an HTTPS URL');
      }
      const allowed = new Set(['action', 'package', 'version', 'registry']);
      for (const key of Object.keys(step)) {
        check(allowed.has(key), `steps[${index}].${key}`, 'unknown field');
      }
      return { action: 'npm_install', package: pkg as string, version: version as string, registry: step.registry as string | undefined };
    }
    case 'pip_install': {
      const pkg = step.package;
      check(typeof pkg === 'string' && pkg.length > 0 && !pkg.startsWith('/') && !pkg.includes('\\') && !pkg.startsWith('.'), `steps[${index}].package`, 'must be a plain package name');
      if (step.version !== undefined && step.version !== null) {
        check(typeof step.version === 'string' && step.version.length > 0, `steps[${index}].version`, 'must be a non-empty string');
      }
      if (step.index_url !== undefined && step.index_url !== null) {
        check(typeof step.index_url === 'string' && isAllowedUrl(step.index_url), `steps[${index}].index_url`, 'must be an HTTPS URL');
      }
      const allowed = new Set(['action', 'package', 'version', 'index_url']);
      for (const key of Object.keys(step)) {
        check(allowed.has(key), `steps[${index}].${key}`, 'unknown field');
      }
      return { action: 'pip_install', package: pkg as string, version: step.version as string | undefined, index_url: step.index_url as string | undefined };
    }
    case 'docker_run': {
      const image = step.image;
      check(typeof image === 'string' && DOCKER_IMAGE_RE.test(image) && !image.includes(' '), `steps[${index}].image`, 'must be a valid docker image reference');
      if (step.tag !== undefined && step.tag !== null) {
        check(typeof step.tag === 'string' && step.tag.length > 0, `steps[${index}].tag`, 'must be a non-empty string');
      }
      for (const key of ['ports', 'volumes', 'env']) {
        if (step[key] !== undefined) {
          check(Array.isArray(step[key]) && (step[key] as unknown[]).every(v => typeof v === 'string'), `steps[${index}].${key}`, 'must be an array of strings');
        }
      }
      const allowed = new Set(['action', 'image', 'tag', 'ports', 'volumes', 'env']);
      for (const key of Object.keys(step)) {
        check(allowed.has(key), `steps[${index}].${key}`, 'unknown field');
      }
      return {
        action: 'docker_run',
        image: image as string,
        tag: step.tag as string | undefined,
        ports: step.ports as string[] | undefined,
        volumes: step.volumes as string[] | undefined,
        env: step.env as string[] | undefined,
      };
    }
    case 'manual_steps': {
      check(typeof step.text === 'string' && step.text.length > 0, `steps[${index}].text`, 'must be a non-empty string');
      if (step.title !== undefined && step.title !== null) {
        check(typeof step.title === 'string', `steps[${index}].title`, 'must be a string');
      }
      const allowed = new Set(['action', 'title', 'text']);
      for (const key of Object.keys(step)) {
        check(allowed.has(key), `steps[${index}].${key}`, 'unknown field');
      }
      return { action: 'manual_steps', title: step.title as string | undefined, text: step.text as string };
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
