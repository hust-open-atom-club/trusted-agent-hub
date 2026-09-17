import type {
  PublicCapabilitySummary,
  PublicPermissionSummary,
  PublicTrustBoundary,
  VersionIntegrity,
  VersionSource,
} from '@/types';

export type PermissionTone = 'safe' | 'caution' | 'danger';

export interface DetailText {
  key: string;
  values: Record<string, string | number | boolean>;
}

export interface FileTreeNode {
  name: string;
  type: 'file' | 'folder';
  children?: FileTreeNode[];
  extension?: string;
  path?: string;
  sizeBytes?: number;
  lineCount?: number;
}

export interface FileEntry {
  path: string;
  name: string;
  extension: string;
  content: string;
  sizeBytes: number;
  lineCount: number;
}

export interface IntegrityRow {
  labelKey: string;
  value: string;
  kind: 'code' | 'link' | 'status' | 'text';
}

export function getFeedbackSummary(
  counts?: { positive: number; neutral: number; negative: number } | null,
): DetailText {
  if (!counts || counts.positive + counts.neutral + counts.negative === 0) {
    return { key: 'detail.feedback_summary.none', values: {} };
  }
  return {
    key: 'detail.feedback_summary.counts',
    values: { positive: counts.positive, negative: counts.negative },
  };
}

export type CapabilityScope = 'none' | 'limited' | 'unrestricted';

export interface CapabilityAxis {
  key: string;
  value: number;
  scope: CapabilityScope;
  tone: PermissionTone;
  detailKey: string;
  detailValues: Record<string, string | number | boolean>;
}

const CAPABILITY_SCOPE_VALUE: Record<CapabilityScope, number> = {
  none: 0,
  limited: 0.5,
  unrestricted: 1,
};

const NO_CAPABILITY_DETAIL_KEY = 'detail.capability.level.none';

function capabilityAxis(
  key: string,
  scope: CapabilityScope,
  tone: PermissionTone,
  detailKey: string,
  detailValues: Record<string, string | number | boolean> = {},
): CapabilityAxis {
  return { key, scope, value: CAPABILITY_SCOPE_VALUE[scope], tone, detailKey, detailValues };
}

export function getCapabilityAxes(summary?: PublicPermissionSummary | null): CapabilityAxis[] {
  const readCount = summary?.filesystem_read_count ?? 0;
  const writeCount = summary?.filesystem_write_count ?? 0;
  const deleteAllowed = Boolean(summary?.filesystem_delete);
  const shellAllowed = Boolean(summary?.shell_allowed);
  const networkAllowed = Boolean(summary?.network_allowed);
  const environmentRead = summary?.environment_read_count ?? 0;
  const environmentWrite = summary?.environment_write_count ?? 0;
  const credentialsCount = summary?.credentials_access_count ?? 0;
  const externalServicesCount = summary?.external_services_count ?? 0;
  const externalDeclared = externalServicesCount > 0
    || Boolean(summary?.database_declared)
    || Boolean(summary?.browser_declared);

  return [
    readCount > 0
      ? capabilityAxis(
          'filesystem_read',
          'limited',
          'safe',
          'detail.capability.value.filesystem_read',
          { count: readCount },
        )
      : capabilityAxis('filesystem_read', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    writeCount > 0
      ? capabilityAxis(
          'filesystem_write',
          'limited',
          'caution',
          'detail.capability.value.filesystem_write',
          { count: writeCount },
        )
      : capabilityAxis('filesystem_write', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    deleteAllowed
      ? capabilityAxis(
          'filesystem_delete',
          'unrestricted',
          'danger',
          'detail.capability.value.filesystem_delete',
        )
      : capabilityAxis('filesystem_delete', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    // 公开投影只有 shell_allowed 布尔值，无法区分命令白名单与任意命令，
    // 因此按范围无法判定处理（保守取最大档）。
    shellAllowed
      ? capabilityAxis('shell', 'unrestricted', 'danger', 'detail.capability.value.shell')
      : capabilityAxis('shell', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    networkAllowed
      ? capabilityAxis('network', 'unrestricted', 'caution', 'detail.capability.value.network')
      : capabilityAxis('network', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    environmentWrite > 0
      ? capabilityAxis(
          'environment',
          'unrestricted',
          'caution',
          'detail.capability.value.environment',
          { read: environmentRead, write: environmentWrite },
        )
      : environmentRead > 0
        ? capabilityAxis(
            'environment',
            'limited',
            'safe',
            'detail.capability.value.environment',
            { read: environmentRead, write: environmentWrite },
          )
        : capabilityAxis('environment', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    credentialsCount > 0
      ? capabilityAxis(
          'credentials_external',
          'unrestricted',
          'danger',
          'detail.capability.value.credentials_external',
          { credentials: credentialsCount, services: externalServicesCount },
        )
      : externalDeclared
        ? capabilityAxis(
            'credentials_external',
            'limited',
            'caution',
            'detail.capability.value.credentials_external',
            { credentials: credentialsCount, services: externalServicesCount },
          )
        : capabilityAxis('credentials_external', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
  ];
}

export function hasDeclaredCapability(axes: CapabilityAxis[]): boolean {
  return axes.some((axis) => axis.value > 0);
}

export interface BoundaryRow {
  key: string;
  allowed: boolean;
  valueKey: string;
  values: Record<string, string | number>;
  tone: PermissionTone;
}

export function getBoundaryRows(
  summary?: PublicPermissionSummary | null,
): BoundaryRow[] {
  const readCount = summary?.filesystem_read_count ?? 0;
  const writeCount = summary?.filesystem_write_count ?? 0;
  const deleteAllowed = Boolean(summary?.filesystem_delete);
  const shellAllowed = Boolean(summary?.shell_allowed);
  const networkAllowed = Boolean(summary?.network_allowed);
  const environmentCount =
    (summary?.environment_read_count ?? 0) + (summary?.environment_write_count ?? 0);
  const credentialsCount = summary?.credentials_access_count ?? 0;

  return [
    {
      key: 'filesystem_read',
      allowed: readCount > 0,
      valueKey: readCount > 0
        ? 'detail.boundary.value.filesystem_read'
        : 'detail.boundary.value.not_allowed',
      values: { count: readCount },
      tone: 'safe',
    },
    {
      key: 'filesystem_write',
      allowed: writeCount > 0,
      valueKey: writeCount > 0
        ? 'detail.boundary.value.filesystem_write'
        : 'detail.boundary.value.not_allowed',
      values: { count: writeCount },
      tone: writeCount > 0 ? 'caution' : 'safe',
    },
    {
      key: 'filesystem_delete',
      allowed: deleteAllowed,
      valueKey: deleteAllowed
        ? 'detail.boundary.value.allowed'
        : 'detail.boundary.value.not_allowed',
      values: {},
      tone: deleteAllowed ? 'danger' : 'safe',
    },
    {
      key: 'shell',
      allowed: shellAllowed,
      valueKey: shellAllowed
        ? 'detail.boundary.value.allowed'
        : 'detail.boundary.value.not_allowed',
      values: {},
      tone: shellAllowed ? 'danger' : 'safe',
    },
    {
      key: 'network',
      allowed: networkAllowed,
      valueKey: networkAllowed
        ? 'detail.boundary.value.allowed'
        : 'detail.boundary.value.not_allowed',
      values: {},
      tone: networkAllowed ? 'caution' : 'safe',
    },
    {
      key: 'environment',
      allowed: environmentCount > 0,
      valueKey: environmentCount > 0
        ? 'detail.boundary.value.environment'
        : 'detail.boundary.value.not_allowed',
      values: { count: environmentCount },
      tone: (summary?.environment_write_count ?? 0) > 0 ? 'caution' : 'safe',
    },
    {
      key: 'credentials',
      allowed: credentialsCount > 0,
      valueKey: credentialsCount > 0
        ? 'detail.boundary.value.credentials'
        : 'detail.boundary.value.not_allowed',
      values: { count: credentialsCount },
      tone: credentialsCount > 0 ? 'danger' : 'safe',
    },
  ];
}

export interface CapabilityHighlight {
  key: string;
  labelKey: string;
  bodyKey: string;
  bodyValues: Record<string, string | number>;
  tone: PermissionTone;
  authorDeclared?: boolean;
}

export function getCapabilityHighlights(
  capabilities?: PublicCapabilitySummary | null,
  boundary?: PublicTrustBoundary | null,
  keywords: string[] = [],
  separator = '、',
): CapabilityHighlight[] {
  const highlights: CapabilityHighlight[] = [];
  const tools = capabilities?.tools ?? [];

  for (const useCase of (capabilities?.use_cases ?? []).slice(0, 6)) {
    highlights.push({
      key: `use_case_${useCase.title}`,
      labelKey: 'detail.capability.tile.use_case_label',
      bodyKey: 'detail.capability.tile.use_case_body',
      bodyValues: { title: useCase.title, description: useCase.description },
      tone: 'safe',
      authorDeclared: true,
    });
  }

  if (tools.length > 0) {
    const sample = tools.slice(0, 3).join(separator);
    highlights.push({
      key: 'tools',
      labelKey: 'detail.capability.tile.tools_label',
      bodyKey: 'detail.capability.tile.tools_body',
      bodyValues: {
        count: tools.length,
        sample: tools.length > 3 ? `${sample}…` : sample,
      },
      tone: 'safe',
    });
  }

  for (const purpose of (capabilities?.purposes ?? []).slice(0, 3)) {
    highlights.push({
      key: `purpose_${purpose.scope}`,
      labelKey: 'detail.capability.tile.purpose_label',
      bodyKey: 'detail.capability.tile.purpose_body',
      bodyValues: {
        scopeKey: `detail.capability.scope.${purpose.scope}`,
        reason: purpose.reason,
      },
      tone: 'caution',
      authorDeclared: true,
    });
  }

  const verification = boundary?.verification ?? 'not_verified';
  highlights.push({
    key: 'boundary',
    labelKey: 'detail.capability.tile.boundary_label',
    bodyKey: `detail.capability.boundary.${verification}`,
    bodyValues: {},
    tone: verification === 'verified_undeclared' ? 'caution' : 'safe',
  });

  if (highlights.length < 3 && keywords.length > 0) {
    highlights.push({
      key: 'keywords',
      labelKey: 'detail.capability.tile.keywords_label',
      bodyKey: 'detail.capability.tile.keywords_body',
      bodyValues: {
        sample: keywords.length > 4
          ? `${keywords.slice(0, 4).join(separator)}…`
          : keywords.join(separator),
      },
      tone: 'safe',
    });
  }

  return highlights.slice(0, 8);
}

export interface BoundaryVerdict {
  key: string;
  values: Record<string, string | number>;
  tone: PermissionTone;
}

export function getBoundaryVerdict(
  summary?: PublicPermissionSummary | null,
  boundary?: PublicTrustBoundary | null,
): BoundaryVerdict {
  if (boundary?.verification === 'verified_undeclared') {
    return { key: 'detail.boundary.verdict.undeclared', values: {}, tone: 'caution' };
  }
  const rows = getBoundaryRows(summary);
  const highRisk = rows.filter((row) => row.allowed && row.tone === 'danger').length;
  if (highRisk > 0) {
    return {
      key: 'detail.boundary.verdict.elevated',
      values: { count: highRisk },
      tone: 'caution',
    };
  }
  if (!hasDeclaredCapability(getCapabilityAxes(summary))) {
    return { key: 'detail.boundary.verdict.none', values: {}, tone: 'safe' };
  }
  return { key: 'detail.boundary.verdict.limited', values: {}, tone: 'safe' };
}

export function formatByteSize(bytes?: number | null): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes < 1024) return `${bytes} B`;

  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  const rounded = Number.isInteger(value) ? String(value) : value.toFixed(1).replace(/\.0$/, '');
  return `${rounded} ${units[unitIndex]}`;
}

export function getFileEntries(fileContents?: Record<string, string> | null): FileEntry[] {
  return Object.entries(fileContents ?? {})
    .filter(([path]) => Boolean(path.trim()))
    .map(([path, content]) => {
      const name = path.split('/').filter(Boolean).at(-1) ?? path;
      const extension = name.includes('.') ? name.split('.').pop() ?? '' : '';
      return {
        path,
        name,
        extension,
        content,
        sizeBytes: new TextEncoder().encode(content).length,
        lineCount: content.split('\n').length,
      };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

export function getDefaultSelectedPath(fileContents?: Record<string, string> | null): string | null {
  const entries = getFileEntries(fileContents);
  const skillFile = entries.find((entry) => entry.path.toLowerCase() === 'skill.md');
  return skillFile?.path ?? entries[0]?.path ?? null;
}

export function buildFileTree(fileContents?: Record<string, string> | null): FileTreeNode[] {
  const roots: FileTreeNode[] = [];

  const ensureFolder = (siblings: FileTreeNode[], name: string): FileTreeNode => {
    let folder = siblings.find((node) => node.type === 'folder' && node.name === name);
    if (!folder) {
      folder = { name, type: 'folder', children: [] };
      siblings.push(folder);
    }
    return folder;
  };

  for (const entry of getFileEntries(fileContents)) {
    const parts = entry.path.split('/').filter(Boolean);
    let siblings = roots;

    for (const part of parts.slice(0, -1)) {
      const folder = ensureFolder(siblings, part);
      folder.children ??= [];
      siblings = folder.children;
    }

    siblings.push({
      name: entry.name,
      type: 'file',
      extension: entry.extension,
      path: entry.path,
      sizeBytes: entry.sizeBytes,
      lineCount: entry.lineCount,
    });
  }

  const sortNodes = (nodes: FileTreeNode[]): FileTreeNode[] =>
    nodes
      .map((node) => node.type === 'folder' ? { ...node, children: sortNodes(node.children ?? []) } : node)
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

  return sortNodes(roots);
}

export function getIntegrityRows(
  _source?: VersionSource | null,
  integrity?: VersionIntegrity | null,
): IntegrityRow[] {
  const rows: IntegrityRow[] = [
    {
      labelKey: 'detail.integrity.sha256',
      value: integrity?.sha256 || 'detail.integrity.missing',
      kind: integrity?.sha256 ? 'code' : 'status',
    },
    {
      labelKey: 'detail.integrity.hash_scope',
      value: integrity?.hash_scope === 'scanned_source'
        ? 'detail.integrity.scope_scanned_source'
        : integrity?.hash_scope === 'artifact_archive'
          ? 'detail.integrity.scope_artifact_archive'
          : 'detail.integrity.unknown',
      kind: 'status',
    },
    {
      labelKey: 'detail.integrity.completeness',
      value: integrity?.is_complete === true
        ? 'detail.integrity.complete'
        : integrity?.is_complete === false
          ? 'detail.integrity.incomplete'
          : 'detail.integrity.unknown',
      kind: 'status',
    },
  ];

  if (integrity?.download_size_bytes != null) {
    rows.push({
      labelKey: 'detail.integrity.download_size',
      value: formatByteSize(integrity.download_size_bytes),
      kind: 'text',
    });
  }

  return rows;
}
