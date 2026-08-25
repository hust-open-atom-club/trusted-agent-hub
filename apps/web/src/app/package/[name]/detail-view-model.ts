import type { VersionIntegrity, VersionPermissions, VersionSource } from '@/types';

export const TYPE_LABELS: Record<string, string> = {
  skill: 'search.skill',
  mcp_server: 'search.mcp_server',
  plugin: 'search.plugin',
  subagent: 'search.subagent',
  command: 'search.command',
  prompt: 'search.prompt',
};

export const RISK_LEVEL_LABELS: Record<string, string> = {
  trusted: 'trust_score.level.trusted',
  low_risk: 'trust_score.level.low_risk',
  medium_risk: 'trust_score.level.medium_risk',
  high_risk: 'trust_score.level.high_risk',
  untrusted: 'trust_score.level.untrusted',
};

export type PermissionTone = 'safe' | 'caution' | 'danger';

export interface PermissionSummaryItem {
  labelKey: string;
  valueKey: string;
  values: Record<string, string | number | boolean>;
  tone: PermissionTone;
}

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

export function getGradeClass(grade: string | null): string {
  if (grade === null) return 'unknown';
  const g = grade.toUpperCase();
  if (g === 'A' || g === 'B') return 'trusted';
  if (g === 'C') return 'caution';
  if (g === 'D' || g === 'E') return 'danger';
  return 'unknown';
}

export function getRiskLabelKey(riskLevel: string | null): string {
  return riskLevel ? (RISK_LEVEL_LABELS[riskLevel] ?? `detail.fallback.${riskLevel}`) : 'detail.unknown';
}

export function getTypeLabelKey(type: string): string {
  return TYPE_LABELS[type] ?? `detail.fallback.${type}`;
}

export function getTrustAdvice(grade: string | null): string {
  if (grade === null) return 'detail.trust_advice.unknown';
  if (grade === 'A') return 'detail.trust_advice.A';
  if (grade === 'B') return 'detail.trust_advice.B';
  if (grade === 'C') return 'detail.trust_advice.C';
  if (grade === 'D') return 'detail.trust_advice.D';
  return 'detail.trust_advice.E';
}

export function getPermissionSummary(perms?: VersionPermissions | null): PermissionSummaryItem[] {
  const filesystem = perms?.filesystem;
  const shell = perms?.shell;
  const network = perms?.network;
  const environment = perms?.environment;
  const credentials = perms?.credentials;

  const hasFilesystemAccess = Boolean(
    filesystem?.read?.length ||
    filesystem?.write?.length ||
    filesystem?.delete,
  );

  const items: PermissionSummaryItem[] = [
    {
      labelKey: 'detail.filesystem',
      valueKey: hasFilesystemAccess
        ? 'detail.permission_summary.filesystem_access'
        : 'detail.permission_summary.filesystem_none',
      values: hasFilesystemAccess
        ? {
            readCount: filesystem?.read?.length ?? 0,
            writeCount: filesystem?.write?.length ?? 0,
            deleteAllowed: Boolean(filesystem?.delete),
          }
        : {},
      tone: filesystem?.delete || Boolean(filesystem?.write?.length) ? 'danger' : 'safe',
    },
    {
      labelKey: 'detail.shell',
      valueKey: shell?.allowed
        ? 'detail.permission_summary.shell_allowed'
        : 'detail.permission_summary.shell_not_allowed',
      values: shell?.allowed ? { commands: shell.commands?.join(', ') ?? '' } : {},
      tone: shell?.allowed ? 'danger' : 'safe',
    },
    {
      labelKey: 'detail.network',
      valueKey: network?.allowed
        ? 'detail.permission_summary.network_allowed'
        : 'detail.permission_summary.network_not_allowed',
      values: network?.allowed ? { domains: network.domains?.join(', ') ?? '' } : {},
      tone: network?.allowed ? 'caution' : 'safe',
    },
  ];

  if (environment?.read?.length || environment?.write?.length) {
    items.push({
      labelKey: 'detail.environment',
      valueKey: environment.write?.length
        ? 'detail.permission_summary.environment_write'
        : 'detail.permission_summary.environment_read',
      values: { count: environment.write?.length || environment.read?.length || 0 },
      tone: environment.write?.length ? 'caution' : 'safe',
    });
  }

  if (credentials?.access?.length) {
    items.push({
      labelKey: 'detail.credentials',
      valueKey: 'detail.permission_summary.credentials_access',
      values: { access: credentials.access.join(', ') },
      tone: 'caution',
    });
  }

  return items;
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
