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
  /**
   * 公开投影只有布尔值、拿不到数量或路径上限时，该轴按最大范围绘制。
   * 这类轴在雷达图上以虚线轴 + 空心顶点标记，区别于作者声明了具体范围的轴。
   */
  unknownBound: boolean;
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
  unknownBound = false,
): CapabilityAxis {
  return {
    key,
    scope,
    value: CAPABILITY_SCOPE_VALUE[scope],
    tone,
    detailKey,
    detailValues,
    unknownBound,
  };
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
          {},
          true,
        )
      : capabilityAxis('filesystem_delete', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    // 公开投影只有 shell_allowed 布尔值，无法区分命令白名单与任意命令。
    shellAllowed
      ? capabilityAxis('shell', 'unrestricted', 'danger', 'detail.capability.value.shell', {}, true)
      : capabilityAxis('shell', 'none', 'safe', NO_CAPABILITY_DETAIL_KEY),
    networkAllowed
      ? capabilityAxis('network', 'unrestricted', 'caution', 'detail.capability.value.network', {}, true)
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

export interface CapabilityHighlightItem {
  key: string;
  /** 直接展示的文字（工具名等） */
  text?: string;
  /** 需要翻译的条目文案；values 里的 scopeKey 由组件翻译后再代入 */
  textKey?: string;
  values?: Record<string, string | number>;
}

export interface CapabilityHighlight {
  key: string;
  labelKey: string;
  tone: PermissionTone;
  authorDeclared?: boolean;
  /** 列表型卡片：同类内容合并成一张卡，逐条展示 */
  items?: CapabilityHighlightItem[];
  variant?: 'lines' | 'tags';
  /** 折叠时展示的条数（仅列表型卡片）；超过时出现「展开查看更多」 */
  collapsedCount?: number;
  /** 单条文字卡片 */
  textKey?: string;
  values?: Record<string, string | number>;
}

/** 折叠阈值：文本列表按条数，工具是短标签所以放得更多 */
const USE_CASE_COLLAPSED_COUNT = 3;
const PURPOSE_COLLAPSED_COUNT = 3;
const TOOL_COLLAPSED_COUNT = 8;

export function getCapabilityHighlights(
  capabilities?: PublicCapabilitySummary | null,
  boundary?: PublicTrustBoundary | null,
  keywords: string[] = [],
  separator = '、',
): CapabilityHighlight[] {
  const highlights: CapabilityHighlight[] = [];
  const useCases = capabilities?.use_cases ?? [];
  const tools = capabilities?.tools ?? [];
  const purposes = capabilities?.purposes ?? [];

  // 同类内容合并成一张卡：同一个标签重复出现多张卡既啰嗦也不好看
  if (useCases.length > 0) {
    highlights.push({
      key: 'use_cases',
      labelKey: 'detail.capability.tile.use_case_label',
      tone: 'safe',
      authorDeclared: true,
      variant: 'lines',
      collapsedCount: USE_CASE_COLLAPSED_COUNT,
      items: useCases.map((useCase) => ({
        key: `use_case_${useCase.title}`,
        textKey: 'detail.capability.tile.use_case_body',
        values: { title: useCase.title, description: useCase.description },
      })),
    });
  }

  if (tools.length > 0) {
    highlights.push({
      key: 'tools',
      labelKey: 'detail.capability.tile.tools_label',
      tone: 'safe',
      variant: 'tags',
      collapsedCount: TOOL_COLLAPSED_COUNT,
      items: tools.map((tool) => ({ key: `tool_${tool}`, text: tool })),
    });
  }

  if (purposes.length > 0) {
    highlights.push({
      key: 'purposes',
      labelKey: 'detail.capability.tile.purpose_label',
      tone: 'caution',
      authorDeclared: true,
      variant: 'lines',
      collapsedCount: PURPOSE_COLLAPSED_COUNT,
      items: purposes.map((purpose) => ({
        key: `purpose_${purpose.scope}`,
        textKey: 'detail.capability.tile.purpose_body',
        values: {
          scopeKey: `detail.capability.scope.${purpose.scope}`,
          reason: purpose.reason,
        },
      })),
    });
  }

  const verification = boundary?.verification ?? 'not_verified';
  if (verification !== 'verified_undeclared') {
    highlights.push({
      key: 'boundary',
      labelKey: 'detail.capability.tile.boundary_label',
      tone: 'safe',
      textKey: `detail.capability.boundary.${verification}`,
    });
  }

  // 关键词只是没有作者声明内容时的兜底；已经声明了适用场景就不再重复一个同标签的卡片
  if (useCases.length === 0 && purposes.length === 0 && keywords.length > 0) {
    highlights.push({
      key: 'keywords',
      labelKey: 'detail.capability.tile.keywords_label',
      tone: 'safe',
      textKey: 'detail.capability.tile.keywords_body',
      values: {
        sample: keywords.length > 4
          ? `${keywords.slice(0, 4).join(separator)}…`
          : keywords.join(separator),
      },
    });
  }

  return highlights;
}

export interface BoundaryVerdict {
  key: string;
  values: Record<string, string | number>;
  tone: PermissionTone;
}

/**
 * 结论只描述「声明了多大范围」。扫描是否观察到声明之外的能力属于内部审核结论，
 * 已发布的版本不再对用户重复提示人工复核。
 */
export function getBoundaryVerdict(
  summary?: PublicPermissionSummary | null,
): BoundaryVerdict {
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
