/**
 * Install method display helpers for the package detail page.
 */

import { PACKAGE_TYPE_INSTALL_CLIENTS } from '../../../../packages/schema/constants';
import type { PackageType } from '../../../../packages/schema/constants';

export interface InstallMethodInfo {
  key: string;
  label: string;
  description: string;
  /** npm/pip/docker 会执行外部命令，安装时需要显式确认。 */
  requiresExternalCommand: boolean;
}

const INSTALL_METHODS: Record<string, InstallMethodInfo> = {
  copy_directory: {
    key: 'copy_directory',
    label: '目录复制',
    description: '下载 ZIP 并校验 SHA-256 后，复制到目标客户端目录。',
    requiresExternalCommand: false,
  },
  npm_install: {
    key: 'npm_install',
    label: 'npm 安装',
    description: '通过 npm 安装到受管目录 ~/.trusted-agent-hub/installed/<name>-npm，不污染系统环境。',
    requiresExternalCommand: true,
  },
  pip_install: {
    key: 'pip_install',
    label: 'pip 安装',
    description: '通过 pip 安装到受管目录 ~/.trusted-agent-hub/installed/<name>-pip。',
    requiresExternalCommand: true,
  },
  docker_run: {
    key: 'docker_run',
    label: 'Docker',
    description: '拉取镜像并生成运行配置（不会自动启动容器）。',
    requiresExternalCommand: true,
  },
  manual_steps: {
    key: 'manual_steps',
    label: '人工步骤',
    description: '按包说明手动完成安装，CLI 只记录步骤。',
    requiresExternalCommand: false,
  },
};

export function getInstallMethodInfo(
  method?: string | null,
): InstallMethodInfo {
  return (
    INSTALL_METHODS[method ?? ''] ?? {
      key: method ?? 'unknown',
      label: method ?? '未知',
      description: '按包说明完成安装。',
      requiresExternalCommand: false,
    }
  );
}

const CLIENT_LABELS: Record<string, string> = {
  'claude-code': 'Claude Code',
  'claude-code-plugin': 'Claude Code 插件',
  cursor: 'Cursor',
};

export const CLIENT_OPTIONS: Array<{ id: string; label: string }> = [
  { id: 'claude-code', label: 'Claude Code' },
  { id: 'claude-code-plugin', label: 'Claude Code 插件' },
  { id: 'cursor', label: 'Cursor' },
];

/**
 * Which install clients each package type may target.
 * Canonical source: packages/schema/constants.ts PACKAGE_TYPE_INSTALL_CLIENTS.
 */


/** All install clients the CLI currently supports. */
const SUPPORTED_INSTALL_CLIENTS = CLIENT_OPTIONS.map((c) => c.id);

export function getClientsForType(type?: string | null): string[] {
  const key = (type || '') as PackageType;
  return [...(PACKAGE_TYPE_INSTALL_CLIENTS[key] ?? [])];
}

/**
 * Resolve the clients shown in the install selector.
 * Declared compatibility is intersected with the clients allowed by the
 * package type; when nothing is declared (or the declared list contains no
 * supported client), the type defaults are used.
 */
export function getSelectableClients(
  type?: string | null,
  compatibility?: string[] | null,
): string[] {
  const allowed = getClientsForType(type);
  const declared = (compatibility ?? []).filter((c) =>
    SUPPORTED_INSTALL_CLIENTS.includes(c),
  );
  if (declared.length === 0) return allowed;
  const selectable = declared.filter((c) => allowed.includes(c));
  return selectable.length > 0 ? selectable : allowed;
}

export function getClientLabel(client: string): string {
  return CLIENT_LABELS[client] ?? client;
}

export function isClientCompatible(
  client: string,
  compatibility: string[] = [],
): boolean {
  return compatibility.includes(client);
}

export interface ClientTarget {
  client?: string;
  destination?: string;
}

/** 根据已选客户端解析安装目标目录。 */
export function getClientTargetPath(
  targets: ClientTarget[] | null | undefined,
  client: string,
  packageName: string,
): string {
  const match = (targets ?? []).find((t) => t.client === client);
  if (match?.destination) {
    return match.destination;
  }
  // claude-code and claude-code-plugin share the skills root: Claude Code
  // auto-loads plugins from ~/.claude/skills/<name>/ (skills-dir plugins).
  const root =
    client === 'cursor' ? '~/.cursor/skills/' : '~/.claude/skills/';
  return `${root}${packageName}/`;
}

/**
 * 生成可直接复制执行的安装命令：
 * - 包只兼容非默认客户端（如 claude-code-plugin）时自动带 --client；
 * - 用户显式选择客户端时优先使用所选客户端；
 * - npm/pip/docker 外部命令方式自动带 --yes（显式确认）。
 */
export function buildInstallCommand(
  packageName: string,
  compatibility: string[] = [],
  method?: string | null,
  selectedClient?: string | null,
): string {
  const effectiveClient =
    selectedClient ||
    (compatibility.length === 1 && compatibility[0] !== 'claude-code'
      ? compatibility[0]
      : undefined);
  const client =
    effectiveClient && effectiveClient !== 'claude-code'
      ? ` --client ${effectiveClient}`
      : '';
  const confirm = ['npm_install', 'pip_install', 'docker_run'].includes(
    method ?? '',
  )
    ? ' --yes'
    : '';
  return `tah install ${packageName}${client}${confirm}`;
}
