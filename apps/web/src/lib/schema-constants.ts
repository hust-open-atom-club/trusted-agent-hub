/**
 * Web 侧使用的 schema 常量（与 packages/schema/constants.ts 保持一致）。
 *
 * Web 的 Docker 构建上下文只包含 apps/web，无法 import 仓库根目录下的
 * packages/，因此这里维护一份本地副本；修改 packages/schema/constants.ts
 * 时需要同步更新本文件。
 */

export const PACKAGE_TYPES = [
  'skill',
  'mcp_server',
  'plugin',
  'subagent',
  'command',
  'prompt',
] as const;

export type PackageType = (typeof PACKAGE_TYPES)[number];

export const PACKAGE_TYPE_INSTALL_CLIENTS: Record<
  PackageType,
  readonly string[]
> = {
  skill: ['claude-code', 'cursor'],
  mcp_server: ['claude-code', 'cursor'],
  plugin: ['claude-code-plugin'],
  subagent: ['claude-code'],
  command: ['claude-code'],
  prompt: ['claude-code'],
};
