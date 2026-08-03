/**
 * MCP client config file writer.
 *
 * Writes `mcpServers` entries into a client's JSON configuration with a
 * backup of the original file, atomic replace, and diff summaries.  Used by
 * the install path when a manifest declares `dependencies.mcp_servers`, and
 * by uninstall/verify to remove or check those entries.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import type { InstallManifest } from './manifest-types';

export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export class ConfigWriteError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = 'ConfigWriteError';
  }
}

export interface McpWriteSummary {
  filePath: string;
  keys: string[];
  diff: string[];
}

/** 返回客户端 MCP 配置文件的绝对路径；不支持则返回 null。 */
export function resolveMcpConfigPath(
  clientType: string,
  homeDir: string,
): string | null {
  if (clientType === 'claude-code') {
    return path.join(homeDir, '.claude.json');
  }
  if (clientType === 'cursor') {
    return path.join(homeDir, '.cursor', 'mcp.json');
  }
  return null;
}

export async function readJsonConfig(
  filePath: string,
): Promise<Record<string, unknown>> {
  try {
    const raw = await fs.promises.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new ConfigWriteError(
        `Config file is not a JSON object: ${filePath}`,
        'config_not_object',
      );
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return {};
    }
    if (err instanceof ConfigWriteError) throw err;
    throw new ConfigWriteError(
      `Cannot parse config file ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
      'config_parse_error',
    );
  }
}

async function atomicWriteJson(
  filePath: string,
  value: Record<string, unknown>,
): Promise<void> {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(
    tmpPath,
    JSON.stringify(value, null, 2) + '\n',
    'utf-8',
  );
  await fs.promises.rename(tmpPath, filePath);
}

export async function backupConfigFile(
  filePath: string,
  homeDir: string,
): Promise<string | null> {
  if (!fs.existsSync(filePath)) return null;
  const backupsRoot = path.join(homeDir, '.trusted-agent-hub', 'backups');
  await fs.promises.mkdir(backupsRoot, { recursive: true });
  const backupPath = path.join(
    backupsRoot,
    `${path.basename(filePath)}.${Date.now()}.bak`,
  );
  await fs.promises.copyFile(filePath, backupPath);
  return backupPath;
}

export async function writeMergedMcpConfig(
  filePath: string,
  entries: Record<string, McpServerEntry>,
  homeDir: string,
): Promise<{ filePath: string; backupPath: string | null }> {
  const backupPath = await backupConfigFile(filePath, homeDir);
  const current = await readJsonConfig(filePath);
  const mcpServers =
    current.mcpServers &&
    typeof current.mcpServers === 'object' &&
    !Array.isArray(current.mcpServers)
      ? (current.mcpServers as Record<string, unknown>)
      : {};
  for (const [key, entry] of Object.entries(entries)) {
    mcpServers[key] = entry;
  }
  current.mcpServers = mcpServers;
  await atomicWriteJson(filePath, current);
  return { filePath, backupPath };
}

export async function removeMcpEntries(
  filePath: string,
  keys: string[],
): Promise<void> {
  const current = await readJsonConfig(filePath);
  const mcpServers =
    current.mcpServers &&
    typeof current.mcpServers === 'object' &&
    !Array.isArray(current.mcpServers)
      ? (current.mcpServers as Record<string, unknown>)
      : {};
  for (const key of keys) {
    delete mcpServers[key];
  }
  current.mcpServers = mcpServers;
  await atomicWriteJson(filePath, current);
}

export async function restoreConfigBackup(
  backupPath: string,
  filePath: string,
): Promise<void> {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.copyFile(backupPath, filePath);
}

export function mcpServersFromManifest(
  manifest: InstallManifest,
): Record<string, McpServerEntry> | null {
  const list = manifest.dependencies?.mcp_servers;
  if (!Array.isArray(list) || list.length === 0) return null;
  const out: Record<string, McpServerEntry> = {};
  for (const raw of list) {
    const item = raw as Record<string, unknown>;
    const name = String(
      item.name || item.package || item.id || item.server || item.key || '',
    );
    if (!name) continue;
    const entry: McpServerEntry = {};
    if (typeof item.url === 'string') {
      entry.url = item.url;
    }
    if (typeof item.command === 'string') {
      entry.command = item.command;
      if (Array.isArray(item.args)) entry.args = item.args.map(String);
      if (
        item.env &&
        typeof item.env === 'object' &&
        !Array.isArray(item.env)
      ) {
        entry.env = item.env as Record<string, string>;
      }
    }
    if (entry.url || entry.command) {
      out[name] = entry;
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function describeMcpDiff(
  current: Record<string, unknown>,
  next: Record<string, McpServerEntry>,
): string[] {
  const existing =
    current.mcpServers &&
    typeof current.mcpServers === 'object' &&
    !Array.isArray(current.mcpServers)
      ? Object.keys(current.mcpServers as Record<string, unknown>)
      : [];
  const lines: string[] = [];
  for (const key of Object.keys(next)) {
    lines.push(
      existing.includes(key)
        ? `  • 覆盖已有 MCP server: ${key}`
        : `  • 新增 MCP server: ${key}`,
    );
  }
  return lines;
}

export function sha256FileSync(filePath: string): string {
  return crypto
    .createHash('sha256')
    .update(fs.readFileSync(filePath))
    .digest('hex');
}
