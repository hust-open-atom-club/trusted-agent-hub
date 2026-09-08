import * as fs from 'fs';
import * as path from 'path';

import { parse, stringify } from 'smol-toml';

import { backupConfigFile, ConfigWriteError } from './config-writer';
import { getCodexStateRoot } from './client-paths';

export interface CodexMcpEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  cwd?: string;
}

export function resolveCodexConfigPath(homeDir: string): string {
  return path.join(getCodexStateRoot(homeDir), 'config.toml');
}

async function readCodexConfig(filePath: string): Promise<string> {
  try {
    return await fs.promises.readFile(filePath, 'utf-8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return '';
    throw err;
  }
}

async function atomicWriteText(filePath: string, value: string): Promise<void> {
  let originalMode: number | undefined;
  try {
    originalMode = (await fs.promises.stat(filePath)).mode & 0o7777;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(tmpPath, value, 'utf-8');
  await fs.promises.chmod(tmpPath, originalMode ?? 0o600);
  await fs.promises.rename(tmpPath, filePath);
}

function validateCodexConfig(text: string, filePath: string): void {
  if (!text) return;
  try {
    parse(text);
  } catch (err) {
    throw new ConfigWriteError(
      `Cannot parse Codex config ${filePath}: ${
        err instanceof Error ? err.message : String(err)
      }`,
      'codex_config_parse_error',
    );
  }
}

const BARE_TOML_KEY = /^[A-Za-z0-9_-]+$/;

function tomlKeyLiteral(key: string): string {
  return BARE_TOML_KEY.test(key) ? key : JSON.stringify(key);
}

function sectionHeaderForKey(key: string): string {
  return `[mcp_servers.${tomlKeyLiteral(key)}]`;
}

function tablePathFromHeader(line: string): string[] | null {
  const noComment = line.replace(/\s+#.*$/, '').trim();
  const isArrayTable = noComment.startsWith('[[');
  if (
    (!noComment.startsWith('[') || !noComment.endsWith(']')) ||
    (isArrayTable &&
      (!noComment.startsWith('[[') || !noComment.endsWith(']]')))
  ) {
    return null;
  }
  const inner = isArrayTable
    ? noComment.slice(2, -2)
    : noComment.slice(1, -1);
  const path: string[] = [];
  let rest = inner;
  while (rest.trim()) {
    rest = rest.trim();
    if (rest.startsWith('"') || rest.startsWith("'")) {
      const quote = rest[0];
      let end = -1;
      for (let i = 1; i < rest.length; i += 1) {
        if (rest[i] === '\\') {
          i += 1;
          continue;
        }
        if (rest[i] === quote) {
          end = i;
          break;
        }
      }
      if (end < 0) return null;
      try {
        path.push(JSON.parse(rest.slice(1, end)));
      } catch {
        path.push(rest.slice(1, end));
      }
      rest = rest.slice(end + 1);
    } else {
      const match = /^[^.\s]+/.exec(rest);
      if (!match) return null;
      path.push(match[0]);
      rest = rest.slice(match[0].length);
    }
    if (rest.trim().startsWith('.')) {
      rest = rest.trim().slice(1);
    } else if (rest.trim()) {
      return null;
    }
  }
  return path;
}

function serverKeyFromHeader(line: string): string | null {
  const path = tablePathFromHeader(line);
  return path && path.length === 2 && path[0] === 'mcp_servers'
    ? path[1]
    : null;
}

function isTableHeader(line: string): boolean {
  const trimmed = line.replace(/\s+#.*$/, '').trim();
  return trimmed.startsWith('[') && trimmed.endsWith(']');
}

function sectionEnd(lines: string[], start: number, key: string): number {
  let end = start + 1;
  while (end < lines.length) {
    if (!isTableHeader(lines[end])) {
      end += 1;
      continue;
    }
    const path = tablePathFromHeader(lines[end]);
    if (
      path &&
      path.length >= 3 &&
      path[0] === 'mcp_servers' &&
      path[1] === key
    ) {
      end += 1;
      continue;
    }
    break;
  }
  return end;
}

function splitLines(text: string): { lines: string[]; eol: string } {
  return {
    lines: text.split(/\r?\n/),
    eol: text.includes('\r\n') ? '\r\n' : '\n',
  };
}

function upsertCodexMcpSection(
  text: string,
  key: string,
  entry: CodexMcpEntry,
): string {
  const { lines, eol } = splitLines(text);
  const header = sectionHeaderForKey(key);
  let rendered = stringify({ mcp_servers: { [key]: entry } }).trimEnd();
  if (!rendered.startsWith(header)) {
    rendered = `${header}\n${rendered}`;
  }

  let existing = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (serverKeyFromHeader(lines[i]) === key) {
      existing = i;
      break;
    }
  }

  if (existing >= 0) {
    lines.splice(
      existing,
      sectionEnd(lines, existing, key) - existing,
      rendered,
    );
  } else {
    while (lines.length > 0 && lines[lines.length - 1].trim() === '') {
      lines.pop();
    }
    lines.push('', rendered);
  }
  return lines.join(eol).replace(/(?:\r?\n)+$/, eol);
}

function removeCodexMcpSectionFromText(text: string, key: string): string {
  const { lines, eol } = splitLines(text);
  const result: string[] = [];
  let removed = false;
  for (let i = 0; i < lines.length; i += 1) {
    if (!removed && serverKeyFromHeader(lines[i]) === key) {
      i = sectionEnd(lines, i, key) - 1;
      removed = true;
      continue;
    }
    result.push(lines[i]);
  }
  return result.join(eol).replace(/\n{3,}/g, '\n\n');
}

function hasCodexMcpSections(
  lines: string[],
  key: string,
): boolean {
  return lines.some((line) => serverKeyFromHeader(line) === key);
}

export async function writeCodexMcpSections(
  filePath: string,
  entries: Record<string, CodexMcpEntry>,
  homeDir: string,
): Promise<{ filePath: string; backupPath: string | null; keys: string[] }> {
  const text = await readCodexConfig(filePath);
  validateCodexConfig(text, filePath);
  const backupPath = await backupConfigFile(filePath, homeDir);
  let output = text;
  for (const [name, entry] of Object.entries(entries)) {
    output = output ? upsertCodexMcpSection(output, name, entry)
      : stringify({ mcp_servers: { [name]: entry } });
  }
  if (!output.endsWith('\n')) output += '\n';
  await atomicWriteText(filePath, output);
  return {
    filePath,
    backupPath,
    keys: Object.keys(entries),
  };
}

export async function removeCodexMcpSections(
  filePath: string,
  keys: string[],
): Promise<void> {
  const text = await readCodexConfig(filePath);
  if (!text) return;
  validateCodexConfig(text, filePath);
  let output = text;
  for (const key of keys) {
    output = removeCodexMcpSectionFromText(output, key);
  }
  await atomicWriteText(filePath, output);
}

export async function hasCodexMcpSection(
  filePath: string,
  key: string,
): Promise<boolean> {
  const text = await readCodexConfig(filePath);
  if (!text) return false;
  const config = parse(text) as Record<string, unknown>;
  return hasCodexMcpSections(splitLines(text).lines, key) ||
    Object.prototype.hasOwnProperty.call(
      config.mcp_servers && typeof config.mcp_servers === 'object' &&
        !Array.isArray(config.mcp_servers)
        ? (config.mcp_servers as Record<string, unknown>)
        : {},
      key,
    );
}
