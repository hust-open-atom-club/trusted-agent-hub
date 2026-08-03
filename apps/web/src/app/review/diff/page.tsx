'use client';

import { useState, useEffect, useMemo, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface DiffHunk {
  path: string;
  base_content: string;
  current_content: string;
  diff_hunks: string[];
}

interface CodeDiff {
  files_added: string[];
  files_removed: string[];
  files_modified: DiffHunk[];
  files_unchanged: number;
  summary: string;
}

interface DiffResponse {
  current: { version_id: string; version: string; source_url: string };
  base: { version_id: string; version: string; source_url: string };
  diff: Record<string, unknown> | null;
  code_diff: CodeDiff | null;
  message?: string;
}

interface FileTreeItem {
  name: string;
  path: string;
  type: 'tree' | 'added' | 'removed' | 'modified';
  changes?: number;
  children: FileTreeItem[];
  fullPath?: string;
}

function buildFileTree(files: { path: string; type: 'added' | 'removed' | 'modified'; changes?: number }[]): FileTreeItem[] {
  const root: FileTreeItem[] = [];

  for (const file of files) {
    const parts = file.path.split('/');
    let current = root;

    for (let i = 0; i < parts.length; i++) {
      const isLast = i === parts.length - 1;
      const name = parts[i];
      let existing = current.find((c) => c.name === name);

      if (!existing) {
        existing = {
          name,
          path: parts.slice(0, i + 1).join('/'),
          type: isLast ? file.type : 'tree',
          changes: isLast ? file.changes : undefined,
          children: [],
          fullPath: isLast ? file.path : undefined,
        };
        current.push(existing);
      }
      if (!isLast) {
        current = existing.children;
      }
    }
  }

  return sortTree(root);
}

function sortTree(items: FileTreeItem[]): FileTreeItem[] {
  return [...items].sort((a, b) => {
    if (a.type === 'tree' && b.type !== 'tree') return -1;
    if (a.type !== 'tree' && b.type === 'tree') return 1;
    return a.name.localeCompare(b.name);
  }).map((item) => ({
    ...item,
    children: item.children.length > 0 ? sortTree(item.children) : item.children,
  }));
}

function DiffContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const versionId = searchParams.get('versionId') || '';
  const baseVersionId = searchParams.get('base') || '';

  const [data, setData] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (authLoading) return;
    if (!versionId) { setError('缺少版本 ID'); setLoading(false); return; }
    if (!token) { setError('请先登录'); setLoading(false); return; }

    let url = `${API_BASE}/api/v0/producer/versions/${versionId}/diff`;
    if (baseVersionId) url += `?base=${encodeURIComponent(baseVersionId)}`;

    apiFetch<DiffResponse>(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((d) => {
        setData(d);
        const firstModified = d.code_diff?.files_modified?.[0]?.path;
        if (firstModified) setSelectedFile(firstModified);
      })
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  }, [versionId, baseVersionId, token, authLoading]);

  const codeDiff: CodeDiff | null = data?.code_diff ?? null;

  const allFiles = useMemo(() => {
    if (!codeDiff) return [];
    try {
      return [
        ...(codeDiff.files_added || []).map((f: string) => ({ path: f, type: 'added' as const })),
        ...(codeDiff.files_removed || []).map((f: string) => ({ path: f, type: 'removed' as const })),
        ...(codeDiff.files_modified || []).map((f: DiffHunk) => ({ path: f.path, type: 'modified' as const, changes: f.diff_hunks?.length ?? 0 })),
      ];
    } catch { return []; }
  }, [codeDiff]);

  const fileTree = useMemo(() => {
    try { return buildFileTree(allFiles); } catch { return []; }
  }, [allFiles]);

  const selected: DiffHunk | null = codeDiff?.files_modified?.find((f: DiffHunk) => f.path === selectedFile) ?? null;

  if (authLoading || loading) {
    return <div className="diff-layout"><div className="empty-state"><div className="empty-state-icon">&#x23F3;</div><h3>加载中...</h3></div></div>;
  }

  if (error || !data) {
    return <div className="diff-layout"><div className="empty-state"><div className="empty-state-icon">&#x26A0;</div><h3>错误</h3><p>{error || '无法加载数据'}</p></div></div>;
  }

  if (data.message && !data.code_diff) {
    return <div className="diff-layout"><div className="empty-state"><div className="empty-state-icon">&#x2139;</div><h3>提示</h3><p>{data.message}</p></div></div>;
  }

  if (!codeDiff) {
    return (
      <div className="diff-layout">
        <div className="empty-state">
          <div className="empty-state-icon">&#x2139;</div>
          <h3>无代码变更数据</h3>
          <p>该版本暂无可对比的源代码记录</p>
        </div>
      </div>
    );
  }

  const toggleTree = (path: string) => {
    setCollapsed((prev) => ({ ...prev, [path]: !prev[path] }));
  };

  const renderTree = (items: FileTreeItem[], depth: number = 0): React.ReactNode => {
    return items.map((item) => {
      const isCollapsed = collapsed[item.path];
      const isDir = item.type === 'tree';
      const isModifiable = item.type === 'modified';

      return (
        <div key={item.path}>
          <button
            className={`diff-file-item ${item.type} ${selectedFile === item.fullPath ? 'active' : ''}`}
            style={{ paddingLeft: `${0.6 + depth * 1}rem` }}
            onClick={() => {
              if (isDir) {
                toggleTree(item.path);
              } else if (isModifiable && item.fullPath) {
                setSelectedFile(item.fullPath);
              }
            }}
            disabled={!isDir && !isModifiable}
          >
            {isDir && (
              <span className="diff-file-icon tree" style={{ fontSize: '0.65rem' }}>
                {isCollapsed ? '▸' : '▾'}
              </span>
            )}
            {!isDir && (
              <span className="diff-file-icon">
                {item.type === 'added' ? '+' : item.type === 'removed' ? '−' : '~'}
              </span>
            )}
            <span className="diff-file-path">{item.name}</span>
            {item.changes !== undefined && (
              <span className="diff-file-changes">{item.changes}</span>
            )}
            {isDir && (
              <span className="diff-file-changes">{countDescendants(item)}</span>
            )}
          </button>
          {isDir && !isCollapsed && item.children.length > 0 && (
            <div>{renderTree(item.children, depth + 1)}</div>
          )}
        </div>
      );
    });
  };

  const countDescendants = (item: FileTreeItem): number => {
    let count = 0;
    for (const child of item.children) {
      if (child.type !== 'tree') count++;
      count += countDescendants(child);
    }
    return count;
  };

  const renderDiffHunks = (hunks: string[]) => {
    const blocks: { header: string; lines: { prefix: string; text: string }[] }[] = [];
    let currentBlock: { header: string; lines: { prefix: string; text: string }[] } | null = null;

    for (const line of hunks) {
      if (line.startsWith('@@')) {
        if (currentBlock) blocks.push(currentBlock);
        currentBlock = { header: line, lines: [] };
      } else if (currentBlock) {
        currentBlock.lines.push({ prefix: line.charAt(0), text: line });
      }
    }
    if (currentBlock) blocks.push(currentBlock);

    return blocks.map((block, bi) => (
      <div key={bi} className="diff-hunk-block">
        <div className="diff-hunk-header">{block.header}</div>
        {block.lines.map((l, li) => (
          <div
            key={li}
            className={`diff-line ${l.prefix === '+' ? 'diff-add' : l.prefix === '-' ? 'diff-del' : ''}`}
          >
            <span className="diff-line-prefix">{l.prefix}</span>
            <span className="diff-line-text">{l.text.slice(1)}</span>
          </div>
        ))}
      </div>
    ));
  };

  return (
    <div className="diff-layout">
      <nav className="diff-top-bar">
        <button onClick={() => router.back()} className="link-btn">← 返回审核详情</button>
        <span className="diff-version-label">{data.base?.version || '—'} → {data.current?.version || '—'}</span>
        <span className="diff-summary-text">
          {codeDiff.summary}{codeDiff.files_unchanged > 0 ? ` · ${codeDiff.files_unchanged} 个文件未变化` : ''}
        </span>
      </nav>

      <div className="diff-body">
        <aside className="diff-sidebar">
          <div className="diff-sidebar-header">
            文件变更 <span className="diff-sidebar-count">{allFiles.length}</span>
          </div>
          {renderTree(fileTree)}
        </aside>

        <main className="diff-main">
          {!selected && (
            <div className="empty-state small">
              <div className="empty-state-icon">
                {(codeDiff.files_added?.length || 0) + (codeDiff.files_removed?.length || 0) > 0 ? '\u{1F4E6}' : '\u{2705}'}
              </div>
              <h3>
                {codeDiff.files_modified?.length === 0 && allFiles.length > 0
                  ? '仅文件增删，无代码行级变更'
                  : '选择左侧文件查看代码差异'}
              </h3>
              <p>
                {codeDiff.files_modified?.length === 0 && allFiles.length > 0
                  ? `本版本对比仅有 ${codeDiff.files_added?.length || 0} 个新增 + ${codeDiff.files_removed?.length || 0} 个删除，无可对比的修改文件。`
                  : '从左侧文件树中选择文件查看差异详情'}
              </p>
            </div>
          )}

          {selected && (
            <>
              <div className="diff-main-header">
                <span className="diff-file-icon modified">~</span>
                <span className="diff-main-path">{selected.path}</span>
                <span className="diff-main-stats">{selected.diff_hunks.length} 行变更</span>
              </div>
              <div className="diff-viewport">
                {renderDiffHunks(selected.diff_hunks)}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default function DiffPage() {
  return (
    <Suspense fallback={<div className="diff-layout"><div className="empty-state"><div className="empty-state-icon">&#x23F3;</div><h3>加载中...</h3></div></div>}>
      <DiffContent />
    </Suspense>
  );
}
