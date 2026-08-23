'use client';

import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FileTree } from '@/components/ui/file-tree';
import {
  buildFileTree,
  formatByteSize,
  getDefaultSelectedPath,
  getFileEntries,
} from './detail-view-model';
import HighlightedCode from './HighlightedCode';

interface PackageFileBrowserProps {
  fileContents?: Record<string, string> | null;
}

type FileViewMode = 'source' | 'preview';

function isMarkdownFile(extension: string): boolean {
  return ['md', 'markdown', 'mdx'].includes(extension.toLowerCase());
}

function MarkdownPreview({ content }: { content: string }) {
  const blocks: JSX.Element[] = [];
  const lines = content.split('\n');
  let listItems: string[] = [];

  const flushList = () => {
    if (!listItems.length) return;
    const items = listItems;
    listItems = [];
    blocks.push(
      <ul key={`list-${blocks.length}`}>
        {items.map((item, index) => (
          <li key={`${item}-${index}`}>{item}</li>
        ))}
      </ul>,
    );
  };

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) {
      flushList();
      return;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushList();
      const level = heading[1].length;
      const text = heading[2];
      if (level === 1) blocks.push(<h1 key={`h-${index}`}>{text}</h1>);
      if (level === 2) blocks.push(<h2 key={`h-${index}`}>{text}</h2>);
      if (level === 3) blocks.push(<h3 key={`h-${index}`}>{text}</h3>);
      return;
    }

    const bullet = /^[-*]\s+(.+)$/.exec(trimmed);
    if (bullet) {
      listItems.push(bullet[1]);
      return;
    }

    flushList();
    blocks.push(<p key={`p-${index}`}>{trimmed}</p>);
  });

  flushList();

  return <div className="markdown-preview">{blocks}</div>;
}

export default function PackageFileBrowser({ fileContents }: PackageFileBrowserProps) {
  const { t } = useTranslation();
  const entries = useMemo(() => getFileEntries(fileContents), [fileContents]);
  const tree = useMemo(() => buildFileTree(fileContents), [fileContents]);
  const [selectedPath, setSelectedPath] = useState<string | null>(() => getDefaultSelectedPath(fileContents));
  const [viewMode, setViewMode] = useState<FileViewMode>('source');

  useEffect(() => {
    setSelectedPath(getDefaultSelectedPath(fileContents));
    setViewMode('source');
  }, [fileContents]);

  if (!entries.length) {
    return (
      <div className="package-files-empty">
        <strong>{String(t('detail.files.empty_title'))}</strong>
        <p>{String(t('detail.files.empty_desc'))}</p>
      </div>
    );
  }

  const selected = entries.find((entry) => entry.path === selectedPath) ?? entries[0];
  const markdown = isMarkdownFile(selected.extension);
  const showMarkdownPreview = markdown && viewMode === 'preview';

  const handleSelectFile = (path: string) => {
    setSelectedPath(path);
    setViewMode('source');
  };

  const copyText = async (value: string) => {
    await navigator.clipboard?.writeText(value);
  };

  return (
    <div className="package-files-browser">
      <div className="package-files-tree">
        <FileTree
          data={tree}
          selectedPath={selected.path}
          onSelectFile={handleSelectFile}
          fileCountLabel={String(t('detail.files.count', { count: entries.length }))}
        />
      </div>
      <div className="package-file-preview">
        <div className="package-file-preview-header">
          <div className="package-file-preview-title">
            <strong>{selected.path}</strong>
            <span>
              {String(t('detail.files.file_meta', {
                lines: selected.lineCount,
                size: formatByteSize(selected.sizeBytes),
              }))}
            </span>
          </div>
          <div className="package-file-preview-actions">
            <button
              type="button"
              className="package-file-copy-btn"
              onClick={() => void copyText(selected.content)}
            >
              {String(t('detail.files.copy_file'))}
            </button>
            {markdown && (
              <div className="package-file-segmented" role="group" aria-label={String(t('detail.files.view_mode'))}>
                <button
                  type="button"
                  aria-pressed={viewMode === 'source'}
                  onClick={() => setViewMode('source')}
                >
                  {String(t('detail.files.source'))}
                </button>
                <button
                  type="button"
                  aria-pressed={viewMode === 'preview'}
                  onClick={() => setViewMode('preview')}
                >
                  {String(t('detail.files.preview'))}
                </button>
              </div>
            )}
          </div>
        </div>
        {showMarkdownPreview ? (
          <MarkdownPreview content={selected.content} />
        ) : (
          <HighlightedCode
            content={selected.content}
            extension={selected.extension}
            path={selected.path}
            renderLimitNotice={String(t('detail.files.render_limit', {
              rendered: 2000,
              total: selected.lineCount,
            }))}
          />
        )}
      </div>
    </div>
  );
}
