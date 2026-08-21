'use client';

import { useEffect, useRef, useState } from 'react';

export interface FileNode {
  name: string;
  type: 'file' | 'folder';
  children?: FileNode[];
  extension?: string;
  path?: string;
  sizeBytes?: number;
  lineCount?: number;
}

interface FileTreeProps {
  data: FileNode[];
  className?: string;
  selectedPath?: string | null;
  onSelectFile?: (path: string) => void;
  fileCountLabel?: string;
}

interface FileItemProps {
  node: FileNode;
  depth: number;
  selectedPath?: string | null;
  onSelectFile?: (path: string) => void;
}

function cx(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

function formatFileSize(bytes?: number): string {
  if (bytes === undefined) return '';
  if (bytes < 1024) return `${bytes} B`;
  const value = bytes / 1024;
  if (value < 1024) return `${Number.isInteger(value) ? value : value.toFixed(1)} KB`;
  const mb = value / 1024;
  return `${Number.isInteger(mb) ? mb : mb.toFixed(1)} MB`;
}

function getFileIcon(extension?: string): string {
  const iconMap: Record<string, string> = {
    tsx: 'R',
    ts: 'T',
    jsx: 'R',
    js: 'J',
    css: '#',
    json: '{}',
    md: 'M',
    svg: 'S',
    png: 'P',
  };
  return iconMap[extension || ''] ?? 'F';
}

function FileItem({ node, depth, selectedPath, onSelectFile }: FileItemProps) {
  const [isOpen, setIsOpen] = useState(true);
  const itemRef = useRef<HTMLButtonElement | null>(null);
  const isFolder = node.type === 'folder';
  const hasChildren = isFolder && Boolean(node.children?.length);
  const isSelected = !isFolder && node.path === selectedPath;
  const label = isFolder ? node.name : `${node.name} ${formatFileSize(node.sizeBytes)}`.trim();

  useEffect(() => {
    if (isSelected && typeof itemRef.current?.scrollIntoView === 'function') {
      itemRef.current.scrollIntoView({ block: 'nearest' });
    }
  }, [isSelected]);

  const handleClick = () => {
    if (isFolder) {
      setIsOpen((value) => !value);
      return;
    }
    if (node.path) {
      onSelectFile?.(node.path);
    }
  };

  return (
    <div className="file-tree-node">
      <button
        ref={itemRef}
        type="button"
        role="treeitem"
        aria-expanded={isFolder ? isOpen : undefined}
        aria-selected={isSelected || undefined}
        className={cx('file-tree-item', isSelected && 'selected')}
        onClick={handleClick}
        style={{ paddingLeft: `${depth * 1 + 0.5}rem` }}
      >
        <span className={cx('file-tree-chevron', isFolder && isOpen && 'open')} aria-hidden="true">
          {isFolder ? '›' : getFileIcon(node.extension)}
        </span>
        <span className={cx('file-tree-icon', isFolder ? 'folder' : `file ext-${node.extension || 'default'}`)} aria-hidden="true">
          {isFolder ? (
            <svg width="16" height="14" viewBox="0 0 16 14" fill="currentColor">
              <path d="M1.5 1C0.67 1 0 1.67 0 2.5v9C0 12.33.67 13 1.5 13h13c.83 0 1.5-.67 1.5-1.5v-7C16 3.67 15.33 3 14.5 3H8L6.5 1h-5Z" />
            </svg>
          ) : (
            <svg width="14" height="16" viewBox="0 0 14 16" fill="currentColor">
              <path d="M1.5 0C.67 0 0 .67 0 1.5v13c0 .83.67 1.5 1.5 1.5h11c.83 0 1.5-.67 1.5-1.5v-10L9.5 0h-8Z" />
              <path d="M9 0v4.5h5" fillOpacity="0.45" />
            </svg>
          )}
        </span>
        <span className="file-tree-name" title={node.name}>{node.name}</span>
        {!isFolder && node.sizeBytes !== undefined && (
          <span className="file-tree-size">{formatFileSize(node.sizeBytes)}</span>
        )}
      </button>
      {hasChildren && isOpen && (
        <div role="group" className="file-tree-group">
          {node.children!.map((child) => (
            <FileItem
              key={`${child.type}-${child.path ?? child.name}`}
              node={child}
              depth={depth + 1}
              selectedPath={selectedPath}
              onSelectFile={onSelectFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function FileTree({
  data,
  className,
  selectedPath,
  onSelectFile,
  fileCountLabel,
}: FileTreeProps) {
  return (
    <div className={cx('file-tree-shell', className)}>
      <div className="file-tree-header">
        <div className="file-tree-dots" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <span>explorer</span>
        {fileCountLabel && <strong>{fileCountLabel}</strong>}
      </div>
      <div role="tree" className="file-tree-list">
        {data.map((node) => (
          <FileItem
            key={`${node.type}-${node.path ?? node.name}`}
            node={node}
            depth={0}
            selectedPath={selectedPath}
            onSelectFile={onSelectFile}
          />
        ))}
      </div>
    </div>
  );
}
