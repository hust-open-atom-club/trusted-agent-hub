'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import type { Finding, VersionDetail } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function FileViewerPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, token, loading: authLoading } = useAuth();
  const targetRef = useRef<HTMLDivElement>(null);

  const versionId = searchParams.get('versionId') || '';
  const filePath = searchParams.get('path') || '';
  const highlightLine = Number(searchParams.get('line') || 0);

  const [fileContent, setFileContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading) return;
    if (!versionId || !filePath) {
      setError('缺少参数');
      setLoading(false);
      return;
    }
    if (!token) {
      setError('请先登录');
      setLoading(false);
      return;
    }

    apiFetch<VersionDetail>(`${API_BASE}/api/v0/producer/versions/${versionId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data) => {
        const content = data.scan_file_contents?.[filePath];
        if (content) {
          setFileContent(content);
        } else {
          setError('该文件内容不可用（可能是旧版扫描报告，请重新扫描）');
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  }, [versionId, filePath, token, authLoading]);

  useEffect(() => {
    if (highlightLine > 0 && targetRef.current) {
      setTimeout(() => {
        targetRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }, 100);
    }
  }, [highlightLine, fileContent]);

  const lines = fileContent ? fileContent.split('\n') : [];
  const lineNumWidth = String(lines.length).length;

  if (loading || authLoading) {
    return (
      <div className="file-viewer-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      </div>
    );
  }

  return (
    <div className="file-viewer-page">
      <nav className="file-viewer-nav">
        <button onClick={() => router.back()} className="link-btn">
          ← 返回审核详情
        </button>
        <span className="file-viewer-file-name">{filePath}</span>
        <span className="file-viewer-info">{lines.length} 行</span>
      </nav>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && fileContent && (
        <div className="file-viewer-code">
          <pre><code>
            {lines.map((line, i) => {
              const lineNum = i + 1;
              const isTarget = lineNum === highlightLine;
              return (
                <div
                  key={lineNum}
                  ref={isTarget ? targetRef : undefined}
                  className={`code-line ${isTarget ? 'code-line-target' : ''}`}
                >
                  <span className="code-line-num">{String(lineNum).padStart(lineNumWidth, ' ')}</span>
                  <span className="code-line-content">{line}</span>
                </div>
              );
            })}
          </code></pre>
        </div>
      )}
    </div>
  );
}
