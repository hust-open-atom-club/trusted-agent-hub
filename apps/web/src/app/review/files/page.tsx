'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import type { FileContext } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function FileViewerPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();
  const targetRef = useRef<HTMLDivElement>(null);

  const versionId = searchParams.get('versionId') || '';
  const filePath = searchParams.get('path') || '';
  const highlightLine = Number(searchParams.get('line') || 0);

  const [fileContent, setFileContent] = useState<string | null>(null);
  const [contextStartLine, setContextStartLine] = useState(1);
  const [totalLines, setTotalLines] = useState(0);
  const [contextTruncated, setContextTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading) return;
    if (!versionId || !filePath) {
      setError(t('review.files.missing_params'));
      setLoading(false);
      return;
    }
    if (!token) {
      setError(t('review.files.login_required'));
      setLoading(false);
      return;
    }

    const query = new URLSearchParams({
      path: filePath,
      line: String(Math.max(1, highlightLine || 1)),
    });
    apiFetch<FileContext>(`${API_BASE}/api/v0/producer/versions/${versionId}/file-context?${query.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data) => {
        setFileContent(data.content);
        setContextStartLine(data.start_line);
        setTotalLines(data.total_lines);
        setContextTruncated(data.truncated);
      })
      .catch((err) => setError(err instanceof Error ? err.message : t('admin.dashboard.load_failed')))
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
  const lineNumWidth = String(totalLines || lines.length).length;

  if (loading || authLoading) {
    return (
      <div className="file-viewer-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>{t('common.loading')}</h3>
        </div>
      </div>
    );
  }

  return (
    <div className="file-viewer-page">
      <nav className="file-viewer-nav">
        <button onClick={() => router.back()} className="link-btn">
          {t('review.files.back_to_detail')}
        </button>
        <span className="file-viewer-file-name">{filePath}</span>
        <span className="file-viewer-info">{t('review.files.line_count', { count: totalLines || lines.length })}</span>
        <span className="file-viewer-info">{t('review.files.context_redacted')}</span>
        {contextTruncated && <span className="file-viewer-info">{t('review.files.context_truncated')}</span>}
      </nav>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>{t('admin.dashboard.load_failed')}</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && fileContent && (
        <div className="file-viewer-code">
          <pre><code>
            {lines.map((line, i) => {
              const lineNum = contextStartLine + i;
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
