'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';
import type { Finding, VersionDetail } from '@/types';

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

    apiFetch<VersionDetail>(`${API_BASE}/api/v0/producer/versions/${versionId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((data) => {
        // Full source is intentionally not part of scan reports. Reviewers see
        // only redacted finding snippets and occurrence locations.
        setError(t('review.files.content_unavailable'));
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
  const lineNumWidth = String(lines.length).length;

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
        <span className="file-viewer-info">{t('review.files.line_count', { count: lines.length })}</span>
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
