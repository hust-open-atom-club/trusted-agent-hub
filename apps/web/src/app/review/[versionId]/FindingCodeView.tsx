'use client';

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiFetch } from '@/lib/api-fetch';
import { API_BASE } from '@/lib/runtime-config';
import type { FileContext, Finding } from '@/types';

export function canPreviewFinding(finding: Finding): boolean {
  const missingReason = finding.evidence_missing_reason || finding.location?.missing_reason;
  if (missingReason === 'sensitive_identifier') return false;
  return !!finding.location?.snippet || !!(
    finding.location?.file && finding.location.line
    && (finding.evidence_missing_reason || finding.location.missing_reason) !== 'source_missing'
  );
}

export default function FindingCodeView({ finding, fileContents, versionId, token }: {
  finding: Finding;
  fileContents?: Record<string, string>;
  versionId: string;
  token: string | null;
}) {
  const { t } = useTranslation();
  const targetRef = useRef<HTMLDivElement>(null);
  const filePath = finding.location?.file || '';
  const targetLine = Math.max(1, finding.location?.line || 1);
  const requestKey = `${versionId}/${filePath}/${targetLine}`;
  const localContent = fileContents?.[filePath];
  const missingReason = finding.evidence_missing_reason || finding.location?.missing_reason;
  const sourceMissing = ['source_missing', 'sensitive_identifier'].includes(
    missingReason || '',
  );
  const [remote, setRemote] = useState<{ key: string; context: FileContext } | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const remoteContext = localContent === undefined && remote?.key === requestKey ? remote.context : null;

  useEffect(() => {
    setRemote(null);
    setFailed(false);
    if (localContent !== undefined || sourceMissing || !token || !filePath) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const query = new URLSearchParams({ path: filePath, line: String(targetLine) });
    apiFetch<FileContext>(`${API_BASE}/api/v0/producer/versions/${versionId}/file-context?${query}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(context => { if (!cancelled) setRemote({ key: requestKey, context }); })
      .catch(() => { if (!cancelled) setFailed(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [localContent, sourceMissing, token, filePath, targetLine, versionId, requestKey, attempt]);

  useEffect(() => {
    targetRef.current?.scrollIntoView?.({ block: 'center', behavior: 'smooth' });
  }, [remoteContext]);

  const fileContent = localContent ?? remoteContext?.content;
  if (fileContent === undefined) {
    return <div className="finding-snippet">
      {finding.location?.snippet && <pre><code>{finding.location.snippet}</code></pre>}
      <p role={loading ? 'status' : 'alert'}>
        {loading ? t('common.loading')
          : sourceMissing ? t(`review.finding.evidence_reason_${missingReason}`)
            : !token ? t('review.files.login_required')
              : t('review.finding.preview_failed')}
      </p>
      {failed && <button onClick={() => setAttempt(value => value + 1)}>
        {t('review.finding.preview_retry')}
      </button>}
    </div>;
  }

  const lines = fileContent.split('\n');
  const displayStart = remoteContext?.start_line ?? Math.max(1, targetLine - 50);
  const displayEnd = remoteContext?.end_line ?? Math.min(lines.length, targetLine + 50);
  const displayLines = remoteContext ? lines : lines.slice(displayStart - 1, displayEnd);
  const lineNumWidth = String(remoteContext?.total_lines ?? displayEnd).length;
  return <div className="finding-snippet finding-snippet-expanded">
    <div className="finding-snippet-info">
      <span>{t('review.finding.lines_range', {
        start: displayStart, end: displayEnd, total: remoteContext?.total_lines ?? lines.length,
      })}</span>
      <a
        className="finding-full-file-toggle"
        href={`/review/files?${new URLSearchParams({ versionId, path: filePath, line: String(targetLine) })}`}
        target="_blank" rel="noopener noreferrer"
      >{t('review.finding.view_full_file')}</a>
    </div>
    {remoteContext?.partial_line && <p role="status">{t('review.files.partial_line')}</p>}
    {remoteContext?.truncated && !remoteContext.partial_line && <p>{t('review.files.context_truncated')}</p>}
    <pre><code>{displayLines.map((line, index) => {
      const number = displayStart + index;
      const target = number === targetLine;
      return <div key={number} ref={target ? targetRef : undefined}
        className={`code-line ${target ? 'code-line-target' : ''}`}>
        <span className="code-line-num">{String(number).padStart(lineNumWidth, ' ')}</span>
        <span className="code-line-content">{line}</span>
      </div>;
    })}</code></pre>
  </div>;
}
