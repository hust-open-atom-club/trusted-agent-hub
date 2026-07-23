'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import ScoreBadge from './ScoreBadge';

type ScanStatus = 'idle' | 'submitting' | 'scanning' | 'complete' | 'error';

interface ScanResult {
  scan_id: string;
  status: string;
  package_name: string;
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    pass_rate: number;
  };
  trust_score?: {
    level: string | null;
    grade: string | null;
    recommendation: string | null;
  };
  llm_review?: {
    triggered: boolean;
    findings_reviewed: number;
    labels_summary?: {
      suspected_malicious: number;
      suspected_negligent: number;
      likely_benign: number;
      uncertain: number;
      unavailable: number;
    };
    error?: string;
    fallback?: string;
  };
  error?: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const LOCAL_SKILLS = [
  { path: 'examples/risky-packages/risky-executor', name: 'risky-executor', desc: 'Malicious skill (15+ attack vectors) — scanner stress test', risk: 'high' },
  { path: 'examples/skills/demo-code-review', name: 'demo-code-review', desc: 'Code review skill — multi-dimension PR analysis', risk: 'low' },
  { path: 'examples/mcp-servers/demo-filesystem', name: 'demo-filesystem', desc: 'Read-only filesystem MCP server', risk: 'medium' },
  { path: 'examples/plugins/demo-dev-toolkit', name: 'demo-dev-toolkit', desc: 'Developer toolkit plugin — aggregates 3 skills', risk: 'low' },
];

interface ScannerFormProps {
  onRepoScanned?: (url: string) => void;
}

export default function ScannerForm({ onRepoScanned }: ScannerFormProps) {
  const router = useRouter();
  const { user } = useAuth();
  const [repoUrl, setRepoUrl] = useState('');
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [statusMessage, setStatusMessage] = useState('');

  // --- 轮询辅助 ---
  const pollUntilDone = useCallback(async (scanId: string, label: string) => {
    setScanStatus('scanning');
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const res = await fetch(`${API_BASE}/api/v0/scan/${scanId}`);
      const data = await res.json();
      if (data.status === 'complete') {
        setScanStatus('complete');
        setScanResult(data);
        setStatusMessage('');
        return;
      }
      if (data.status === 'error') {
        setScanStatus('error');
        setScanResult(data);
        setStatusMessage('');
        return;
      }
      setStatusMessage(data.status + '...');
    }
    throw new Error('Timeout');
  }, []);

  // --- GitHub URL 扫描 ---
  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const url = repoUrl.trim();
      if (!url) return;
      setScanStatus('submitting');
      setScanResult(null);
      setStatusMessage('Submitting...');
      try {
        const r = await fetch(`${API_BASE}/api/v0/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repo_url: url }) });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || 'Failed'); }
        const { scan_id } = await r.json();
        await pollUntilDone(scan_id, url);
      } catch (err: unknown) {
        setScanStatus('error');
        setScanResult({ scan_id: '', status: 'error', package_name: 'unknown', error: err instanceof Error ? err.message : 'Unknown error' });
      }
    },
    [repoUrl, pollUntilDone]
  );

  // --- 本地路径扫描 ---
  const scanLocalPath = useCallback(async (localPath: string, label: string) => {
    setScanStatus('submitting');
      setScanResult(null);
    setRepoUrl(localPath);
    setStatusMessage(`Scanning ${label}...`);
    try {
      const r = await fetch(`${API_BASE}/api/v0/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ local_path: localPath }) });
      if (!r.ok) { const e = await r.json(); throw new Error(e.detail || 'Failed'); }
      const { scan_id } = await r.json();
      await pollUntilDone(scan_id, label);
    } catch (err: unknown) {
      setScanStatus('error');
      setScanResult({ scan_id: '', status: 'error', package_name: 'unknown', error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }, [pollUntilDone]);

  const handleReset = () => {
    setScanStatus('idle');
    setScanResult(null);
    setRepoUrl('');
    setStatusMessage('');
  };

  const isBusy = scanStatus === 'submitting' || scanStatus === 'scanning';

  return (
    <div className="scanner-section">
      <div className="scanner-card">
        <div className="scanner-header">
          <h2 className="scanner-title">
            <svg className="scanner-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            Submit a Package for Trust Scan
          </h2>
          <p className="scanner-desc">
            Paste a GitHub URL or pick a built-in local skill to scan for security risks.
          </p>
        </div>

        {(scanStatus === 'idle' || scanStatus === 'error') && (
          <form className="scanner-form" onSubmit={handleSubmit}>
            <div className="scanner-input-row">
              <input type="url" className="scanner-url-input"
                placeholder="https://github.com/username/agent-package"
                value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
                disabled={isBusy} required />
              <button type="submit" className="scanner-submit-btn" disabled={isBusy || !repoUrl.trim()}>
                {isBusy ? 'Scanning...' : 'Start Scan'}
              </button>
            </div>
            <p className="scanner-hint">Only public GitHub repositories (HTTPS URL).</p>

            {/* Local skills quick-access */}
            <div className="scanner-test-area">
              <span className="scanner-test-label">Or pick a built-in local skill to test:</span>
            </div>
            <div className="local-skills-grid">
              {LOCAL_SKILLS.map((skill) => (
                <button type="button" key={skill.name}
                  className={`local-skill-btn skill-${skill.risk}`}
                  onClick={() => scanLocalPath(skill.path, skill.name)}
                  disabled={isBusy}>
                  <span className="local-skill-name">{skill.name}</span>
                  <span className="local-skill-desc">{skill.desc}</span>
                </button>
              ))}
            </div>
          </form>
        )}

        {/* Status */}
        {isBusy && (
          <div className="scanner-status scanner-status-busy">
            <div className="scanner-spinner" />
            <div>
              <p className="scanner-status-title">Scan in Progress</p>
              <p className="scanner-status-msg">{statusMessage}</p>
            </div>
          </div>
        )}

        {scanStatus === 'error' && scanResult && (
          <div className="scanner-status scanner-status-error">
            <div className="scanner-status-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            </div>
            <div>
              <p className="scanner-status-title">Scan Failed</p>
              <p className="scanner-status-msg">{scanResult.error || 'Unknown error'}</p>
            </div>
            <button className="scanner-retry-btn" onClick={handleReset}>Try Again</button>
          </div>
        )}

        {/* Results */}
        {scanStatus === 'complete' && scanResult && (
          <div className="scanner-result">
            <div className="scanner-result-header">
              <div className="scanner-result-score">
                <span className="scanner-result-label">Trust Score</span>
                <ScoreBadge grade={scanResult.trust_score?.grade ?? null} size="lg" />
                {scanResult.trust_score?.grade && (
                  <span className={`scanner-result-grade grade-${scanResult.trust_score.grade.toLowerCase()}`}>
                    Grade {scanResult.trust_score.grade}
                  </span>
                )}
                {scanResult.trust_score?.level && (
                  <span className="scanner-result-level">{scanResult.trust_score.level.replace(/_/g, ' ')}</span>
                )}
              </div>
              <div className="scanner-result-meta">
                <span className="scanner-result-pkg">{scanResult.package_name}</span>
                {scanResult.trust_score?.recommendation && (
                  <span className="scanner-result-recommendation">
                    {scanResult.trust_score.recommendation === 'safe' ? 'Safe to install'
                      : scanResult.trust_score.recommendation === 'review_recommended' ? 'Review recommended'
                      : scanResult.trust_score.recommendation === 'blocked' ? 'Blocked'
                      : scanResult.trust_score.recommendation}
                  </span>
                )}
              </div>
              {scanResult.llm_review?.triggered && (
                <div className="scanner-result-llm">
                  <span className="llm-review-badge" title={`LLM reviewed ${scanResult.llm_review.findings_reviewed} findings`}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    LLM Review: {scanResult.llm_review.findings_reviewed} findings
                  </span>
                  {scanResult.llm_review.labels_summary && (
                    <div className="llm-labels-summary">
                      {scanResult.llm_review.labels_summary.suspected_malicious > 0 && (
                        <span className="llm-label malicious">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                          {scanResult.llm_review.labels_summary.suspected_malicious} malicious
                        </span>
                      )}
                      {scanResult.llm_review.labels_summary.suspected_negligent > 0 && (
                        <span className="llm-label negligent">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                          {scanResult.llm_review.labels_summary.suspected_negligent} negligent
                        </span>
                      )}
                      {scanResult.llm_review.labels_summary.uncertain > 0 && (
                        <span className="llm-label uncertain">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                          {scanResult.llm_review.labels_summary.uncertain} uncertain
                        </span>
                      )}
                    </div>
                  )}
                  {scanResult.llm_review.fallback && (
                    <span className="llm-fallback-note">({scanResult.llm_review.fallback})</span>
                  )}
                </div>
              )}
            </div>

            {scanResult.summary && (
              <div className="scanner-result-findings">
                <h4>Security Findings</h4>
                <div className="findings-grid">
                  {(['critical','high','medium','low','info'] as const).map((sev) => (
                    <div key={sev} className={`finding-item ${sev}`}>
                      <span className="finding-count">{scanResult.summary![sev]}</span>
                      <span className="finding-label">{sev}</span>
                    </div>
                  ))}
                </div>
                <div className="findings-pass-rate">Pass Rate: {scanResult.summary.pass_rate}%</div>
              </div>
            )}

            <div className="scanner-result-actions">
              {user ? (
                onRepoScanned ? (
                  <button
                    className="btn btn-primary"
                    onClick={() => onRepoScanned(repoUrl)}
                  >
                    填入表单继续提交
                  </button>
                ) : (
                  <button
                    className="btn btn-primary"
                    onClick={() =>
                      router.push(
                        `/submit?repo_url=${encodeURIComponent(repoUrl)}`
                      )
                    }
                  >
                    提交入库审核
                  </button>
                )
              ) : (
                <p className="scanner-login-hint">
                  <a href="/login">登录</a>后即可提交入库审核
                </p>
              )}
              <button className="scanner-reset-btn" onClick={handleReset}>
                Scan Another Package
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
