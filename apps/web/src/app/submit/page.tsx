'use client';

import { useState, Suspense } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const PACKAGE_TYPES = [
  { value: 'skill', label: 'Skill' },
  { value: 'mcp_server', label: 'MCP Server' },
  { value: 'plugin', label: 'Plugin' },
  { value: 'command', label: 'Command' },
  { value: 'prompt', label: 'Prompt' },
];

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$/;

const INITIAL_PERMISSIONS = {
  filesystem: false,
  shell: false,
  network: false,
  environment: false,
  credentials: false,
};

interface ScanResult {
  scan_id: string;
  status: string;
  package_name: string;
  trust_score?: { grade: string | null; level: string | null; recommendation: string | null };
  summary?: { total: number; critical: number; high: number; medium: number; low: number; info: number; pass_rate: number };
}

interface PackageMetadata {
  name: string;
  version: string;
  description: string;
  type: string;
  license: string;
  author?: { name?: string; email?: string; url?: string };
  keywords?: string[];
  category?: string;
  homepage?: string | null;
  compatibility?: string[];
  permissions?: Record<string, unknown>;
  source?: Record<string, unknown>;
  installation?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
}

type ScanPhase = 'input' | 'scanning' | 'confirm' | 'submitting' | 'done';

function SubmitForm() {
  const router = useRouter();
  const { token } = useAuth();

  const [repoUrl, setRepoUrl] = useState('');
  const [phase, setPhase] = useState<ScanPhase>('input');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [metadata, setMetadata] = useState<PackageMetadata | null>(null);

  const [pkgName, setPkgName] = useState('');
  const [pkgType, setPkgType] = useState('skill');
  const [pkgLicense, setPkgLicense] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState('');
  const [statusMsg, setStatusMsg] = useState('');

  // 处理 GitHub URL 扫描
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const url = repoUrl.trim();
    if (!url || !url.startsWith('https://github.com/')) {
      setError('请输入有效的 GitHub 仓库地址 (https://github.com/...)');
      return;
    }
    setError('');
    setPhase('scanning');
    setStatusMsg('正在提交扫描任务...');

    try {
      const r = await fetch(`${API_BASE}/api/v0/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: url }),
      });
      if (!r.ok) {
        const e = await r.json();
        throw new Error(e.detail || '扫描提交失败');
      }
      const { scan_id } = await r.json();

      // 轮询扫描完成
      for (let i = 0; i < 120; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const sr = await fetch(`${API_BASE}/api/v0/scan/${scan_id}`);
        const data = await sr.json();
        setStatusMsg(`扫描中... (${data.status})`);

        if (data.status === 'complete') {
          // 获取完整元数据
          let meta: PackageMetadata | null = null;
          try {
            const mr = await fetch(`${API_BASE}/api/v0/scan/${scan_id}/metadata`);
            if (mr.ok) {
              const md = await mr.json();
              meta = md.metadata;
            }
          } catch { /* ignore */ }

          setScanResult(data);
          setMetadata(meta);
          setPkgName(meta?.name || data.package_name || '');
          setPkgLicense(meta?.license || '');

          // 自动推断类型
          if (meta?.type === 'skill') setPkgType('skill');
          else if (meta?.type === 'mcp_server') setPkgType('mcp_server');
          else if (meta?.type === 'plugin') setPkgType('plugin');

          setPhase('confirm');
          return;
        }

        if (data.status === 'error') {
          throw new Error(data.error || '扫描失败');
        }
      }
      throw new Error('扫描超时，请重试');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '扫描失败');
      setPhase('input');
    }
  };

  // 提交审核
  const handleSubmit = async () => {
    if (!token) {
      setError('请先登录');
      return;
    }
    if (!pkgName.trim()) {
      setError('请输入包名称');
      return;
    }
    setError('');
    setPhase('submitting');

    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };

    try {
      const meta = metadata || {} as PackageMetadata;
      const version = meta.version && SEMVER_RE.test(meta.version) ? meta.version : '0.1.0';

      const pkgBody: Record<string, unknown> = {
        name: pkgName.trim(),
        type: pkgType,
        description: meta.description || pkgName.trim(),
        license: pkgLicense.trim() || meta.license || 'UNKNOWN',
        keywords: meta.keywords || [],
        category: meta.category || 'other',
        homepage: meta.homepage || null,
        author: meta.author || { name: 'unknown', email: 'unknown@unknown.org' },
        permissions: meta.permissions || INITIAL_PERMISSIONS,
        compatibility: meta.compatibility || [],
        installation: meta.installation || undefined,
        source: meta.source || { type: 'github', repository_url: repoUrl.trim(), ref: 'main', commit_hash: '0'.repeat(40) },
      };

      // Step 1: 创建包
      const pkgRes = await fetch(`${API_BASE}/api/v0/producer/packages`, {
        method: 'POST', headers, body: JSON.stringify(pkgBody),
      });
      if (!pkgRes.ok) {
        const err = await pkgRes.json().catch(() => ({ detail: '创建包失败' }));
        throw new Error(err.detail || `创建包失败 (${pkgRes.status})`);
      }
      const pkgData = await pkgRes.json();
      const packageId: string = pkgData.id;

      // Step 2: 创建版本
      const verBody: Record<string, unknown> = {
        version,
        repo_url: repoUrl.trim(),
        description: meta.description || pkgName.trim(),
      };
      const verRes = await fetch(`${API_BASE}/api/v0/producer/packages/${packageId}/versions`, {
        method: 'POST', headers, body: JSON.stringify(verBody),
      });
      if (!verRes.ok) {
        const err = await verRes.json().catch(() => ({ detail: '创建版本失败' }));
        throw new Error(err.detail || `创建版本失败 (${verRes.status})`);
      }
      const verData = await verRes.json();
      const versionId: string = verData.id;

      // Step 3: 提交审核
      const subRes = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
        method: 'POST', headers,
      });
      if (!subRes.ok) {
        const err = await subRes.json().catch(() => ({ detail: '提交审核失败' }));
        throw new Error(err.detail || `提交审核失败 (${subRes.status})`);
      }

      setPhase('done');
      setTimeout(() => {
        router.push(`/packages/${encodeURIComponent(pkgName.trim())}/versions/${encodeURIComponent(version)}/status?vid=${encodeURIComponent(versionId)}`);
      }, 1000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '提交失败，请重试');
      setPhase('confirm');
    }
  };

  const isBusy = phase === 'scanning' || phase === 'submitting';

  return (
    <div className="submit-page">
      <div className="submit-container">
        <div className="submit-header">
          <h1>提交 Agent 能力包</h1>
          <p>输入 GitHub 仓库地址，系统自动扫描提取元数据。</p>
        </div>

        {error && <div className="submit-error">{error}</div>}

        {/* Phase 1: 输入 GitHub URL */}
        {phase === 'input' && (
          <form className="scanner-form" onSubmit={handleStartScan}>
            <div className="scanner-input-row">
              <input
                type="url"
                className="scanner-url-input"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                disabled={isBusy}
                required
              />
              <button type="submit" className="scanner-submit-btn" disabled={isBusy || !repoUrl.trim()}>
                开始扫描
              </button>
            </div>
            <p className="scanner-hint">仅支持公开 GitHub 仓库 (HTTPS URL)，扫描完成后自动提取包信息。</p>
          </form>
        )}

        {/* Phase 2: 扫描中 */}
        {phase === 'scanning' && (
          <div className="scanner-status scanner-status-busy">
            <div className="scanner-spinner" />
            <div>
              <p className="scanner-status-title">正在扫描仓库</p>
              <p className="scanner-status-msg">{statusMsg}</p>
              <p className="scanning-estimate">预计耗时 30–90 秒，正在自动提取元数据...</p>
            </div>
          </div>
        )}

        {/* Phase 3: 确认信息 */}
        {phase === 'confirm' && scanResult && (
          <div className="confirm-section">
            <div className="scan-summary-card">
              <div className="scan-summary-header">
                <span className="scan-result-pkg">{scanResult.package_name}</span>
                {scanResult.trust_score?.grade && (
                  <span className={`grade-badge ${scanResult.trust_score.grade.toLowerCase()}`}>
                    {scanResult.trust_score.grade}
                  </span>
                )}
              </div>
              {scanResult.summary && (
                <div className="scan-summary-stats">
                  <span className="stat-item">
                    发现问题: <strong>{scanResult.summary.total}</strong>
                  </span>
                  <span className="stat-item">
                    通过率: <strong>{scanResult.summary.pass_rate}%</strong>
                  </span>
                </div>
              )}
            </div>

            <div className="form-section">
              <div className="form-field">
                <label htmlFor="pkgName">包名称 *</label>
                <input
                  id="pkgName"
                  type="text"
                  value={pkgName}
                  onChange={(e) => setPkgName(e.target.value)}
                  placeholder="自动提取，可修改"
                  disabled={isBusy}
                  required
                />
                <span className="form-hint">从仓库元数据自动提取</span>
              </div>

              <div className="form-field">
                <label htmlFor="pkgType">类型 *</label>
                <select
                  id="pkgType"
                  value={pkgType}
                  onChange={(e) => setPkgType(e.target.value)}
                  disabled={isBusy}
                >
                  {PACKAGE_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
                <span className="form-hint">已根据代码结构自动推断</span>
              </div>

              <div className="form-field">
                <label htmlFor="pkgLicense">许可证</label>
                <input
                  id="pkgLicense"
                  type="text"
                  value={pkgLicense}
                  onChange={(e) => setPkgLicense(e.target.value)}
                  placeholder="自动提取，可修改"
                  disabled={isBusy}
                />
                <span className="form-hint">从 LICENSE 文件自动提取</span>
              </div>

              {metadata && (
                <details className="meta-details" style={{ marginTop: '1rem' }}>
                  <summary style={{ cursor: 'pointer', color: 'var(--color-muted)', fontSize: '0.85rem' }}>
                    查看提取的完整元数据 ({Object.keys(metadata).length} 项) ...
                  </summary>
                  <pre className="meta-preview" style={{
                    fontSize: '0.75rem',
                    background: 'var(--color-paper-1)',
                    padding: '0.75rem',
                    borderRadius: 'var(--radius-md)',
                    maxHeight: '200px',
                    overflow: 'auto',
                    marginTop: '0.5rem',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {JSON.stringify(metadata, null, 2)}
                  </pre>
                </details>
              )}

              <label className="confirm-checkbox" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '1.25rem' }}>
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  disabled={isBusy}
                />
                <span style={{ fontSize: '0.88rem' }}>我已确认以上信息正确，提交审核</span>
              </label>
            </div>

            <div className="submit-actions">
              <button type="button" className="btn btn-secondary" onClick={() => { setPhase('input'); setScanResult(null); setMetadata(null); }} disabled={isBusy}>
                重新扫描
              </button>
              <button type="button" className="btn btn-primary btn-lg" onClick={handleSubmit} disabled={isBusy || !confirmed || !pkgName.trim()}>
                提交审核
              </button>
            </div>
          </div>
        )}

        {/* Phase: Submitting */}
        {phase === 'submitting' && (
          <div className="scanner-status scanner-status-busy">
            <div className="scanner-spinner" />
            <div>
              <p className="scanner-status-title">正在提交审核...</p>
              <p className="scanner-status-msg">正在创建包信息和版本，请稍候</p>
            </div>
          </div>
        )}

        {/* Phase: Done */}
        {phase === 'done' && (
          <div className="scanner-status" style={{ background: 'var(--color-success-bg)', borderColor: 'var(--color-success)' }}>
            <div>
              <p className="scanner-status-title" style={{ color: 'var(--color-success)' }}>提交成功</p>
              <p className="scanner-status-msg">正在跳转到审核状态页面...</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function SubmitPage() {
  return (
    <Suspense fallback={<div className="submit-page"><div className="submit-container"><p>加载中...</p></div></div>}>
      <SubmitForm />
    </Suspense>
  );
}
