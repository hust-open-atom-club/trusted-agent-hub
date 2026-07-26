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

const SPDX_LICENSES = [
  { value: 'MIT', label: 'MIT' },
  { value: 'Apache-2.0', label: 'Apache-2.0' },
  { value: 'GPL-3.0', label: 'GPL-3.0' },
  { value: 'AGPL-3.0', label: 'AGPL-3.0' },
  { value: 'BSD-3-Clause', label: 'BSD-3-Clause' },
  { value: 'BSD-2-Clause', label: 'BSD-2-Clause' },
  { value: 'MPL-2.0', label: 'MPL-2.0' },
  { value: 'ISC', label: 'ISC' },
  { value: 'Unlicense', label: 'Unlicense' },
  { value: 'BSL-1.0', label: 'BSL-1.0' },
  { value: 'LGPL-3.0', label: 'LGPL-3.0' },
  { value: 'UNLICENSED', label: 'UNLICENSED' },
  { value: 'OTHER', label: '其他' },
];

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$/;

interface ScanResult {
  scan_id: string;
  status: string;
  package_name: string;
  trust_score?: { grade: string | null; level: string | null; recommendation: string | null };
  summary?: { total: number; critical: number; high: number; medium: number; low: number; info: number };
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

function isPlaceholderStr(v: string | undefined | null): boolean {
  if (!v || v.trim() === '') return true;
  if (v === 'UNKNOWN' || v === 'unknown@unknown.org' || v === 'UNLICENSED') return true;
  if (v.includes('github.com/unknown/')) return true;
  return false;
}

function SubmitForm() {
  const router = useRouter();
  const { token } = useAuth();

  const [repoUrl, setRepoUrl] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [inputMode, setInputMode] = useState<'github' | 'local'>('github');
  const [phase, setPhase] = useState<ScanPhase>('input');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [metadata, setMetadata] = useState<PackageMetadata | null>(null);

  const [pkgName, setPkgName] = useState('');
  const [pkgType, setPkgType] = useState('skill');
  const [pkgVersion, setPkgVersion] = useState('');
  const [pkgDescription, setPkgDescription] = useState('');
  const [pkgLicense, setPkgLicense] = useState('');
  const [pkgSourceUrl, setPkgSourceUrl] = useState('');
  const [pkgAuthorName, setPkgAuthorName] = useState('');
  const [pkgAuthorEmail, setPkgAuthorEmail] = useState('');
  const [pkgCategory, setPkgCategory] = useState('');
  const [pkgHomepage, setPkgHomepage] = useState('');
  const [pkgCompatibility, setPkgCompatibility] = useState('');
  const [pkgKeywords, setPkgKeywords] = useState('');

  const [error, setError] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [confirmed, setConfirmed] = useState(false);

  const isBusy = phase === 'scanning' || phase === 'submitting';

  /* ── 字段来源追踪 ── */
  const [fieldSource, setFieldSource] = useState<Record<string, string>>({});

  function markField(field: string, value: unknown): void {
    setFieldSource((prev) => ({
      ...prev,
      [field]: isPlaceholderStr(typeof value === 'string' ? value : '') ? 'manual' : 'auto',
    }));
  }

  /* ── 扫描 ── */
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    let body: Record<string, string>;
    if (inputMode === 'local') {
      if (!localPath.trim()) { setError('请输入有效的本地目录路径'); return; }
      body = { local_path: localPath.trim() };
    } else {
      if (!repoUrl.trim() || !repoUrl.trim().startsWith('https://github.com/')) {
        setError('请输入有效的 GitHub 仓库地址'); return;
      }
      body = { repo_url: repoUrl.trim() };
    }

    setPhase('scanning');
    setStatusMsg('正在提交扫描任务...');
    try {
      const r = await fetch(`${API_BASE}/api/v0/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      if (!r.ok) { const e = await r.json(); throw new Error(e.detail || '扫描提交失败'); }
      const { scan_id } = await r.json();

      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const sr = await fetch(`${API_BASE}/api/v0/scan/${scan_id}`);
        const data = await sr.json();
        setStatusMsg(`扫描中... (${data.status})`);

        if (data.status === 'complete') {
          let meta: PackageMetadata | null = null;
          try {
            const mr = await fetch(`${API_BASE}/api/v0/scan/${scan_id}/metadata`);
            if (mr.ok) { const md = await mr.json(); meta = md.metadata; }
          } catch { /* ignore */ }

          setScanResult(data);
          setMetadata(meta);

          const nameV = meta?.name || '';
          const verV = meta?.version || '';
          const descV = meta?.description || '';
          const licV = meta?.license || '';
          const typeV = meta?.type || 'skill';
          const srcV = (meta?.source && typeof meta.source === 'object'
            ? String((meta.source as Record<string, unknown>).repository_url || '') : '');
          const auth = (meta?.author && typeof meta.author === 'object'
            ? meta.author as { name?: string; email?: string } : null);
          const catV = meta?.category || '';
          const hpV = meta?.homepage || '';
          const kwV = meta?.keywords?.join(', ') || '';
          const cmV = meta?.compatibility?.join(', ') || '';

          setPkgName(nameV);
          setPkgVersion(verV);
          setPkgDescription(descV);
          setPkgLicense(licV);
          setPkgType(typeV === 'mcp_server' ? 'mcp_server' : typeV === 'plugin' ? 'plugin' : typeV === 'command' ? 'command' : typeV === 'prompt' ? 'prompt' : 'skill');
          setPkgSourceUrl(srcV);
          setPkgAuthorName(auth?.name || '');
          setPkgAuthorEmail(auth?.email || '');
          setPkgCategory(catV);
          setPkgHomepage(hpV);
          setPkgKeywords(kwV);
          setPkgCompatibility(cmV);

          const fs: Record<string, string> = {};
          fs['name'] = isPlaceholderStr(nameV) ? 'manual' : 'auto';
          fs['version'] = isPlaceholderStr(verV) ? 'manual' : 'auto';
          fs['description'] = isPlaceholderStr(descV) ? 'manual' : 'auto';
          fs['license'] = isPlaceholderStr(licV) ? 'manual' : 'auto';
          fs['source.repository_url'] = isPlaceholderStr(srcV) ? 'manual' : 'auto';
          fs['type'] = 'auto';
          if (auth?.name) fs['author.name'] = isPlaceholderStr(auth.name) ? 'manual' : 'auto';
          if (auth?.email) fs['author.email'] = isPlaceholderStr(auth.email) ? 'manual' : 'auto';
          if (catV) fs['category'] = 'auto';
          if (hpV) fs['homepage'] = 'auto';
          if (kwV) fs['keywords'] = 'auto';
          if (cmV) fs['compatibility'] = 'auto';
          setFieldSource(fs);

          setPhase('confirm');
          return;
        }
        if (data.status === 'error') throw new Error(data.error || '扫描失败');
      }
      throw new Error('扫描超时，请重试');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '扫描失败');
      setPhase('input');
    }
  };

  /* ── 提交 ── */
  const handleSubmit = async () => {
    if (!token) { setError('请先登录'); return; }
    if (!pkgName.trim()) { setError('请输入包名称'); return; }
    if (!pkgSourceUrl.trim() || !pkgSourceUrl.trim().startsWith('https://')) {
      setError('请输入有效的源码仓库地址'); return;
    }
    if (!pkgLicense.trim() || pkgLicense === 'UNLICENSED') {
      setError('请选择有效的许可证'); return;
    }
    setError('');
    setPhase('submitting');

    const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
    const fs = { ...fieldSource };

    try {
      const meta = metadata || {} as PackageMetadata;
      const version = pkgVersion && SEMVER_RE.test(pkgVersion) ? pkgVersion : '0.1.0';
      const sUrl = pkgSourceUrl.trim();

      const sourceObj: Record<string, unknown> = {
        type: 'github', repository_url: sUrl, ref: 'main', commit_hash: '0'.repeat(40),
      };
      if (meta.source && typeof meta.source === 'object') {
        const ms = meta.source as Record<string, unknown>;
        if (ms.commit_hash && String(ms.commit_hash).length === 40) sourceObj.commit_hash = ms.commit_hash;
        if (ms.ref && String(ms.ref) !== 'HEAD') sourceObj.ref = ms.ref;
        if (ms.ref_type) sourceObj.ref_type = ms.ref_type;
        if (ms.owner && ms.owner !== 'unknown') sourceObj.owner = ms.owner;
        if (ms.repo && ms.repo !== 'unknown') sourceObj.repo = ms.repo;
      }
      sourceObj.repository_url = sUrl;

      const authorObj = { name: pkgAuthorName.trim() || 'unknown', email: pkgAuthorEmail.trim() || 'unknown@unknown.org' };
      const compatList = pkgCompatibility ? pkgCompatibility.split(',').map(s => s.trim()).filter(Boolean) : meta.compatibility || [];
      const kwList = pkgKeywords ? pkgKeywords.split(',').map(s => s.trim()).filter(Boolean) : meta.keywords || [];

      const pkgBody: Record<string, unknown> = {
        name: pkgName.trim(), type: pkgType, description: pkgDescription.trim() || pkgName.trim(),
        license: pkgLicense.trim(), keywords: kwList, category: pkgCategory.trim() || meta.category || 'other',
        homepage: pkgHomepage.trim() || meta.homepage || null, author: authorObj,
        permissions: (meta.permissions && typeof meta.permissions === 'object' ? meta.permissions : {}),
        compatibility: compatList, installation: meta.installation, source: sourceObj,
        field_source: fs,
      };

      const pkgRes = await fetch(`${API_BASE}/api/v0/producer/packages`, { method: 'POST', headers, body: JSON.stringify(pkgBody) });
      if (!pkgRes.ok) { const e = await pkgRes.json().catch(() => ({ detail: '创建包失败' })); throw new Error(e.detail || `创建包失败 (${pkgRes.status})`); }
      const pkgData = await pkgRes.json();
      const packageId: string = pkgData.id;

      const verBody: Record<string, unknown> = {
        version, repo_url: sUrl, description: pkgDescription.trim() || pkgName.trim(),
        source: sourceObj, field_source: fs,
      };
      const verRes = await fetch(`${API_BASE}/api/v0/producer/packages/${packageId}/versions`, { method: 'POST', headers, body: JSON.stringify(verBody) });
      if (!verRes.ok) { const e = await verRes.json().catch(() => ({ detail: '创建版本失败' })); throw new Error(e.detail || `创建版本失败 (${verRes.status})`); }
      const verData = await verRes.json();
      const versionId: string = verData.id;

      const subRes = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
        method: 'POST', headers,
        body: JSON.stringify({ initial_scan_id: scanResult?.scan_id || '' }),
      });
      if (!subRes.ok) { const e = await subRes.json().catch(() => ({ detail: '提交审核失败' })); throw new Error(e.detail || `提交审核失败 (${subRes.status})`); }

      setPhase('done');
      setTimeout(() => {
        router.push(`/packages/${encodeURIComponent(pkgName.trim())}/versions/${encodeURIComponent(version)}/status?vid=${encodeURIComponent(versionId)}`);
      }, 1000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '提交失败，请重试');
      setPhase('confirm');
    }
  };

  /* ── 辅助函数 ── */
  const isAuto = (field: string) => fieldSource[field] === 'auto';

  const badge = (variant: 'auto' | 'manual'): React.CSSProperties => {
    if (variant === 'auto') return {
      display: 'inline-flex', alignItems: 'center', padding: '0.1rem 0.45rem',
      borderRadius: 'var(--radius-pill)', fontSize: '0.68rem', fontWeight: 700,
      background: 'oklch(92% 0.03 140)', color: 'oklch(45% 0.10 140)', whiteSpace: 'nowrap',
    };
    return {
      display: 'inline-flex', alignItems: 'center', padding: '0.1rem 0.45rem',
      borderRadius: 'var(--radius-pill)', fontSize: '0.68rem', fontWeight: 700,
      background: 'oklch(94% 0.04 85)', color: 'oklch(55% 0.14 85)', whiteSpace: 'nowrap',
    };
  };

  const sectionStyle: React.CSSProperties = {
    background: 'var(--color-paper)', borderRadius: 'var(--radius-lg)',
    border: '1px solid var(--color-rule)', padding: '1.5rem', marginBottom: '1.25rem',
  };

  const fieldStyle: React.CSSProperties = { display: 'flex', flexDirection: 'column', gap: '0.3rem', marginBottom: '1rem' };
  const lbl: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.88rem', fontWeight: 600, color: 'var(--color-ink)' };
  const inp: React.CSSProperties = { padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-rule)', background: 'var(--color-paper)', color: 'var(--color-ink)', fontSize: '0.88rem', fontFamily: 'inherit', outline: 'none', width: '100%', boxSizing: 'border-box', transition: 'border-color 0.15s, box-shadow 0.15s' };
  const roInp: React.CSSProperties = { ...inp, background: 'var(--color-paper-3)', borderStyle: 'dashed', color: 'var(--color-muted)', cursor: 'not-allowed' };
  const hint: React.CSSProperties = { fontSize: '0.76rem', color: 'var(--color-muted)', lineHeight: 1.4 };
  const warnHint: React.CSSProperties = { ...hint, color: 'var(--color-warning)' };

  return (
    <div className="submit-page" style={{ paddingBottom: '80px' }}>
      <div className="submit-container">
        <div className="submit-header">
          <h1>提交 Agent 能力包</h1>
          <p>输入 GitHub 仓库地址或本地路径，系统自动扫描提取元数据。</p>
        </div>

        {error && <div className="submit-error">{error}</div>}

        {/* ══ Phase: 输入 ══ */}
        {phase === 'input' && (
          <form className="scanner-form" onSubmit={handleStartScan}>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <button type="button" className={`btn ${inputMode === 'github' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }} onClick={() => setInputMode('github')}>
                GitHub URL
              </button>
              <button type="button" className={`btn ${inputMode === 'local' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }} onClick={() => setInputMode('local')}>
                本地路径
              </button>
            </div>
            {inputMode === 'github' ? (
              <div className="scanner-input-row">
                <input type="url" className="scanner-url-input" placeholder="https://github.com/owner/repo" value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)} disabled={isBusy} required />
                <button type="submit" className="scanner-submit-btn" disabled={isBusy || !repoUrl.trim()}>开始扫描</button>
              </div>
            ) : (
              <div className="scanner-input-row">
                <input type="text" className="scanner-url-input" placeholder="E:\path\to\package" value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)} disabled={isBusy} required />
                <button type="submit" className="scanner-submit-btn" disabled={isBusy || !localPath.trim()}>开始扫描</button>
              </div>
            )}
            <p className="scanner-hint">
              {inputMode === 'github' ? '仅支持公开 GitHub 仓库，扫描完成后自动提取元数据。' : '输入本地 capability 包目录的绝对路径。'}
            </p>
          </form>
        )}

        {/* ══ Phase: 扫描中 ══ */}
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

        {/* ══ Phase: Submitting ══ */}
        {phase === 'submitting' && (
          <div className="scanner-status scanner-status-busy">
            <div className="scanner-spinner" />
            <div><p className="scanner-status-title">正在提交审核...</p><p className="scanner-status-msg">正在创建包信息和版本，请稍候</p></div>
          </div>
        )}

        {/* ══ Phase: Done ══ */}
        {phase === 'done' && (
          <div className="scanner-status" style={{ background: 'oklch(92% 0.03 140)', borderColor: 'oklch(72% 0.10 140)' }}>
            <div><p className="scanner-status-title" style={{ color: 'oklch(45% 0.10 140)' }}>提交成功</p>
              <p className="scanner-status-msg">正在跳转到审核状态页面...</p></div>
          </div>
        )}

        {/* ══ Phase: 确认 ══ */}
        {phase === 'confirm' && scanResult && (
          <>
            {/* 扫描摘要 */}
            <div style={sectionStyle}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' }}>
                <span style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-ink)' }}>{scanResult.package_name}</span>
                {scanResult.trust_score?.grade && (
                  <span className={`grade-badge ${scanResult.trust_score.grade.toLowerCase()}`}
                    style={{ padding: '0.12rem 0.5rem', fontSize: '0.78rem', fontWeight: 700 }}>
                    {scanResult.trust_score.grade}
                  </span>
                )}
              </div>
              {scanResult.summary && (
                <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.83rem', color: 'var(--color-neutral)' }}>
                  <span>发现问题: <strong>{scanResult.summary.total}</strong></span>
                  <span>
                    Critical: <strong style={{ color: scanResult.summary.critical > 0 ? 'var(--color-danger)' : 'inherit' }}>{scanResult.summary.critical}</strong>
                    {' · '}High: <strong>{scanResult.summary.high}</strong>
                    {' · '}Medium: <strong>{scanResult.summary.medium}</strong>
                    {' · '}Low: <strong>{scanResult.summary.low}</strong>
                  </span>
                </div>
              )}
            </div>

            {/* ── 必填字段 ── */}
            <div style={sectionStyle}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: '0 0 1rem 0', color: 'var(--color-ink)' }}>
                必填信息
              </h3>

              {/* 名称 */}
              <div style={fieldStyle}>
                <label style={lbl}>包名称 {isAuto('name') && <span style={badge('auto')}>自动识别</span>}</label>
                <input type="text" value={pkgName} onChange={(e) => { setPkgName(e.target.value); setFieldSource(p => ({ ...p, name: 'manual' })); }}
                  readOnly={isAuto('name')} disabled={isBusy}
                  style={isAuto('name') ? roInp : inp} />
                {isAuto('name') && <span style={hint}>来源: SKILL.md / manifest.json 自动提取，不可修改</span>}
                {!isAuto('name') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>

              {/* 类型 — 分段按钮组 */}
              <div style={fieldStyle}>
                <label style={lbl}>类型</label>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {PACKAGE_TYPES.map((t) => (
                    <button key={t.value} type="button" onClick={() => setPkgType(t.value)} disabled={isBusy}
                      style={{
                        padding: '0.4rem 0.8rem', borderRadius: 'var(--radius-pill)',
                        border: pkgType === t.value ? '2px solid var(--color-accent)' : '1px solid var(--color-rule)',
                        background: pkgType === t.value ? 'oklch(95% 0.04 95)' : 'var(--color-paper)',
                        color: pkgType === t.value ? 'var(--color-ink)' : 'var(--color-muted)',
                        fontWeight: pkgType === t.value ? 600 : 400, fontSize: '0.83rem',
                        fontFamily: 'inherit', cursor: isBusy ? 'not-allowed' : 'pointer',
                        transition: 'all 0.15s', outline: 'none',
                      }}>
                      {t.label}
                    </button>
                  ))}
                </div>
                <span style={hint}>根据代码结构自动推断，可手动修改</span>
              </div>

              {/* 版本号 */}
              <div style={fieldStyle}>
                <label style={lbl}>版本号 {isAuto('version') && <span style={badge('auto')}>自动识别</span>}</label>
                <input type="text" value={pkgVersion} onChange={(e) => { setPkgVersion(e.target.value); setFieldSource(p => ({ ...p, version: 'manual' })); }}
                  readOnly={isAuto('version')} disabled={isBusy} placeholder="0.1.0"
                  style={isAuto('version') ? roInp : inp} />
                <span style={hint}>格式: 主版本.次版本.修订版 (如 1.0.0)</span>
                {!isAuto('version') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>

              {/* 描述 */}
              <div style={fieldStyle}>
                <label style={lbl}>描述 {isAuto('description') && <span style={badge('auto')}>自动识别</span>}</label>
                <textarea rows={3} value={pkgDescription}
                  onChange={(e) => { setPkgDescription(e.target.value); setFieldSource(p => ({ ...p, description: 'manual' })); }}
                  readOnly={isAuto('description')} disabled={isBusy}
                  style={{ ...(isAuto('description') ? roInp : inp), resize: 'vertical', minHeight: '3.5rem', fontFamily: 'inherit' }} />
                {isAuto('description') && <span style={hint}>来源: SKILL.md 自动提取</span>}
                {!isAuto('description') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>

              {/* 许可证 */}
              <div style={fieldStyle}>
                <label style={lbl}>许可证 {isAuto('license') && <span style={badge('auto')}>自动识别</span>}
                  {!isAuto('license') && <span style={{ color: 'var(--color-danger)', fontSize: '0.72rem', fontWeight: 400 }}>*必填</span>}
                </label>
                {isAuto('license') ? (
                  <input type="text" value={pkgLicense} readOnly disabled style={roInp} />
                ) : (
                  <select value={pkgLicense} onChange={(e) => { setPkgLicense(e.target.value); setFieldSource(p => ({ ...p, license: 'manual' })); }}
                    disabled={isBusy}
                    style={{
                      ...inp, cursor: 'pointer', appearance: 'none',
                      backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5l3 3 3-3' stroke='%238B7B6B' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E")`,
                      backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.75rem center', paddingRight: '2rem',
                    }}>
                    <option value="">-- 请选择许可证 --</option>
                    {SPDX_LICENSES.map((l) => (
                      <option key={l.value} value={l.value}>{l.label}</option>
                    ))}
                  </select>
                )}
                {!isAuto('license') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户选择</span>}
              </div>

              {/* 源码地址 */}
              <div style={fieldStyle}>
                <label style={lbl}>源码地址
                  {isAuto('source.repository_url') && <span style={badge('auto')}>自动识别</span>}
                  <span style={{ color: 'var(--color-danger)', fontSize: '0.72rem', fontWeight: 400, marginLeft: '0.2rem' }}>*必填</span>
                </label>
                <input type="url" value={pkgSourceUrl}
                  onChange={(e) => { setPkgSourceUrl(e.target.value); setFieldSource(p => ({ ...p, 'source.repository_url': 'manual' })); }}
                  disabled={isBusy} placeholder="https://github.com/owner/repo"
                  style={isAuto('source.repository_url') ? roInp : inp} />
                {inputMode === 'local' && !isAuto('source.repository_url') && (
                  <span style={warnHint}>本地路径扫描无法自动获取 GitHub 地址，请手动填写</span>
                )}
                {!isAuto('source.repository_url') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>
            </div>

            {/* ── 选填字段（可折叠） ── */}
            <details style={{ ...sectionStyle, cursor: 'pointer' }}>
              <summary style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--color-ink)', outline: 'none' }}>
                选填信息（展开编辑）
              </summary>
              <div style={{ marginTop: '1rem' }}>
                {/* 作者 */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
                  <div style={fieldStyle}>
                    <label style={lbl}>作者名称</label>
                    <input type="text" value={pkgAuthorName} onChange={(e) => setPkgAuthorName(e.target.value)}
                      disabled={isBusy} placeholder="unknown" style={inp} />
                  </div>
                  <div style={fieldStyle}>
                    <label style={lbl}>作者邮箱</label>
                    <input type="email" value={pkgAuthorEmail} onChange={(e) => setPkgAuthorEmail(e.target.value)}
                      disabled={isBusy} placeholder="unknown@unknown.org" style={inp} />
                  </div>
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>分类</label>
                  <input type="text" value={pkgCategory} onChange={(e) => setPkgCategory(e.target.value)}
                    disabled={isBusy} placeholder="如 security, frontend, devops..." style={inp} />
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>项目主页</label>
                  <input type="url" value={pkgHomepage} onChange={(e) => setPkgHomepage(e.target.value)}
                    disabled={isBusy} placeholder="https://..." style={inp} />
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>关键词</label>
                  <input type="text" value={pkgKeywords} onChange={(e) => setPkgKeywords(e.target.value)}
                    disabled={isBusy} placeholder="逗号分隔: ai, design, landing" style={inp} />
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>兼容客户端</label>
                  <input type="text" value={pkgCompatibility} onChange={(e) => setPkgCompatibility(e.target.value)}
                    disabled={isBusy} placeholder="逗号分隔: claude-code, vscode" style={inp} />
                </div>

                {/* 原始元数据预览 */}
                {metadata && (
                  <details style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--color-muted)' }}>
                      查看原始提取元数据 ({Object.keys(metadata).length} 项) ...
                    </summary>
                    <pre style={{
                      fontSize: '0.68rem', background: 'var(--color-paper-2)', padding: '0.75rem',
                      borderRadius: 'var(--radius-md)', maxHeight: '180px', overflow: 'auto',
                      marginTop: '0.5rem', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap',
                    }}>
                      {JSON.stringify(metadata, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            </details>
          </>
        )}

        {/* ══ Sticky 底部操作栏 ══ */}
        {phase === 'confirm' && scanResult && (
          <div style={{
            position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 100,
            background: 'var(--color-paper)', borderTop: '1px solid var(--color-rule)',
            padding: '0.85rem 2rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            boxShadow: '0 -4px 20px oklch(0% 0 0 / 0.06)',
          }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: 'var(--color-ink)', cursor: 'pointer' }}>
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)}
                disabled={isBusy}
                style={{ width: '0.95rem', height: '0.95rem', cursor: 'pointer', accentColor: 'var(--color-accent)' }} />
              我已确认以上信息正确，提交审核
            </label>
            <div style={{ display: 'flex', gap: '0.6rem' }}>
              <button type="button" className="btn btn-secondary"
                onClick={() => { setPhase('input'); setScanResult(null); setMetadata(null); setFieldSource({}); }}
                disabled={isBusy}>
                重新扫描
              </button>
              <button type="button" className="btn btn-primary btn-lg" onClick={handleSubmit}
                disabled={isBusy || !confirmed || !pkgName.trim() || !pkgSourceUrl.trim() || !pkgLicense.trim() || pkgLicense === 'UNLICENSED'}>
                提交审核
              </button>
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
