'use client';

import { useRef, useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch, authFetch } from '@/lib/api-fetch';
import {
  formatScanStatusMessage,
  isScanTerminalFailure,
  scanPollDelayMs,
  scanPollIntervalMs,
  SCAN_FRONTEND_WAIT_MS,
  type ScanStatusPayload,
} from '@/lib/scan-polling';
import {
  clearPendingScanState,
  readPendingScanState,
  type PendingScanState,
  writePendingScanState,
} from '@/lib/pending-scan';
import {
  clearPendingSubmitContext,
  patchPendingSubmitContext,
  pendingSubmitNeedsConfirmation,
  readPendingSubmitContext,
  writePendingSubmitContext,
} from '@/lib/pending-submit';
import {
  forgetScanPackageContext,
  readScanPackageContext,
  rememberScanPackageContext,
} from '@/lib/scan-package-context';
import {
  CLIENT_LABELS,
  PACKAGE_TYPE_INSTALL_CLIENTS,
} from '../../../../../packages/schema/constants';
import {
  canonicalComparisonUrl,
  distinctProjectHomepage,
  getAllowedSubmissionClients,
  inferGithubOwnerHomepage,
  isHttpsUrl,
  normalizeSubmissionClients,
  redactAuthorEmailForPreview,
} from '@/lib/submission-metadata';

import { API_BASE } from '@/lib/runtime-config';

const PACKAGE_TYPES = [
  { value: 'skill', label: 'Skill' },
  { value: 'mcp_server', label: 'MCP Server' },
  { value: 'plugin', label: 'Plugin' },
  { value: 'subagent', label: 'Subagent' },
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
  { value: 'OTHER', label: '其他' },
];

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$/;

const TYPE_CONFIG_KEYS = [
  'skill_config',
  'mcp_server_config',
  'plugin_config',
  'subagent_config',
] as const;

function buildTypeConfig(meta: PackageMetadata): Record<string, unknown> | null {
  const entries = TYPE_CONFIG_KEYS
    .map((key) => [key, meta[key]] as const)
    .filter(([, value]) => value !== undefined && value !== null);
  return entries.length > 0 ? Object.fromEntries(entries) : null;
}

function createClientRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `web-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

type ScanResult = ScanStatusPayload;

interface PackageMetadata {
  name: string;
  version: string;
  description: string;
  type: string;
  license: string;
  author?: { name?: string; email?: string; url?: string };
  keywords?: string[];
  use_cases?: Array<{ title: string; description: string }>;
  category?: string;
  homepage?: string | null;
  compatibility?: string[];
  permissions?: Record<string, unknown>;
  skill_config?: Record<string, unknown>;
  mcp_server_config?: Record<string, unknown>;
  plugin_config?: Record<string, unknown>;
  subagent_config?: Record<string, unknown>;
  source?: Record<string, unknown>;
  integrity?: Record<string, unknown>;
  installation?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
}

type ScanPhase = 'input' | 'scanning' | 'background' | 'confirm' | 'submitting' | 'done';

class TerminalScanError extends Error {}

class ResumeAccessError extends Error {}

class ScanStatusHttpError extends Error {
  readonly httpStatus: number;

  constructor(message: string, httpStatus: number) {
    super(message);
    this.httpStatus = httpStatus;
  }
}

interface ScanConflictDetail {
  message: string;
  conflict_scan_id: string;
  lifecycle: string;
  delete_allowed: boolean;
}

function parseScanConflictDetail(raw: unknown): ScanConflictDetail | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const d = raw as Record<string, unknown>;
  if (typeof d.conflict_scan_id !== 'string' || !d.conflict_scan_id) return null;
  return {
    message:
      typeof d.message === 'string' && d.message
        ? d.message
        : '该源码已有扫描任务，不允许重复扫描',
    conflict_scan_id: d.conflict_scan_id,
    lifecycle: typeof d.lifecycle === 'string' ? d.lifecycle : 'unknown',
    delete_allowed: d.delete_allowed === true,
  };
}

/** Extract the error message from a submission response body, keeping the
 * structured scan-conflict detail (dict) readable instead of "[object Object]". */
function submissionErrorMessage(detail: unknown, fallback: string): ScanConflictDetail {
  return parseScanConflictDetail(detail) ?? {
    message: typeof detail === 'string' && detail ? detail : fallback,
    conflict_scan_id: '',
    lifecycle: 'unknown',
    delete_allowed: false,
  };
}

function isPlaceholderStr(v: string | undefined | null): boolean {
  if (!v || v.trim() === '') return true;
  const normalized = v.trim().toLowerCase();
  if (normalized === 'unknown' || normalized === 'unknown@unknown.org' || normalized === 'unknown@unknown.com' || normalized === 'unlicensed') return true;
  if (normalized.includes('github.com/unknown/')) return true;
  return false;
}

function isReusableCommitHash(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const commitHash = value.trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(commitHash) && !/^0{40}$/.test(commitHash);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function pendingScanMatchesDraft(
  pending: PendingScanState | null,
  packageId: string,
  repositoryUrl: string,
): boolean {
  if (!pending) return false;
  if (pending.scanId && packageId) {
    const boundPackageId = readScanPackageContext(pending.scanId);
    if (boundPackageId && boundPackageId !== packageId) return false;
  }
  if (pending.repoUrl && repositoryUrl) {
    if (
      canonicalComparisonUrl(pending.repoUrl)
      !== canonicalComparisonUrl(repositoryUrl)
    ) return false;
  }
  return true;
}

function SubmitForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { token } = useAuth();
  const { t } = useTranslation();
  const packageId = searchParams.get('packageId') || '';
  const isNewVersion = !!packageId;
  const urlScanParam = (searchParams.get('scan') || '').trim();

  const [repoUrl, setRepoUrl] = useState('');
  const [phase, setPhase] = useState<ScanPhase>('input');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [metadata, setMetadata] = useState<PackageMetadata | null>(null);
  const [capabilities, setCapabilities] = useState<
    { path: string; name: string; type: string }[]
  >([]);
  const [selectedCapability, setSelectedCapability] = useState('');
  const [scanBase, setScanBase] = useState('');
  const [scanRef, setScanRef] = useState('');

  const [pkgName, setPkgName] = useState('');
  const [pkgType, setPkgType] = useState('skill');
  const [pkgVersion, setPkgVersion] = useState('');
  const [pkgDescription, setPkgDescription] = useState('');
  const [pkgLicense, setPkgLicense] = useState('');
  const [pkgSourceUrl, setPkgSourceUrl] = useState('');
  const [pkgAuthorUrl, setPkgAuthorUrl] = useState('');
  const [pkgCategory, setPkgCategory] = useState('');
  const [pkgHomepage, setPkgHomepage] = useState('');
  const [pkgCompatibility, setPkgCompatibility] = useState<string[]>(
    () => [...PACKAGE_TYPE_INSTALL_CLIENTS.skill],
  );
  const [pkgKeywords, setPkgKeywords] = useState('');

  const [error, setError] = useState('');
  const [conflict, setConflict] = useState<ScanConflictDetail | null>(null);
  const [conflictBusy, setConflictBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [activeScanId, setActiveScanId] = useState('');
  const [scanTerminal, setScanTerminal] = useState(false);
  const [checkingBackground, setCheckingBackground] = useState(false);
  const [checkingResume, setCheckingResume] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [fieldSource, setFieldSource] = useState<Record<string, string>>({});

  const isBusy = phase === 'scanning' || phase === 'submitting' || checkingResume;

  const [resumeNotice, setResumeNotice] = useState('');
  const [resumeNeedsDecision, setResumeNeedsDecision] = useState(false);
  const [resumePromptPackageId, setResumePromptPackageId] = useState('');
  const [resumeGateOpen, setResumeGateOpen] = useState(false);
  const [restoredDraft, setRestoredDraft] = useState(false);
  const preserveRestoredDraftRef = useRef(false);

  useEffect(() => {
    if (!token) {
      setCheckingResume(false);
      return;
    }
    let cancelled = false;
    setCheckingResume(true);

    const prefillNewVersion = async () => {
      if (!isNewVersion) return;
      try {
        const pkg = await apiFetch<{
          name: string;
          type: string;
          description: string;
          license: string;
        }>(
          `${API_BASE}/api/v0/producer/packages/${packageId}`,
          { headers: { Authorization: `Bearer ${token}` } },
        );
        if (cancelled) return;
        setPkgName(pkg.name || '');
        if (pkg.type) setPkgType(pkg.type);
        if (pkg.description) setPkgDescription(pkg.description);
        if (pkg.license) setPkgLicense(pkg.license);
        setFieldSource((prev) => ({ ...prev, name: 'auto', type: 'auto' }));
      } catch {}
    };

    const context = readPendingSubmitContext();
    const hasScanToRecover = () => Boolean(readPendingScanState() || urlScanParam);
    if (!context) {
      setResumeNotice('');
      setResumeNeedsDecision(false);
      setResumeGateOpen(true);
      setCheckingResume(false);
      if (!hasScanToRecover()) void prefillNewVersion();
      return () => { cancelled = true; };
    }

    const submissionLabel = `“${context.packageName} ${context.version}”`;
    const targetPackageId = isNewVersion ? packageId : null;
    if (pendingSubmitNeedsConfirmation(context, targetPackageId)) {
      setResumePromptPackageId(context.packageId ?? '');
      setResumeNeedsDecision(true);
      setResumeGateOpen(false);
      setPhase('input');
      setCheckingResume(false);
      setResumeNotice(
        `检测到${submissionLabel}的未完成提交，但它与当前提交目标不一致。请选择前往该提交或忽略这条恢复记录。`,
      );
      return () => { cancelled = true; };
    }
    setResumePromptPackageId('');
    setResumeNeedsDecision(false);
    setResumeNotice(`正在检查${submissionLabel}的恢复状态…`);

    const fetchVersion = async (): Promise<Record<string, unknown> | null> => {
      const res = await authFetch(
        `${API_BASE}/api/v0/producer/versions/${encodeURIComponent(context.versionId!)}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (res.status === 404) return null;
      if (res.status === 403) {
        throw new ResumeAccessError(
          '当前账号无权访问上次未完成的提交；请切换回原账号，或清除本地恢复记录。',
        );
      }
      if (!res.ok) throw new Error(`版本状态查询失败 (${res.status})`);
      return await res.json();
    };

    const resume = async () => {
      const DRAFT = 'draft';
      if (!context.versionId) {
        setResumeGateOpen(true);
        setResumeNotice(`${submissionLabel}在创建版本前中断，已保留恢复信息；请继续完成扫描和提交。`);
        if (!hasScanToRecover()) await prefillNewVersion();
        return;
      }
      let detail: Record<string, unknown> | null = null;
      try {
        detail = await fetchVersion();
      } catch (err: unknown) {
        if (!cancelled) {
          const accessDenied = err instanceof ResumeAccessError;
          setResumeGateOpen(!accessDenied);
          setError(
            err instanceof Error
              ? err.message
              : '上次提交状态查询失败，请手动重新提交',
          );
          setResumeNotice(`${submissionLabel}的本地恢复记录已保留。`);
          if (!accessDenied && !hasScanToRecover()) await prefillNewVersion();
        }
        return;
      }
      if (cancelled) return;

      if (detail === null) {
        clearPendingSubmitContext();
        setResumeNotice('');
        setResumeGateOpen(true);
        if (!hasScanToRecover()) await prefillNewVersion();
        return;
      }

      const packageIdV = String(detail.package_id ?? context.packageId ?? '');
      if (!packageIdV) {
        clearPendingSubmitContext();
        setResumeNotice('');
        setResumeGateOpen(true);
        if (!hasScanToRecover()) await prefillNewVersion();
        return;
      }
      if (isNewVersion && packageIdV !== packageId) {
        setResumePromptPackageId(packageIdV);
        setResumeNeedsDecision(true);
        setResumeGateOpen(false);
        setPhase('input');
        setResumeNotice(
          `${submissionLabel}实际属于另一个包。请选择前往该提交或忽略这条恢复记录。`,
        );
        return;
      }

      const status = String(detail.status ?? '');
      if (status !== DRAFT) {
        clearPendingSubmitContext();
        const pendingScan = readPendingScanState();
        const source = asRecord(detail.source);
        const repositoryUrl = String(source?.repository_url ?? '');
        if (pendingScanMatchesDraft(pendingScan, packageIdV, repositoryUrl)) {
          if (pendingScan?.scanId) {
            forgetScanPackageContext(pendingScan.scanId);
          }
          clearPendingScanState();
        }
        router.push(
          `/packages/${encodeURIComponent(context.packageName)}/versions/${encodeURIComponent(context.version)}/status?vid=${encodeURIComponent(context.versionId!)}`,
        );
        return;
      }

      let pkg: Record<string, unknown> | null = null;
      try {
        const pkgRes = await authFetch(
          `${API_BASE}/api/v0/producer/packages/${encodeURIComponent(packageIdV)}`,
          { headers: { Authorization: `Bearer ${token}` } },
        );
        if (pkgRes.ok) pkg = await pkgRes.json();
      } catch {
        pkg = null;
      }
      if (cancelled) return;
      if (!pkg) {
        setError('已找到上次创建的草稿版本，但包信息加载失败；请重新扫描后提交，同名草稿会自动续接。');
        return;
      }
      const source = (detail.source ?? {}) as Record<string, unknown>;
      const author = (detail.author ?? null) as { url?: string } | null;
      const typeConfig = asRecord(detail.type_config) ?? {};
      const restoredFieldSource: Record<string, string> = {};
      for (const [key, value] of Object.entries(asRecord(detail.field_source) ?? {})) {
        if (typeof value === 'string') restoredFieldSource[key] = value;
      }
      const typeV = PACKAGE_TYPES.some((item) => item.value === pkg!.type)
        ? String(pkg.type) : 'skill';
      const keywords = Array.isArray(pkg.keywords)
        ? pkg.keywords.map(String) : [];
      const pendingScan = readPendingScanState();
      const repositoryUrl = String(source.repository_url ?? '');
      const recoverPendingScan = pendingScanMatchesDraft(
        pendingScan,
        packageIdV,
        repositoryUrl,
      );
      preserveRestoredDraftRef.current = recoverPendingScan;
      setRestoredDraft(true);
      setScanResult(null);
      setScanTerminal(false);
      setCapabilities([]);
      setSelectedCapability('');
      setMetadata({
        name: String(pkg.name ?? ''),
        version: String(detail.version ?? context.version),
        description: String(detail.description ?? pkg.description ?? ''),
        type: typeV,
        license: String(detail.license ?? pkg.license ?? ''),
        author: author ?? undefined,
        keywords,
        use_cases: Array.isArray(detail.use_cases)
          ? detail.use_cases as Array<{ title: string; description: string }>
          : undefined,
        category: String(pkg.category ?? ''),
        homepage: (pkg.homepage ?? null) as string | null,
        compatibility: Array.isArray(detail.compatibility)
          ? detail.compatibility.map(String) : [],
        permissions: (detail.permissions ?? {}) as Record<string, unknown>,
        source,
        integrity: (detail.integrity ?? undefined) as Record<string, unknown> | undefined,
        installation: (detail.installation ?? undefined) as Record<string, unknown> | undefined,
        dependencies: (detail.dependencies ?? undefined) as Record<string, unknown> | undefined,
        skill_config: asRecord(typeConfig.skill_config),
        mcp_server_config: asRecord(typeConfig.mcp_server_config),
        plugin_config: asRecord(typeConfig.plugin_config),
        subagent_config: asRecord(typeConfig.subagent_config),
      });
      setPkgName(String(pkg.name ?? context.packageName));
      setPkgType(typeV);
      setPkgVersion(String(detail.version ?? context.version));
      setPkgDescription(String(detail.description ?? pkg.description ?? ''));
      setPkgLicense(String(detail.license ?? pkg.license ?? ''));
      setPkgSourceUrl(String(source.repository_url ?? ''));
      setPkgAuthorUrl(author?.url ?? '');
      setPkgCategory(String(pkg.category ?? ''));
      setPkgHomepage(String(pkg.homepage ?? ''));
      setPkgKeywords(keywords.join(', '));
      setPkgCompatibility(normalizeSubmissionClients(typeV, Array.isArray(detail.compatibility) ? detail.compatibility.map(String) : undefined));
      setFieldSource({
        ...restoredFieldSource,
        name: 'manual',
        version: 'manual',
        description: 'manual',
        license: 'manual',
        type: 'manual',
      });
      setScanSourceFields(String(source.repository_url ?? ''));
      setActiveScanId('');
      setConfirmed(false);
      setResumeGateOpen(recoverPendingScan);
      setResumeNotice(
        recoverPendingScan
          ? `已恢复${submissionLabel}的草稿字段，正在重新关联原扫描结果；手动编辑内容将保留。`
          : pendingScan
            ? `已恢复${submissionLabel}的草稿字段；检测到另一提交的扫描任务，未将其关联。再次提交将重新扫描。`
            : `已恢复${submissionLabel}的草稿字段；当前没有可复用扫描结果，再次提交将重新扫描。`,
      );
      setPhase('confirm');
    };

    void resume().finally(() => {
      if (!cancelled) setCheckingResume(false);
    });
    return () => { cancelled = true; };
  }, [isNewVersion, packageId, router, token, urlScanParam]);

  const handleContinueResume = () => {
    setResumeNotice('正在打开上次未完成的提交…');
    router.replace(resumePromptPackageId
      ? `/submit?packageId=${encodeURIComponent(resumePromptPackageId)}`
      : '/submit');
  };

  const handleIgnoreMismatchedResume = () => {
    const pendingScan = readPendingScanState();
    const boundPackageId = pendingScan?.scanId
      ? readScanPackageContext(pendingScan.scanId)
      : null;
    const currentTargetPackageId = isNewVersion ? packageId : null;
    const belongsToCurrentTarget = Boolean(
      pendingScan?.scanId
      && boundPackageId
      && currentTargetPackageId
      && boundPackageId === currentTargetPackageId
    );
    if (pendingScan && !belongsToCurrentTarget) {
      if (pendingScan.scanId) forgetScanPackageContext(pendingScan.scanId);
      clearPendingScanState();
    }
    clearPendingSubmitContext();
    window.location.reload();
  };

  const handleClearLocalRecovery = () => {
    const pendingScan = readPendingScanState();
    if (pendingScan?.scanId) forgetScanPackageContext(pendingScan.scanId);
    clearPendingSubmitContext();
    clearPendingScanState();
    const nextUrl = new URL(window.location.href);
    nextUrl.searchParams.delete('scan');
    window.location.replace(nextUrl.toString());
  };

  /* ── 扫描 ── */
  const fetchScanStatus = async (scanId: string): Promise<ScanStatusPayload> => {
    const response = await authFetch(`${API_BASE}/api/v0/scan/${scanId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new ScanStatusHttpError(
        body.detail || `扫描状态查询失败 (${response.status})`,
        response.status,
      );
    }
    return response.json();
  };

  const setScanSourceFields = (url: string): void => {
    const normalizedUrl = url.trim();
    // The backend resolves the real default branch and returns it as
    // source_ref; the regex here only captures an explicit /tree/<ref>
    // spelling. Branch names may contain slashes, so the subdirectory is
    // everything after the first tree segment.
    const m = normalizedUrl.match(
      /^https:\/\/github\.com\/([^/]+\/[^/]+?)(?:\/tree\/([^/]+)(?:\/(.*))?)?$/,
    );
    setScanBase(m ? `https://github.com/${m[1]}` : normalizedUrl.replace(/\/tree\/.*$/, ''));
    setScanRef(m?.[2] || '');
  };

  const submitScanRequest = async (
    url: string,
    clientRequestId: string,
  ): Promise<string> => {
    const normalizedUrl = url.trim();
    const r = await authFetch(`${API_BASE}/api/v0/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'Idempotency-Key': clientRequestId,
      },
      body: JSON.stringify({
        repo_url: normalizedUrl,
        client_request_id: clientRequestId,
      }),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      const conflictDetail = parseScanConflictDetail(e.detail);
      if (conflictDetail) {
        throw Object.assign(new Error(conflictDetail.message), {
          conflictDetail,
        });
      }
      throw new Error(
        typeof e.detail === 'string' && e.detail ? e.detail : '扫描提交失败',
      );
    }
    const payload = await r.json() as {
      scan_id?: unknown;
      client_request_id?: unknown;
    };
    if (typeof payload.scan_id !== 'string' || !payload.scan_id) {
      throw new Error('扫描提交响应缺少 scan_id');
    }
    const responseRequestId = typeof payload.client_request_id === 'string'
      && payload.client_request_id
      ? payload.client_request_id
      : clientRequestId;
    writePendingScanState({
      scanId: payload.scan_id,
      clientRequestId: responseRequestId,
      repoUrl: normalizedUrl,
    });
    if (isNewVersion && packageId) {
      rememberScanPackageContext(payload.scan_id, packageId);
    }
    setActiveScanId(payload.scan_id);
    return payload.scan_id;
  };

  const applyCompletedScan = async (
    scanId: string,
    data: ScanStatusPayload,
  ): Promise<void> => {
    let meta: PackageMetadata | null = null;
    let caps: { path: string; name: string; type: string }[] = [];
    try {
      const mr = await authFetch(`${API_BASE}/api/v0/scan/${scanId}/metadata`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (mr.ok) {
        const md = await mr.json();
        meta = md.metadata;
        caps = Array.isArray(md.capabilities) ? md.capabilities : [];
      }
    } catch { /* 元数据获取失败不影响扫描结果展示 */ }

    setScanResult(data);
    setScanTerminal(false);
    setCapabilities(caps);
    setSelectedCapability('');

    if (preserveRestoredDraftRef.current) {
      setRestoredDraft(false);
      setResumeNotice('已重新关联原扫描结果，并保留草稿中手动编辑的字段。');
      setPhase('confirm');
      return;
    }

    setRestoredDraft(false);
    setResumeNotice('');
    setMetadata(meta);

    const nameV = meta?.name || '';
    const verV = meta?.version || '';
    const descV = meta?.description || '';
    const rawLicense = meta?.license || '';
    const licV = isPlaceholderStr(rawLicense) ? '' : rawLicense;
    const typeV = meta?.type || 'skill';
    const normalizedType = PACKAGE_TYPES.some((item) => item.value === typeV)
      ? typeV
      : 'skill';
    const srcV = (meta?.source && typeof meta.source === 'object'
      ? String((meta.source as Record<string, unknown>).repository_url || '') : '');
    const auth = (meta?.author && typeof meta.author === 'object'
      ? meta.author as { name?: string; email?: string; url?: string } : null);
    const sourceOwner = (meta?.source && typeof meta.source === 'object'
      ? String((meta.source as Record<string, unknown>).owner || '') : '');
    const inferredAuthorUrl = inferGithubOwnerHomepage(srcV, sourceOwner);
    const scannedAuthorUrl = auth?.url?.trim() ?? '';
    const authorUrl = !isPlaceholderStr(scannedAuthorUrl) ? scannedAuthorUrl : inferredAuthorUrl;
    const catV = meta?.category || '';
    const hpV = distinctProjectHomepage(meta?.homepage, srcV);
    const kwV = meta?.keywords?.join(', ') || '';
    const cmV = normalizeSubmissionClients(normalizedType, meta?.compatibility);

    setPkgName(nameV);
    setPkgVersion(verV);
    setPkgDescription(descV);
    setPkgLicense(licV);
    setPkgType(normalizedType);
    setPkgSourceUrl(srcV);
    setPkgAuthorUrl(authorUrl);
    setPkgCategory(catV);
    setPkgHomepage(hpV);
    setPkgKeywords(kwV);
    setPkgCompatibility(cmV);

    const fs: Record<string, string> = {};
    fs.name = isPlaceholderStr(nameV) ? 'manual' : 'auto';
    fs.version = isPlaceholderStr(verV) ? 'manual' : 'auto';
    fs.description = isPlaceholderStr(descV) ? 'manual' : 'auto';
    fs.license = isPlaceholderStr(licV) ? 'manual' : 'auto';
    fs['source.repository_url'] = isPlaceholderStr(srcV) ? 'manual' : 'auto';
    fs.type = 'auto';
    if (authorUrl) {
      fs['author.url'] = inferredAuthorUrl
        && canonicalComparisonUrl(authorUrl) === canonicalComparisonUrl(inferredAuthorUrl)
        ? 'inferred'
        : 'auto';
    }
    if (catV) fs.category = 'auto';
    if (hpV) fs.homepage = 'auto';
    if (kwV) fs.keywords = 'auto';
    if (cmV.length > 0) fs.compatibility = 'auto';
    setFieldSource(fs);

    // The pending scan stays recorded until the submission succeeds so a
    // refresh on this confirmation form can restore the scanned state.
    setPhase('confirm');
  };

  const handlePolledStatus = async (
    scanId: string,
    data: ScanStatusPayload,
  ): Promise<boolean> => {
    setStatusMsg(formatScanStatusMessage(data));
    if (data.lifecycle === 'submitted_reviewing') {
      clearPendingScanState();
      setScanTerminal(true);
      setStatusMsg(t('scans.status.submitted_reviewing_hint'));
      setPhase('background');
      return true;
    }
    if (data.lifecycle === 'callback_pending') {
      // The scan finished but the submission callback has not been
      // persisted yet. Keep polling so the user sees the real terminal
      // state instead of a premature "submitted".
      setStatusMsg(t('scans.status.callback_pending_hint'));
      return false;
    }
    if (data.status === 'complete') {
      await applyCompletedScan(scanId, data);
      return true;
    }
    if (isScanTerminalFailure(data.status)) {
      setScanTerminal(true);
      throw new TerminalScanError(data.error || formatScanStatusMessage(data));
    }
    return false;
  };

  const pollScanUntilSettled = async (
    scanId: string,
    initial?: ScanStatusPayload,
  ): Promise<boolean> => {
    const pollingStartedAt = Date.now();
    let latest: ScanStatusPayload = initial || { scan_id: scanId, status: 'pending' };
    if (initial && await handlePolledStatus(scanId, initial)) return true;

    while (Date.now() - pollingStartedAt < SCAN_FRONTEND_WAIT_MS) {
      const remainingMs = SCAN_FRONTEND_WAIT_MS - (Date.now() - pollingStartedAt);
      // scanPollIntervalMs returns 0 for states its callers are expected
      // to have short-circuited; scanPollDelayMs clamps it so a missed
      // terminal-state check degrades to a slow poll, never a 0ms loop.
      const intervalMs = scanPollDelayMs(scanPollIntervalMs(latest), remainingMs);
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      latest = await fetchScanStatus(scanId);
      if (await handlePolledStatus(scanId, latest)) return true;
    }

    // The final query closes the race where the backend completes as the
    // frontend wait budget expires.
    latest = await fetchScanStatus(scanId);
    return handlePolledStatus(scanId, latest);
  };

  const runScan = async (url: string) => {
    preserveRestoredDraftRef.current = false;
    setRestoredDraft(false);
    setResumeNotice('');
    setError('');
    setActiveScanId('');
    setScanTerminal(false);
    const normalizedUrl = url.trim();
    const pending = readPendingScanState();
    const clientRequestId = pending
      && !pending.scanId
      && pending.repoUrl === normalizedUrl
      && pending.clientRequestId
      ? pending.clientRequestId
      : createClientRequestId();
    // Persist before POST /scan.  If the browser refreshes after the request
    // reaches the server but before its response arrives, the same key can
    // recover the existing task instead of creating a duplicate scan.
    writePendingScanState({
      scanId: null,
      clientRequestId,
      repoUrl: normalizedUrl,
    });
    setScanSourceFields(normalizedUrl);

    setPhase('scanning');
    setStatusMsg('正在提交扫描任务...');
    try {
      const scanId = await submitScanRequest(normalizedUrl, clientRequestId);
      if (await pollScanUntilSettled(scanId)) return;
      setStatusMsg('扫描仍在后台进行，您可以稍后刷新查看结果。');
      setPhase('background');
    } catch (err: unknown) {
      const conflictDetail = (
        err as { conflictDetail?: ScanConflictDetail | null } | null
      )?.conflictDetail;
      if (conflictDetail && conflictDetail.delete_allowed) {
        setConflict(conflictDetail);
      } else {
        setConflict(null);
      }
      setError(err instanceof Error ? err.message : '扫描失败');
      setPhase(err instanceof TerminalScanError ? 'background' : 'input');
    }
  };

  const handleDeleteConflictedTask = async () => {
    if (!conflict || conflictBusy) return;
    setConflictBusy(true);
    setError('');
    try {
      const r = await authFetch(
        `${API_BASE}/api/v0/scan/${conflict.conflict_scan_id}`,
        { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
      );
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        throw new Error(
          typeof e.detail === 'string' && e.detail
            ? e.detail
            : '删除旧扫描任务失败',
        );
      }
      const retryRequestId = createClientRequestId();
      writePendingScanState({
        scanId: null,
        clientRequestId: retryRequestId,
        repoUrl: repoUrl.trim(),
      });
      setConflict(null);
      setPhase('scanning');
      setStatusMsg('旧扫描任务已删除，正在重新提交扫描...');
      const scanId = await submitScanRequest(
        repoUrl.trim(),
        retryRequestId,
      );
      if (await pollScanUntilSettled(scanId)) return;
      setStatusMsg('扫描仍在后台进行，您可以稍后刷新查看结果。');
      setPhase('background');
    } catch (err: unknown) {
      const retryConflict = (
        err as { conflictDetail?: ScanConflictDetail | null } | null
      )?.conflictDetail;
      if (retryConflict && retryConflict.delete_allowed) {
        setConflict(retryConflict);
      } else {
        setConflict(null);
      }
      setError(err instanceof Error ? err.message : '删除旧扫描任务失败');
      setPhase('input');
    } finally {
      setConflictBusy(false);
    }
  };

  const checkBackgroundScan = async () => {
    if (!activeScanId || checkingBackground) return;
    setCheckingBackground(true);
    setError('');
    try {
      const latest = await fetchScanStatus(activeScanId);
      if (await handlePolledStatus(activeScanId, latest)) return;
      setStatusMsg('扫描仍在后台进行，您可以稍后刷新查看结果。');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '扫描状态查询失败');
      if (err instanceof TerminalScanError) setPhase('background');
    } finally {
      setCheckingBackground(false);
    }
  };

  // An explicit "continue submission" link (/submit?scan=<id>) hands a
  // completed scan back to this page from the scan list.  The parameter is
  // one-shot: it is stripped so later refreshes keep using the persisted
  // pending state instead of a stale URL value.
  useEffect(() => {
    if (!token || !urlScanParam) return;
    const existing = readPendingScanState();
    if (existing?.scanId !== urlScanParam) {
      writePendingScanState({
        scanId: urlScanParam,
        clientRequestId: '',
        repoUrl: '',
      });
    }
    const nextParams = new URLSearchParams(searchParams.toString());
    nextParams.delete('scan');
    const query = nextParams.toString();
    router.replace(query ? `/submit?${query}` : '/submit');
  }, [router, searchParams, token, urlScanParam]);

  useEffect(() => {
    if (!token || !resumeGateOpen) return;
    const pending = readPendingScanState();
    if (!pending) return;
    if (pending.repoUrl) {
      setRepoUrl(pending.repoUrl);
      setScanSourceFields(pending.repoUrl);
    }
    if (pending.scanId) setActiveScanId(pending.scanId);
    setStatusMsg('正在恢复扫描任务状态...');
    setPhase('background');

    let cancelled = false;
    const recover = async () => {
      try {
        let scanId = pending.scanId;
        if (!scanId) {
          if (!pending.repoUrl || !pending.clientRequestId) {
            throw new Error('无法恢复扫描请求，请重新发起扫描');
          }
          scanId = await submitScanRequest(pending.repoUrl, pending.clientRequestId);
        }
        if (cancelled) return;
        setActiveScanId(scanId);
        const settled = await pollScanUntilSettled(scanId);
        if (!settled && !cancelled) {
          setStatusMsg('扫描仍在后台进行，您可以稍后刷新查看结果。');
          setPhase('background');
        }
      } catch (err: unknown) {
        if (cancelled) return;
        const httpStatus = err instanceof ScanStatusHttpError ? err.httpStatus : null;
        if (httpStatus === 404 || httpStatus === 403) {
          clearPendingScanState();
          if (preserveRestoredDraftRef.current) {
            preserveRestoredDraftRef.current = false;
            setRestoredDraft(true);
            setResumeNotice(
              '草稿字段已恢复，但原扫描结果不可用；再次提交将重新扫描源码。',
            );
            setError(
              httpStatus === 404
                ? '原扫描任务不存在或已过期'
                : '当前账号无法访问原扫描任务',
            );
            setPhase('confirm');
            return;
          }
          setError(
            httpStatus === 404
              ? '扫描任务不存在或已过期，请重新扫描'
              : '无法访问该扫描任务，请重新扫描',
          );
          setPhase('input');
          return;
        }
        setError(err instanceof Error ? err.message : '扫描状态恢复失败');
        setPhase(err instanceof TerminalScanError ? 'background' : 'input');
      }
    };
    void recover();
    return () => { cancelled = true; };
  }, [resumeGateOpen, token]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (checkingResume) return;
    if (!repoUrl.trim() || !repoUrl.trim().startsWith('https://github.com/')) {
      setError('请输入有效的 GitHub 仓库地址'); return;
    }
    await runScan(repoUrl);
  };

  /* ── 提交 ── */
  const handleSubmit = async () => {
    if (!token) { setError('请先登录'); return; }
    if (!pkgName.trim()) { setError('请输入包名称'); return; }
    if (!pkgSourceUrl.trim() || !pkgSourceUrl.trim().startsWith('https://')) {
      setError('请输入有效的源码仓库地址'); return;
    }
    if (pkgAuthorUrl.trim() && !isHttpsUrl(pkgAuthorUrl)) {
      setError('请输入有效的 HTTPS 作者主页，例如 https://example.com/author'); return;
    }
    if (!pkgLicense.trim() || pkgLicense === 'UNLICENSED') {
      setError('请选择有效的许可证'); return;
    }
    if (pkgCompatibility.length === 0) {
      setError('请至少选择一个兼容客户端'); return;
    }
    setError('');
    setConflict(null);
    setPhase('submitting');

    const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
    const fs = { ...fieldSource };

    try {
      const meta = metadata || {} as PackageMetadata;
      const version = pkgVersion && SEMVER_RE.test(pkgVersion) ? pkgVersion : '0.1.0';
      const sUrl = pkgSourceUrl.trim();

      writePendingSubmitContext({
        packageId: packageId || null,
        versionId: null,
        packageName: pkgName.trim(),
        version,
      });

      const sourceObj: Record<string, unknown> = {
        type: 'github', repository_url: sUrl, ref: 'main', commit_hash: '0'.repeat(40),
      };
      if (meta.source && typeof meta.source === 'object') {
        const ms = meta.source as Record<string, unknown>;
        if (isReusableCommitHash(ms.commit_hash)) {
          sourceObj.commit_hash = ms.commit_hash.trim().toLowerCase();
        }
        if (ms.ref && String(ms.ref) !== 'HEAD') sourceObj.ref = ms.ref;
        if (ms.ref_type) sourceObj.ref_type = ms.ref_type;
        if (ms.owner && ms.owner !== 'unknown') sourceObj.owner = ms.owner;
        if (ms.repo && ms.repo !== 'unknown') sourceObj.repo = ms.repo;
        if (ms.subdirectory) sourceObj.subdirectory = ms.subdirectory;
      }
      sourceObj.repository_url = sUrl;
      const initialScanId = (
        scanResult?.status === 'complete'
        && scanResult.scan_id
        && isReusableCommitHash(sourceObj.commit_hash)
      ) ? scanResult.scan_id : undefined;
      const submitBody = initialScanId ? { initial_scan_id: initialScanId } : {};

      const clearSubmissionScanState = (submittedPackageId: string) => {
        const pending = readPendingScanState();
        if (!pending) return;
        const boundPackageId = pending.scanId
          ? readScanPackageContext(pending.scanId)
          : null;
        const matchesBoundPackage = !boundPackageId
          || boundPackageId === submittedPackageId;
        const matchesRepository = !pending.repoUrl
          || canonicalComparisonUrl(pending.repoUrl)
            === canonicalComparisonUrl(sUrl);
        const belongsToSubmission = Boolean(
          (initialScanId && pending.scanId === initialScanId)
          || ((boundPackageId || pending.repoUrl)
            && matchesBoundPackage
            && matchesRepository),
        );
        if (!belongsToSubmission) return;
        if (pending.scanId) forgetScanPackageContext(pending.scanId);
        clearPendingScanState();
      };

      const authorObj = pkgAuthorUrl.trim() ? { url: pkgAuthorUrl.trim() } : null;
      const compatList = normalizeSubmissionClients(pkgType, pkgCompatibility);
      const kwList = pkgKeywords ? pkgKeywords.split(',').map(s => s.trim()).filter(Boolean) : meta.keywords || [];
      const homepage = distinctProjectHomepage(pkgHomepage, sUrl);

      if (isNewVersion) {
        const verBody: Record<string, unknown> = {
          version, repo_url: sUrl, description: pkgDescription.trim() || pkgName.trim(),
          author: authorObj,
          license: pkgLicense.trim(),
          source: sourceObj,
          integrity: meta.integrity || null,
          permissions: (meta.permissions && typeof meta.permissions === 'object' ? meta.permissions : {}),
          use_cases: Array.isArray(meta.use_cases) ? meta.use_cases : null,
          type_config: buildTypeConfig(meta),
          compatibility: compatList,
          installation: meta.installation || null,
          dependencies: meta.dependencies || null,
          field_source: fs,
        };
        const verRes = await authFetch(`${API_BASE}/api/v0/producer/packages/${packageId}/versions`, { method: 'POST', headers, body: JSON.stringify(verBody) });
        if (!verRes.ok) { const e = await verRes.json().catch(() => ({ detail: '创建版本失败' })); throw new Error(submissionErrorMessage(e.detail, `创建版本失败 (${verRes.status})`).message); }
        const verData = await verRes.json();
        const versionId: string = verData.id;
        patchPendingSubmitContext({ versionId });
        const subRes = await authFetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
          method: 'POST', headers,
          body: JSON.stringify(submitBody),
        });
        if (!subRes.ok) {
          const e = await subRes.json().catch(() => ({ detail: '提交审核失败' }));
          const subConflict = parseScanConflictDetail(e.detail);
          if (subConflict) { setConflict(subConflict); setPhase('input'); }
          throw new Error(
            subConflict?.message ?? `提交审核失败 (${subRes.status})`,
          );
        }
        clearSubmissionScanState(packageId);
        clearPendingSubmitContext();
        if (initialScanId) forgetScanPackageContext(initialScanId);
        setResumeNotice('');
        setResumeNeedsDecision(false);
        setRestoredDraft(false);
        preserveRestoredDraftRef.current = false;
        setPhase('done');
        setTimeout(() => {
          router.push(`/packages/${encodeURIComponent(pkgName.trim())}/versions/${encodeURIComponent(version)}/status?vid=${encodeURIComponent(versionId)}`);
        }, 1000);
        return;
      }

      const pkgBody: Record<string, unknown> = {
        name: pkgName.trim(), type: pkgType, description: pkgDescription.trim() || pkgName.trim(),
        license: pkgLicense.trim(), keywords: kwList, category: pkgCategory.trim() || meta.category || 'other',
        homepage: homepage || null, author: authorObj,
        permissions: (meta.permissions && typeof meta.permissions === 'object' ? meta.permissions : {}),
        use_cases: Array.isArray(meta.use_cases) ? meta.use_cases : null,
        type_config: buildTypeConfig(meta),
        compatibility: compatList, installation: meta.installation, source: sourceObj,
        dependencies: meta.dependencies || null,
        field_source: fs,
      };

      const pkgRes = await authFetch(`${API_BASE}/api/v0/producer/packages`, { method: 'POST', headers, body: JSON.stringify(pkgBody) });
      if (!pkgRes.ok) { const e = await pkgRes.json().catch(() => ({ detail: '创建包失败' })); throw new Error(e.detail || `创建包失败 (${pkgRes.status})`); }
      const pkgData = await pkgRes.json();
      const createdPkgId: string = pkgData.id;
      patchPendingSubmitContext({ packageId: createdPkgId });

      const verBody: Record<string, unknown> = {
        version, repo_url: sUrl, description: pkgDescription.trim() || pkgName.trim(),
        author: authorObj,
        license: pkgLicense.trim(),
        source: sourceObj,
        integrity: meta.integrity || null,
        permissions: (meta.permissions && typeof meta.permissions === 'object' ? meta.permissions : {}),
        use_cases: Array.isArray(meta.use_cases) ? meta.use_cases : null,
        type_config: buildTypeConfig(meta),
        compatibility: compatList,
        installation: meta.installation || null,
        dependencies: meta.dependencies || null,
        field_source: fs,
      };
      const verRes = await authFetch(`${API_BASE}/api/v0/producer/packages/${createdPkgId}/versions`, { method: 'POST', headers, body: JSON.stringify(verBody) });
      if (!verRes.ok) { const e = await verRes.json().catch(() => ({ detail: '创建版本失败' })); throw new Error(submissionErrorMessage(e.detail, `创建版本失败 (${verRes.status})`).message); }
      const verData = await verRes.json();
      const versionId: string = verData.id;
      patchPendingSubmitContext({ versionId });

      const subRes = await authFetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
        method: 'POST', headers,
        body: JSON.stringify(submitBody),
      });
      if (!subRes.ok) {
        const e = await subRes.json().catch(() => ({ detail: '提交审核失败' }));
        const subConflict = parseScanConflictDetail(e.detail);
        if (subConflict) { setConflict(subConflict); setPhase('input'); }
        throw new Error(
          subConflict?.message ?? `提交审核失败 (${subRes.status})`,
        );
      }

      clearSubmissionScanState(createdPkgId);
      clearPendingSubmitContext();
      if (initialScanId) forgetScanPackageContext(initialScanId);
      setResumeNotice('');
      setResumeNeedsDecision(false);
      setRestoredDraft(false);
      preserveRestoredDraftRef.current = false;
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
  const isInferred = (field: string) => fieldSource[field] === 'inferred';

  const badge = (variant: 'auto' | 'inferred' | 'manual'): React.CSSProperties => {
    if (variant === 'auto') return {
      display: 'inline-flex', alignItems: 'center', padding: '0.1rem 0.45rem',
      borderRadius: 'var(--radius-pill)', fontSize: '0.68rem', fontWeight: 700,
      background: 'oklch(92% 0.03 140)', color: 'oklch(45% 0.10 140)', whiteSpace: 'nowrap',
    };
    if (variant === 'inferred') return {
      display: 'inline-flex', alignItems: 'center', padding: '0.1rem 0.45rem',
      borderRadius: 'var(--radius-pill)', fontSize: '0.68rem', fontWeight: 700,
      background: 'oklch(93% 0.04 230)', color: 'oklch(48% 0.11 230)', whiteSpace: 'nowrap',
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
  const availableClients = getAllowedSubmissionClients(pkgType);
  const showConfirmation = phase === 'confirm' && Boolean(scanResult || restoredDraft);

  return (
    <div className={`submit-page${showConfirmation ? ' submit-page--with-actions' : ''}`}>
      <div className="submit-container">
        <div className="submit-header">
          <h1>{isNewVersion ? '创建新版本' : '提交 Agent 能力包'}</h1>
          <p>{isNewVersion ? `为 ${pkgName || '已有包'} 创建新版本，输入 GitHub 仓库地址后扫描提交。` : '输入 GitHub 仓库地址，系统自动扫描提取元数据。'}</p>
        </div>

        {error && <div className="submit-error">{error}</div>}
        {resumeNotice && phase !== 'submitting' && phase !== 'done' && (
          <div className="submit-notice" role="status">
            <span>{resumeNotice}</span>
            <div className="submit-notice__actions">
              {resumeNeedsDecision && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleContinueResume}
                  disabled={isBusy}
                >
                  前往该提交
                </button>
              )}
              {resumeNeedsDecision ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleIgnoreMismatchedResume}
                  disabled={isBusy}
                >
                  忽略该记录
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleClearLocalRecovery}
                  disabled={isBusy}
                  title="仅清除本机恢复记录，服务端草稿仍会保留"
                >
                  清除本地记录（保留草稿）
                </button>
              )}
            </div>
          </div>
        )}
        {error && conflict?.delete_allowed && (
          <div style={{ marginTop: '0.5rem' }}>
            <button
              type="button"
              className="scanner-submit-btn"
              onClick={handleDeleteConflictedTask}
              disabled={conflictBusy}
            >
              {conflictBusy ? '正在删除旧任务...' : '删除旧任务并重试'}
            </button>
          </div>
        )}

        {/* ══ Phase: 输入 ══ */}
        {phase === 'input' && !resumeNeedsDecision && (
          <form className="scanner-form" onSubmit={handleStartScan}>
            <div className="scanner-input-row">
              <input type="url" className="scanner-url-input" placeholder="https://github.com/owner/repo" value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)} disabled={isBusy} required />
              <button type="submit" className="scanner-submit-btn" disabled={isBusy || !repoUrl.trim()}>开始扫描</button>
            </div>
            <p className="scanner-hint">
              仅支持公开 GitHub 仓库，扫描完成后自动提取元数据。
            </p>
          </form>
        )}

        {/* ══ Phase: 扫描中 ══ */}
        {phase === 'scanning' && (
          <div className="scanner-status scanner-status-busy">
            <div className="scanner-spinner" />
            <div>
              <p className="scanner-status-title">
                {statusMsg.includes('LLM') ? '正在进行 LLM 审查' : '正在扫描仓库'}
              </p>
              <p className="scanner-status-msg" style={{ whiteSpace: 'pre-line' }}>{statusMsg}</p>
              <p className="scanning-estimate">
                {statusMsg.includes('LLM')
                  ? 'LLM 审查最长 15 分钟，页面会自动降低轮询频率'
                  : '正在下载代码、执行静态扫描并自动提取元数据...'}
              </p>
            </div>
          </div>
        )}

        {/* ══ Phase: 后台继续 ══ */}
        {phase === 'background' && (
          <div className="scanner-status">
            <div>
              <p className="scanner-status-title">
                {scanTerminal ? '扫描任务已结束' : '扫描仍在后台进行'}
              </p>
              <p className="scanner-status-msg">{statusMsg}</p>
              <p className="scanning-estimate">扫描 ID：{activeScanId}</p>
              {scanTerminal ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => router.push('/scans')}
                  style={{ marginTop: '0.75rem' }}
                >
                  {t('scans.goto_management')}
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={checkBackgroundScan}
                  disabled={checkingBackground}
                  style={{ marginTop: '0.75rem' }}
                >
                  {checkingBackground ? '查询中...' : '刷新查看结果'}
                </button>
              )}
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
        {showConfirmation && (
          <>
            {/* 多能力仓库：选择要提交的子目录 */}
            {capabilities.length > 1 && (
              <div style={sectionStyle}>
                <p style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--color-warning)' }}>
                  仓库包含 {capabilities.length} 个能力，请选择要提交的子目录（选择后会重新扫描该目录）：
                </p>
                <select
                  value={selectedCapability}
                  onChange={(e) => {
                    const value = e.target.value;
                    setSelectedCapability(value);
                    if (value && scanBase) {
                      setPhase('scanning');
                      setStatusMsg(t('scans.scanning_subdirectory', { value }));
                      // Prefer the backend-resolved default branch over any
                      // local guess: source_ref comes from the completed
                      // scan's immutable source identity.
                      const resolvedRef = scanResult?.source_ref || scanRef;
                      runScan(
                        resolvedRef
                          ? `${scanBase}/tree/${resolvedRef}/${value}`
                          : `${scanBase}/${value}`,
                      );
                    }
                  }}
                  style={{
                    width: '100%',
                    padding: '0.5rem 0.75rem',
                    fontSize: '0.85rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--color-rule)',
                    background: 'var(--color-paper)',
                    color: 'var(--color-ink)',
                  }}
                >
                  <option value="">保持当前扫描（整个仓库）</option>
                  {capabilities.map((cap) => (
                    <option key={cap.path || '.'} value={cap.path}>
                      {cap.name}（{cap.type}）{cap.path ? ` — ${cap.path}` : ''}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* 扫描摘要 */}
            {scanResult ? (
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
                {(scanResult.llm_review?.status === 'timeout'
                  || scanResult.llm_review?.status === 'degraded'
                  || Boolean(scanResult.llm_review?.fallback)) && (
                  <div className="submit-error" style={{ marginTop: '0.9rem', marginBottom: 0 }}>
                    LLM 审查未能完成全部裁决；扫描结果已保存，未解决的问题需要人工审核。
                  </div>
                )}
              </div>
            ) : (
              <div style={sectionStyle}>
                <p className="scanner-status-title">已恢复草稿字段</p>
                <p className="scanner-status-msg">
                  当前没有可复用的扫描结果。提交审核后，系统会重新扫描源码，再进入审核流程。
                </p>
              </div>
            )}

            {/* ── 必填字段 ── */}
            <div style={sectionStyle}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: '0 0 1rem 0', color: 'var(--color-ink)' }}>
                必填信息
              </h3>

              {/* 名称 */}
              <div style={fieldStyle}>
                <label style={lbl}>包名称 {isAuto('name') || isNewVersion ? <span style={badge('auto')}>{isNewVersion ? '已有包' : '自动识别'}</span> : null}</label>
                <input type="text" value={pkgName} onChange={(e) => { setPkgName(e.target.value); setFieldSource(p => ({ ...p, name: 'manual' })); }}
                  readOnly={isAuto('name') || isNewVersion} disabled={isBusy}
                  style={(isAuto('name') || isNewVersion) ? roInp : inp} />
                {isAuto('name') && !isNewVersion && <span style={hint}>来源: SKILL.md / manifest.json 自动提取，不可修改</span>}
                {isNewVersion && <span style={hint}>为已有包创建新版本，包名称不可修改</span>}
                {!isAuto('name') && !isNewVersion && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>

              {/* 类型 — 分段按钮组 */}
              <div style={fieldStyle}>
                <label style={lbl}>类型</label>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {PACKAGE_TYPES.map((t) => (
                    <button key={t.value} type="button" onClick={() => {
                      setPkgType(t.value);
                      setPkgCompatibility((prev) => normalizeSubmissionClients(t.value, prev));
                      setFieldSource((prev) => ({
                        ...prev,
                        type: 'manual',
                        compatibility: 'manual',
                      }));
                    }} disabled={isBusy}
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
                <label style={lbl}>版本号 {!isNewVersion && isAuto('version') && <span style={badge('auto')}>自动识别</span>}</label>
                <input type="text" value={pkgVersion} onChange={(e) => { setPkgVersion(e.target.value); setFieldSource(p => ({ ...p, version: 'manual' })); }}
                  readOnly={!isNewVersion && isAuto('version')} disabled={isBusy} placeholder="0.1.0"
                  style={(!isNewVersion && isAuto('version')) ? roInp : inp} />
                <span style={hint}>格式: 主版本.次版本.修订版 (如 1.0.0){isNewVersion ? '，请填写新版本号' : ''}</span>
                {!isNewVersion && !isAuto('version') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
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
                  readOnly={isAuto('source.repository_url')} disabled={isBusy} placeholder="https://github.com/owner/repo"
                  style={isAuto('source.repository_url') ? roInp : inp} />
                {isAuto('source.repository_url') && <span style={hint}>源码地址与本次扫描内容绑定；如需更换，请使用“重新扫描”。</span>}
                {!isAuto('source.repository_url') && <span style={{ ...badge('manual'), marginTop: '0.25rem' }}>需用户补充</span>}
              </div>
            </div>

            {/* ── 选填字段（可折叠） ── */}
            <details style={{ ...sectionStyle, cursor: 'pointer' }}>
              <summary style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--color-ink)', outline: 'none' }}>
                选填信息（展开编辑）
              </summary>
              <div style={{ marginTop: '1rem' }}>
                {/* 作者主页 */}
                <div style={fieldStyle}>
                  <label style={lbl}>作者主页
                    {isInferred('author.url') && <span style={badge('inferred')}>自动推断</span>}
                    {isAuto('author.url') && <span style={badge('auto')}>自动识别</span>}
                  </label>
                  <input type="url" value={pkgAuthorUrl} onChange={(e) => {
                    setPkgAuthorUrl(e.target.value);
                    setFieldSource((prev) => ({ ...prev, 'author.url': 'manual' }));
                  }} disabled={isBusy} placeholder="https://example.com/author" style={inp} />
                  <span style={hint}>支持任意 HTTPS 个人或组织主页；自动推断值可以修改或清空。</span>
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>分类</label>
                  <input type="text" value={pkgCategory} onChange={(e) => setPkgCategory(e.target.value)}
                    disabled={isBusy} placeholder="如 security, frontend, devops..." style={inp} />
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>项目主页 / 文档</label>
                  <input type="url" value={pkgHomepage} onChange={(e) => {
                    setPkgHomepage(e.target.value);
                    setFieldSource((prev) => ({ ...prev, homepage: 'manual' }));
                  }}
                    disabled={isBusy} placeholder="https://..." style={inp} />
                  <span style={hint}>填写独立官网、文档、Demo 或产品介绍页；与源码地址相同的值不会保存。</span>
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>关键词</label>
                  <input type="text" value={pkgKeywords} onChange={(e) => setPkgKeywords(e.target.value)}
                    disabled={isBusy} placeholder="逗号分隔: ai, design, landing" style={inp} />
                </div>

                <div style={fieldStyle}>
                  <label style={lbl}>兼容客户端</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.55rem' }}>
                    {availableClients.map((client) => {
                      const checked = pkgCompatibility.includes(client);
                      return (
                        <label key={client} style={{
                          display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                          padding: '0.45rem 0.7rem', border: '1px solid var(--color-rule)',
                          borderRadius: 'var(--radius-sm)', background: checked ? 'oklch(95% 0.04 95)' : 'var(--color-paper)',
                          cursor: isBusy ? 'not-allowed' : 'pointer', fontSize: '0.84rem',
                        }}>
                          <input type="checkbox" checked={checked}
                            disabled={isBusy || (checked && pkgCompatibility.length === 1)}
                            onChange={(event) => {
                              setPkgCompatibility((previous) => event.target.checked
                                ? Array.from(new Set([...previous, client]))
                                : previous.filter((value) => value !== client));
                              setFieldSource((previous) => ({ ...previous, compatibility: 'manual' }));
                            }} />
                          {CLIENT_LABELS[client as keyof typeof CLIENT_LABELS] ?? client}
                        </label>
                      );
                    })}
                  </div>
                  <span style={hint}>
                    {pkgType === 'plugin'
                      ? 'Plugin 仅支持 Claude Code Plugin。'
                      : pkgType === 'skill'
                        ? 'Skill 可安装到 Claude Code、Cursor 或 Codex。'
                        : pkgType === 'mcp_server'
                          ? 'MCP Server 可安装到 Claude Code、Cursor 或 Codex。Codex 会把服务文件装入受管目录并通过 ~/.codex/config.toml 注册；存量包需重新上传并声明 Codex 兼容才会显示该选项。'
                        : '该类型仅支持安装到 Claude Code。'}
                    {' '}至少保留一个客户端。
                  </span>
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
                      {JSON.stringify(redactAuthorEmailForPreview(metadata as unknown as Record<string, unknown>), null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            </details>
          </>
        )}

        {/* ══ Sticky 底部操作栏 ══ */}
        {showConfirmation && (
          <div className="submit-sticky-actions">
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: 'var(--color-ink)', cursor: 'pointer' }}>
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)}
                disabled={isBusy}
                style={{ width: '0.95rem', height: '0.95rem', cursor: 'pointer', accentColor: 'var(--color-accent)' }} />
              我已确认以上信息正确，提交审核
            </label>
            <div style={{ display: 'flex', gap: '0.6rem' }}>
              <button type="button" className="btn btn-secondary"
                onClick={() => {
                  preserveRestoredDraftRef.current = false;
                  clearPendingScanState();
                  setRestoredDraft(false);
                  setResumeNotice('');
                  setPhase('input');
                  setScanResult(null);
                  setMetadata(null);
                  setFieldSource({});
                }}
                disabled={isBusy}>
                重新扫描
              </button>
              <button type="button" className="btn btn-primary btn-lg" onClick={handleSubmit}
                disabled={isBusy || !confirmed || !pkgName.trim() || !pkgSourceUrl.trim() || !pkgLicense.trim() || pkgLicense === 'UNLICENSED' || pkgCompatibility.length === 0}>
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
