'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const PACKAGE_TYPES = [
  { value: 'skill', label: 'Skill' },
  { value: 'mcp_server', label: 'MCP Server' },
  { value: 'plugin', label: 'Plugin' },
  { value: 'command', label: 'Command' },
  { value: 'prompt', label: 'Prompt' },
];

const CLIENTS = ['codewhale', 'cursor', 'claude', 'copilot', 'windsurf'];

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$/;

interface FormData {
  name: string;
  description: string;
  type: string;
  version: string;
  repoUrl: string;
  license: string;
  keywords: string;
  category: string;
  homepage: string;
  authorName: string;
  authorEmail: string;
  permissions: {
    filesystem: boolean;
    shell: boolean;
    network: boolean;
    environment: boolean;
    credentials: boolean;
  };
  compatibility: string[];
}

const INITIAL_FORM: FormData = {
  name: '',
  description: '',
  type: 'skill',
  version: '',
  repoUrl: '',
  license: '',
  keywords: '',
  category: '',
  homepage: '',
  authorName: '',
  authorEmail: '',
  permissions: {
    filesystem: false,
    shell: false,
    network: false,
    environment: false,
    credentials: false,
  },
  compatibility: [],
};

function SubmitForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { token } = useAuth();
  const [form, setForm] = useState<FormData>(() => {
    const repoUrl = searchParams.get('repo_url');
    if (repoUrl) return { ...INITIAL_FORM, repoUrl: decodeURIComponent(repoUrl) };
    return INITIAL_FORM;
  });
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [step, setStep] = useState<'form' | 'submitting'>('form');

  const updateField = (field: keyof FormData, value: unknown) => {
    setForm((prev) => ({ ...prev, [field]: value }));
    setError('');
  };

  const togglePermission = (key: keyof FormData['permissions']) => {
    setForm((prev) => ({
      ...prev,
      permissions: { ...prev.permissions, [key]: !prev.permissions[key] },
    }));
  };

  const toggleClient = (client: string) => {
    setForm((prev) => ({
      ...prev,
      compatibility: prev.compatibility.includes(client)
        ? prev.compatibility.filter((c) => c !== client)
        : [...prev.compatibility, client],
    }));
  };

  const validate = (): string | null => {
    if (!form.name.trim()) return '请输入包名称';
    if (!form.description.trim()) return '请输入包描述';
    if (!SEMVER_RE.test(form.version.trim())) return '版本号不符合 SemVer 规范（如 1.0.0）';
    if (!form.repoUrl.trim()) return '请输入 GitHub 仓库地址';
    if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+/.test(form.repoUrl.trim())) {
      return 'GitHub URL 格式不正确（应为 https://github.com/用户名/仓库名）';
    }
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    if (!token) {
      setError('请先登录');
      return;
    }

    setError('');
    setSubmitting(true);
    setStep('submitting');

    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };

    try {
      // Step 1: 创建包
      const pkgBody: Record<string, unknown> = {
        name: form.name.trim(),
        type: form.type,
        description: form.description.trim(),
      };
      if (form.license.trim()) pkgBody.license = form.license.trim();
      if (form.keywords.trim()) pkgBody.keywords = form.keywords.split(',').map((k) => k.trim()).filter(Boolean);
      if (form.category.trim()) pkgBody.category = form.category.trim();
      if (form.homepage.trim()) pkgBody.homepage = form.homepage.trim();
      if (form.authorName.trim() || form.authorEmail.trim()) {
        pkgBody.author = {
          name: form.authorName.trim() || '',
          email: form.authorEmail.trim() || '',
        };
      }

      // 权限声明
      const perm: Record<string, unknown> = {};
      if (form.permissions.filesystem) perm.filesystem = { read: ['workspace'], write: [], delete: false };
      if (form.permissions.shell) perm.shell = { allowed: true, commands: [], description: '需要 Shell 权限' };
      if (form.permissions.network) perm.network = { allowed: true, domains: [], description: '需要网络权限' };
      if (form.permissions.environment) perm.environment = { read: [], write: [] };
      if (form.permissions.credentials) perm.credentials = { access: [], description: '需要凭据访问权限' };
      if (Object.keys(perm).length > 0) pkgBody.permissions = perm;

      if (form.compatibility.length > 0) pkgBody.compatibility = form.compatibility;

      const pkgRes = await fetch(`${API_BASE}/api/v0/producer/packages`, {
        method: 'POST',
        headers,
        body: JSON.stringify(pkgBody),
      });

      if (!pkgRes.ok) {
        const err = await pkgRes.json().catch(() => ({ detail: '创建包失败' }));
        throw new Error(err.detail || `创建包失败 (${pkgRes.status})`);
      }

      const pkgData = await pkgRes.json();
      const packageId: string = pkgData.id;

      // Step 2: 创建版本
      const verBody: Record<string, unknown> = {
        version: form.version.trim(),
        repo_url: form.repoUrl.trim(),
      };
      if (form.description.trim()) verBody.description = form.description.trim();

      const verRes = await fetch(`${API_BASE}/api/v0/producer/packages/${packageId}/versions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(verBody),
      });

      if (!verRes.ok) {
        const err = await verRes.json().catch(() => ({ detail: '创建版本失败' }));
        throw new Error(err.detail || `创建版本失败 (${verRes.status})`);
      }

      const verData = await verRes.json();
      const versionId: string = verData.id;

      // Step 3: 提交审核
      const subRes = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/submit`, {
        method: 'POST',
        headers,
      });

      if (!subRes.ok) {
        const err = await subRes.json().catch(() => ({ detail: '提交审核失败' }));
        throw new Error(err.detail || `提交审核失败 (${subRes.status})`);
      }

      router.push(`/packages/${encodeURIComponent(form.name.trim())}/versions/${encodeURIComponent(form.version.trim())}/status?vid=${encodeURIComponent(versionId)}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '提交失败，请重试';
      setError(msg);
      setStep('form');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="submit-page">
      <div className="submit-container">
        <div className="submit-header">
          <h1>提交新 Skill</h1>
          <p>填写以下信息将您的 Skill 提交至平台审核。审核通过后将公开发布。</p>
        </div>

        {error && <div className="submit-error">{error}</div>}

        <form className="submit-form" onSubmit={handleSubmit}>
          {/* 基础信息 */}
          <fieldset className="form-section">
            <legend>基础信息</legend>

            <div className="form-row">
              <div className="form-field">
                <label htmlFor="name">包名称 *</label>
                <input
                  id="name"
                  type="text"
                  value={form.name}
                  onChange={(e) => updateField('name', e.target.value)}
                  placeholder="如 my-awesome-skill"
                  disabled={submitting}
                  required
                />
              </div>
              <div className="form-field">
                <label htmlFor="type">类型 *</label>
                <select
                  id="type"
                  value={form.type}
                  onChange={(e) => updateField('type', e.target.value)}
                  disabled={submitting}
                >
                  {PACKAGE_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="form-field">
              <label htmlFor="description">描述 *</label>
              <textarea
                id="description"
                value={form.description}
                onChange={(e) => updateField('description', e.target.value)}
                placeholder="简短描述您的 Skill 功能..."
                rows={3}
                disabled={submitting}
                required
              />
            </div>

            <div className="form-row form-row-3">
              <div className="form-field">
                <label htmlFor="version">版本号 *</label>
                <input
                  id="version"
                  type="text"
                  value={form.version}
                  onChange={(e) => updateField('version', e.target.value)}
                  placeholder="1.0.0"
                  disabled={submitting}
                  required
                />
                <span className="form-hint">SemVer 格式</span>
              </div>
              <div className="form-field">
                <label htmlFor="license">许可证</label>
                <input
                  id="license"
                  type="text"
                  value={form.license}
                  onChange={(e) => updateField('license', e.target.value)}
                  placeholder="MIT"
                  disabled={submitting}
                />
              </div>
              <div className="form-field">
                <label htmlFor="category">分类</label>
                <input
                  id="category"
                  type="text"
                  value={form.category}
                  onChange={(e) => updateField('category', e.target.value)}
                  placeholder="如 dev-tools"
                  disabled={submitting}
                />
              </div>
            </div>

            <div className="form-field">
              <label htmlFor="keywords">关键词</label>
              <input
                id="keywords"
                type="text"
                value={form.keywords}
                onChange={(e) => updateField('keywords', e.target.value)}
                placeholder="用逗号分隔，如 code-review, git, pr"
                disabled={submitting}
              />
            </div>

            <div className="form-field">
              <label htmlFor="homepage">主页</label>
              <input
                id="homepage"
                type="url"
                value={form.homepage}
                onChange={(e) => updateField('homepage', e.target.value)}
                placeholder="https://..."
                disabled={submitting}
              />
            </div>
          </fieldset>

          {/* 源码 */}
          <fieldset className="form-section">
            <legend>源码地址</legend>

            <div className="form-field">
              <label htmlFor="repoUrl">GitHub 仓库 *</label>
              <input
                id="repoUrl"
                type="url"
                value={form.repoUrl}
                onChange={(e) => updateField('repoUrl', e.target.value)}
                placeholder="https://github.com/用户名/仓库名"
                disabled={submitting}
                required
              />
            </div>

            <div className="form-row">
              <div className="form-field form-field-disabled">
                <label>npm 包名</label>
                <input type="text" placeholder="即将推出" disabled />
                <span className="form-hint form-hint-coming">开发中</span>
              </div>
              <div className="form-field form-field-disabled">
                <label>本地上传 ZIP</label>
                <input type="text" placeholder="即将推出" disabled />
                <span className="form-hint form-hint-coming">开发中</span>
              </div>
            </div>
          </fieldset>

          {/* 作者 */}
          <fieldset className="form-section">
            <legend>作者信息</legend>
            <div className="form-row">
              <div className="form-field">
                <label htmlFor="authorName">作者名</label>
                <input
                  id="authorName"
                  type="text"
                  value={form.authorName}
                  onChange={(e) => updateField('authorName', e.target.value)}
                  placeholder="您的名字"
                  disabled={submitting}
                />
              </div>
              <div className="form-field">
                <label htmlFor="authorEmail">邮箱</label>
                <input
                  id="authorEmail"
                  type="email"
                  value={form.authorEmail}
                  onChange={(e) => updateField('authorEmail', e.target.value)}
                  placeholder="your@email.com"
                  disabled={submitting}
                />
              </div>
            </div>
          </fieldset>

          {/* 权限 */}
          <fieldset className="form-section">
            <legend>权限声明</legend>
            <p className="form-section-desc">
              请如实声明您的 Skill 所需的权限。这些信息将展示给用户，帮助其做出安装决策。
            </p>

            <div className="permission-grid">
              {[
                { key: 'filesystem' as const, label: '文件系统', desc: '读取/写入/删除文件' },
                { key: 'shell' as const, label: 'Shell', desc: '执行 Shell 命令' },
                { key: 'network' as const, label: '网络', desc: '访问外部网络' },
                { key: 'environment' as const, label: '环境变量', desc: '读取系统环境变量' },
                { key: 'credentials' as const, label: '凭据', desc: '访问 SSH 密钥等凭据' },
              ].map((perm) => (
                <label key={perm.key} className="permission-item">
                  <input
                    type="checkbox"
                    checked={form.permissions[perm.key]}
                    onChange={() => togglePermission(perm.key)}
                    disabled={submitting}
                  />
                  <div>
                    <span className="permission-label">{perm.label}</span>
                    <span className="permission-desc">{perm.desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </fieldset>

          {/* 适配客户端 */}
          <fieldset className="form-section">
            <legend>适配客户端</legend>
            <p className="form-section-desc">选择您的 Skill 支持的 AI 客户端平台。</p>
            <div className="client-chips">
              {CLIENTS.map((client) => (
                <button
                  key={client}
                  type="button"
                  className={`client-chip ${form.compatibility.includes(client) ? 'active' : ''}`}
                  onClick={() => toggleClient(client)}
                  disabled={submitting}
                >
                  {client}
                </button>
              ))}
            </div>
          </fieldset>

          {/* 提交 */}
          <div className="submit-actions">
            <button type="submit" className="btn btn-primary btn-lg" disabled={submitting}>
              {submitting ? '提交中...' : '提交审核'}
            </button>
          </div>
        </form>
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
