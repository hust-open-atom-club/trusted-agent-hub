'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { apiFetch } from '@/lib/api-fetch';

import { API_BASE } from '@/lib/runtime-config';

interface UserItem {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

const ROLES = ['user', 'submitter', 'reviewer', 'admin'] as const;

const ROLE_LABELS: Record<string, string> = {
  user: '普通用户',
  submitter: '提交者',
  reviewer: '审核员',
  admin: '管理员',
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

export default function AdminUsersPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, token, loading: authLoading } = useAuth();

  const [items, setItems] = useState<UserItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [page, setPage] = useState(0);
  const [updating, setUpdating] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const pageSize = 50;

  const fetchUsers = () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    const params = new URLSearchParams();
    params.set('limit', String(pageSize));
    params.set('offset', String(page * pageSize));
    if (search.trim()) params.set('search', search.trim());
    if (roleFilter) params.set('role', roleFilter);

    apiFetch<{ items: UserItem[]; total: number }>(
      `${API_BASE}/api/v0/admin/users?${params.toString()}`,
      { headers: { Authorization: `Bearer ${token}` } },
    )
      .then((data) => { setItems(data.items); setTotal(data.total); })
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) { setLoading(false); setError('请先登录管理员账号'); return; }
    fetchUsers();
  }, [user, token, authLoading, page]);

  const handleRoleChange = async (userId: string, newRole: string) => {
    setUpdating(userId);
    setError(null);
    try {
      await apiFetch(`${API_BASE}/api/v0/admin/users/${userId}/role`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ role: newRole }),
      });
      setSuccessMsg('角色已更新');
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : '修改失败');
    } finally {
      setUpdating(null);
    }
  };

  const handleStatusToggle = async (userId: string, isActive: boolean) => {
    setUpdating(userId);
    setError(null);
    try {
      await apiFetch(`${API_BASE}/api/v0/admin/users/${userId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ is_active: !isActive }),
      });
      setSuccessMsg(isActive ? '用户已禁用' : '用户已启用');
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败');
    } finally {
      setUpdating(null);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchUsers();
  };

  if (authLoading || loading) {
    return (
      <div className="admin-page">
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      </div>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="admin-page">
      <nav className="admin-nav">
        <button onClick={() => router.push('/admin')} className="link-btn">
          ← 返回管理面板
        </button>
      </nav>

      <div className="admin-section-header">
        <h1>用户管理</h1>
        <p>管理角色与账户状态 · 共 {total} 个用户</p>
      </div>

      {successMsg && (
        <div className="admin-success-msg" style={{ marginBottom: '1rem' }}>
          {successMsg}
        </div>
      )}

      <form onSubmit={handleSearch} className="admin-filter-row">
        <div className="admin-filter-item">
          <label className="admin-filter-label">搜索</label>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="邮箱或昵称..."
            className="admin-filter-input"
            style={{ width: '320px' }}
          />
        </div>

        <div className="admin-filter-item">
          <label className="admin-filter-label">角色</label>
          <select
            value={roleFilter}
            onChange={(e) => { setRoleFilter(e.target.value); setPage(0); }}
            className="admin-select"
          >
            <option value="">全部角色</option>
            {ROLES.map((r) => (
              <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>
            ))}
          </select>
        </div>

        <div className="admin-filter-item" style={{ alignSelf: 'flex-end' }}>
          <button type="submit" className="btn btn-primary btn-sm admin-search-btn">
            查询
          </button>
        </div>
      </form>

      {error && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>错误</h3>
          <p>{error}</p>
        </div>
      )}

      {!error && items.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F465;</div>
          <h3>暂无用户</h3>
          <p>没有匹配的用户记录</p>
        </div>
      )}

      {!error && items.length > 0 && (
        <>
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>邮箱</th>
                  <th>昵称</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>注册时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td data-label="邮箱" className="admin-mono-cell">{item.email}</td>
                    <td data-label="昵称">{item.display_name}</td>
                    <td data-label="角色">
                      <select
                        value={item.role}
                        disabled={updating === item.id}
                        onChange={(e) => handleRoleChange(item.id, e.target.value)}
                        className="admin-select"
                        style={{ padding: '0.3rem 0.5rem', fontSize: '0.8rem', minHeight: 'auto' }}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>
                        ))}
                      </select>
                    </td>
                    <td data-label="状态">
                      <span className={`status-badge ${item.is_active ? 'published' : 'yanked'}`}>
                        {item.is_active ? '正常' : '已禁用'}
                      </span>
                    </td>
                    <td data-label="注册时间" className="admin-mono-cell">{formatDate(item.created_at)}</td>
                    <td data-label="操作">
                      <button
                        className={`btn btn-sm user-toggle-btn ${item.is_active ? 'user-toggle-danger' : 'user-toggle-safe'}`}
                        disabled={updating === item.id}
                        onClick={() => handleStatusToggle(item.id, item.is_active)}
                      >
                        {updating === item.id ? '...' : item.is_active ? '禁用' : '启用'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{
            display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem',
            marginTop: '1.5rem', fontFamily: 'var(--font-sans)',
          }}>
            <button
              className={`btn btn-secondary btn-sm`}
              disabled={page <= 0}
              onClick={() => setPage((p) => p - 1)}
            >
              上一页
            </button>
            <span style={{ fontSize: '0.85rem', color: 'var(--color-ink-2)' }}>
              第 {page + 1} / {totalPages} 页
            </span>
            <button
              className={`btn btn-secondary btn-sm`}
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              下一页
            </button>
          </div>
        </>
      )}
    </div>
  );
}
