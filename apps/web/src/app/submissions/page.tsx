'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface VersionItem {
  version_id: string;
  package_id: string;
  package_name: string;
  version: string;
  status: string;
  submitted_at: string | null;
}

const STATUS_LABELS: Record<string, { label: string; className: string }> = {
  draft:        { label: '草稿',     className: 'draft' },
  submitted:    { label: '已提交',   className: 'submitted' },
  scanning:     { label: '扫描中',   className: 'scanning' },
  pending_review: { label: '等待审核', className: 'pending_review' },
  approved:     { label: '审核通过', className: 'approved' },
  published:    { label: '已发布',   className: 'published' },
  rejected:     { label: '已驳回',   className: 'rejected' },
  changes_requested: { label: '需修改', className: 'changes_requested' },
  error:        { label: '错误',     className: 'error' },
  yanked:       { label: '已下架',   className: 'yanked' },
};

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
  try {
    const d = new Date(iso);
    return d.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export default function MySubmissionsPage() {
  const router = useRouter();
  const { user, loading: authLoading } = useAuth();
  const [items, setItems] = useState<VersionItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      setLoading(false);
      setError('请先登录');
      return;
    }

    fetch(`${API_BASE}/api/v0/producer/versions?submitter_id=${encodeURIComponent(user.id)}`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data: VersionItem[]) => setItems(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user, authLoading]);

  const filtered = search.trim()
    ? items.filter(
        (item) =>
          item.version_id.toLowerCase().includes(search.toLowerCase()) ||
          item.package_name.toLowerCase().includes(search.toLowerCase())
      )
    : items;

  const hasResults = filtered.length > 0;

  return (
    <div className="status-page">
      <div className="status-header">
        <h1>我的提交</h1>
        <p>查看你提交的所有能力包及其审核状态</p>
      </div>

      <div style={{ maxWidth: '640px', margin: '0 auto 2rem' }}>
        <form
          onSubmit={(e) => e.preventDefault()}
          style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}
        >
          <input
            type="text"
            className="scanner-url-input"
            placeholder="搜索版本 ID 或包名..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              flex: 1,
              borderRadius: 'var(--radius-pill)',
              padding: '0.7rem 1rem',
              fontFamily: 'var(--font-mono)',
            }}
          />
          <Link href="/submit" className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
            + 提交新包
          </Link>
        </form>
      </div>

      {loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      )}

      {error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && !hasResults && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4E6;</div>
          <h3>还没有提交记录</h3>
          <p>你还没有提交过任何能力包，去提交一个吧！</p>
          <Link href="/submit" className="btn btn-primary" style={{ marginTop: '1rem' }}>
            前往提交
          </Link>
        </div>
      )}

      {!loading && !error && hasResults && (
        <div style={{ maxWidth: '720px', margin: '0 auto' }}>
          {filtered.map((item) => {
            const st = STATUS_LABELS[item.status] || { label: item.status, className: 'status-unknown' };
            const statusUrl = `/packages/${encodeURIComponent(item.package_name)}/versions/${encodeURIComponent(item.version)}/status?vid=${encodeURIComponent(item.version_id)}`;
            return (
              <div
                key={item.version_id}
                className="submission-card"
                style={{
                  background: 'var(--color-paper-2)',
                  borderRadius: 'var(--radius-lg)',
                  padding: '1.25rem 1.5rem',
                  marginBottom: '0.75rem',
                  border: '1px solid var(--color-rule)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '0.75rem',
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                    <strong style={{ fontSize: '1.05rem', color: 'var(--color-ink)' }}>
                      {item.package_name}
                    </strong>
                    <span className={`status-badge ${st.className}`} style={{
                      display: 'inline-block',
                      padding: '0.15rem 0.6rem',
                      borderRadius: 'var(--radius-pill)',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                    }}>
                      {st.label}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>
                    <span>v{item.version}</span>
                    <span style={{ margin: '0 0.5rem', opacity: 0.4 }}>|</span>
                    <span title={item.version_id} style={{ fontSize: '0.75rem', opacity: 0.7 }}>
                      {item.version_id.slice(0, 12)}...
                    </span>
                  </div>
                  {item.submitted_at && (
                    <div style={{ fontSize: '0.78rem', color: 'var(--color-muted)', marginTop: '0.3rem' }}>
                      {formatDate(item.submitted_at)}
                    </div>
                  )}
                </div>
                <button
                  className="btn btn-primary"
                  onClick={() => router.push(statusUrl)}
                  style={{ flexShrink: 0 }}
                >
                  查看状态
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
