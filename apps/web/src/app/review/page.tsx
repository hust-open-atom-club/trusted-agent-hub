'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ReviewItem {
  version_id: string;
  package_id: string;
  package_name: string;
  package_type: string | null;
  version: string;
  status: string;
  submitted_at: string | null;
  grade: string | null;
  grade_label: string | null;
  findings_count: number;
}

const GRADE_OPTIONS = ['全部', 'A', 'B', 'C', 'D', 'E', 'F'];

const PACKAGE_TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
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

export default function ReviewPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();
  const [items, setItems] = useState<ReviewItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gradeFilter, setGradeFilter] = useState('全部');

  useEffect(() => {
    if (authLoading) return;
    if (!user || !token) {
      setLoading(false);
      setError('请先登录审核员账号');
      return;
    }

    const fetchItems = async () => {
      try {
        const res = await fetch(
          `${API_BASE}/api/v0/producer/versions?status=pending_review`,
          {
            headers: { Authorization: `Bearer ${token}` },
          },
        );
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: '加载失败' }));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data: ReviewItem[] = await res.json();
        setItems(data);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : '加载失败');
      } finally {
        setLoading(false);
      }
    };

    fetchItems();
  }, [user, token, authLoading]);

  const filtered = useMemo(() => {
    if (gradeFilter === '全部') return items;
    return items.filter((item) => item.grade === gradeFilter);
  }, [items, gradeFilter]);

  // 统计各等级数量
  const gradeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      const g = item.grade || '—';
      counts[g] = (counts[g] || 0) + 1;
    }
    return counts;
  }, [items]);

  const hasResults = filtered.length > 0;

  return (
    <div className="review-page">
      <div className="review-header">
        <h1>待审核列表</h1>
        <p>
          共 {items.length} 个版本等待审核
          {gradeFilter !== '全部' && (
            <span>（已筛选 {gradeFilter} 级）</span>
          )}
        </p>
      </div>

      {/* 筛选栏 */}
      {!loading && !error && (
        <div className="review-toolbar">
          <div className="review-filter">
            <label htmlFor="grade-filter">风险等级：</label>
            <select
              id="grade-filter"
              value={gradeFilter}
              onChange={(e) => setGradeFilter(e.target.value)}
              className="review-select"
            >
              {GRADE_OPTIONS.map((g) => (
                <option key={g} value={g}>
                  {g}
                  {g !== '全部' && gradeCounts[g]
                    ? ` (${gradeCounts[g]})`
                    : g === '全部'
                      ? ` (${items.length})`
                      : ''}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* 加载态 */}
      {loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x23F3;</div>
          <h3>加载中...</h3>
        </div>
      )}

      {/* 错误态 */}
      {error && !loading && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x26A0;</div>
          <h3>加载失败</h3>
          <p>{error}</p>
        </div>
      )}

      {/* 空态 */}
      {!loading && !error && !hasResults && (
        <div className="empty-state">
          <div className="empty-state-icon">&#x2705;</div>
          <h3>暂无待审核版本</h3>
          <p>
            {gradeFilter !== '全部'
              ? `没有 ${gradeFilter} 级的待审核版本`
              : '所有提交的版本都已审核完毕'}
          </p>
        </div>
      )}

      {/* 表格列表 */}
      {!loading && !error && hasResults && (
        <div className="review-table-wrapper">
          <table className="review-table">
            <thead>
              <tr>
                <th>包名称</th>
                <th>版本</th>
                <th>风险</th>
                <th>问题数</th>
                <th>提交时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.version_id}
                  onClick={() => router.push(`/review/${item.version_id}`)}
                  className="review-row"
                >
                  <td className="review-pkg-name" data-label="包名称">
                    <div className="review-pkg-title">
                      {item.package_type && (
                        <span className={`type-badge ${item.package_type}`}>
                          {PACKAGE_TYPE_LABELS[item.package_type] || item.package_type}
                        </span>
                      )}
                      <span>{item.package_name}</span>
                    </div>
                  </td>
                  <td className="review-version" data-label="版本">
                    <code>v{item.version}</code>
                  </td>
                  <td className="review-grade" data-label="风险">
                    <span
                      className={`grade-badge grade-${item.grade || 'unknown'}`}
                    >
                      {item.grade || '—'}
                    </span>
                  </td>
                  <td className="review-findings" data-label="问题数">
                    <span
                      className={
                        item.findings_count > 0
                          ? 'review-findings-danger'
                          : 'review-findings-ok'
                      }
                    >
                      {item.findings_count}
                    </span>
                  </td>
                  <td className="review-date" data-label="提交时间">
                    {formatDate(item.submitted_at)}
                  </td>
                  <td className="review-action">
                    <span className="review-arrow">→</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
