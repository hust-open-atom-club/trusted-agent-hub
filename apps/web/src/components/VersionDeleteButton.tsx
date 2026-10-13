'use client';

import { useEffect, useRef, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { authFetch, clearFetchCache } from '@/lib/api-fetch';
import { API_BASE } from '@/lib/runtime-config';
import { clearPendingSubmitContext, readPendingSubmitContext } from '@/lib/pending-submit';

export const WITHDRAWABLE_STATUSES = new Set(['draft', 'pending_review', 'changes_requested', 'rejected', 'error']);

interface DeletionPlan {
  version_id: string; package_name: string; version: string; status: string;
  allowed: boolean; action: string; reason: string | null;
  scan_count: number; report_count: number; review_count: number;
}

export default function VersionDeleteButton({ versionId, status, onDeleted }: {
  versionId: string; status: string; onDeleted: () => void;
}) {
  const { user, token } = useAuth();
  const eligible = WITHDRAWABLE_STATUSES.has(status) || (status === 'yanked' && user?.role === 'admin');
  const [plan, setPlan] = useState<DeletionPlan | null>(null);
  const [open, setOpen] = useState(false);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const trigger = useRef<HTMLButtonElement>(null);

  async function loadPlan(signal?: AbortSignal): Promise<DeletionPlan | null> {
    const res = await authFetch(`${API_BASE}/api/v0/producer/versions/${encodeURIComponent(versionId)}/deletion-preview`, {
      headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal,
    });
    if (res.status === 403 || res.status === 404) return null;
    if (!res.ok) throw new Error('无法读取删除范围，请稍后刷新重试');
    return res.json();
  }

  useEffect(() => {
    setPlan(null);
    setOpen(false);
    if (!token || !eligible) return;
    const controller = new AbortController();
    loadPlan(controller.signal).then(value => {
      if (!controller.signal.aborted) setPlan(value);
    }).catch(() => { /* Fail closed: never offer deletion without server authorization. */ });
    return () => controller.abort();
  }, [versionId, status, token, user?.role, eligible]);

  function close() {
    if (busy) return;
    setOpen(false);
    setChecked(false);
    setError('');
    trigger.current?.focus();
  }

  async function showPreview() {
    setBusy(true);
    setError('');
    try {
      const latest = await loadPlan();
      setPlan(latest);
      if (latest?.allowed) { setChecked(false); setOpen(true); }
      else setError(latest?.reason || '该版本已不存在或当前账号无权删除');
    } catch (err) { setError(err instanceof Error ? err.message : '无法读取删除范围'); }
    finally { setBusy(false); }
  }

  async function remove() {
    if (!plan || !checked || busy) return;
    if (!window.confirm(`二次确认：${plan.action} ${plan.package_name} v${plan.version}？将永久删除清单中的目标版本及关联记录，无法恢复；包本身、其他版本和独立操作审计保留。`)) return;
    setBusy(true);
    setError('');
    try {
      const res = await authFetch(`${API_BASE}/api/v0/producer/versions/${encodeURIComponent(versionId)}`, {
        method: 'DELETE', cache: 'no-store',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirmed: true, expected_status: plan.status }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(typeof body.detail === 'string' ? body.detail : '删除失败，请刷新后重试');
      }
      if (readPendingSubmitContext()?.versionId === versionId) clearPendingSubmitContext();
      clearFetchCache();
      setOpen(false);
      setPlan(null);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : '删除失败');
      setChecked(false);
    } finally { setBusy(false); }
  }

  if (!eligible || !token) return null;
  return <>
    {plan?.allowed && <button ref={trigger} type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={showPreview}>
      {busy ? '处理中…' : plan.action}
    </button>}
    {error && !open && <span role="alert">{error}</span>}
    {open && plan && <div className="modal-overlay" onClick={close}>
      <div className="modal-dialog" role="dialog" aria-modal="true" aria-label="版本删除范围清单"
        style={{ maxWidth: '560px' }} onClick={e => e.stopPropagation()}
        onKeyDown={e => {
          if (e.key === 'Escape') close();
          if (e.key === 'Tab') {
            const controls = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)'));
            const first = controls[0], last = controls[controls.length - 1];
            if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
            if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
          }
        }}>
        <h3>{plan.action}</h3>
        <p><strong>{plan.package_name} v{plan.version}</strong> · {plan.status}</p>
        <p>范围 V：以下数据将永久删除，无法恢复。</p>
        <ul>
          <li>目标提交版本：1 个（含版本评分、安装记录）</li>
          <li>关联扫描记录：{plan.scan_count} 条</li>
          <li>版本扫描报告：{plan.report_count} 份</li>
          <li>版本审核记录：{plan.review_count} 条</li>
        </ul>
        <p>保留：包本身、其他版本、独立操作审计。删除后不会自动发布其他版本。</p>
        <label style={{ display: 'flex', gap: '0.5rem', margin: '1rem 0' }}>
          <input type="checkbox" autoFocus checked={checked} disabled={busy} onChange={e => setChecked(e.target.checked)} />
          我已核对目标版本和删除范围，理解此操作不可恢复
        </label>
        {error && <p role="alert" className="submit-error">{error}</p>}
        <div className="submit-notice__actions">
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={close}>取消</button>
          <button type="button" className="btn btn-danger" disabled={!checked || busy} onClick={remove}>继续二次确认</button>
        </div>
      </div>
    </div>}
  </>;
}
