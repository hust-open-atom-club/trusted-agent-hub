'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import { authFetch, clearFetchCache } from '@/lib/api-fetch';
import { API_BASE } from '@/lib/runtime-config';
import { clearPendingSubmitContext, readPendingSubmitContext } from '@/lib/pending-submit';
import styles from './VersionDeleteButton.module.css';

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
  const { t } = useTranslation();
  const eligible = WITHDRAWABLE_STATUSES.has(status) || (status === 'yanked' && user?.role === 'admin');
  const [plan, setPlan] = useState<DeletionPlan | null>(null);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<'review' | 'confirm'>('review');
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const trigger = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const descriptionId = useId();

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    const returnTarget = trigger.current;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
      returnTarget?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (open) dialog.current?.focus();
  }, [open, step]);

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
      if (latest?.allowed) { setChecked(false); setStep('review'); setOpen(true); }
      else setError(latest?.reason || '该版本已不存在或当前账号无权删除');
    } catch (err) { setError(err instanceof Error ? err.message : '无法读取删除范围'); }
    finally { setBusy(false); }
  }

  async function remove() {
    if (!plan || !checked || busy || step !== 'confirm') return;
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
      setStep('review');
    } finally { setBusy(false); }
  }

  if (!eligible || !token) return null;
  return <>
    {plan?.allowed && <button ref={trigger} type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={showPreview}>
      {busy ? '处理中…' : plan.action}
    </button>}
    {error && !open && <span role="alert" className={styles.inlineError}>{error}</span>}
    {open && plan && createPortal(<div className={styles.overlay} onClick={close}>
      <div ref={dialog} className={styles.dialog} role="dialog" aria-modal="true" tabIndex={-1}
        aria-label={step === 'review' ? '版本删除范围清单' : '确认永久删除'}
        aria-describedby={descriptionId} aria-busy={busy} onClick={e => e.stopPropagation()}
        onKeyDown={e => {
          if (e.key === 'Escape') { e.stopPropagation(); close(); }
          if (e.key === 'Tab') {
            const controls = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled)'));
            const first = controls[0], last = controls[controls.length - 1];
            if (!first) { e.preventDefault(); e.currentTarget.focus(); }
            else if (e.shiftKey && (document.activeElement === first || document.activeElement === e.currentTarget)) {
              e.preventDefault(); last?.focus();
            } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
          }
        }}>
        <header className={styles.header}>
          <span className={styles.icon} aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6" />
            </svg>
          </span>
          <div className={styles.heading}>
            <h2>{step === 'review' ? plan.action : '确认永久删除'}</h2>
            <p id={descriptionId}>{step === 'review' ? '删除前，请核对目标版本与影响范围。' : '这是最后一步，请再次确认以下删除内容。'}</p>
          </div>
          <button type="button" className={styles.close} aria-label="关闭删除确认" disabled={busy} onClick={close}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden="true"><path d="m6 6 12 12M6 18 18 6" /></svg>
          </button>
        </header>

        <ol className={styles.steps} aria-label="删除确认步骤">
          <li aria-current={step === 'review' ? 'step' : undefined} data-complete={step === 'confirm'}><span>1</span>核对删除范围</li>
          <li aria-current={step === 'confirm' ? 'step' : undefined}><span>2</span>最终确认</li>
        </ol>

        <div className={styles.body}>
          <section className={styles.target} aria-label="目标版本">
            <span className={styles.caption}>目标版本</span>
            <strong className={styles.packageName}>{plan.package_name}</strong>
            <div className={styles.metadata}>
              <span className={styles.version}>v{plan.version}</span>
              <span className={styles.status}>{t(`submissions.status.${plan.status}`, { defaultValue: plan.status })}</span>
            </div>
          </section>

          <div className={styles.scope}>
            <div className={styles.sectionHeading}><h3>将永久删除</h3><span>仅限当前版本</span></div>
            <dl className={styles.inventory}>
              <div><dt>目标提交版本<small>含版本评分、安装记录</small></dt><dd><strong>1</strong> 个</dd></div>
              <div><dt>关联扫描记录</dt><dd><strong>{plan.scan_count}</strong> 条</dd></div>
              <div><dt>版本扫描报告</dt><dd><strong>{plan.report_count}</strong> 份</dd></div>
              <div><dt>版本审核记录</dt><dd><strong>{plan.review_count}</strong> 条</dd></div>
            </dl>
          </div>

          <div className={styles.retained}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></svg>
            <div><strong>包本身、其他版本和独立操作审计将保留</strong><p>删除后不会自动发布其他版本。</p></div>
          </div>

          {step === 'review' ? <label className={styles.acknowledgement} data-checked={checked}>
            <input type="checkbox" checked={checked} disabled={busy} onChange={e => setChecked(e.target.checked)} />
            <span><strong>我已核对目标版本和删除范围</strong><small>我理解此操作将永久删除以上数据，且无法恢复。</small></span>
          </label> : <div className={styles.warning} role="note">
            <strong>删除后无法恢复</strong>
            <p>点击“确认永久删除”后，将立即删除上述版本及关联记录。</p>
          </div>}
          {error && <p role="alert" className={styles.error}>{error}</p>}
        </div>

        <footer className={styles.footer}>
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={step === 'review' ? close : () => setStep('review')}>
            {step === 'review' ? '取消' : '返回核对'}
          </button>
          {step === 'review' ? <button type="button" className={`btn btn-primary ${styles.next}`} disabled={!checked || busy} onClick={() => setStep('confirm')}>
            继续二次确认 <span aria-hidden="true">→</span>
          </button> : <button type="button" className="btn btn-danger" disabled={busy} onClick={remove}>
            {busy ? '正在删除…' : '确认永久删除'}
          </button>}
        </footer>
      </div>
    </div>, document.body)}
  </>;
}
