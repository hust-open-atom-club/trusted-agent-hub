'use client';

import { useState } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const GRADE_OPTIONS = [
  { value: 'A', label: 'A — 高度可信' },
  { value: 'B', label: 'B — 可信' },
  { value: 'C', label: 'C — 需注意' },
  { value: 'D', label: 'D — 有风险' },
  { value: 'E', label: 'E — 高风险' },
];

interface Props {
  versionId: string;
  autoGrade: string | null;
  currentManualGrade: string | null;
  currentReason: string | null;
  token: string;
  onClose: () => void;
  onComplete: () => void;
}

export default function GradeOverrideModal({
  versionId,
  autoGrade,
  currentManualGrade,
  currentReason,
  token,
  onClose,
  onComplete,
}: Props) {
  const [grade, setGrade] = useState<string>(currentManualGrade || '');
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const isResetting = grade === '__reset__';
  const hasChanges = isResetting ? true : (grade !== (currentManualGrade || '') && grade !== '');

  const handleSubmit = async () => {
    if (!reason.trim()) { setError('请填写修改理由'); return; }
    if (!confirmed) { setError('请勾选确认'); return; }

    setError('');
    setSubmitting(true);
    try {
      const body: Record<string, string | null> = {
        grade: isResetting ? null : grade,
        reason: reason.trim(),
      };
      const res = await fetch(`${API_BASE}/api/v0/producer/versions/${versionId}/grade`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({ detail: '操作失败' }));
        throw new Error(e.detail || `HTTP ${res.status}`);
      }
      onComplete();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '操作失败');
    } finally {
      setSubmitting(false);
    }
  };

  const close = () => { if (!submitting) onClose(); };

  const autoLabel = autoGrade ? `${autoGrade} (${levelLabel(autoGrade)})` : '未评分';
  const newLabel = isResetting ? '恢复自动评分' : (grade ? `${grade} (${levelLabel(grade)})` : '—');

  return (
    <div className="modal-overlay" onClick={close}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
        <div className="modal-header">
          <h3>修改手动评级</h3>
          <button className="modal-close" onClick={close} disabled={submitting}>✕</button>
        </div>

        <div style={{ padding: '1.25rem' }}>
          <div style={{
            display: 'flex', gap: '1.5rem', marginBottom: '1rem',
            padding: '0.75rem 1rem',
            background: 'var(--color-paper-2)',
            borderRadius: 'var(--radius-md)',
            fontSize: '0.85rem',
          }}>
            <div>
              <span style={{ color: 'var(--color-muted)', fontSize: '0.72rem' }}>自动评分</span>
              <div style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{autoLabel}</div>
            </div>
            <div style={{ color: 'var(--color-muted)', alignSelf: 'center' }}>→</div>
            <div>
              <span style={{ color: 'var(--color-muted)', fontSize: '0.72rem' }}>手动评级</span>
              <div style={{ fontWeight: 600, color: hasChanges ? 'var(--color-accent)' : 'var(--color-muted)' }}>
                {newLabel}
              </div>
            </div>
          </div>

          {currentManualGrade && currentReason && (
            <div style={{
              marginBottom: '1rem', padding: '0.6rem 0.85rem',
              background: 'oklch(94% 0.02 90)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem', color: 'var(--color-ink-2)',
              borderLeft: '3px solid var(--color-accent)',
            }}>
              <span style={{ fontWeight: 600 }}>当前手动评级: {currentManualGrade}</span>
              <br />
              理由: {currentReason}
            </div>
          )}

          <label style={{ display: 'block', marginBottom: '0.3rem', fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-ink)' }}>
            选择评级
          </label>
          <select
            value={grade}
            onChange={(e) => { setGrade(e.target.value); setError(''); }}
            disabled={submitting}
            style={{
              width: '100%', padding: '0.55rem 0.75rem',
              borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-rule)',
              background: 'var(--color-paper)',
              color: 'var(--color-ink)', fontSize: '0.88rem',
              fontFamily: 'inherit', outline: 'none', cursor: 'pointer',
              marginBottom: '1rem',
            }}>
            <option value="">— 请选择评级 —</option>
            {GRADE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
            <option disabled>──────────────</option>
            <option value="__reset__">恢复自动评分</option>
          </select>

          <label style={{ display: 'block', marginBottom: '0.3rem', fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-ink)' }}>
            修改理由 <span style={{ color: 'var(--color-danger)' }}>*</span>
          </label>
          <textarea
            rows={3}
            value={reason}
            onChange={(e) => { setReason(e.target.value); setError(''); }}
            placeholder={
              isResetting
                ? '请说明为何恢复自动评分...'
                : '请说明为何与自动评分不同...'
            }
            disabled={submitting}
            style={{
              width: '100%', padding: '0.55rem 0.75rem',
              borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-rule)',
              background: 'var(--color-paper)',
              color: 'var(--color-ink)', fontSize: '0.88rem',
              fontFamily: 'inherit', outline: 'none', resize: 'vertical',
              minHeight: '3.5rem', marginBottom: '1rem',
              boxSizing: 'border-box',
            }}
          />

          {hasChanges && (
            <div style={{
              padding: '0.75rem 1rem',
              marginBottom: '0.75rem',
              borderRadius: 'var(--radius-md)',
              border: `1px solid ${Math.abs(getGradeDiff(autoGrade, isResetting ? null : grade)) >= 3 ? 'var(--color-danger)' : 'var(--color-warning)'}`,
              background: 'var(--color-paper-2)',
            }}>
              <label style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                cursor: submitting ? 'not-allowed' : 'pointer',
                fontSize: '0.82rem', color: 'var(--color-ink)', userSelect: 'none',
              }}>
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  disabled={submitting}
                  style={{ width: '1rem', height: '1rem', cursor: submitting ? 'not-allowed' : 'pointer', accentColor: 'var(--color-accent)' }}
                />
                {isResetting
                  ? '我确认恢复自动评分，清除人工干预'
                  : `我确认将评级改为 ${grade}（自动评分: ${autoGrade ?? '—'}），理解此操作的影响。`}
              </label>
            </div>
          )}

          {error && (
            <div style={{
              padding: '0.5rem 0.75rem', marginBottom: '0.75rem',
              fontSize: '0.78rem', color: 'var(--color-danger)',
              background: 'oklch(94% 0.03 20)', borderRadius: 'var(--radius-sm)',
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.6rem', justifyContent: 'flex-end' }}>
            <button className="btn btn-secondary" onClick={close} disabled={submitting}>
              取消
            </button>
            <button
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={submitting || !hasChanges || !reason.trim() || !confirmed}
            >
              {submitting ? '提交中...' : '确认修改'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function levelLabel(grade: string): string {
  const m: Record<string, string> = {
    A: '高度可信', B: '可信', C: '需注意', D: '有风险', E: '高风险',
  };
  return m[grade] ?? grade;
}

function getGradeDiff(a: string | null, b: string | null): number {
  const order = ['A', 'B', 'C', 'D', 'E'];
  const ai = a ? order.indexOf(a) : -1;
  const bi = b ? order.indexOf(b) : -1;
  if (ai < 0 || bi < 0) return 0;
  return Math.abs(ai - bi);
}
