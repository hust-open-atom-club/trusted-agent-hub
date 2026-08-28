'use client';

import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { API_BASE } from '@/lib/runtime-config';


interface Props {
  versionId: string;
  autoGrade: string | null;
  currentManualGrade: string | null;
  currentReason: string | null;
  token: string;
  onClose: () => void;
  onComplete: () => void;
}

function getGradeDiff(a: string | null, b: string | null): number {
  const order = ['A', 'B', 'C', 'D', 'E', 'F'];
  const ai = a ? order.indexOf(a) : -1;
  const bi = b ? order.indexOf(b) : -1;
  if (ai < 0 || bi < 0) return 0;
  return Math.abs(ai - bi);
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
  const { t } = useTranslation();

  const gradeOptions = [
    { value: 'A', key: 'A-highly_trusted' },
    { value: 'B', key: 'B-trusted' },
    { value: 'C', key: 'C-caution' },
    { value: 'D', key: 'D-risky' },
    { value: 'E', key: 'E-high_risk' },
    { value: 'F', key: 'F-critical' },
  ];

  const gradeLabelMap: Record<string, string> = {
    A: t('grade_modal.grade_label.A-highly_trusted'),
    B: t('grade_modal.grade_label.B-trusted'),
    C: t('grade_modal.grade_label.C-caution'),
    D: t('grade_modal.grade_label.D-risky'),
    E: t('grade_modal.grade_label.E-high_risk'),
    F: t('grade_modal.grade_label.F-critical'),
  };

  const [grade, setGrade] = useState<string>(currentManualGrade || '');
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const isResetting = grade === '__reset__';
  const hasChanges = isResetting ? true : (grade !== (currentManualGrade || '') && grade !== '');

  const handleSubmit = async () => {
    if (!reason.trim()) { setError(t('grade_modal.reason_required')); return; }
    if (!confirmed) { setError(t('grade_modal.confirm_required')); return; }

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
        const e = await res.json().catch(() => ({ detail: t('grade_modal.error') }));
        throw new Error(e.detail || `HTTP ${res.status}`);
      }
      onComplete();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('grade_modal.error'));
    } finally {
      setSubmitting(false);
    }
  };

  const close = () => { if (!submitting) onClose(); };

  const autoLabel = autoGrade ? `${autoGrade} (${gradeLabelMap[autoGrade] ?? autoGrade})` : t('grade_modal.not_scored');
  const newLabel = isResetting ? t('grade_modal.reset_to_auto') : (grade ? `${grade} (${gradeLabelMap[grade] ?? grade})` : '—');

  return (
    <div className="modal-overlay" onClick={close}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
        <div className="modal-header">
          <h3>{t('grade_modal.title')}</h3>
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
              <span style={{ color: 'var(--color-muted)', fontSize: '0.72rem' }}>{t('grade_modal.auto_grade_label')}</span>
              <div style={{ fontWeight: 600, color: 'var(--color-ink)' }}>{autoLabel}</div>
            </div>
            <div style={{ color: 'var(--color-muted)', alignSelf: 'center' }}>→</div>
            <div>
              <span style={{ color: 'var(--color-muted)', fontSize: '0.72rem' }}>{t('grade_modal.manual_grade_label')}</span>
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
              <span style={{ fontWeight: 600 }}>{t('grade_modal.current_manual')}: {currentManualGrade}</span>
              <br />
              {t('grade_modal.reason_label')}: {currentReason}
            </div>
          )}

          <label style={{ display: 'block', marginBottom: '0.3rem', fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-ink)' }}>
            {t('grade_modal.select_grade')}
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
            <option value="">{t('grade_modal.select_placeholder')}</option>
            {gradeOptions.map((o) => (
              <option key={o.value} value={o.value}>{t(`grade_modal.grade_option.${o.key}`)}</option>
            ))}
            <option disabled>──────────────</option>
            <option value="__reset__">{t('grade_modal.reset_to_auto_option')}</option>
          </select>

          <label style={{ display: 'block', marginBottom: '0.3rem', fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-ink)' }}>
            {t('grade_modal.reason_label')} <span style={{ color: 'var(--color-danger)' }}>*</span>
          </label>
          <textarea
            rows={3}
            value={reason}
            onChange={(e) => { setReason(e.target.value); setError(''); }}
            placeholder={
              isResetting
                ? t('grade_modal.reason_placeholder_reset')
                : t('grade_modal.reason_placeholder')
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
              border: `1px solid ${getGradeDiff(autoGrade, isResetting ? null : grade) >= 3 ? 'var(--color-danger)' : 'var(--color-warning)'}`,
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
                  ? t('grade_modal.confirm_auto')
                  : t('grade_modal.confirm_manual', { grade, auto: autoGrade ?? '—' })}
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
              {t('grade_modal.cancel')}
            </button>
            <button
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={submitting || !hasChanges || !reason.trim() || !confirmed}
            >
              {submitting ? t('grade_modal.submitting') : t('grade_modal.confirm')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

