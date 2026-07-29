'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchFeedback, submitFeedback } from '@/data/packages';
import type { FeedbackPage, FeedbackRecord, FeedbackLevel } from '@/types';

interface FeedbackSectionProps {
  packageName: string;
  user: { id: string } | null;
  token: string | null;
}

export default function FeedbackSection({ packageName, user, token }: FeedbackSectionProps) {
  const { t } = useTranslation();

  const levelLabels: Record<FeedbackLevel, { label: string; emoji: string }> = {
    positive: { label: t('feedback.positive'), emoji: '👍' },
    neutral: { label: t('feedback.neutral'), emoji: '😐' },
    negative: { label: t('feedback.negative'), emoji: '👎' },
  };
  const [feedbackPage, setFeedbackPage] = useState<FeedbackPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [selectedLevel, setSelectedLevel] = useState<FeedbackLevel | null>(null);
  const [comment, setComment] = useState('');
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchFeedback(packageName);
      setFeedbackPage(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load feedback');
    } finally {
      setLoading(false);
    }
  }, [packageName]);

  useEffect(() => {
    load();
  }, [load]);

  const handleSubmit = async () => {
    if (!selectedLevel || !token) return;
    setSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(false);

    try {
      await submitFeedback(packageName, selectedLevel, comment || null, token);
      setSubmitSuccess(true);
      setComment('');
      // Reload feedback list
      await load();
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : 'Failed to submit');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && !feedbackPage) {
    return (
      <div className="detail-section">
        <h2>{t('feedback.title')}</h2>
        <p style={{ color: 'var(--color-muted)', fontSize: '0.82rem' }}>{t('feedback.loading')}</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="detail-section">
        <h2>{t('feedback.title')}</h2>
        <p style={{ color: 'var(--color-muted)', fontSize: '0.82rem' }}>{t('feedback.unavailable')}</p>
      </div>
    );
  }

  const counts = feedbackPage?.level_counts ?? { positive: 0, neutral: 0, negative: 0 };
  const totalFeedback = counts.positive + counts.neutral + counts.negative;
  const items = feedbackPage?.items ?? [];

  return (
    <div className="detail-section">
      <h2>{t('feedback.title')}{totalFeedback > 0 && ` (${totalFeedback})`}</h2>

      {/* Feedback counts */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '0.75rem' }}>
        {(Object.entries(levelLabels) as [FeedbackLevel, { label: string; emoji: string }][]).map(([level, { label, emoji }]) => (
          <div key={level} style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.3rem',
            fontSize: '0.82rem',
            color: 'var(--color-ink-2)',
          }}>
            <span>{emoji}</span>
            <span>{label}</span>
            <strong style={{ color: 'var(--color-ink)' }}>{counts[level] ?? 0}</strong>
          </div>
        ))}
      </div>

      {/* Submit form (only for logged-in users) */}
      {user ? (
        <div style={{
          padding: '0.75rem',
          background: 'var(--color-paper-2)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-rule)',
          marginBottom: '1rem',
        }}>
          <p style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.5rem' }}>{t('feedback.share')}</p>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
            {(Object.entries(levelLabels) as [FeedbackLevel, { label: string; emoji: string }][]).map(([level, { label, emoji }]) => (
              <button
                key={level}
                className={`btn btn-sm ${selectedLevel === level ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSelectedLevel(level)}
                disabled={submitting}
              >
                {emoji} {label}
              </button>
            ))}
          </div>
          <textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder={t('feedback.comment_placeholder')}
            maxLength={1000}
            rows={2}
            disabled={submitting}
            style={{
              width: '100%',
              padding: '0.5rem',
              fontSize: '0.8rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-rule)',
              background: 'var(--color-paper)',
              color: 'var(--color-ink)',
              resize: 'vertical',
              marginBottom: '0.5rem',
            }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              className="btn btn-sm btn-primary"
              disabled={!selectedLevel || submitting}
              onClick={handleSubmit}
            >
              {submitting ? t('feedback.submitting') : t('feedback.submit')}
            </button>
            {submitSuccess && (
              <span style={{ color: 'var(--color-success)', fontSize: '0.8rem' }}>✓ {t('feedback.thank_you')}</span>
            )}
            {submitError && (
              <span style={{ color: 'var(--color-danger)', fontSize: '0.8rem' }}>{submitError}</span>
            )}
          </div>
        </div>
      ) : (
        <div style={{
          padding: '0.75rem',
          background: 'var(--color-paper-2)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-rule)',
          marginBottom: '1rem',
          fontSize: '0.82rem',
          color: 'var(--color-muted)',
        }}>
          <a href="/login" style={{ color: 'var(--color-accent)', fontWeight: 600 }}>{t('feedback.login_hint')}</a>{t('feedback.login_to_submit')}
        </div>
      )}

      {/* Feedback list */}
      {items.length > 0 ? (
        <div>
          {items.map((fb) => (
            <div key={fb.id} style={{
              padding: '0.5rem 0',
              borderBottom: '1px solid var(--color-rule)',
              fontSize: '0.82rem',
            }}>
              <span style={{ marginRight: '0.5rem' }}>
                {levelLabels[fb.level]?.emoji ?? '❓'}
              </span>
              <span style={{ color: 'var(--color-ink-2)' }}>
                {fb.comment || (levelLabels[fb.level]?.label ?? fb.level)}
              </span>
              <span style={{ color: 'var(--color-muted)', marginLeft: '0.75rem', fontSize: '0.72rem' }}>
                {new Date(fb.created_at).toLocaleDateString()}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ fontSize: '0.82rem', color: 'var(--color-muted)' }}>
          {t('feedback.no_feedback')}
        </p>
      )}
    </div>
  );
}
