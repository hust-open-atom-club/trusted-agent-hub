'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import type { PointerEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { fetchFeedback, submitFeedback } from '@/data/packages';
import type { FeedbackPage, FeedbackLevel } from '@/types';

interface FeedbackSectionProps {
  packageName: string;
  user: { id: string } | null;
  token: string | null;
}

interface FeedbackMood {
  level: FeedbackLevel;
  label: string;
  tone: 'negative' | 'neutral' | 'positive';
  position: string;
  bgColor: string;
  inkColor: string;
  trackColor: string;
  noteText: string;
  noteColor: string;
  noteX: string;
  eyeWidth: number;
  eyeHeight: number;
  eyeRadius: string;
  mouthRotate: number;
  indicatorRotate: number;
}

function HandDrawnSmileIcon({
  stroke,
  className,
}: {
  stroke: string;
  className?: string;
}) {
  return (
    <motion.svg
      className={className}
      width="100%"
      height="100%"
      viewBox="0 0 100 60"
      fill="none"
      aria-hidden="true"
    >
      <motion.path
        d="M10 30 Q50 70 90 30"
        stroke={stroke}
        strokeWidth="12"
        strokeLinecap="round"
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      />
    </motion.svg>
  );
}

export default function FeedbackSection({ packageName, user, token }: FeedbackSectionProps) {
  const { t } = useTranslation();

  const feedbackMoods: FeedbackMood[] = [
    {
      level: 'negative',
      label: t('feedback.negative_mood'),
      tone: 'negative',
      position: '0%',
      bgColor: '#fff0eb',
      inkColor: '#711f13',
      trackColor: '#f0b09e',
      noteText: t('feedback.negative_note'),
      noteColor: '#c54a2f',
      noteX: '0%',
      eyeWidth: 18,
      eyeHeight: 18,
      eyeRadius: '999px',
      mouthRotate: 180,
      indicatorRotate: 180,
    },
    {
      level: 'neutral',
      label: t('feedback.neutral_mood'),
      tone: 'neutral',
      position: '50%',
      bgColor: '#fff8df',
      inkColor: '#5d4109',
      trackColor: '#ead071',
      noteText: t('feedback.neutral_note'),
      noteColor: '#b17c10',
      noteX: '-100%',
      eyeWidth: 32,
      eyeHeight: 7,
      eyeRadius: '999px',
      mouthRotate: 180,
      indicatorRotate: 180,
    },
    {
      level: 'positive',
      label: t('feedback.positive_mood'),
      tone: 'positive',
      position: '100%',
      bgColor: '#edfaee',
      inkColor: '#1d5226',
      trackColor: '#addaa7',
      noteText: t('feedback.positive_note'),
      noteColor: '#5f984d',
      noteX: '-200%',
      eyeWidth: 34,
      eyeHeight: 34,
      eyeRadius: '999px',
      mouthRotate: 0,
      indicatorRotate: 0,
    },
  ];

  const levelLabels: Record<FeedbackLevel, { label: string; dot: string }> = {
    positive: { label: t('feedback.positive'), dot: 'var(--color-success)' },
    neutral: { label: t('feedback.neutral'), dot: 'var(--color-warning)' },
    negative: { label: t('feedback.negative'), dot: 'var(--color-danger)' },
  };
  const [feedbackPage, setFeedbackPage] = useState<FeedbackPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [selectedLevel, setSelectedLevel] = useState<FeedbackLevel | null>(null);
  const [comment, setComment] = useState('');
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const trackRef = useRef<HTMLDivElement | null>(null);

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
  const activeMood = feedbackMoods.find((mood) => mood.level === (selectedLevel ?? 'neutral')) ?? feedbackMoods[1];
  const motionTransition = { type: 'spring' as const, stiffness: 310, damping: 28 };

  const selectLevelFromPosition = (clientX: number) => {
    const track = trackRef.current;
    if (!track || submitting) return;

    const rect = track.getBoundingClientRect();
    const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    const nextIndex = ratio < 0.25 ? 0 : ratio > 0.75 ? 2 : 1;
    setSelectedLevel(feedbackMoods[nextIndex].level);
  };

  const handleTrackPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (submitting) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    selectLevelFromPosition(event.clientX);
  };

  const handleTrackPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (submitting || (event.buttons & 1) !== 1) return;
    selectLevelFromPosition(event.clientX);
  };

  return (
    <div className="detail-section feedback-section">
      <div className="detail-section-heading">
        <h2>{t('feedback.title')}{totalFeedback > 0 && ` (${totalFeedback})`}</h2>
        <span>{t('feedback.section_kicker')}</span>
      </div>

      {totalFeedback > 0 && (
        <p className="feedback-summary-line">
          {t('feedback.summary_line', {
            positive: counts.positive ?? 0,
            neutral: counts.neutral ?? 0,
            negative: counts.negative ?? 0,
          })}
        </p>
      )}

      {user ? (
        <motion.div
          className={`feedback-composer ${activeMood.tone}`}
          animate={{ backgroundColor: activeMood.bgColor, borderColor: activeMood.trackColor }}
          transition={motionTransition}
        >
          <div className="feedback-slider-mini">
            <motion.h3
              className="feedback-slider-question"
              animate={{ color: activeMood.inkColor }}
              transition={motionTransition}
            >
              {t('feedback.platform_question')}
            </motion.h3>

            <div className="feedback-face-stage">
              <div className="feedback-face-eyes">
                {[0, 1].map((eye) => (
                  <motion.span
                    key={eye}
                    animate={{
                      width: activeMood.eyeWidth,
                      height: activeMood.eyeHeight,
                      borderRadius: activeMood.eyeRadius,
                      backgroundColor: activeMood.inkColor,
                    }}
                    transition={motionTransition}
                  />
                ))}
              </div>
              <motion.div
                className="feedback-face-mouth"
                animate={{ rotate: activeMood.mouthRotate }}
                transition={motionTransition}
              >
                <HandDrawnSmileIcon stroke={activeMood.inkColor} />
              </motion.div>
            </div>

            <div className="feedback-note-window">
              <motion.div
                className="feedback-note-strip"
                animate={{ x: activeMood.noteX }}
                transition={motionTransition}
              >
                {feedbackMoods.map((mood) => (
                  <div className="feedback-note-slide" key={mood.level}>
                    <h3 style={{ color: mood.noteColor }}>{mood.noteText}</h3>
                  </div>
                ))}
              </motion.div>
            </div>

            <div className="feedback-mood-control">
              <div
                ref={trackRef}
                className="feedback-mood-track"
                onPointerDown={handleTrackPointerDown}
                onPointerMove={handleTrackPointerMove}
              >
                <motion.div
                  className="feedback-mood-track-line"
                  animate={{ backgroundColor: activeMood.trackColor }}
                  transition={motionTransition}
                />
                <motion.div
                  className="feedback-mood-indicator"
                  animate={{
                    left: activeMood.position,
                    x: '-50%',
                    y: '-50%',
                    rotate: activeMood.indicatorRotate,
                    backgroundColor: activeMood.inkColor,
                  }}
                  transition={motionTransition}
                >
                  <HandDrawnSmileIcon stroke={activeMood.bgColor} />
                </motion.div>
                {feedbackMoods.map((mood) => (
                  <button
                    key={mood.level}
                    type="button"
                    className={selectedLevel === mood.level ? 'active' : undefined}
                    onClick={() => setSelectedLevel(mood.level)}
                    disabled={submitting}
                    aria-pressed={selectedLevel === mood.level}
                    aria-label={mood.label}
                  />
                ))}
              </div>
              <div className="feedback-mood-labels">
                {feedbackMoods.map((mood) => (
                  <button
                    key={mood.level}
                    type="button"
                    className={selectedLevel === mood.level ? 'active' : undefined}
                    onClick={() => setSelectedLevel(mood.level)}
                    disabled={submitting}
                  >
                    {mood.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="feedback-form-copy">
            <p className="feedback-share-title">{t('feedback.share')}</p>
            <span>{t('feedback.share_hint')}</span>
          </div>

          <textarea
            className="feedback-comment-input"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder={t('feedback.comment_placeholder')}
            maxLength={1000}
            rows={2}
            disabled={submitting}
          />
          <div className="feedback-submit-row">
            <button
              className="btn btn-sm btn-primary"
              disabled={!selectedLevel || submitting}
              onClick={handleSubmit}
            >
              {submitting ? t('feedback.submitting') : t('feedback.submit')}
            </button>
            {submitSuccess && (
              <span className="feedback-submit-success">✓ {t('feedback.thank_you')}</span>
            )}
            {submitError && (
              <span className="feedback-submit-error">{submitError}</span>
            )}
          </div>
        </motion.div>
      ) : (
        <div className="feedback-login-card">
          <a href="/login">{t('feedback.login_hint')}</a>{t('feedback.login_to_submit')}
        </div>
      )}

      {items.length > 0 ? (
        <div className="feedback-list">
          {items.map((fb) => (
            <div key={fb.id} className="feedback-list-item">
              <span
                className="feedback-list-level"
                style={{ color: levelLabels[fb.level]?.dot ?? 'var(--color-muted)' }}
              >
                {levelLabels[fb.level]?.label ?? fb.level}
              </span>
              <span className="feedback-list-comment">
                {fb.comment || (levelLabels[fb.level]?.label ?? fb.level)}
              </span>
              <span className="feedback-list-date">
                {new Date(fb.created_at).toLocaleDateString()}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className="feedback-empty">
          {t('feedback.no_feedback')}
        </p>
      )}
    </div>
  );
}
