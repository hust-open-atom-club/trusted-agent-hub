'use client';

import { useTranslation } from 'react-i18next';
import type { TrustScore } from '@/types';

/* ── Grade → visual helpers ─────────────────────────────────────────── */

const GRADE_COLORS: Record<string, { bg: string; fg: string; border: string }> = {
  A: { bg: 'oklch(92% 0.04 140)', fg: 'oklch(35% 0.08 140)', border: 'oklch(75% 0.06 140)' },
  B: { bg: 'oklch(94% 0.03 220)', fg: 'oklch(35% 0.06 220)', border: 'oklch(78% 0.05 220)' },
  C: { bg: 'oklch(92% 0.06 85)',  fg: 'oklch(35% 0.08 80)',  border: 'oklch(75% 0.08 85)' },
  D: { bg: 'oklch(90% 0.05 45)',  fg: 'oklch(35% 0.09 40)',  border: 'oklch(72% 0.07 45)' },
  E: { bg: 'oklch(88% 0.05 20)',  fg: 'oklch(38% 0.10 20)',  border: 'oklch(68% 0.07 20)' },
};

const TOP_RISK_KEYS: Record<string, string> = {
  'Source provenance is opaque — origin cannot be verified': 'source_opaque',
  'No content integrity hash or signature': 'integrity_missing',
  'Dangerous permission combination declared': 'permissions_dangerous',
  'Permissions are excessive for package type': 'permissions_excessive',
  'Scan found critical/high-severity dangerous findings': 'scan_dangerous',
  'Scan results are suspicious or unavailable': 'scan_suspicious',
  'Behavior inconsistency indicates deception or malicious intent': 'behavior_deceptive',
  'Declared permissions exceed what scan findings suggest is needed': 'behavior_overreaching',
  'Package was rejected during manual review': 'review_rejected',
  'Author has a tainted history with serious violations': 'author_tainted',
  'Author has an inconsistent publishing record': 'author_inconsistent',
  'No significant risks identified': 'none',
};

/** effective_grade → risk_level */
function gradeToRiskLevel(grade: string | null | undefined): string {
  if (!grade) return '';
  const map: Record<string, string> = {
    A: 'trusted', B: 'low_risk', C: 'medium_risk', D: 'high_risk', E: 'untrusted',
  };
  return map[grade] ?? '';
}

/** effective_grade → install_recommendation */
function gradeToRecommendation(grade: string | null | undefined): string {
  if (!grade) return '';
  const map: Record<string, string> = {
    A: 'safe', B: 'review_recommended', C: 'caution', D: 'not_recommended', E: 'blocked',
  };
  return map[grade] ?? '';
}

export interface TrustScoreDetailProps {
  trustScore: TrustScore | null | undefined;
  /** Effective grade (manual_grade ?? auto_grade) from version detail */
  effectiveGrade?: string | null;
  /** Auto grade from scan result */
  autoGrade?: string | null;
  /** Manual grade set by reviewer */
  manualGrade?: string | null;
  /** Reason for manual grade override */
  manualGradeReason?: string | null;
}

export default function TrustScoreDetail({
  trustScore,
  effectiveGrade,
  autoGrade,
  manualGrade,
  manualGradeReason,
}: TrustScoreDetailProps) {
  const { t } = useTranslation();

  if (!trustScore) return null;

  const summary = trustScore.risk_summary;
  const topRisks = summary?.top_risks ?? [];
  const explanations = trustScore.explanations;
  const modelFingerprint = trustScore.model_fingerprint;
  const fingerprintPreview = modelFingerprint && modelFingerprint.length > 12
    ? `${modelFingerprint.slice(0, 12)}…`
    : modelFingerprint;
  const hasModelMetadata = Boolean(trustScore.model_version || modelFingerprint);

  // Use effective_grade from props first, fall back to risk_summary.grade
  const grade = effectiveGrade ?? summary?.grade;
  const riskLevel = gradeToRiskLevel(grade);
  const recommendation = gradeToRecommendation(grade);

  const gradeColor = grade ? GRADE_COLORS[grade] : null;
  const gradeLabel = (value: string) => t(`trust_score.grade.${value}`, value);
  const localizeTopRisk = (risk: string) => {
    const key = TOP_RISK_KEYS[risk];
    return key ? t(`trust_score.risk.${key}`) : risk;
  };
  const localizeExplanation = (message: string) => {
    const assessed = message.match(/^(.+): assessed as '(.+)'$/);
    if (assessed) {
      return t('trust_score.explanation.assessed', {
        dimension: t(`trust_score.dim.${assessed[1]}`, assessed[1]),
        level: t(`trust_score.assessment.${assessed[2]}`, assessed[2]),
      });
    }
    const behavior = message.match(/^Behavior consistency check: (.+)$/);
    if (behavior) {
      return t('trust_score.explanation.behavior', {
        level: t(`trust_score.assessment.${behavior[1]}`, behavior[1]),
      });
    }
    const veto = message.match(/^Veto triggered: (.+) — package forced to untrusted$/);
    if (veto) return t('trust_score.explanation.veto', { rule: veto[1] });
    const fixed: Record<string, string> = {
      'Upgrade applied: approved review + safe scan + consistent behavior': 'upgrade',
      'Downgrade applied: opaque source + newcomer author': 'downgrade',
    };
    return fixed[message] ? t(`trust_score.explanation.${fixed[message]}`) : message;
  };

  return (
    <div style={{
      background: 'var(--color-paper-2)',
      borderRadius: 'var(--radius-md)',
      border: '1px solid var(--color-rule)',
      overflow: 'hidden',
    }}>
      {/* ── Header: grade badge + risk level + recommendation ── */}
      <div style={{
        padding: '1rem 1.25rem',
        borderBottom: '1px solid var(--color-rule)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        flexWrap: 'wrap',
      }}>
        {/* Grade badge */}
        {grade && gradeColor && (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            padding: '0.2rem 0.75rem',
            borderRadius: 'var(--radius-pill)',
            fontSize: '0.85rem',
            fontWeight: 700,
            background: gradeColor.bg,
            color: gradeColor.fg,
            border: `1px solid ${gradeColor.border}`,
          }}>
            {gradeLabel(grade)}
          </span>
        )}

        {/* Risk level */}
        {riskLevel && (
          <span style={{
            fontSize: '0.78rem',
            fontWeight: 600,
            color: 'var(--color-muted)',
          }}>
            {t(`trust_score.level.${riskLevel}`, riskLevel)}
          </span>
        )}

        {/* Recommendation */}
        {recommendation && (
          <span style={{
            fontSize: '0.75rem',
            color: 'var(--color-ink-2)',
            fontStyle: 'italic',
          }}>
            {t(`trust_score.recommendation.${recommendation}`, recommendation)}
          </span>
        )}
      </div>

      {/* ── Grade source: auto vs manual ── */}
      {(autoGrade || manualGrade) && (
        <div style={{
          padding: '0.6rem 1.25rem',
          borderBottom: '1px solid var(--color-rule)',
          fontSize: '0.75rem',
          color: 'var(--color-ink-2)',
          lineHeight: 1.6,
        }}>
          {autoGrade && (
            <div>
              <span style={{ fontWeight: 600, color: 'var(--color-muted)' }}>
                {t('trust_score.auto_grade')}:
              </span>
              {' '}{gradeLabel(autoGrade)}
            </div>
          )}
          {manualGrade && (
            <div>
              <span style={{ fontWeight: 600, color: 'var(--color-muted)' }}>
                {t('trust_score.manual_grade')}:
              </span>
              {' '}{gradeLabel(manualGrade)}
              {manualGradeReason && (
                <span style={{ marginLeft: '0.5rem' }}>
                  — {manualGradeReason}
                </span>
              )}
            </div>
          )}
          {!manualGrade && autoGrade && (
            <div style={{ fontSize: '0.7rem', color: 'var(--color-muted)', marginTop: '0.15rem' }}>
              {t('trust_score.no_manual_override')}
            </div>
          )}
        </div>
      )}

      {/* ── Top risks ── */}
      {topRisks.length > 0 && (
        <div style={{
          padding: '0.75rem 1.25rem',
          borderBottom: '1px solid var(--color-rule)',
        }}>
          <div style={{
            fontSize: '0.72rem',
            fontWeight: 700,
            color: 'var(--color-muted)',
            textTransform: 'uppercase',
            marginBottom: '0.4rem',
          }}>
            {t('trust_score.top_risks')}
          </div>
          <ul style={{
            margin: 0,
            paddingLeft: '1.2rem',
            fontSize: '0.76rem',
            color: 'var(--color-ink-2)',
            lineHeight: 1.6,
          }}>
            {topRisks.map((risk, i) => (
              <li key={i}>{localizeTopRisk(risk)}</li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Explanations (messages only, no deduction scores) ── */}
      {explanations && explanations.length > 0 && (
        <div style={{ padding: '0.75rem 1.25rem' }}>
          <div style={{
            fontSize: '0.72rem',
            fontWeight: 700,
            color: 'var(--color-muted)',
            textTransform: 'uppercase',
            marginBottom: '0.4rem',
          }}>
            {t('trust_score.explanations')}
          </div>
          <ul style={{
            margin: 0,
            paddingLeft: '1.2rem',
            fontSize: '0.76rem',
            color: 'var(--color-ink-2)',
            lineHeight: 1.6,
          }}>
            {explanations.map((exp, i) => (
              <li key={i}>{localizeExplanation(exp.message)}</li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Trust-score model identity ── */}
      {hasModelMetadata && (
        <div style={{
          padding: '0.6rem 1.25rem',
          borderTop: '1px solid var(--color-rule)',
          display: 'flex',
          gap: '1rem',
          flexWrap: 'wrap',
          fontSize: '0.72rem',
          color: 'var(--color-ink-2)',
        }}>
          {trustScore.model_version && (
            <div>
              <span style={{ fontWeight: 600, color: 'var(--color-muted)' }}>
                {t('trust_score.model_version')}:
              </span>
              {' '}
              <code>{trustScore.model_version}</code>
            </div>
          )}
          {modelFingerprint && (
            <div>
              <span style={{ fontWeight: 600, color: 'var(--color-muted)' }}>
                {t('trust_score.model_fingerprint')}:
              </span>
              {' '}
              <code title={modelFingerprint}>{fingerprintPreview}</code>
            </div>
          )}
        </div>
      )}

      {/* ── Empty state ── */}
      {!grade && topRisks.length === 0 && (!explanations || explanations.length === 0) && !hasModelMetadata && (
        <div style={{
          padding: '1.5rem 1.25rem',
          textAlign: 'center',
          fontSize: '0.78rem',
          color: 'var(--color-muted)',
        }}>
          {t('trust_score.no_data')}
        </div>
      )}
    </div>
  );
}
