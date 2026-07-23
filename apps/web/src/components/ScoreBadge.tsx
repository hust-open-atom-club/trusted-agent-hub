'use client';

interface ScoreBadgeProps {
  grade: string | null;
  size?: 'sm' | 'lg';
}

function getGradeClass(grade: string | null): string {
  if (grade === null) return 'unknown';
  const g = grade.toUpperCase();
  if (g === 'A' || g === 'B') return 'trusted';
  if (g === 'C') return 'caution';
  if (g === 'D' || g === 'E' || g === 'F') return 'danger';
  return 'unknown';
}

export default function ScoreBadge({ grade, size = 'sm' }: ScoreBadgeProps) {
  const classNames = [
    'score-badge',
    getGradeClass(grade),
    size === 'lg' ? 'size-lg' : '',
  ]
    .filter(Boolean)
    .join(' ');

  const display = grade ?? '--';

  return <span className={classNames}>{display}</span>;
}
