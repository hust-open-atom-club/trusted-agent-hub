'use client';

import { useRouter } from 'next/navigation';
import type { Package } from '@/data/packages';
import TypeBadge from './TypeBadge';
import ScoreBadge from './ScoreBadge';
import StatusBadge from './StatusBadge';

interface PackageCardProps {
  pkg: Package;
}

const ICON_PROPS = {
  width: 16,
  height: 16,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const;

function TypeIcon({ type }: { type: string }) {
  switch (type) {
    case 'skill':
      return (
        <svg {...ICON_PROPS}>
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
        </svg>
      );
    case 'mcp_server':
      return (
        <svg {...ICON_PROPS}>
          <path d="M12 22v-5" />
          <path d="M9 8V2" />
          <path d="M15 8V2" />
          <path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z" />
        </svg>
      );
    case 'plugin':
      return (
        <svg {...ICON_PROPS}>
          <path d="M16.5 9.4 7.55 4.24" />
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
          <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
          <line x1="12" y1="22.08" x2="12" y2="12" />
        </svg>
      );
    case 'command':
      return (
        <svg {...ICON_PROPS}>
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      );
    case 'subagent':
      return (
        <svg {...ICON_PROPS}>
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
      );
    case 'prompt':
      return (
        <svg {...ICON_PROPS}>
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      );
    default:
      return (
        <svg {...ICON_PROPS}>
          <path d="M16.5 9.4 7.55 4.24" />
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
          <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
          <line x1="12" y1="22.08" x2="12" y2="12" />
        </svg>
      );
  }
}

function formatFeedback(
  counts?: { positive: number; neutral: number; negative: number } | null,
): string {
  if (
    !counts ||
    counts.positive + counts.neutral + counts.negative === 0
  ) {
    return '暂无评分';
  }
  return `好评 ${counts.positive} · 差评 ${counts.negative}`;
}

export default function PackageCard({ pkg }: PackageCardProps) {
  const router = useRouter();

  const handleClick = () => {
    router.push(`/package/${encodeURIComponent(pkg.name)}`);
  };

  const installCountDisplay =
    pkg.install_count >= 1000
      ? `${(pkg.install_count / 1000).toFixed(1)}k`
      : pkg.install_count;

  return (
    <div className={`package-card card-accent-${pkg.type}`} onClick={handleClick}>
      <div className="card-header">
        <div className="card-title-row">
          <span className="card-type-icon" aria-hidden="true">
            <TypeIcon type={pkg.type} />
          </span>
          <h3 className="card-name">{pkg.name}</h3>
        </div>
        <div className="card-header-right">
          <ScoreBadge grade={pkg.grade} />
        </div>
      </div>

      <p className="card-description">{pkg.description}</p>

      <div className="card-badges">
        <TypeBadge type={pkg.type} />
        <StatusBadge status={pkg.status} />
        {pkg.risk_level && (
          <span className={`risk-level-badge ${pkg.risk_level}`}>{pkg.risk_level.replace(/_/g, ' ')}</span>
        )}
      </div>

      <div className="card-cta">
        <span>查看详情</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
      </div>

      <div className="card-meta">
        <span className="card-meta-item">
          {formatFeedback(pkg.feedback_counts)}
        </span>
        <span className="card-meta-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          {installCountDisplay}
        </span>
        <span className="card-meta-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          v{pkg.latest_version}
        </span>
      </div>
    </div>
  );
}
