'use client';

import { useRouter } from 'next/navigation';
import type { Package } from '@/data/packages';
import TypeBadge from './TypeBadge';
import ScoreBadge from './ScoreBadge';
import StatusBadge from './StatusBadge';

interface PackageCardProps {
  pkg: Package;
}

export default function PackageCard({ pkg }: PackageCardProps) {
  const router = useRouter();

  const handleClick = () => {
    router.push(`/package/${encodeURIComponent(pkg.name)}`);
  };

  const ratingDisplay =
    pkg.avg_rating !== null ? pkg.avg_rating.toFixed(1) : '--';

  const installCountDisplay =
    pkg.install_count >= 1000
      ? `${(pkg.install_count / 1000).toFixed(1)}k`
      : pkg.install_count;

  return (
    <div className="package-card" onClick={handleClick}>
      <div className="card-header">
        <h3 className="card-name">{pkg.name}</h3>
        <div className="card-header-right">
          {pkg.grade && (
            <span className={`card-grade grade-${pkg.grade.toLowerCase()}`} title={`Trust Grade ${pkg.grade}`}>
              {pkg.grade}
            </span>
          )}
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

      <div className="card-meta">
        <span className="card-meta-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          {ratingDisplay}
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
