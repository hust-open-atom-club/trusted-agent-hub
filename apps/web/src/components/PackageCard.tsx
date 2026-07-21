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
            <span className={`card-grade grade-${pkg.grade.toLowerCase()}`} title={`安全等级 ${pkg.grade}`}>
              {pkg.grade}
            </span>
          )}
          <ScoreBadge score={pkg.trust_score} />
        </div>
      </div>

      <p className="card-description">{pkg.description}</p>

      <div className="card-badges">
        <TypeBadge type={pkg.type} />
        <StatusBadge status={pkg.status} />
        {pkg.risk_level && (
          <span className={`risk-level-badge risk-${pkg.risk_level}`}>{pkg.risk_level.replace(/_/g, ' ')}</span>
        )}
      </div>

      <div className="card-meta">
        <span className="card-meta-item">
          &#11088; {ratingDisplay}
        </span>
        <span className="card-meta-item">
          &#8595; {installCountDisplay}
        </span>
        <span className="card-meta-item">v{pkg.latest_version}</span>
      </div>
    </div>
  );
}
