'use client';

import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { fetchPackage, type Package } from '@/data/packages';
import ScoreBadge from '@/components/ScoreBadge';
import TypeBadge from '@/components/TypeBadge';
import StatusBadge from '@/components/StatusBadge';

const TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

const RISK_LEVEL_LABELS: Record<string, string> = {
  trusted: 'Trusted',
  low_risk: 'Low Risk',
  medium_risk: 'Medium Risk',
  high_risk: 'High Risk',
  untrusted: 'Untrusted',
};

function getGradeClass(grade: string | null): string {
  if (grade === null) return 'unknown';
  const g = grade.toUpperCase();
  if (g === 'A' || g === 'B') return 'trusted';
  if (g === 'C') return 'caution';
  return 'danger';
}

function DetailSkeleton() {
  return (
    <div className="detail-page">
      <div className="skeleton" style={{ marginBottom: '1.5rem' }}>
        <div className="skeleton-bar" style={{ width: '10rem' }} />
      </div>

      <div className="detail-header">
        <div className="detail-title-row">
          <div className="skeleton" style={{ flex: 1 }}>
            <div className="skeleton-bar" style={{ width: '16rem', height: '2rem' }} />
          </div>
        </div>
        <div className="skeleton" style={{ marginTop: '0.5rem' }}>
          <div className="skeleton-bar" style={{ width: '12rem' }} />
        </div>
        <div className="skeleton" style={{ marginTop: '0.75rem' }}>
          <div className="skeleton-bar" style={{ width: '100%' }} />
          <div className="skeleton-bar" style={{ width: '60%', marginTop: '0.25rem' }} />
        </div>
        <div className="detail-meta-grid" style={{ marginTop: '1rem' }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div className="detail-meta-item" key={i}>
              <div className="skeleton">
                <div className="skeleton-bar" style={{ width: '3rem', marginBottom: '0.25rem' }} />
                <div className="skeleton-bar" style={{ width: '5rem' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {['Trust Score', 'Keywords', 'Permissions', 'Installation', 'Versions'].map((section) => (
        <div className="detail-section" key={section}>
          <div className="skeleton" style={{ marginBottom: '0.75rem' }}>
            <div className="skeleton-bar" style={{ width: '8rem', height: '1.25rem' }} />
          </div>
          <div className="skeleton">
            <div className="skeleton-bar" style={{ width: '70%' }} />
            <div className="skeleton-bar" style={{ width: '50%', marginTop: '0.3rem' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function PackageDetailPage() {
  const params = useParams();
  const router = useRouter();
  const name = decodeURIComponent(params.name as string);

  const [pkg, setPkg] = useState<Package | null | undefined>(undefined);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setPkg(undefined);
    fetchPackage(name)
      .then(setPkg)
      .catch(() => setPkg(null))
      .finally(() => setLoading(false));
  }, [name]);

  if (loading) {
    return (
      <div className="detail-page">
        <button className="detail-back" onClick={() => router.push('/')}>
          &larr; Back to packages
        </button>
        <DetailSkeleton />
      </div>
    );
  }

  if (!pkg) {
    return (
      <div className="detail-page">
        <button className="detail-back" onClick={() => router.push('/')}>
          &larr; Back to packages
        </button>
        <div className="empty-state">
          <div className="empty-state-icon">&#x1F4E6;</div>
          <h3>Package not found</h3>
          <p>The package &quot;{name}&quot; does not exist.</p>
        </div>
      </div>
    );
  }

  const gradeClass = getGradeClass(pkg.grade);
  const riskLabel = pkg.risk_level
    ? (RISK_LEVEL_LABELS[pkg.risk_level] ?? pkg.risk_level)
    : 'Unknown';
  const typeLabel = TYPE_LABELS[pkg.type] ?? pkg.type;
  const ratingDisplay =
    pkg.avg_rating !== null ? pkg.avg_rating.toFixed(1) : 'N/A';

  const trustAdvice =
    pkg.grade === null
      ? 'This package has not been evaluated yet.'
      : pkg.grade === 'A' || pkg.grade === 'B'
        ? 'This package has passed all security scans and is safe to install.'
        : pkg.grade === 'C'
          ? 'This package has medium trust. Review the details before installing.'
          : 'This package has low trust. Installation is not recommended without thorough review.';

  return (
    <div className="detail-page">
      <button className="detail-back" onClick={() => router.push('/')}>
        &larr; Back to packages
      </button>

      <div className="detail-header">
        <div className="detail-title-row">
          <h1 className="detail-name">{pkg.name}</h1>
          <TypeBadge type={pkg.type} />
          <StatusBadge status={pkg.status} />
        </div>
        {pkg.owner && (
          <p className="detail-owner">
            by <strong>{pkg.owner.display_name}</strong> (@{pkg.owner.username})
          </p>
        )}
        <p className="detail-description">{pkg.description}</p>

        <div className="detail-meta-grid">
          <div className="detail-meta-item">
            <span className="detail-meta-label">Version</span>
            <span className="detail-meta-value">v{pkg.latest_version}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">License</span>
            <span className="detail-meta-value">{pkg.license}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Type</span>
            <span className="detail-meta-value">{typeLabel}</span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Installs</span>
            <span className="detail-meta-value">
              {pkg.install_count.toLocaleString()}
            </span>
          </div>
          <div className="detail-meta-item">
            <span className="detail-meta-label">Rating</span>
            <span className="detail-meta-value">
              &#11088; {ratingDisplay}
            </span>
          </div>
        </div>
      </div>

      <div className="detail-section">
        <h2>Trust Score</h2>
        <div className={`trust-level ${gradeClass}`}>
          <ScoreBadge grade={pkg.grade} size="lg" />
          <div>
            <span className="trust-label">{riskLabel}</span>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-ink-2)', marginTop: 4 }}>
              {trustAdvice}
            </p>
          </div>
        </div>
      </div>

      <div className="detail-section">
        <h2>Keywords</h2>
        <div className="keyword-list">
          {pkg.keywords.map((kw) => (
            <span key={kw} className="keyword-tag">
              {kw}
            </span>
          ))}
        </div>
      </div>

      <div className="detail-section">
        <h2>Permissions</h2>
        <p>
          This package is a <strong>{typeLabel}</strong>. Based on its type,
          permissions and security checks applied include:
        </p>
        <ul style={{ marginTop: 8 }}>
          <li>Category: {pkg.category}</li>
          <li>Status: {pkg.status.replace(/_/g, ' ')}</li>
          <li>
            Risk Level:{' '}
            {pkg.risk_level ? RISK_LEVEL_LABELS[pkg.risk_level] ?? pkg.risk_level : 'Not evaluated'}
          </li>
        </ul>
      </div>

      <div className="detail-section">
        <h2>Installation</h2>
        <p style={{ marginBottom: 12 }}>
          Install this {typeLabel.toLowerCase()} using the TrustedAgentHub CLI:
        </p>
        <div className="install-block">
          <span className="comment"># Install {pkg.name}</span>
          {'\n'}tah install {pkg.name}
        </div>
        {pkg.homepage && (
          <p style={{ marginTop: 16 }}>
            <strong>Homepage: </strong>
            <a
              href={pkg.homepage}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--color-accent)' }}
            >
              {pkg.homepage}
            </a>
          </p>
        )}
      </div>

      <div className="detail-section">
        <h2>Versions</h2>
        <ul>
          <li>
            <strong>v{pkg.latest_version}</strong> — latest
            {pkg.created_at && (
              <span style={{ color: 'var(--color-muted)', marginLeft: 8 }}>
                ({new Date(pkg.created_at).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                })})
              </span>
            )}
          </li>
        </ul>
      </div>
    </div>
  );
}
