'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { Package } from '@/data/packages';
import TypeBadge from './TypeBadge';
import ScoreBadge from './ScoreBadge';
import StatusBadge from './StatusBadge';
import PackageIconImage from './PackageIconImage';

interface PackageCardProps {
  pkg: Package;
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

function formatRiskLevel(riskLevel: string | null): string {
  const labels: Record<string, string> = {
    trusted: '可信',
    low_risk: '低风险',
    medium_risk: '中风险',
    high_risk: '高风险',
    untrusted: '不可信',
  };
  return riskLevel ? labels[riskLevel] ?? riskLevel.replace(/_/g, ' ') : '未评级';
}

const CARD_NAME_FONT_SIZES = [16, 15, 14, 13];

function CardName({ name }: { name: string }) {
  const nameRef = useRef<HTMLHeadingElement>(null);
  const [fontSize, setFontSize] = useState(CARD_NAME_FONT_SIZES[0]);

  useEffect(() => {
    const element = nameRef.current;
    if (!element) return undefined;

    const fitName = () => {
      let fittedSize = CARD_NAME_FONT_SIZES[CARD_NAME_FONT_SIZES.length - 1];

      for (const size of CARD_NAME_FONT_SIZES) {
        element.style.fontSize = `${size}px`;
        if (element.scrollWidth <= element.clientWidth) {
          fittedSize = size;
          break;
        }
      }

      setFontSize((currentSize) => currentSize === fittedSize ? currentSize : fittedSize);
    };

    fitName();

    if (typeof ResizeObserver === 'undefined') {
      return undefined;
    }

    const observer = new ResizeObserver(fitName);
    observer.observe(element);
    return () => observer.disconnect();
  }, [name]);

  return (
    <h3
      ref={nameRef}
      className="card-name"
      style={{ fontSize: `${fontSize}px` }}
      title={name}
    >
      {name}
    </h3>
  );
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
  const trustSummary = `${pkg.grade ?? '--'} · ${formatRiskLevel(pkg.risk_level)}`;

  return (
    <div className={`package-card card-accent-${pkg.type}`} onClick={handleClick}>
      <div className="card-header">
        <div className="card-title-row">
          <span className="card-type-icon">
            <PackageIconImage
              type={pkg.type}
              iconUrl={pkg.icon_url}
              alt={`${pkg.name} icon`}
              className="card-type-image"
            />
          </span>
          <div className="card-title-copy">
            <CardName name={pkg.name} />
            <span className={`card-trust-summary risk-${pkg.risk_level ?? 'unknown'}`}>
              {trustSummary}
            </span>
          </div>
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
          <span className={`risk-level-badge ${pkg.risk_level}`}>{formatRiskLevel(pkg.risk_level)}</span>
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
