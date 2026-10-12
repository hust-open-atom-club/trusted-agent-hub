'use client';

import { useTranslation } from 'react-i18next';
import type { PermissionEvidence } from '@/types';

export default function PermissionEvidenceList({ items }: { items: PermissionEvidence[] }) {
  const { t } = useTranslation();
  return (
    <div className="review-meta-grid">
      {items.map((item, index) => (
        <div className="review-meta-field full" key={`${item.capability}-${item.file || 'package'}-${index}`}>
          <span className="review-meta-label" title={item.capability}>
            {t(item.capability.includes('.')
              ? `review.permission.${item.capability}`
              : `review.permission_evidence.capability.${item.capability}`, item.capability)}
          </span>
          <span className="review-meta-value">
            {t(`review.permission_evidence.status.${item.status}`, item.status)}
            {' · '}{Math.round(item.confidence * 100)}%
            {' · '}{t(`review.permission_evidence.source.${item.source}`, item.source)}
            {item.file ? ` · ${item.file}` : ''}
          </span>
          <span className="review-meta-value">
            {item.evidence === '包元数据明确声明该权限'
              ? t('review.permission_evidence.manifest_declared')
              : item.evidence}
          </span>
        </div>
      ))}
    </div>
  );
}
