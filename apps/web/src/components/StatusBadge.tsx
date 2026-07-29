'use client';

import { useTranslation } from 'react-i18next';

interface StatusBadgeProps {
  status: string;
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const { t } = useTranslation();

  const statusLabels: Record<string, string> = {
    published: t('status_badge.published'),
    pending_review: t('status_badge.pending_review'),
    rejected: t('status_badge.rejected'),
    draft: t('status_badge.draft'),
    yanked: t('status_badge.yanked'),
  };

  const label = statusLabels[status] ?? status;
  const className = `status-badge ${status}`;

  return <span className={className}>{label}</span>;
}
