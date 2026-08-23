'use client';

import { useTranslation } from 'react-i18next';

interface TypeBadgeProps {
  type: string;
}

export default function TypeBadge({ type }: TypeBadgeProps) {
  const { t } = useTranslation();
  const label = t(`search.${type}`, { defaultValue: type });
  const className = `type-badge ${type}`;

  return <span className={className}>{label}</span>;
}
