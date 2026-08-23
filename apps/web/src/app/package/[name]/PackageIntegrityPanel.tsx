'use client';

import { useTranslation } from 'react-i18next';
import type { VersionIntegrity, VersionSource } from '@/types';
import { getIntegrityRows } from './detail-view-model';

interface PackageIntegrityPanelProps {
  source?: VersionSource | null;
  integrity?: VersionIntegrity | null;
}

export default function PackageIntegrityPanel({ source, integrity }: PackageIntegrityPanelProps) {
  const { t } = useTranslation();
  const rows = getIntegrityRows(source, integrity);

  return (
    <div className="integrity-summary">
      <p>{String(t('detail.integrity.verify_hint'))}</p>
      <div className="integrity-grid">
        {rows.map((row) => (
          <div className={`integrity-row ${row.kind}`} key={row.labelKey}>
            <span>{String(t(row.labelKey))}</span>
            {row.kind === 'code' ? (
              <code>{row.value}</code>
            ) : row.value.startsWith('detail.') ? (
              <strong>{String(t(row.value))}</strong>
            ) : (
              <strong>{row.value}</strong>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
