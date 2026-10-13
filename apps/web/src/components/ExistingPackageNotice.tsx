'use client';

import Link from 'next/link';
import { useTranslation } from 'react-i18next';
import { blocksNewPackage, RESUBMITTABLE_STATUSES, versionStatusHref, type ExistingPackage } from '@/lib/submission-workflow';

export default function ExistingPackageNotice({ existing, version, scanId, onNavigate }: {
  existing: ExistingPackage;
  version: string;
  scanId?: string;
  onNavigate: () => void;
}) {
  const { t } = useTranslation();
  const selected = existing.versions.find(v => v.version === version)
    ?? [...existing.versions].sort((a, b) =>
      (Date.parse(b.submitted_at ?? '') || 0) - (Date.parse(a.submitted_at ?? '') || 0)
      || b.version.localeCompare(a.version, undefined, { numeric: true }))[0];
  const statusHref = selected
    ? versionStatusHref(existing.package_name, selected.version, selected.id)
    : null;
  const newVersionQuery = new URLSearchParams({ packageId: existing.package_id });
  if (scanId) newVersionQuery.set('scan', scanId);

  return (
    <section className="submit-notice" aria-label="已有包提交指引">
      <div>
        <strong>检测到已有包：{existing.package_name}</strong>
        {selected && <p>v{selected.version} · {t(`submissions.status.${selected.status}`, { defaultValue: selected.status })}</p>}
        <p>{blocksNewPackage(existing)
          ? '包名已存在。请查看已有版本；需修改或扫描失败的版本可重新提交，也可创建不同版本号的新版本。已有包和审核历史会保留。'
          : '检测到未完成的草稿。源码一致时可继续提交，或先查看草稿状态。'}</p>
      </div>
      <div className="submit-notice__actions">
        {statusHref && <Link href={statusHref} onClick={onNavigate} className="btn btn-secondary btn-sm">查看状态</Link>}
        {selected && RESUBMITTABLE_STATUSES.has(selected.status) && (
          <Link href={`${versionStatusHref(existing.package_name, selected.version, selected.id, scanId)}#resubmit`}
            onClick={onNavigate} className="btn btn-primary btn-sm">重新提交</Link>
        )}
        <Link href={`/submit?${newVersionQuery}`} onClick={onNavigate} className="btn btn-secondary btn-sm">创建新版本</Link>
      </div>
    </section>
  );
}
