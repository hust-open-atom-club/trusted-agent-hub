'use client';

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ScanTaskItem } from '@/types';

/** Only unsubmitted terminal tasks have a cleanup deadline. */
export default function ScanRetentionNotice({ item }: { item: ScanTaskItem }) {
  const { t, i18n } = useTranslation();
  const [now, setNow] = useState<number | null>(null);
  const eligible = !item.submission
    && !['submitted_reviewing', 'callback_pending'].includes(item.lifecycle)
    && ['complete', 'error', 'llm_timeout', 'total_timeout'].includes(item.status);
  const deadline = item.expires_at ? Date.parse(item.expires_at) : NaN;
  const visible = eligible && Number.isFinite(deadline);

  useEffect(() => {
    if (!visible) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, [visible, deadline]);

  if (!visible || now === null) return null;
  const remaining = deadline - now;
  const minutes = Math.max(0, Math.ceil(remaining / 60_000));
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const countdown = days > 0
    ? t('scans.cleanup_days_hours', { days, hours })
    : minutes >= 60
      ? t('scans.cleanup_hours_minutes', { hours, minutes: minutes % 60 })
      : t('scans.cleanup_minutes', { minutes });

  return (
    <div className="scan-retention-notice">
      <p>
        {remaining <= 0
          ? t('scans.cleanup_due')
          : item.status === 'complete'
            ? t('scans.submit_soon')
            : t('scans.failed_retention')}
      </p>
      {remaining > 0 && <p>{t('scans.cleanup_remaining', { remaining: countdown })}</p>}
      <p>
        {t('scans.cleanup_at')}: {' '}
        <time dateTime={item.expires_at!}>
          {new Date(deadline).toLocaleString(i18n.language === 'zh' ? 'zh-CN' : 'en-US', {
            dateStyle: 'medium', timeStyle: 'short',
          })}
        </time>
      </p>
    </div>
  );
}
