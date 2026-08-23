'use client';

import PackageIconImage, { getPackageIconSrc } from '@/components/PackageIconImage';

export { getPackageIconSrc };

interface PackageIconProps {
  type?: string | null;
  iconUrl?: string | null;
  label?: string;
}

export default function PackageIcon({ type, iconUrl, label }: PackageIconProps) {
  return (
    <div className="detail-identity-mark">
      <PackageIconImage type={type} iconUrl={iconUrl} alt={label || 'Package icon'} />
    </div>
  );
}
