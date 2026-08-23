'use client';

import { useEffect, useMemo, useState } from 'react';

const PACKAGE_ICON_FALLBACK = '/package-icons/package.svg';

const PACKAGE_ICON_BY_TYPE: Record<string, string> = {
  command: '/package-icons/command.svg',
  'mcp-server': '/package-icons/mcp-server.svg',
  mcp_server: '/package-icons/mcp-server.svg',
  plugin: '/package-icons/plugin.svg',
  prompt: '/package-icons/prompt.svg',
  skill: '/package-icons/skill.svg',
  subagent: '/package-icons/subagent.svg',
};

export function getPackageIconSrc(type?: string | null): string {
  if (!type) {
    return PACKAGE_ICON_FALLBACK;
  }

  return PACKAGE_ICON_BY_TYPE[type] ?? PACKAGE_ICON_FALLBACK;
}

interface PackageIconImageProps {
  type?: string | null;
  iconUrl?: string | null;
  alt: string;
  className?: string;
}

export default function PackageIconImage({ type, iconUrl, alt, className }: PackageIconImageProps) {
  const preferredSrc = useMemo(() => iconUrl || getPackageIconSrc(type), [iconUrl, type]);
  const [src, setSrc] = useState(preferredSrc);

  useEffect(() => {
    setSrc(preferredSrc);
  }, [preferredSrc]);

  return (
    <img
      className={className}
      src={src}
      alt={alt}
      onError={() => setSrc(PACKAGE_ICON_FALLBACK)}
    />
  );
}
