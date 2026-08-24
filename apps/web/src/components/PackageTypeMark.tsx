import type { Package } from '@/types';

interface PackageTypeMarkProps {
  type: Package['type'];
}

function TypeGlyph({ type }: PackageTypeMarkProps) {
  switch (type) {
    case 'skill':
      return (
        <>
          <path d="M5 2.75h6.7a1.3 1.3 0 0 1 1.3 1.3v8.2a.75.75 0 0 1-1.18.62l-2.3-1.55a.9.9 0 0 0-1.01 0l-2.3 1.55A.75.75 0 0 1 5 12.25v-9.5Z" />
          <path d="m8.35 5.1.45.92 1.02.15-.74.72.17 1.02-.9-.48-.91.48.17-1.02-.74-.72 1.02-.15.46-.92Z" />
        </>
      );
    case 'mcp_server':
      return (
        <>
          <rect x="5.25" y="5.25" width="5.5" height="5.5" rx="1.25" />
          <path d="M8 5.25V3.4M5.25 8H3.4m7.85 0h1.85M8 10.75v1.85" />
          <circle cx="8" cy="3" r=".85" />
          <circle cx="3" cy="8" r=".85" />
          <circle cx="13" cy="8" r=".85" />
          <circle cx="8" cy="13" r=".85" />
        </>
      );
    case 'plugin':
      return (
        <path d="M5.15 3.25a1.4 1.4 0 0 1 2.8 0v1.1h1.8a1.25 1.25 0 0 1 1.25 1.25v1.8h1.1a1.4 1.4 0 1 1 0 2.8H11v1.8a1.25 1.25 0 0 1-1.25 1.25h-1.8v-1.1a1.4 1.4 0 1 0-2.8 0v1.1h-1.1a1.25 1.25 0 0 1-1.25-1.25v-1.8h1.1a1.4 1.4 0 1 0 0-2.8H2.8V5.6a1.25 1.25 0 0 1 1.25-1.25h1.1v-1.1Z" />
      );
    case 'command':
      return (
        <>
          <rect x="2.6" y="3.4" width="10.8" height="9.2" rx="1.6" />
          <path d="m5.1 6.4 1.45 1.55L5.1 9.5m3 .05h2" />
        </>
      );
    case 'subagent':
      return (
        <>
          <rect x="3" y="4.25" width="10" height="8" rx="3" />
          <path d="M8 4.25V2.75M6.25 8h.01M9.75 8h.01M6.2 10h3.6" />
          <circle cx="8" cy="2.35" r=".55" />
        </>
      );
    case 'prompt':
      return (
        <>
          <path d="M3.1 4.1A1.6 1.6 0 0 1 4.7 2.5h6.6a1.6 1.6 0 0 1 1.6 1.6v4.4a1.6 1.6 0 0 1-1.6 1.6H7.8l-2.7 2.1v-2.1H4.7a1.6 1.6 0 0 1-1.6-1.6V4.1Z" />
          <path d="M5.4 5.25h5.2M5.4 7.35h3.4" />
        </>
      );
    default:
      return <circle cx="8" cy="8" r="4.5" />;
  }
}

export default function PackageTypeMark({ type }: PackageTypeMarkProps) {
  return (
    <span
      className={`market-type-mark market-type-mark--${type}`}
      aria-hidden="true"
    >
      <svg
        className="market-type-mark__glyph"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.35"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <TypeGlyph type={type} />
      </svg>
    </span>
  );
}
