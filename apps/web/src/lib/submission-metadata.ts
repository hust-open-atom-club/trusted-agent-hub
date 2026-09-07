import {
  PACKAGE_TYPE_INSTALL_CLIENTS,
  type PackageType,
} from '../../../../packages/schema/constants';

export function getAllowedSubmissionClients(packageType: string): string[] {
  return [
    ...(PACKAGE_TYPE_INSTALL_CLIENTS[packageType as PackageType] ?? []),
  ];
}

export function normalizeSubmissionClients(
  packageType: string,
  values: readonly string[] | null | undefined,
): string[] {
  const allowed = getAllowedSubmissionClients(packageType);
  const selected = Array.from(new Set(values ?? [])).filter((value) =>
    allowed.includes(value),
  );
  return selected.length > 0 ? selected : allowed;
}

export function canonicalComparisonUrl(value: string | null | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    let pathname = parsed.pathname.replace(/\/+$/, '');
    if (pathname.toLowerCase().endsWith('.git')) pathname = pathname.slice(0, -4);
    if (parsed.hostname.toLowerCase() === 'github.com') pathname = pathname.toLowerCase();
    return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${pathname}`;
  } catch {
    return trimmed.replace(/\/+$/, '');
  }
}

export function distinctProjectHomepage(
  homepage: string | null | undefined,
  repositoryUrl: string | null | undefined,
): string {
  const value = homepage?.trim() ?? '';
  if (
    value
    && canonicalComparisonUrl(value) === canonicalComparisonUrl(repositoryUrl)
  ) {
    return '';
  }
  return value;
}

export function inferGithubOwnerHomepage(
  repositoryUrl: string | null | undefined,
  repositoryOwner?: string | null,
): string {
  const suppliedOwner = repositoryOwner?.trim();
  if (
    suppliedOwner
    && suppliedOwner.toLowerCase() !== 'unknown'
    && !suppliedOwner.includes('/')
  ) {
    return `https://github.com/${suppliedOwner}`;
  }
  const match = repositoryUrl?.trim().match(
    /^https?:\/\/github\.com\/([^/?#]+)\/[^/?#]+?(?:\.git)?(?:\/|$)/i,
  );
  return match ? `https://github.com/${match[1]}` : '';
}

export function isGithubProfileUrl(value: string): boolean {
  try {
    const parsed = new URL(value.trim());
    const segments = parsed.pathname.split('/').filter(Boolean);
    return (
      parsed.protocol === 'https:'
      && parsed.hostname.toLowerCase() === 'github.com'
      && segments.length === 1
      && !parsed.search
      && !parsed.hash
    );
  } catch {
    return false;
  }
}

export function redactAuthorEmailForPreview(
  metadata: Record<string, unknown>,
): Record<string, unknown> {
  const author = metadata.author;
  if (!author || typeof author !== 'object' || Array.isArray(author)) {
    return metadata;
  }
  const safeAuthor = { ...(author as Record<string, unknown>) };
  delete safeAuthor.email;
  return { ...metadata, author: safeAuthor };
}
