interface SourceReference {
  repository_url?: string | null;
  subdirectory?: string | null;
  commit_hash?: string | null;
  ref?: string | null;
}

/** Link to the exact scanned revision and directory when GitHub supplies them. */
export function sourceCodeUrl(source?: SourceReference | null): string | undefined {
  if (!source?.repository_url) return undefined;
  try {
    const url = new URL(source.repository_url);
    if (!['http:', 'https:'].includes(url.protocol)) return undefined;
    if (url.hostname !== 'github.com') return url.href;
    const [owner, repository] = url.pathname.split('/').filter(Boolean);
    if (!owner || !repository) return url.href;
    const root = `${url.origin}/${owner}/${repository.replace(/\.git$/, '')}`;
    const directory = source.subdirectory?.split('/').filter(Boolean) ?? [];
    if (directory.some((part) => part === '.' || part === '..')) return root;
    const revision = source.commit_hash || source.ref;
    if (!revision && directory.length === 0) return root;
    const path = directory.map(encodeURIComponent).join('/');
    return `${root}/tree/${encodeURIComponent(revision || 'HEAD')}${path ? `/${path}` : ''}`;
  } catch {
    return undefined;
  }
}
