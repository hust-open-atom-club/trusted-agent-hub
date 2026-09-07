import { describe, expect, it } from 'vitest';

import {
  distinctProjectHomepage,
  getAllowedSubmissionClients,
  inferGithubOwnerHomepage,
  isGithubProfileUrl,
  normalizeSubmissionClients,
  redactAuthorEmailForPreview,
} from './submission-metadata';

describe('submission client choices', () => {
  it('allows Codex for Skills but not MCP servers', () => {
    expect(getAllowedSubmissionClients('skill')).toEqual([
      'claude-code',
      'cursor',
      'codex',
    ]);
    expect(getAllowedSubmissionClients('mcp_server')).toEqual([
      'claude-code',
      'cursor',
    ]);
  });

  it('filters invalid scanned values and always returns a non-empty default', () => {
    expect(normalizeSubmissionClients('skill', ['cursor', 'invalid', 'cursor'])).toEqual(['cursor']);
    expect(normalizeSubmissionClients('plugin', [])).toEqual(['claude-code-plugin']);
  });
});

describe('submission author and homepage metadata', () => {
  it('infers a GitHub owner homepage from source metadata', () => {
    expect(inferGithubOwnerHomepage('https://github.com/acme/demo', 'acme')).toBe('https://github.com/acme');
    expect(inferGithubOwnerHomepage('https://github.com/octo/repo.git')).toBe('https://github.com/octo');
  });

  it('accepts only GitHub profile or organization URLs', () => {
    expect(isGithubProfileUrl('https://github.com/acme')).toBe(true);
    expect(isGithubProfileUrl('https://github.com/acme/')).toBe(true);
    expect(isGithubProfileUrl('https://github.com/acme/project')).toBe(false);
    expect(isGithubProfileUrl('https://example.com/acme')).toBe(false);
  });

  it('drops a homepage that repeats the source repository', () => {
    expect(distinctProjectHomepage(
      'https://github.com/Acme/Demo/',
      'https://github.com/acme/demo.git',
    )).toBe('');
    expect(distinctProjectHomepage(
      'https://docs.example.com/demo',
      'https://github.com/acme/demo',
    )).toBe('https://docs.example.com/demo');
  });

  it('hides only the author email in raw metadata previews', () => {
    expect(redactAuthorEmailForPreview({
      name: 'demo',
      author: { name: 'Acme', email: 'private@example.com', url: 'https://github.com/acme' },
    })).toEqual({
      name: 'demo',
      author: { name: 'Acme', url: 'https://github.com/acme' },
    });
  });
});
