import { describe, expect, it } from 'vitest';
import { sourceCodeUrl } from './source-url';

describe('sourceCodeUrl', () => {
  it('pins a package subdirectory to its acquired commit rather than a moving branch', () => {
    expect(sourceCodeUrl({
      repository_url: 'https://github.com/beibainian/package.git',
      commit_hash: 'a21b461ccad3ee11749f1eabff4c84c455b7517a',
      ref: 'main', subdirectory: 'test-tool-poisoning-mcp',
    })).toBe('https://github.com/beibainian/package/tree/a21b461ccad3ee11749f1eabff4c84c455b7517a/test-tool-poisoning-mcp');
  });

  it('encodes a branch and nested path independently', () => {
    expect(sourceCodeUrl({ repository_url: 'https://github.com/org/repo', ref: 'feature/test', subdirectory: 'packages/hello world' }))
      .toBe('https://github.com/org/repo/tree/feature%2Ftest/packages/hello%20world');
  });

  it('uses GitHub HEAD only when the directory has no recorded revision', () => {
    expect(sourceCodeUrl({ repository_url: 'https://github.com/org/repo', subdirectory: 'tools' }))
      .toBe('https://github.com/org/repo/tree/HEAD/tools');
    expect(sourceCodeUrl({ repository_url: 'https://github.com/org/repo' }))
      .toBe('https://github.com/org/repo');
  });

  it('preserves other hosts and does not turn unsafe URLs into links', () => {
    expect(sourceCodeUrl({ repository_url: 'https://gitlab.com/org/repo', subdirectory: 'tools' }))
      .toBe('https://gitlab.com/org/repo');
    expect(sourceCodeUrl({ repository_url: 'javascript:alert(1)' })).toBeUndefined();
    expect(sourceCodeUrl({ repository_url: 'invalid' })).toBeUndefined();
    expect(sourceCodeUrl(null)).toBeUndefined();
  });
});
