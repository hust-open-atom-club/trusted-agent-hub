import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { ScanProvenance } from '@/types';

import ProvenanceSummary from './ProvenanceSummary';

const repositoryUrl = 'https://github.com/example/trusted-agent';

const provenance: ScanProvenance = {
  acquisition_facts: {
    source: {
      repository_url: repositoryUrl,
      owner: 'example',
      repo: 'trusted-agent',
      ref_type: 'commit',
      ref: 'a'.repeat(40),
      commit_hash: 'a'.repeat(40),
      verified_owner: false,
      subdirectory: 'packages/demo',
    },
    integrity: {
      sha256: 'b'.repeat(64),
      hash_scope: 'scanned_source',
      is_complete: false,
    },
    verification: {
      repository: true,
      owner: false,
      signature: false,
      attestation: true,
      sbom: false,
    },
    acquisition_method: 'git',
  },
  package_claims: {
    source: { repository_url: 'https://claims.example/source' },
    integrity: {},
  },
};

describe('ProvenanceSummary', () => {
  it('renders acquisition, source, integrity and verification facts', () => {
    render(<ProvenanceSummary provenance={provenance} />);

    expect(screen.getByText('git')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: repositoryUrl })).toHaveAttribute(
      'href',
      repositoryUrl,
    );
    expect(screen.getAllByText('a'.repeat(40)).length).toBeGreaterThan(0);
    expect(screen.getByText('不完整')).toBeInTheDocument();
    expect(screen.getByText('仓库身份验证').parentElement).toHaveTextContent('已验证');
    expect(screen.getByText('所有者验证').parentElement).toHaveTextContent('未验证');
    expect(screen.getByText('源码声明：1 个字段')).toBeInTheDocument();
  });

  it('renders nothing when provenance is unavailable', () => {
    const { container } = render(<ProvenanceSummary provenance={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
