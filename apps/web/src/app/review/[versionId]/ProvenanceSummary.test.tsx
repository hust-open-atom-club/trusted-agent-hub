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
    verification_capabilities: {
      repository: true,
      owner: true,
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
  it('deduplicates a commit ref and shows only meaningful verification results', () => {
    render(<ProvenanceSummary provenance={provenance} />);

    expect(screen.getByText('git')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: repositoryUrl })).toHaveAttribute(
      'href',
      repositoryUrl,
    );
    expect(screen.getAllByText('a'.repeat(40))).toHaveLength(1);
    expect(screen.getByText('不完整，不用于完整性验证')).toBeInTheDocument();
    expect(screen.getByTestId('supply-chain-verification')).toHaveTextContent('1 项已验证，1 项未通过');
    expect(screen.queryByText('签名')).not.toBeInTheDocument();
    expect(screen.queryByText('SBOM')).not.toBeInTheDocument();
  });

  it('shows only package claims that differ from server facts', () => {
    render(<ProvenanceSummary provenance={provenance} />);

    const differences = screen.getByTestId('package-claim-differences');
    expect(differences).toHaveTextContent('https://claims.example/source');
    expect(differences).toHaveTextContent(repositoryUrl);
  });

  it('hides empty claims and unavailable verification checks', () => {
    const quiet: ScanProvenance = {
      ...provenance,
      acquisition_facts: {
        ...provenance.acquisition_facts,
        verification: {
          repository: true,
          owner: false,
          signature: false,
          attestation: false,
          sbom: false,
        },
        verification_capabilities: {
          repository: true,
          owner: false,
          signature: false,
          attestation: false,
          sbom: false,
        },
      },
      package_claims: {
        source: { repository_url: '', mirrors: [] },
        integrity: {},
      },
    };

    render(<ProvenanceSummary provenance={quiet} />);

    expect(screen.queryByTestId('supply-chain-verification')).not.toBeInTheDocument();
    expect(screen.queryByTestId('package-claim-differences')).not.toBeInTheDocument();
  });

  it('renders nothing when provenance is unavailable', () => {
    const { container } = render(<ProvenanceSummary provenance={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
