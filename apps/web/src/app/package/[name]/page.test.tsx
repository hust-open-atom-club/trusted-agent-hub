import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Package, PublicVersionDetail } from '@/types';

const mocks = vi.hoisted(() => ({
  fetchPackage: vi.fn(),
  fetchPackageVersion: vi.fn(),
  fetchPackageVersions: vi.fn(),
}));

vi.mock('@/data/packages', () => ({
  fetchPackage: mocks.fetchPackage,
  fetchPackageVersion: mocks.fetchPackageVersion,
  fetchPackageVersions: mocks.fetchPackageVersions,
}));

vi.mock('@/lib/auth', () => ({
  useAuth: () => ({ user: null, token: null }),
}));

vi.mock('next/navigation', () => ({
  useParams: () => ({ name: 'demo-skill' }),
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    prefetch: vi.fn(),
  }),
}));

vi.mock('@/components/FeedbackSection', () => ({
  default: () => null,
}));

// The app-router motion wrappers rely on IntersectionObserver, which jsdom lacks.
vi.mock('framer-motion', async () => {
  const React = await import('react');
  const motionOnlyProps = new Set([
    'variants',
    'initial',
    'animate',
    'whileInView',
    'viewport',
    'transition',
    'layout',
  ]);

  const createMotionComponent = (tag: string) =>
    function MotionComponent({ children, ...props }: { children?: unknown }) {
      const domProps = Object.fromEntries(
        Object.entries(props).filter(([key]) => !motionOnlyProps.has(key)),
      );
      return React.createElement(tag, domProps, children as never);
    };

  return {
    motion: new Proxy({}, {
      get: (_target, tag: string) => createMotionComponent(tag),
    }),
  };
});

import PackageDetailPage from './page';

function makePackage(overrides: Partial<Package> = {}): Package {
  return {
    id: 'pkg-1',
    name: 'demo-skill',
    description: 'Demo description',
    type: 'skill',
    license: 'MIT',
    keywords: ['alpha'],
    category: 'development',
    homepage: null,
    icon_url: null,
    owner: { id: 'owner-1', display_name: 'Demo Owner', role: 'producer' },
    latest_version: '1.0.0',
    status: 'published',
    risk_level: 'trusted',
    grade: 'A',
    install_count: 42,
    avg_rating: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z',
    ...overrides,
  };
}

function makeVersionDetail(
  overrides: Partial<PublicVersionDetail> = {},
): PublicVersionDetail {
  return {
    name: 'demo-skill',
    version: '1.0.0',
    compatibility: ['claude-code', 'cursor', 'codex'],
    permission_summary: {
      filesystem_read_count: 1,
      filesystem_write_count: 0,
      filesystem_delete: false,
      shell_allowed: true,
      network_allowed: false,
      environment_read_count: 0,
      environment_write_count: 0,
      credentials_access_count: 0,
      database_declared: false,
      browser_declared: false,
      external_services_count: 0,
    },
    installation: {
      method: 'copy_directory',
      targets: [
        { client: 'claude-code', destination: '~/.claude/skills/demo-skill/' },
        { client: 'cursor', destination: '~/.cursor/skills/demo-skill/' },
        { client: 'codex', destination: '~/.codex/skills/demo-skill/' },
      ],
      target_client: 'claude-code',
    },
    effective_grade: 'A',
    risk_level: 'trusted',
    install_recommendation: 'safe',
    ...overrides,
  };
}

describe('PackageDetailPage summary duplication', () => {
  beforeEach(() => {
    mocks.fetchPackage.mockResolvedValue(makePackage());
    mocks.fetchPackageVersion.mockResolvedValue(makeVersionDetail());
    mocks.fetchPackageVersions.mockResolvedValue([
      {
        id: 'version-1',
        version: '1.0.0',
        status: 'published',
        submitted_at: '2026-01-01T00:00:00Z',
      },
    ]);
  });

  it('renders each package summary fact exactly once', async () => {
    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(
      screen.getAllByText('读取 1 个路径 · 写入 0 个路径 · 删除权限：未允许'),
    ).toHaveLength(1);
    expect(screen.getAllByText('可安全安装')).toHaveLength(1);
    expect(screen.getAllByText('评级 A · 可信')).toHaveLength(1);
    expect(screen.getAllByText('Skill')).toHaveLength(1);
    expect(screen.queryByText('类型')).not.toBeInTheDocument();
    expect(screen.getAllByText('兼容客户端')).toHaveLength(1);
    expect(screen.queryByText(/^兼容客户端：/)).not.toBeInTheDocument();
    expect(screen.getAllByText('~/.claude/skills/demo-skill/')).toHaveLength(1);
    expect(screen.getAllByText('~/.cursor/skills/demo-skill/')).toHaveLength(1);
    expect(screen.getAllByText('~/.codex/skills/demo-skill/')).toHaveLength(1);
    expect(screen.getByText('tah install demo-skill')).toBeInTheDocument();
  });

  it('keeps a single destination fallback when no install targets are declared', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        installation: {
          method: 'copy_directory',
          targets: null,
          target_client: 'claude-code',
        },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.getAllByText('~/.claude/skills/demo-skill/')).toHaveLength(1);
    expect(screen.getByText('目标路径')).toBeInTheDocument();
    expect(screen.queryByText('安装目标')).not.toBeInTheDocument();
  });

  it('shows the trust empty state when the version has no grade', async () => {
    mocks.fetchPackage.mockResolvedValue(makePackage({ grade: null, risk_level: null }));
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        effective_grade: null,
        risk_level: null,
        install_recommendation: null,
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.getByText('此版本暂无详细信任评分。')).toBeInTheDocument();
  });
});
