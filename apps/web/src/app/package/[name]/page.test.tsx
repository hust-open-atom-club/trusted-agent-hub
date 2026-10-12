import { fireEvent, render, screen } from '@testing-library/react';
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
    const { container } = render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.getAllByText('允许读取 1 个路径（受限）')).toHaveLength(1);
    expect(screen.getAllByText('可安全安装')).toHaveLength(1);
    expect(screen.getAllByText('评级 A · 可信')).toHaveLength(1);
    expect(screen.getAllByText('Skill')).toHaveLength(1);
    expect(screen.queryByText('类型')).not.toBeInTheDocument();
    expect(screen.getAllByText('兼容客户端')).toHaveLength(1);
    expect(screen.queryByText(/^兼容客户端：/)).not.toBeInTheDocument();
    // 安装区只留在右侧栏：目标路径跟随所选客户端，正文不再逐个列出
    expect(screen.getAllByText('~/.claude/skills/demo-skill/')).toHaveLength(1);
    expect(screen.queryByText('~/.cursor/skills/demo-skill/')).not.toBeInTheDocument();
    expect(screen.queryByText('~/.codex/skills/demo-skill/')).not.toBeInTheDocument();
    expect(screen.getByText('tah install demo-skill')).toBeInTheDocument();
    // 没有已删除的 i18n key 泄漏成原文
    expect(container.textContent).not.toMatch(/detail\.[a-z_]+\./);
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

  it('renders the capability radar next to the permission summary', async () => {
    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    const radar = screen.getByTestId('capability-radar');
    const axes = radar.querySelectorAll('[data-axis]');

    expect(axes).toHaveLength(7);
    expect(radar.querySelector('[data-axis="filesystem_read"]')).toHaveAttribute(
      'data-scope',
      'limited',
    );
    expect(radar.querySelector('[data-axis="shell"]')).toHaveAttribute(
      'data-scope',
      'unrestricted',
    );
    expect(radar.querySelector('[data-axis="network"]')).toHaveAttribute('data-scope', 'none');
    expect(screen.getByText('能力与风险概览')).toBeInTheDocument();
    expect(screen.getAllByText('可执行 Shell 命令')).toHaveLength(1);
  });

  it('lays the boundary section out as radar + verdict list', async () => {
    const { container } = render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.getByRole('heading', { level: 2, name: '安全能力边界' })).toBeInTheDocument();
    expect(screen.getByText('这个 Skill 能做什么 / 不能做什么')).toBeInTheDocument();
    // 主区权限清单 + 侧栏权限摘要各渲染一次
    expect(screen.getAllByText('文件系统读取')).toHaveLength(2);
    expect(screen.getByText('允许读取 1 个路径（受限）')).toBeInTheDocument();
    expect(screen.getAllByText('Shell 执行')).toHaveLength(2);
    // Shell 与文件系统写入都属于不允许，至少各出现一次
    expect(screen.getAllByText('不允许').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('该版本声明了 1 项高风险权限，请确认你能接受这些能力。'))
      .toBeInTheDocument();
    // 结论跟着雷达走，右栏只留评级与权限明细（否则两栏高低差一大截）
    expect(container.querySelector('.boundary-radar > .boundary-verdict')).not.toBeNull();
    expect(container.querySelector('.boundary-panel .boundary-verdict')).toBeNull();
  });

  it('explains what the package does from declared metadata', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        capabilities: {
          tools: ['Bash', 'Read'],
          purposes: [{ scope: 'shell', reason: '整理仓库' }],
          use_cases: [
            { title: '写规格再开发', description: '编码前先形成清晰规格，减少返工。' },
          ],
        },
        trust_boundary: { verification: 'verified_consistent', scanned_at: '2026-09-01T00:00:00Z' },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.getByRole('heading', { level: 2, name: '这个 Skill 是干什么的？' })).toBeInTheDocument();
    // 工具以标签形式全部列出，不再截成「前 3 个 + 省略号」
    expect(screen.getByText('Bash')).toBeInTheDocument();
    expect(screen.getByText('Read')).toBeInTheDocument();
    expect(screen.getByText('命令执行：整理仓库')).toBeInTheDocument();
    expect(
      screen.getByText('写规格再开发 — 编码前先形成清晰规格，减少返工。'),
    ).toBeInTheDocument();
    // 作者声明卡（用途/权限依据）带归属标签；工具卡可能是平台推断、核验卡是平台结论，都不带
    expect(screen.getAllByText('作者声明')).toHaveLength(2);
    expect(screen.getByText('扫描未发现未声明的能力。')).toBeInTheDocument();
  });

  it('groups repeated capability facts into one card and expands the rest on demand', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        capabilities: {
          tools: ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'Task', 'WebFetch', 'WebSearch'],
          purposes: [{ scope: 'shell', reason: '整理仓库' }],
          use_cases: Array.from({ length: 5 }, (_, index) => ({
            title: `场景${index + 1}`,
            description: `描述${index + 1}`,
          })),
        },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    // 同类内容合并成一张卡，同一个标签只出现一次
    expect(screen.getAllByText('适用场景')).toHaveLength(1);
    expect(screen.getAllByText('权限用途')).toHaveLength(1);
    expect(screen.getAllByText('工具')).toHaveLength(1);

    // 适用场景折叠到 3 条
    expect(screen.getByText('场景1 — 描述1')).toBeInTheDocument();
    expect(screen.getByText('场景3 — 描述3')).toBeInTheDocument();
    expect(screen.queryByText('场景4 — 描述4')).not.toBeInTheDocument();

    // 工具是短标签，9 个里先给 8 个
    expect(screen.getByText('WebFetch')).toBeInTheDocument();
    expect(screen.queryByText('WebSearch')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '展开查看更多（共 5 项）' }));
    expect(screen.getByText('场景5 — 描述5')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '收起' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '展开查看更多（共 9 项）' }));
    expect(screen.getByText('WebSearch')).toBeInTheDocument();
  });

  it('explains the empty scope instead of drawing an all-zero radar', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        permission_summary: {
          filesystem_read_count: 0,
          filesystem_write_count: 0,
          filesystem_delete: false,
          shell_allowed: false,
          network_allowed: false,
          environment_read_count: 0,
          environment_write_count: 0,
          credentials_access_count: 0,
          database_declared: false,
          browser_declared: false,
          external_services_count: 0,
        },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    expect(screen.queryByTestId('capability-radar')).not.toBeInTheDocument();
    // 边界卡与侧栏权限摘要各提示一次
    expect(screen.getAllByText('此版本未声明任何敏感权限。')).toHaveLength(2);
    expect(screen.getAllByText('不允许').length).toBeGreaterThanOrEqual(7);
  });

  it('does not ask readers to re-review findings of an already published version', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        trust_boundary: { verification: 'verified_undeclared', scanned_at: '2026-09-01T00:00:00Z' },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    // 唯一的公开结论是「已声明的权限范围」，不再出现人工复核提示
    expect(screen.getByText('该版本声明了 1 项高风险权限，请确认你能接受这些能力。'))
      .toBeInTheDocument();
    expect(screen.queryByText(/建议人工复核/)).not.toBeInTheDocument();
    expect(screen.queryByText('边界核验')).not.toBeInTheDocument();
  });

  it('keeps installation in the rail instead of a duplicated section', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({
        installation: {
          method: 'copy_directory',
          targets: [{ client: 'claude-code', destination: '~/.claude/skills/demo-skill/' }],
          target_client: 'claude-code',
          pre_install_message: '将安装 demo-skill@1.0.0 到 claude-code',
          post_install_message: '安装完成。请在客户端中确认工具可用。',
        },
      }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    // 安装命令与目标路径只在右侧栏出现一次；正文不再有「安装」章节
    expect(screen.getByText('tah install demo-skill')).toBeInTheDocument();
    expect(screen.getByText('~/.claude/skills/demo-skill/')).toBeInTheDocument();
    expect(screen.queryByText('目录复制')).not.toBeInTheDocument();
    expect(screen.queryByText('安装方式')).not.toBeInTheDocument();
    expect(screen.queryByText('安装目标')).not.toBeInTheDocument();
    expect(screen.queryByText('将安装 demo-skill@1.0.0 到 claude-code')).not.toBeInTheDocument();
    expect(screen.queryByText('安装完成。请在客户端中确认工具可用。')).not.toBeInTheDocument();
  });

  it('keeps the trust grade when the version declares no permission manifest', async () => {
    mocks.fetchPackageVersion.mockResolvedValue(
      makeVersionDetail({ permission_summary: null }),
    );

    render(<PackageDetailPage />);
    await screen.findByRole('heading', { level: 1, name: 'demo-skill' });

    // 评级与「作者是否声明权限」无关，不能跟着一起消失
    expect(screen.getByText('评级 A · 可信')).toBeInTheDocument();
    expect(
      screen.getByText('作者未声明权限范围，平台无法核验它的能力边界。'),
    ).toBeInTheDocument();
    // 没有清单时不列权限明细，也不给出「未声明任何权限」这种结论
    expect(screen.queryByTestId('capability-radar')).not.toBeInTheDocument();
    expect(screen.queryByText('文件系统读取')).not.toBeInTheDocument();
    expect(screen.queryByText('该版本未声明任何敏感权限。')).not.toBeInTheDocument();
  });
});
