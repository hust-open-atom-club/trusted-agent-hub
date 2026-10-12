import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { getCapabilityAxes } from '@/app/package/[name]/detail-view-model';
import type { PublicPermissionSummary } from '@/types';

import CapabilityRadar from './CapabilityRadar';

const SIZE = 260;
const CENTRE = SIZE / 2;
const OUTER_RADIUS = CENTRE - SIZE * 0.115;

function permissionSummary(
  overrides: Partial<PublicPermissionSummary> = {},
): PublicPermissionSummary {
  return {
    filesystem_read_count: 1,
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
    ...overrides,
  };
}

function areaDistances(container: HTMLElement): number[] {
  const points = container.querySelector('.capability-radar-area')?.getAttribute('points') ?? '';

  return points
    .split(' ')
    .filter(Boolean)
    .map((pair) => pair.split(',').map(Number))
    .map(([x, y]) => Math.hypot(x - CENTRE, y - CENTRE));
}

describe('CapabilityRadar', () => {
  it('draws one vertex per axis inside the drawing box', () => {
    const { container } = render(
      <CapabilityRadar
        axes={getCapabilityAxes(
          permissionSummary({
            filesystem_write_count: 1,
            filesystem_delete: true,
            shell_allowed: true,
            network_allowed: true,
          }),
        )}
        packageName="demo-skill"
      />,
    );
    const points = container.querySelector('.capability-radar-area')?.getAttribute('points') ?? '';
    const coordinates = points
      .split(' ')
      .filter(Boolean)
      .map((pair) => pair.split(',').map(Number));

    expect(coordinates).toHaveLength(7);
    for (const [x, y] of coordinates) {
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(SIZE);
      expect(y).toBeGreaterThanOrEqual(0);
      expect(y).toBeLessThanOrEqual(SIZE);
    }
    expect(container.querySelectorAll('.capability-radar-ring')).toHaveLength(4);
    expect(container.querySelectorAll('.capability-radar-ring.is-tier')).toHaveLength(2);
    // 面积保持中性，严重度只由顶点颜色承载
    expect(container.querySelector('.capability-radar-area')?.getAttribute('class')).toBe(
      'capability-radar-area',
    );
    // 声明了具体范围的轴用实心顶点，上限未知的轴用同色描边
    expect(
      container.querySelectorAll('.capability-radar-vertex[fill="var(--color-success)"]').length,
    ).toBeGreaterThan(0);
    expect(
      container.querySelectorAll('.capability-radar-vertex[stroke="var(--color-danger)"]').length,
    ).toBeGreaterThan(0);
  });

  it('scales each vertex by the declared scope, not by raw chart coordinates', () => {
    const { container } = render(
      <CapabilityRadar
        axes={getCapabilityAxes(
          permissionSummary({
            filesystem_write_count: 1,
            filesystem_delete: true,
            shell_allowed: true,
            network_allowed: true,
            environment_write_count: 1,
            credentials_access_count: 1,
          }),
        )}
        packageName="demo-skill"
      />,
    );
    const distances = areaDistances(container);
    const outer = Math.max(...distances);

    expect(outer).toBeCloseTo(OUTER_RADIUS, 1);
    // 声明了具体路径的两根轴落在中圈，其余五根落在外圈
    expect(distances.filter((distance) => Math.abs(distance - outer / 2) < 1)).toHaveLength(2);
    expect(distances.filter((distance) => Math.abs(distance - outer) < 1)).toHaveLength(5);
  });

  it('collapses undeclared axes to the centre', () => {
    const { container } = render(
      <CapabilityRadar
        axes={getCapabilityAxes(permissionSummary({ filesystem_read_count: 1 }))}
        packageName="demo-skill"
      />,
    );
    const distances = areaDistances(container);

    expect(distances.filter((distance) => distance > 1)).toHaveLength(1);
    expect(Math.min(...distances)).toBeLessThan(1);
  });

  it('exposes the declared scope as an accessible table', () => {
    render(
      <CapabilityRadar
        axes={getCapabilityAxes(permissionSummary({ filesystem_delete: true }))}
        packageName="demo-skill"
      />,
    );

    const table = screen.getByRole('table', { name: 'demo-skill 的能力与风险概览' });

    expect(table.querySelectorAll('tbody tr')).toHaveLength(7);
    expect(screen.getAllByText('可删除文件')).toHaveLength(1);
    // 五条未声明轴（表格）
    expect(screen.getAllByText('未声明')).toHaveLength(5);
    expect(screen.getByText('当前权限')).toBeInTheDocument();
    // 文件删除只有布尔声明，上限未知 → 图例给出对应说明
    expect(screen.getByText('未声明上限')).toBeInTheDocument();
    expect(screen.getByText('内圈受限 · 外圈最大范围')).toBeInTheDocument();
  });

  it('marks the axes whose upper bound is not declared', () => {
    const { container } = render(
      <CapabilityRadar
        axes={getCapabilityAxes(permissionSummary({ shell_allowed: true }))}
        packageName="demo-skill"
      />,
    );

    expect(container.querySelector('[data-axis="shell"]')).toHaveAttribute('data-bound', 'unknown');
    expect(container.querySelector('[data-axis="filesystem_read"]')).toHaveAttribute(
      'data-bound',
      'declared',
    );
    expect(container.querySelectorAll('.capability-radar-spoke.is-unknown')).toHaveLength(1);
    expect(container.querySelectorAll('.capability-radar-vertex.is-unknown')).toHaveLength(1);
    // 不填背景色：否则会在该轴落点处把外圈「擦」出一个缺口
    expect(container.querySelector('.capability-radar-vertex.is-unknown')).toHaveAttribute(
      'fill',
      'none',
    );
  });

  it('keeps the legend to the current scope when every axis declares a bound', () => {
    render(
      <CapabilityRadar
        axes={getCapabilityAxes(
          permissionSummary({ filesystem_read_count: 1, filesystem_write_count: 2 }),
        )}
        packageName="demo-skill"
      />,
    );

    expect(screen.getByText('当前权限')).toBeInTheDocument();
    expect(screen.queryByText('未声明上限')).not.toBeInTheDocument();
    // 半径刻度说明与数据无关，始终展示
    expect(screen.getByText('内圈受限 · 外圈最大范围')).toBeInTheDocument();
  });

  it('renders nothing when fewer than three axes are available', () => {
    const { container } = render(
      <CapabilityRadar axes={getCapabilityAxes(null).slice(0, 2)} packageName="demo-skill" />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
