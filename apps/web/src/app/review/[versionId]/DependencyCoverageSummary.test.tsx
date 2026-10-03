import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { DependencyScan } from '@/types';

import DependencyCoverageSummary from './DependencyCoverageSummary';

describe('DependencyCoverageSummary', () => {
  it('shows acquisition, integrity, and manifest coverage with readable reason codes', () => {
    const dependencyScan: DependencyScan = {
      status: 'complete',
      artifact_acquisition: {
        status: 'partial',
        requested_count: 101,
        fetched_count: 100,
        unavailable_count: 1,
        bytes_downloaded: 4096,
        unavailable_reasons: { artifact_limit: 1 },
      },
      integrity: {
        status: 'partial',
        claimed_count: 101,
        verified_count: 100,
        mismatch_count: 0,
        unavailable_count: 1,
        unsupported_count: 0,
        unavailable_reasons: { artifact_limit: 1 },
      },
      manifest_lock: {
        status: 'matched',
        checked_pairs: 4,
        mismatch_count: 0,
        unchecked_count: 0,
      },
    };

    render(<DependencyCoverageSummary dependencyScan={dependencyScan} />);

    expect(screen.getByRole('heading', { name: '依赖验证覆盖' })).toBeInTheDocument();
    expect(screen.getByText('依赖扫描状态: 完整')).toBeInTheDocument();
    expect(screen.getByTestId('dependency-artifact-acquisition')).toHaveTextContent(
      '请求数101已获取100不可用1下载字节数4,096',
    );
    expect(screen.getByTestId('dependency-acquisition-reasons')).toHaveTextContent(
      '达到制品验证数量上限 (artifact_limit): 1',
    );
    expect(screen.getByTestId('dependency-integrity-coverage')).toHaveTextContent(
      '完整性声明101已验证100不匹配0不可用1不支持0',
    );
    expect(screen.getByTestId('dependency-manifest-lock')).toHaveTextContent(
      '状态一致已比对项4不匹配0未能比对0',
    );
  });

  it('shows manifest collection failures even when no dependencies were parsed', () => {
    render(
      <DependencyCoverageSummary
        dependencyScan={{
          status: 'partial',
          artifact_acquisition: {
            status: 'partial',
            requested_count: 0,
            fetched_count: 0,
            unavailable_count: 0,
            bytes_downloaded: 0,
            collection_errors: ['dependency_parse_error'],
          },
          manifest_lock: {
            status: 'not_checked',
            checked_pairs: 0,
            mismatch_count: 0,
            unchecked_count: 0,
          },
        }}
      />,
    );

    expect(screen.getByText('清单采集错误')).toBeInTheDocument();
    expect(screen.getByText('依赖清单解析失败 (dependency_parse_error)')).toBeInTheDocument();
    expect(screen.getByTestId('dependency-manifest-lock')).toHaveTextContent(
      '状态未检查已比对项0不匹配0未能比对0',
    );
  });

  it('makes incomplete vulnerability lookup explicit instead of looking clean', () => {
    render(
      <DependencyCoverageSummary
        dependencyCheck={{
          known_vulnerabilities: null,
          vulnerability_status: 'not_assessed',
        }}
        dependencyScan={{
          status: 'unavailable',
          total_unique_dependencies: 396,
          queryable: 396,
          queried: 100,
          succeeded: 90,
          failed: 6,
          rate_limited: 4,
          skipped: 296,
          unsupported: 0,
          remaining: 306,
          cache_hits: 20,
          query_limit: 5000,
          failure_reasons: {
            network_error: 6,
            rate_limited: 4,
            query_limit_exceeded: 296,
          },
          non_osv_manifest_dependencies: {
            total: 2,
            categories: { system: 1, mcp_servers: 1 },
          },
        }}
      />,
    );

    expect(screen.getByTestId('dependency-vulnerability-coverage')).toHaveTextContent(
      '唯一坐标数396可查询396查询成功90查询失败6被限流4未查询296不支持0未完成306缓存命中20查询上限5,000',
    );
    expect(screen.getByTestId('dependency-vulnerability-coverage')).toHaveTextContent(
      '已知漏洞数未完成评估',
    );
    expect(screen.getByTestId('dependency-non-osv-manifest')).toHaveTextContent(
      '不属于 OSV 包生态的清单依赖：2System: 1Mcp Servers: 1',
    );
    expect(screen.getByText(
      '漏洞查询尚未完整执行；未报告漏洞不代表这些依赖没有已知漏洞。',
    )).toBeInTheDocument();
    expect(screen.getByTestId('dependency-vulnerability-reasons')).toHaveTextContent(
      'OSV 网络请求失败 (network_error): 6',
    );
  });

  it('renders nothing when coverage data is unavailable', () => {
    const { container } = render(
      <DependencyCoverageSummary dependencyScan={{ status: 'complete' }} />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
