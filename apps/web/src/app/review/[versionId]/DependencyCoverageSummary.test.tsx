import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import type { DependencyQueryResult, DependencyScan } from '@/types';
import en from '@/i18n/locales/en/common.json';
import zh from '@/i18n/locales/zh/common.json';

import DependencyCoverageSummary from './DependencyCoverageSummary';

describe('DependencyCoverageSummary', () => {
  it('keeps dependency coverage keys and OSV reasons available in both languages', () => {
    const prefix = 'dependency_coverage_';
    const enKeys = Object.keys(en.review.detail).filter((key) => key.startsWith(prefix)).sort();
    const zhKeys = Object.keys(zh.review.detail).filter((key) => key.startsWith(prefix)).sort();
    expect(enKeys).toEqual(zhKeys);
    for (const reason of [
      'osv_timeout', 'response_parse_error', 'provider_client_error', 'provider_query_error',
      'response_too_large', 'missing_client_result', 'invalid_client_response',
      'unsupported_ecosystem', 'non_exact_version',
    ]) {
      for (const locale of [en, zh]) {
        expect(locale.review.detail).toHaveProperty(`${prefix}reason_${reason}`, expect.any(String));
      }
    }
    expect(en.review.detail.dependency_coverage_reason_osv_timeout).not.toEqual(en.review.detail.dependency_coverage_reason_timeout);
    expect(zh.review.detail.dependency_coverage_reason_osv_timeout).not.toEqual(zh.review.detail.dependency_coverage_reason_timeout);
  });

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
          provider_requests: 8,
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
    expect(screen.getByTestId('dependency-vulnerability-coverage')).toHaveTextContent(
      'OSV HTTP 请求次数（含重试）8',
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

  it('expands coordinate failures, cache evidence and source occurrences with truncation notices', async () => {
    const user = userEvent.setup();
    const cached: DependencyQueryResult = {
      ecosystem: 'npm',
      package_name: 'cached-package',
      version: '1.0.0',
      status: 'succeeded',
      data_source: 'OSV',
      queried_at: '2026-10-07T00:00:00Z',
      response_status: 200,
      failure_reason: null,
      from_cache: true,
      cache_source: 'persistent',
      cache_age_seconds: 0,
      attempts: 0,
      vulnerability_count: 0,
      occurrence_count: 101,
      occurrences_truncated: true,
      occurrences: [{
        source_file: 'package-lock.json',
        source_ref: '#/packages/node_modules/cached-package',
        line: 12,
        scope: 'runtime',
        direct: true,
        registry: 'https://registry.npmjs.org/',
      }],
    };
    const results: DependencyQueryResult[] = [
      cached,
      { ...cached, package_name: 'timed-out', status: 'failed', failure_reason: 'osv_timeout', from_cache: false, cache_source: undefined, cache_age_seconds: undefined, response_status: null, attempts: 3 },
      { ...cached, package_name: 'limited', status: 'rate_limited', failure_reason: 'rate_limited', from_cache: false, response_status: 429 },
      { ...cached, package_name: '@internal/private', status: 'not_queried', failure_reason: 'non_public_registry_not_queried', from_cache: false, queried_at: null, response_status: null },
    ];
    render(<DependencyCoverageSummary dependencyScan={{ status: 'partial', query_results: results, query_results_truncated: true }} />);

    expect(screen.getByText('明细已截断，仅显示 4 个坐标；汇总统计仍包含全部坐标。')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    await user.click(screen.getByText('坐标查询明细（4）'));

    const table = await screen.findByRole('table');
    const cachedRow = within(table).getByText('cached-package@1.0.0').closest('tr')!;
    expect(cachedRow).toHaveTextContent('持久缓存缓存时间距今 0 秒');
    expect(within(table).getByText('timed-out@1.0.0').closest('tr')).toHaveTextContent('失败OSV 请求超时');
    expect(within(table).getByText('limited@1.0.0').closest('tr')).toHaveTextContent('被限流');
    expect(within(table).getByText('@internal/private@1.0.0').closest('tr')).toHaveTextContent('未查询');
    expect(within(table).queryByText('制品获取超时')).not.toBeInTheDocument();
    expect(within(cachedRow).queryByText('package-lock.json:12')).not.toBeInTheDocument();
    await user.click(within(cachedRow).getByText('来源位置（101）'));
    expect(await within(cachedRow).findByText('package-lock.json:12')).toBeVisible();
    expect(cachedRow).toHaveTextContent('运行时 · 直接依赖');
    expect(cachedRow).toHaveTextContent('#/packages/node_modules/cached-package');
    expect(cachedRow).toHaveTextContent('https://registry.npmjs.org/');
    expect(cachedRow).toHaveTextContent('报告中已省略其余来源位置。');
  });

  it('paginates large reports, renders sources lazily and clamps the page after replacement', async () => {
    const user = userEvent.setup();
    const results: DependencyQueryResult[] = Array.from({ length: 120 }, (_, index) => ({
      ecosystem: 'npm', package_name: `package-${index}`, version: '1.0.0',
      status: 'not_queried', data_source: 'OSV', queried_at: null, response_status: null,
      failure_reason: 'query_limit_exceeded', from_cache: false, attempts: 0,
      vulnerability_count: 0, occurrence_count: 1, occurrences_truncated: false,
      occurrences: [{ source_file: `source-${index}/package-lock.json`, scope: 'runtime', direct: true }],
    }));
    const { rerender } = render(<DependencyCoverageSummary dependencyScan={{
      status: 'partial', query_results: results, query_results_truncated: true,
      query_results_omitted: 4881, resumed_queries: 3,
    }} />);
    expect(screen.getByTestId('dependency-vulnerability-coverage')).toHaveTextContent('本次恢复查询数3');
    expect(screen.getByRole('note')).toHaveTextContent('已省略 4881 个坐标的明细');
    await user.click(screen.getByText('坐标查询明细（120）'));
    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(51);
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled();
    expect(screen.getByRole('status')).toHaveTextContent('第 1 / 3 页');
    expect(screen.queryByText('package-50@1.0.0')).not.toBeInTheDocument();
    expect(screen.queryByText('source-0/package-lock.json')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '下一页' }));
    expect(screen.getByText('package-50@1.0.0')).toBeVisible();
    expect(screen.queryByText('package-0@1.0.0')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '下一页' }));
    expect(within(table).getAllByRole('row')).toHaveLength(21);
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled();
    rerender(<DependencyCoverageSummary dependencyScan={{ status: 'partial', query_results: results.slice(0, 1) }} />);
    expect(await screen.findByText('package-0@1.0.0')).toBeVisible();
    expect(screen.queryByRole('navigation', { name: '查询明细分页' })).not.toBeInTheDocument();
  });

  it('bounds rendered rows even when reading an older oversized report', async () => {
    const user = userEvent.setup();
    const results: DependencyQueryResult[] = Array.from({ length: 5001 }, (_, index) => ({
      ecosystem: 'npm', package_name: `package-${index}`, version: '1.0.0', status: 'succeeded',
      data_source: 'OSV', queried_at: null, response_status: 200, failure_reason: null,
      from_cache: false, attempts: 1, vulnerability_count: 0, occurrence_count: 1,
      occurrences: [{ source_file: 'package-lock.json', scope: 'runtime', direct: true }],
      occurrences_truncated: false,
    }));
    render(<DependencyCoverageSummary dependencyScan={{ status: 'complete', query_results: results }} />);
    await user.click(screen.getByText('坐标查询明细（5001）'));
    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(51);
    expect(screen.getByRole('status')).toHaveTextContent('第 1 / 101 页');
  });

  it('uses separate OSV timeout and integrity-unsupported labels', () => {
    render(<DependencyCoverageSummary dependencyScan={{
      status: 'unavailable',
      queryable: 1,
      failure_reasons: { osv_timeout: 1 },
      artifact_acquisition: { status: 'partial', unavailable_reasons: { timeout: 1 } },
      integrity: { status: 'unsupported', claimed_count: 1, unsupported_count: 1 },
    }} />);

    expect(screen.getByTestId('dependency-vulnerability-reasons')).toHaveTextContent('OSV 请求超时 (osv_timeout): 1');
    expect(screen.getByTestId('dependency-acquisition-reasons')).toHaveTextContent('制品获取超时 (timeout): 1');
    expect(screen.getByTestId('dependency-integrity-coverage')).toHaveTextContent('完整性格式不受支持');
  });

  it('renders nothing when coverage data is unavailable', () => {
    const { container } = render(
      <DependencyCoverageSummary dependencyScan={{ status: 'complete' }} />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
