/**
 * Unit tests for the API client.
 *
 * Run: npx ts-node tests/api-client.test.ts
 */

import * as assert from 'assert';
import { createApiClient, ApiError } from '../src/api-client';
import type { FetchFn } from '../src/api-client';

// ---------------------------------------------------------------------------
// Mock fetch builder
// ---------------------------------------------------------------------------

interface MockResponse {
  status: number;
  ok: boolean;
  body: unknown;
}

function mockFetchFn(responses: MockResponse[]): FetchFn & { urls: string[] } {
  const urls: string[] = [];
  const fn = (async (url: string, _init?: RequestInit) => {
    urls.push(url);
    const next = responses.shift();
    if (!next) {
      throw new Error('No more mock responses configured');
    }
    return {
      status: next.status,
      ok: next.ok,
      headers: new Headers(),
      json: async () => next.body,
      text: async () => JSON.stringify(next.body),
    } as Response;
  }) as FetchFn & { urls: string[] };
  fn.urls = urls;
  return fn;
}

function mockErrorFetch(message: string): FetchFn {
  return async () => {
    throw new Error(message);
  };
}

function mockAbortFetch(): FetchFn {
  return async () => {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    // Also try the DOMException check path
    throw err;
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const samplePackage = {
  id: '1', name: 'test-skill', description: 'A test', type: 'skill',
  license: 'MIT', keywords: [], category: null, homepage: null, icon_url: null,
  owner: { id: 'o1', username: 'dev', display_name: 'Dev', role: 'submitter' },
  latest_version: '1.0.0', status: 'published',
  risk_level: 'low_risk', grade: 'B', install_count: 10, avg_rating: 4.5,
  created_at: '2026-01-01', updated_at: '2026-06-01',
};

const sampleVersion = {
  id: 'v1', package_id: '1', version: '1.0.0', status: 'published',
  author: { name: 'Dev', email: 'dev@test.com' },
  source: { type: 'github', repository_url: 'https://github.com/x/y',
    owner: 'x', repo: 'y', ref_type: 'tag', ref: 'v1.0.0',
    commit_hash: 'a'.repeat(40), verified_owner: true },
  compatibility: ['claude-code'],
  permissions: {},
  installation: { method: 'copy_directory', targets: [] },
  trust_score: { risk_summary: {
    level: 'low_risk', grade: 'B', top_risks: [], install_recommendation: 'safe',
  }},
  created_at: null, submitted_at: null,
};

async function test_searchPackages_success() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { items: [samplePackage], total: 1, page: 1, page_size: 20, total_pages: 1 } }]);
  const c = createApiClient(fetchFn);

  const result = await c.searchPackages({ q: 'test' });
  assert.strictEqual(result.items.length, 1);
  assert.strictEqual(result.items[0].name, 'test-skill');
  assert.strictEqual(result.items[0].grade, 'B');
  assert.ok(!('trust_score' in result.items[0]));
  assert.ok(fetchFn.urls[0].includes('/api/v0/packages'));
  assert.ok(fetchFn.urls[0].includes('q=test'));
  console.log('  ✓ searchPackages success');
}

async function test_searchPackages_empty() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 } }]);
  const c = createApiClient(fetchFn);
  const result = await c.searchPackages({ q: 'nonexistent' });
  assert.strictEqual(result.items.length, 0);
  console.log('  ✓ searchPackages empty');
}

async function test_getPackage_success() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: samplePackage }]);
  const c = createApiClient(fetchFn);
  const pkg = await c.getPackage('test-skill');
  assert.strictEqual(pkg.name, 'test-skill');
  assert.strictEqual(pkg.grade, 'B');
  assert.ok(fetchFn.urls[0].includes('/api/v0/packages/test-skill'));
  console.log('  ✓ getPackage success');
}

async function test_getPackage_404() {
  const fetchFn = mockFetchFn([{ status: 404, ok: false, body: { error: { message: 'Not found' } } }]);
  const c = createApiClient(fetchFn);
  try {
    await c.getPackage('no-such-pkg');
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.strictEqual((err as ApiError).statusCode, 404);
  }
  console.log('  ✓ getPackage 404');
}

async function test_getVersionDetail_success() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: sampleVersion }]);
  const c = createApiClient(fetchFn);
  const detail = await c.getVersionDetail('test-skill', '1.0.0');
  assert.strictEqual(detail.id, 'v1');
  assert.strictEqual(detail.trust_score?.risk_summary?.grade, 'B');
  console.log('  ✓ getVersionDetail success');
}

async function test_networkError() {
  const c = createApiClient(mockErrorFetch('fetch failed'));
  try {
    await c.searchPackages({});
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('Cannot reach API'));
  }
  console.log('  ✓ network error');
}

async function test_timeout() {
  const c = createApiClient(mockAbortFetch());
  try {
    await c.searchPackages({});
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('timed out'));
  }
  console.log('  ✓ timeout');
}

async function test_malformedResponse() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: 'not-json' }]);
  // Override json to throw
  const brokenFetch: FetchFn = async (url, init) => {
    return {
      status: 200,
      ok: true,
      headers: new Headers(),
      json: async () => { throw new SyntaxError('bad json'); },
      text: async () => 'not-json',
    } as Response;
  };
  const c = createApiClient(brokenFetch);
  try {
    await c.searchPackages({});
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('parse'));
  }
  console.log('  ✓ malformed JSON');
}

async function test_searchWithFilters() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { items: [], total: 0, page: 1, page_size: 10, total_pages: 0 } }]);
  const c = createApiClient(fetchFn);
  await c.searchPackages({ type: 'skill', client: 'claude-code', page: 2, page_size: 10 });
  assert.ok(fetchFn.urls[0].includes('type=skill'));
  assert.ok(fetchFn.urls[0].includes('client=claude-code'));
  assert.ok(fetchFn.urls[0].includes('page=2'));
  assert.ok(fetchFn.urls[0].includes('page_size=10'));
  console.log('  ✓ search filters');
}

async function test_isApiReachable() {
  const good = createApiClient(mockFetchFn([{ status: 200, ok: true, body: { status: 'ok' } }]));
  assert.strictEqual(await good.isApiReachable(), true);

  const bad = createApiClient(mockErrorFetch('fail'));
  assert.strictEqual(await bad.isApiReachable(), false);

  console.log('  ✓ isApiReachable');
}

async function test_validation_rejects_invalid_package() {
  // Missing required field 'name'
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { id: '1', type: 'skill' } }]);
  const c = createApiClient(fetchFn);
  try {
    await c.getPackage('bad');
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('must be a string'));
  }
  console.log('  ✓ validation rejects invalid package');
}

async function test_validation_rejects_empty_object() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: {} }]);
  const c = createApiClient(fetchFn);
  try {
    await c.getPackage('bad');
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
  }
  console.log('  ✓ validation rejects empty object');
}

async function test_validation_rejects_invalid_page() {
  // Missing 'items' array
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { total: 1 } }]);
  const c = createApiClient(fetchFn);
  try {
    await c.searchPackages({});
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('must be'));
  }
  console.log('  ✓ validation rejects invalid page');
}

async function test_pageSize_clamped() {
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { items: [], total: 0, page: 1, page_size: 100, total_pages: 0 } }]);
  const c = createApiClient(fetchFn);
  await c.searchPackages({ page_size: 999 });
  assert.ok(!fetchFn.urls[0].includes('page_size=999'), 'page_size should be clamped');
  assert.ok(fetchFn.urls[0].includes('page_size=100'), 'page_size should be 100');
  console.log('  ✓ page_size clamped to 100');
}

async function test_strictPage_rejects_missing_fields() {
  // { items: [] } without total/page/page_size/total_pages should be rejected
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: { items: [] } }]);
  const c = createApiClient(fetchFn);
  try {
    await c.searchPackages({});
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.ok((err as Error).message.includes('must be an integer'));
  }
  console.log('  ✓ strict page rejects missing fields');
}

async function test_nullOwner_accepted() {
  const pkgWithNullOwner = { ...samplePackage, owner: null };
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: pkgWithNullOwner }]);
  const c = createApiClient(fetchFn);
  const pkg = await c.getPackage('test');
  assert.strictEqual(pkg.owner, null);
  console.log('  ✓ null owner accepted');
}

async function test_versionDetail_500_propagates() {
  // 500 on version detail should NOT be silently swallowed
  const fetchFn = mockFetchFn([{ status: 500, ok: false, body: { error: { message: 'Server error' } } }]);
  const c = createApiClient(fetchFn);
  try {
    await c.getVersionDetail('pkg', '1.0.0');
    assert.fail('Expected ApiError');
  } catch (err: unknown) {
    assert.ok(err instanceof ApiError);
    assert.strictEqual((err as ApiError).statusCode, 500);
  }
  console.log('  ✓ version detail 500 propagates');
}

async function test_nullCreatedAt_accepted() {
  const pkgWithNullDates = { ...samplePackage, created_at: null, updated_at: null };
  const fetchFn = mockFetchFn([{ status: 200, ok: true, body: pkgWithNullDates }]);
  const c = createApiClient(fetchFn);
  const pkg = await c.getPackage('test');
  assert.strictEqual(pkg.created_at, null);
  assert.strictEqual(pkg.updated_at, null);
  console.log('  ✓ null created_at/updated_at accepted');
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

(async () => {
  console.log('\nCLI API Client Tests\n');

  await test_searchPackages_success();
  await test_searchPackages_empty();
  await test_getPackage_success();
  await test_getPackage_404();
  await test_getVersionDetail_success();
  await test_networkError();
  await test_timeout();
  await test_malformedResponse();
  await test_searchWithFilters();
  await test_isApiReachable();
  await test_validation_rejects_invalid_package();
  await test_validation_rejects_empty_object();
  await test_validation_rejects_invalid_page();
  await test_pageSize_clamped();
  await test_strictPage_rejects_missing_fields();
  await test_nullOwner_accepted();
  await test_versionDetail_500_propagates();
  await test_nullCreatedAt_accepted();

  console.log('\n  ✓ All tests passed!\n');
})();
