import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  fetchFeedback,
  fetchPackage,
  fetchPackages,
  fetchPackageVersion,
  fetchPackageVersions,
  fetchTrustHistory,
  submitFeedback,
} from './packages';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const API_BASE = 'http://localhost:8000';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('fetchPackages', () => {
  it('omits query string when no filters are given', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchPackages();
    expect(fetchMock).toHaveBeenCalledWith(`${API_BASE}/api/v0/packages`);
  });

  it('sends every supported filter parameter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchPackages({
      q: 'summarize',
      type: 'skill',
      client: 'claude-code',
      category: 'productivity',
      tag: 'summary',
      min_grade: 'B',
      min_score: 60,
      max_score: 90,
      updated_since: '2026-07-01T00:00:00Z',
      sort_by: 'grade',
      order: 'asc',
      page: 2,
      page_size: 20,
    });

    const calledUrl = vi.mocked(fetchMock).mock.calls[0][0] as string;
    expect(calledUrl).toBe(
      `${API_BASE}/api/v0/packages?q=summarize&type=skill&client=claude-code&category=productivity&tag=summary&min_grade=B&min_score=60&max_score=90&updated_since=2026-07-01T00%3A00%3A00Z&sort_by=grade&order=asc&page=2&page_size=20`,
    );
  });

  it('omits page=1 and includes zero min_score', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchPackages({ min_score: 0, page: 1 });
    const calledUrl = vi.mocked(fetchMock).mock.calls[0][0] as string;
    expect(calledUrl).toBe(`${API_BASE}/api/v0/packages?min_score=0`);
  });

  it('throws on non-OK response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({}, 503)));
    await expect(fetchPackages()).rejects.toThrow('Failed to fetch packages: 503');
  });
});

describe('package detail fetchers', () => {
  it('fetchPackage encodes the name and returns null on 404', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ name: 'demo' }))
      .mockResolvedValueOnce(jsonResponse({}, 404));
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchPackage('demo sum')).resolves.toEqual({ name: 'demo' });
    await expect(fetchPackage('missing')).resolves.toBeNull();
    expect(fetchMock.mock.calls[0][0]).toBe(
      `${API_BASE}/api/v0/packages/demo%20sum`,
    );
  });

  it('fetchPackageVersion builds the versions URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ version: '1.0.0' }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchPackageVersion('demo', '1.0.0');
    expect(fetchMock).toHaveBeenCalledWith(
      `${API_BASE}/api/v0/packages/demo/versions/1.0.0`,
    );
  });

  it('fetchPackageVersions and fetchTrustHistory hit their endpoints', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse([{ score: 76 }]));
    vi.stubGlobal('fetch', fetchMock);

    await fetchPackageVersions('demo');
    await fetchTrustHistory('demo');

    expect(fetchMock.mock.calls[0][0]).toBe(
      `${API_BASE}/api/v0/packages/demo/versions`,
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      `${API_BASE}/api/v0/packages/demo/trust-history`,
    );
  });
});

describe('feedback', () => {
  it('fetchFeedback passes page and page_size', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    vi.stubGlobal('fetch', fetchMock);

    await fetchFeedback('demo', 3, 5);
    expect(fetchMock).toHaveBeenCalledWith(
      `${API_BASE}/api/v0/packages/demo/feedback?page=3&page_size=5`,
    );
  });

  it('submitFeedback posts level/comment with bearer token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ id: 'fb-1', level: 'positive' }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await submitFeedback('demo', 'positive', 'great', 'tok-123');
    const [url, init] = vi.mocked(fetchMock).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${API_BASE}/api/v0/packages/demo/feedback`);
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>).Authorization).toBe(
      'Bearer tok-123',
    );
    expect(init.body).toBe(JSON.stringify({ level: 'positive', comment: 'great' }));
  });

  it('submitFeedback maps 401 to a login message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({}, 401)));
    await expect(submitFeedback('demo', 'neutral', null, 'bad')).rejects.toThrow(
      'Please login to submit feedback',
    );
  });
});
