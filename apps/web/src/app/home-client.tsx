'use client';

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { Package } from '@/types';
import { fetchPackages, type SortField, type SortOrder } from '@/data/packages';
import SearchBar from '@/components/SearchBar';
import PackageCard from '@/components/PackageCard';
import PackageIconImage from '@/components/PackageIconImage';

const PAGE_SIZE = 18;

interface MarketplaceHeroProps {
  totalPackages: number | string;
  publishedCount: number | string;
  topRatedCount: number | string;
}

function MarketplaceHero({ totalPackages, publishedCount, topRatedCount }: MarketplaceHeroProps) {
  const { t } = useTranslation();

  return (
    <section className="hero market-hero">
      <div className="hero-bg" />
      <div className="hero-content market-hero-content">
        <div className="market-hero-copy">
          <span className="hero-chip">{t('home.chip')}</span>
          <h1 className="hero-title">
            {t('home.title')}<br />
            <span className="hero-title-accent">{t('home.title_accent')}</span>
          </h1>
          <p className="hero-desc">{t('home.desc')}</p>
          <div className="hero-stats">
            <div className="hero-stat">
              <span className="hero-stat-num">{totalPackages}</span>
              <span className="hero-stat-label">{t('home.stat_packages')}</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat">
              <span className="hero-stat-num">{publishedCount}</span>
              <span className="hero-stat-label">{t('home.stat_published')}</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat">
              <span className="hero-stat-num">{topRatedCount}</span>
              <span className="hero-stat-label">{t('home.stat_top_rated')}</span>
            </div>
          </div>
        </div>

        <div className="market-trust-panel" aria-label={t('home.trust_panel_label')}>
          <div className="market-trust-panel__header">
            <span>{t('home.trust_panel_eyebrow')}</span>
            <strong>{t('home.trust_panel_title')}</strong>
          </div>
          <div className="market-trust-panel__grid">
            <div>
              <span>{t('home.signal_scan')}</span>
              <strong>{t('home.signal_scan_value')}</strong>
            </div>
            <div>
              <span>{t('home.signal_permissions')}</span>
              <strong>{t('home.signal_permissions_value')}</strong>
            </div>
            <div>
              <span>{t('home.signal_integrity')}</span>
              <strong>{t('home.signal_integrity_value')}</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function formatShelfRisk(riskLevel: string | null): string {
  const labels: Record<string, string> = {
    trusted: '可信',
    low_risk: '低风险',
    medium_risk: '中风险',
    high_risk: '高风险',
    untrusted: '不可信',
  };

  return riskLevel ? labels[riskLevel] ?? riskLevel.replace(/_/g, ' ') : '未知风险';
}

interface MarketplaceShelfProps {
  title: string;
  kicker: string;
  items: Package[];
}

function MarketplaceShelf({ title, kicker, items }: MarketplaceShelfProps) {
  if (items.length === 0) {
    return null;
  }

  return (
    <section className="market-shelf">
      <div className="market-shelf__heading">
        <span>{kicker}</span>
        <h2>{title}</h2>
      </div>
      <div className="market-shelf__list">
        {items.map((pkg) => (
          <a className="market-shelf-item" href={`/package/${encodeURIComponent(pkg.name)}`} key={`${title}-${pkg.id}`}>
            <PackageIconImage
              type={pkg.type}
              iconUrl={pkg.icon_url}
              alt={`${pkg.name} icon`}
              className="market-shelf-item__icon"
            />
            <span className="market-shelf-item__copy">
              <strong>{pkg.name}</strong>
              <span>{pkg.grade ?? '--'} · {formatShelfRisk(pkg.risk_level)}</span>
            </span>
            <span className="market-shelf-item__meta">{pkg.install_count}</span>
          </a>
        ))}
      </div>
    </section>
  );
}

export default function HomeClient() {
  const { t } = useTranslation();

  /* ── 筛选状态 ── */
  const [query, setQuery] = useState('');
  const [activeType, setActiveType] = useState('all');
  const [category, setCategory] = useState('');
  const [client, setClient] = useState('');
  const [tag, setTag] = useState('');
  const [minGrade, setMinGrade] = useState('');
  const [minScore, setMinScore] = useState('');
  const [maxScore, setMaxScore] = useState('');
  const [updatedDays, setUpdatedDays] = useState('');
  const [sortBy, setSortBy] = useState<SortField>('updated_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  /* ── 数据状态 ── */
  const [items, setItems] = useState<Package[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /* 追踪请求序号以避免竞态 */
  const requestIdRef = useRef(0);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  const buildQuery = useCallback(
    (targetPage: number) => {
      const minScoreNum = minScore === '' ? undefined : Number(minScore);
      const maxScoreNum = maxScore === '' ? undefined : Number(maxScore);
      const updatedSince =
        updatedDays === ''
          ? undefined
          : new Date(Date.now() - Number(updatedDays) * 86400000).toISOString();
      return {
        q: query || undefined,
        type: activeType !== 'all' ? activeType : undefined,
        category: category || undefined,
        client: client || undefined,
        tag: tag || undefined,
        min_grade: minGrade || undefined,
        min_score: minScoreNum,
        max_score: maxScoreNum,
        updated_since: updatedSince,
        sort_by: sortBy,
        order: sortOrder,
        page: targetPage,
        page_size: PAGE_SIZE,
      };
    },
    [query, activeType, category, client, tag, minGrade, minScore, maxScore, updatedDays, sortBy, sortOrder],
  );

  /* 首页/筛选变化时加载第一页 */
  const loadFirstPage = useCallback(async () => {
    const rid = ++requestIdRef.current;
    setLoading(true);
    setError(null);
    setItems([]);
    setPage(1);
    try {
      const result = await fetchPackages(buildQuery(1));
      if (rid !== requestIdRef.current) return;
      setItems(result.items);
      setTotal(result.total);
      setTotalPages(result.total_pages);
      setPage(1);
    } catch (err: unknown) {
      if (rid === requestIdRef.current) {
        setError(err instanceof Error ? err.message : 'Failed to load packages');
      }
    } finally {
      if (rid === requestIdRef.current) setLoading(false);
    }
  }, [buildQuery]);

  /* 无限滚动：追加下一页 */
  const loadMore = useCallback(async () => {
    if (loading || loadingMore || page >= totalPages || error) return;
    const rid = requestIdRef.current;
    const nextPage = page + 1;
    setLoadingMore(true);
    try {
      const result = await fetchPackages(buildQuery(nextPage));
      if (rid !== requestIdRef.current) return;
      setItems((prev) => {
        const seen = new Set(prev.map((p) => p.id));
        return [...prev, ...result.items.filter((p) => !seen.has(p.id))];
      });
      setPage(nextPage);
      setTotal(result.total);
      setTotalPages(result.total_pages);
    } catch {
      if (rid === requestIdRef.current) {
        setError('Failed to load more packages');
      }
    } finally {
      if (rid === requestIdRef.current) setLoadingMore(false);
    }
  }, [buildQuery, loading, loadingMore, page, totalPages, error]);

  useEffect(() => {
    loadFirstPage();
  }, [loadFirstPage]);

  /* 滚动哨兵：进入视口时加载下一页 */
  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) loadMore();
      },
      { rootMargin: '400px 0px' },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [loadMore]);

  /* 筛选变更时回到第 1 页 */
  const handleQueryChange = useCallback((v: string) => {
    setQuery(v);
    setPage(1);
  }, []);
  const handleTypeChange = useCallback((v: string) => {
    setActiveType(v);
    setPage(1);
  }, []);
  const handleCategoryChange = useCallback((v: string) => {
    setCategory(v);
    setPage(1);
  }, []);
  const handleClientChange = useCallback((v: string) => {
    setClient(v);
    setPage(1);
  }, []);
  const handleTagChange = useCallback((v: string) => {
    setTag(v);
    setPage(1);
  }, []);
  const handleMinGradeChange = useCallback((v: string) => {
    setMinGrade(v);
    setPage(1);
  }, []);
  const handleMinScoreChange = useCallback((v: string) => {
    setMinScore(v);
    setPage(1);
  }, []);
  const handleMaxScoreChange = useCallback((v: string) => {
    setMaxScore(v);
    setPage(1);
  }, []);
  const handleUpdatedDaysChange = useCallback((v: string) => {
    setUpdatedDays(v);
    setPage(1);
  }, []);
  const handleSortChange = useCallback((field: SortField, order: SortOrder) => {
    setSortBy(field);
    setSortOrder(order);
    setPage(1);
  }, []);

  /* ── 派生数据 ── */
  const packages = items;
  const totalPackages = total;
  const hasMore = page < totalPages;

  /* ── 统计（来自 API 实际返回的 total） ── */
  const publishedCount = totalPackages;
  const topRatedCount = packages.filter(p => p.grade === 'A' || p.grade === 'B').length;
  const lowRiskPackages = useMemo(
    () => packages
      .filter((pkg) => pkg.grade === 'A' || pkg.grade === 'B' || pkg.risk_level === 'low_risk')
      .slice(0, 4),
    [packages],
  );
  const popularPackages = useMemo(
    () => [...packages]
      .sort((a, b) => b.install_count - a.install_count)
      .slice(0, 4),
    [packages],
  );
  const recentPackages = useMemo(
    () => [...packages]
      .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
      .slice(0, 4),
    [packages],
  );

  /* ── 加载骨架屏 ── */
  if (loading && packages.length === 0) {
    return (
      <>
        <MarketplaceHero totalPackages="--" publishedCount="--" topRatedCount="--" />

        <div className="page-container">
          <SearchBar
            query={query}
            activeType={activeType}
            sortBy={sortBy}
            sortOrder={sortOrder}
            category={category}
            client={client}
            tag={tag}
            minGrade={minGrade}
            minScore={minScore}
            maxScore={maxScore}
            updatedDays={updatedDays}
            onQueryChange={handleQueryChange}
            onTypeChange={handleTypeChange}
            onCategoryChange={handleCategoryChange}
            onSortChange={handleSortChange}
            onClientChange={handleClientChange}
            onTagChange={handleTagChange}
            onMinGradeChange={handleMinGradeChange}
            onMinScoreChange={handleMinScoreChange}
            onMaxScoreChange={handleMaxScoreChange}
            onUpdatedDaysChange={handleUpdatedDaysChange}
          />

          <div className="package-grid-skeleton">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="package-card skeleton">
                <div className="skeleton-bar" style={{ width: '60%', height: '1.1rem', marginBottom: '0.5rem' }} />
                <div className="skeleton-bar" style={{ width: '90%', marginBottom: '0.25rem' }} />
                <div className="skeleton-bar" style={{ width: '70%', marginBottom: '0.75rem' }} />
                <div className="skeleton-bar" style={{ width: '40%', height: '0.75rem' }} />
              </div>
            ))}
          </div>
        </div>
      </>
    );
  }

  /* ── 错误状态 ── */
  if (error && packages.length === 0) {
    return (
      <>
        <MarketplaceHero totalPackages="--" publishedCount="--" topRatedCount="--" />

        <div className="page-container">
          <div className="empty-state">
            <div className="empty-state-icon">&#x26A0;</div>
            <h3>Failed to load packages</h3>
            <p>{error}</p>
            <button className="btn btn-secondary" style={{ marginTop: '1rem' }} onClick={loadFirstPage}>
              Retry
            </button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <MarketplaceHero
        totalPackages={totalPackages}
        publishedCount={publishedCount}
        topRatedCount={topRatedCount}
      />

      <div className="page-container">
          <SearchBar
            query={query}
            activeType={activeType}
            sortBy={sortBy}
            sortOrder={sortOrder}
            category={category}
            client={client}
            tag={tag}
            minGrade={minGrade}
            minScore={minScore}
            maxScore={maxScore}
            updatedDays={updatedDays}
            onQueryChange={handleQueryChange}
            onTypeChange={handleTypeChange}
            onCategoryChange={handleCategoryChange}
            onSortChange={handleSortChange}
            onClientChange={handleClientChange}
            onTagChange={handleTagChange}
            onMinGradeChange={handleMinGradeChange}
            onMinScoreChange={handleMinScoreChange}
            onMaxScoreChange={handleMaxScoreChange}
            onUpdatedDaysChange={handleUpdatedDaysChange}
          />

        {packages.length > 0 && (
          <div className="market-shelves" aria-label={t('home.market_sections')}>
            <MarketplaceShelf
              title={t('home.section_low_risk')}
              kicker={t('home.section_low_risk_kicker')}
              items={lowRiskPackages}
            />
            <MarketplaceShelf
              title={t('home.section_popular')}
              kicker={t('home.section_popular_kicker')}
              items={popularPackages}
            />
            <MarketplaceShelf
              title={t('home.section_recent')}
              kicker={t('home.section_recent_kicker')}
              items={recentPackages}
            />
          </div>
        )}

        {/* 加载指示条（已有数据时的刷新） */}
        {loading && (
          <div className="loading-bar" />
        )}

        {/* 错误提示（已有缓存数据时） */}
        {error && packages.length > 0 && (
          <div className="error-banner">
            <span>{error}</span>
            <button className="btn btn-sm btn-secondary" onClick={loadFirstPage}>Retry</button>
          </div>
        )}

        <div className="market-results-header">
          <div>
            <span>{t('home.results_kicker')}</span>
            <h2>{t('home.results_title')}</h2>
          </div>
          <p className="results-meta">
            {totalPackages === 1
              ? t('home.results_count', { count: totalPackages })
              : t('home.results_count_plural', { count: totalPackages })}
          </p>
        </div>

        {packages.length === 0 ? (
          <div className="empty-state">
            <svg className="empty-state-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <h3>{t('home.no_results')}</h3>
            <p>{t('home.no_results_hint')}</p>
          </div>
        ) : (
          <>
            <div className="package-grid">
              {packages.map((pkg) => (
                <PackageCard key={pkg.id} pkg={pkg} />
              ))}
            </div>

            {hasMore ? (
              <>
                <div ref={sentinelRef} className="infinite-scroll-sentinel" />
                {loadingMore && (
                  <div className="infinite-scroll-status" role="status">
                    <span className="infinite-scroll-spinner" aria-hidden="true" />
                    <span>{t('home.loading_more')}</span>
                  </div>
                )}
              </>
            ) : packages.length > 0 ? (
              <div className="infinite-scroll-status infinite-scroll-end">
                <span>{t('home.all_loaded', { count: totalPackages })}</span>
              </div>
            ) : null}
          </>
        )}
      </div>
    </>
  );
}
