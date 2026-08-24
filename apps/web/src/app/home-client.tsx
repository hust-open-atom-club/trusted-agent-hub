'use client';

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { Package } from '@/types';
import { fetchPackages, type SortField, type SortOrder } from '@/data/packages';
import SearchBar from '@/components/SearchBar';
import PackageCard from '@/components/PackageCard';
import PackageIconImage from '@/components/PackageIconImage';
import { AnimatePresence, fadeUp, listItem, listStagger, motion, pageStagger, softPanel } from '@/components/Motion';

const PAGE_SIZE = 18;
const DISCOVERY_PAGE_SIZE = 60;

type MarketView = 'all' | 'low_risk' | 'popular' | 'recent';

interface MarketplaceHeroProps {
  totalPackages: number | string;
  publishedCount: number | string;
  topRatedCount: number | string;
}

function MarketplaceHero({ totalPackages, publishedCount, topRatedCount }: MarketplaceHeroProps) {
  const { t } = useTranslation();

  return (
    <motion.section
      className="hero market-hero"
      variants={pageStagger}
      initial="hidden"
      animate="visible"
    >
      <div className="hero-bg" />
      <div className="hero-content market-hero-content">
        <motion.div className="market-hero-copy" variants={fadeUp}>
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
        </motion.div>

      </div>
    </motion.section>
  );
}

interface MarketplaceShelfProps {
  title: string;
  kicker: string;
  items: Package[];
  isActive: boolean;
  onActivate: () => void;
}

function MarketplaceShelf({ title, kicker, items, isActive, onActivate }: MarketplaceShelfProps) {
  const { t } = useTranslation();

  if (items.length === 0) {
    return null;
  }

  return (
    <motion.section
      className={`market-shelf ${isActive ? 'is-active' : ''}`}
      variants={fadeUp}
      whileInView="visible"
      initial="hidden"
      viewport={{ once: true, amount: 0.2 }}
    >
      <div className="market-shelf__heading">
        <div>
          <span>{kicker}</span>
          <h2>{title}</h2>
        </div>
        <button
          type="button"
          className="market-shelf__action"
          aria-pressed={isActive}
          onClick={onActivate}
        >
          {isActive ? t('home.section_active') : t('home.section_view')}
        </button>
      </div>
      <motion.div className="market-shelf__list" variants={listStagger} initial="hidden" animate="visible">
        {items.map((pkg) => (
          <motion.a
            className="market-shelf-item"
            href={`/package/${encodeURIComponent(pkg.name)}`}
            key={pkg.id}
            variants={listItem}
            whileHover={{ x: 3 }}
            whileTap={{ scale: 0.99 }}
          >
            <PackageIconImage
              type={pkg.type}
              iconUrl={pkg.icon_url}
              alt={`${pkg.name} icon`}
              className="market-shelf-item__icon"
            />
            <span className="market-shelf-item__copy">
              <strong>{pkg.name}</strong>
              <span>
                {pkg.grade ?? '--'} · {pkg.risk_level
                  ? t(`trust_score.level.${pkg.risk_level}`, { defaultValue: pkg.risk_level.replace(/_/g, ' ') })
                  : t('detail.unknown')}
              </span>
            </span>
            <span className="market-shelf-item__meta">{pkg.install_count}</span>
          </motion.a>
        ))}
      </motion.div>
    </motion.section>
  );
}

interface MarketplaceShelvesProps {
  lowRiskPackages: Package[];
  popularPackages: Package[];
  recentPackages: Package[];
  activeMarketView: MarketView;
  onMarketViewChange: (view: MarketView, shouldScroll?: boolean) => void;
}

function MarketplaceShelves({
  lowRiskPackages,
  popularPackages,
  recentPackages,
  activeMarketView,
  onMarketViewChange,
}: MarketplaceShelvesProps) {
  const { t } = useTranslation();
  const hasShelfItems = lowRiskPackages.length > 0 || popularPackages.length > 0 || recentPackages.length > 0;

  if (!hasShelfItems) {
    return null;
  }

  return (
    <motion.div className="market-shelves" aria-label={t('home.market_sections')} variants={listStagger}>
      <MarketplaceShelf
        title={t('home.section_low_risk')}
        kicker={t('home.section_low_risk_kicker')}
        items={lowRiskPackages}
        isActive={activeMarketView === 'low_risk'}
        onActivate={() => onMarketViewChange('low_risk', true)}
      />
      <MarketplaceShelf
        title={t('home.section_popular')}
        kicker={t('home.section_popular_kicker')}
        items={popularPackages}
        isActive={activeMarketView === 'popular'}
        onActivate={() => onMarketViewChange('popular', true)}
      />
      <MarketplaceShelf
        title={t('home.section_recent')}
        kicker={t('home.section_recent_kicker')}
        items={recentPackages}
        isActive={activeMarketView === 'recent'}
        onActivate={() => onMarketViewChange('recent', true)}
      />
    </motion.div>
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
  const [activeMarketView, setActiveMarketView] = useState<MarketView>('all');

  /* ── 数据状态 ── */
  const [items, setItems] = useState<Package[]>([]);
  const [discoveryItems, setDiscoveryItems] = useState<Package[]>([]);
  const [marketplaceTotal, setMarketplaceTotal] = useState(0);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /* 追踪请求序号以避免竞态 */
  const requestIdRef = useRef(0);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  const loadDiscovery = useCallback(async () => {
    try {
      const result = await fetchPackages({
        sort_by: 'updated_at',
        order: 'desc',
        page: 1,
        page_size: DISCOVERY_PAGE_SIZE,
      });
      setDiscoveryItems(result.items);
      setMarketplaceTotal(result.total);
    } catch {
      setDiscoveryItems([]);
      setMarketplaceTotal(0);
    }
  }, []);

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

  useEffect(() => {
    loadDiscovery();
  }, [loadDiscovery]);

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

  const scrollToMarketplaceResults = useCallback(() => {
    window.setTimeout(() => {
      document.getElementById('marketplace-results')?.scrollIntoView({
        behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
        block: 'start',
      });
    }, 80);
  }, []);

  const handleMarketViewChange = useCallback((view: MarketView, shouldScroll = false) => {
    setActiveMarketView(view);
    setQuery('');
    setActiveType('all');
    setCategory('');
    setClient('');
    setTag('');
    setMinScore('');
    setMaxScore('');
    setUpdatedDays('');

    if (view === 'low_risk') {
      setMinGrade('B');
      setSortBy('grade');
      setSortOrder('asc');
    } else if (view === 'popular') {
      setMinGrade('');
      setSortBy('install_count');
      setSortOrder('desc');
    } else {
      setMinGrade('');
      setSortBy('updated_at');
      setSortOrder('desc');
    }

    setPage(1);
    if (shouldScroll) {
      scrollToMarketplaceResults();
    }
  }, [scrollToMarketplaceResults]);

  /* ── 派生数据 ── */
  const packages = items;
  const discoveryPackages = discoveryItems.length > 0 ? discoveryItems : packages;
  const totalPackages = total;
  const hasMore = page < totalPages;

  /* ── 统计（来自 API 实际返回的 total） ── */
  const heroPackageCount = marketplaceTotal || totalPackages;
  const publishedCount = heroPackageCount;
  const topRatedCount = discoveryPackages.filter(p => p.grade === 'A' || p.grade === 'B').length;
  const lowRiskPackages = useMemo(
    () => discoveryPackages
      .filter((pkg) => pkg.grade === 'A' || pkg.grade === 'B' || pkg.risk_level === 'low_risk')
      .slice(0, 4),
    [discoveryPackages],
  );
  const popularPackages = useMemo(
    () => [...discoveryPackages]
      .sort((a, b) => b.install_count - a.install_count)
      .slice(0, 4),
    [discoveryPackages],
  );
  const recentPackages = useMemo(
    () => [...discoveryPackages]
      .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
      .slice(0, 4),
    [discoveryPackages],
  );

  /* ── 加载骨架屏 ── */
  if (loading && packages.length === 0) {
    return (
      <>
        <MarketplaceHero
          totalPackages={marketplaceTotal || '--'}
          publishedCount={marketplaceTotal || '--'}
          topRatedCount={topRatedCount || '--'}
        />

        <motion.div className="page-container" variants={pageStagger} initial="hidden" animate="visible">
          <MarketplaceShelves
            lowRiskPackages={lowRiskPackages}
            popularPackages={popularPackages}
            recentPackages={recentPackages}
            activeMarketView={activeMarketView}
            onMarketViewChange={handleMarketViewChange}
          />

          <motion.div id="marketplace-results" className="market-results-header" variants={fadeUp}>
            <div>
              <span>{t('home.results_kicker')}</span>
              <h2>{t('home.results_title')}</h2>
            </div>
            <p className="results-meta">{t('home.loading')}</p>
          </motion.div>

          <motion.div className="search-motion-layer" variants={fadeUp}>
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
              activeMarketView={activeMarketView}
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
              onMarketViewChange={handleMarketViewChange}
            />
          </motion.div>

          <motion.div className="package-grid-skeleton" variants={listStagger}>
            {Array.from({ length: 6 }).map((_, i) => (
              <motion.div key={i} className="package-card skeleton" variants={listItem}>
                <div className="skeleton-bar" style={{ width: '60%', height: '1.1rem', marginBottom: '0.5rem' }} />
                <div className="skeleton-bar" style={{ width: '90%', marginBottom: '0.25rem' }} />
                <div className="skeleton-bar" style={{ width: '70%', marginBottom: '0.75rem' }} />
                <div className="skeleton-bar" style={{ width: '40%', height: '0.75rem' }} />
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </>
    );
  }

  /* ── 错误状态 ── */
  if (error && packages.length === 0) {
    return (
      <>
        <MarketplaceHero totalPackages="--" publishedCount="--" topRatedCount="--" />

        <div className="page-container">
          <motion.div className="empty-state" variants={softPanel} initial="hidden" animate="visible">
            <div className="empty-state-icon">&#x26A0;</div>
            <h3>Failed to load packages</h3>
            <p>{error}</p>
            <button className="btn btn-secondary" style={{ marginTop: '1rem' }} onClick={loadFirstPage}>
              Retry
            </button>
          </motion.div>
        </div>
      </>
    );
  }

  return (
    <>
      <MarketplaceHero
        totalPackages={heroPackageCount}
        publishedCount={publishedCount}
        topRatedCount={topRatedCount}
      />

      <motion.div className="page-container" variants={pageStagger} initial="hidden" animate="visible">
        <MarketplaceShelves
          lowRiskPackages={lowRiskPackages}
          popularPackages={popularPackages}
          recentPackages={recentPackages}
          activeMarketView={activeMarketView}
          onMarketViewChange={handleMarketViewChange}
        />

        <motion.div id="marketplace-results" className="market-results-header" variants={fadeUp}>
          <div>
            <span>{t('home.results_kicker')}</span>
            <h2>{t('home.results_title')}</h2>
          </div>
          <p className="results-meta">
            {totalPackages === 1
              ? t('home.results_count', { count: totalPackages })
              : t('home.results_count_plural', { count: totalPackages })}
          </p>
        </motion.div>

        <motion.div className="search-motion-layer" variants={fadeUp}>
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
            activeMarketView={activeMarketView}
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
            onMarketViewChange={handleMarketViewChange}
          />
        </motion.div>

        {/* 加载指示条（已有数据时的刷新） */}
        <AnimatePresence>
          {loading && (
            <motion.div className="loading-bar" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
          )}
        </AnimatePresence>

        {/* 错误提示（已有缓存数据时） */}
        <AnimatePresence>
          {error && packages.length > 0 && (
            <motion.div className="error-banner" variants={softPanel} initial="hidden" animate="visible" exit="exit">
              <span>{error}</span>
              <button className="btn btn-sm btn-secondary" onClick={loadFirstPage}>Retry</button>
            </motion.div>
          )}
        </AnimatePresence>

        {packages.length === 0 ? (
          <motion.div className="empty-state" variants={softPanel} initial="hidden" animate="visible">
            <svg className="empty-state-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <h3>{t('home.no_results')}</h3>
            <p>{t('home.no_results_hint')}</p>
          </motion.div>
        ) : (
          <>
            <motion.div className="package-grid" variants={listStagger}>
              <AnimatePresence mode="popLayout">
                {packages.map((pkg) => (
                  <motion.div key={pkg.id} layout variants={listItem} initial="hidden" animate="visible" exit="exit">
                    <PackageCard pkg={pkg} />
                  </motion.div>
                ))}
              </AnimatePresence>
            </motion.div>

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
      </motion.div>
    </>
  );
}
