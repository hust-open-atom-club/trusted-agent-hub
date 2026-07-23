'use client';

import { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchPackages, type Package } from '@/data/packages';
import SearchBar from '@/components/SearchBar';
import PackageCard from '@/components/PackageCard';

export default function HomePage() {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [activeType, setActiveType] = useState('all');
  const [packages, setPackages] = useState<Package[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPackages()
      .then(setPackages)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();

    return packages.filter((pkg) => {
      if (activeType !== 'all' && pkg.type !== activeType) {
        return false;
      }

      if (!q) return true;

      const matchName = pkg.name.toLowerCase().includes(q);
      const matchDesc = pkg.description.toLowerCase().includes(q);
      const matchKeyword = pkg.keywords.some((kw) =>
        kw.toLowerCase().includes(q)
      );

      return matchName || matchDesc || matchKeyword;
    });
  }, [query, activeType, packages]);

  return (
    <>
      <section className="hero">
        <div className="hero-bg" />
        <div className="hero-content">
          <span className="hero-chip">{t('home.chip')}</span>
          <h1 className="hero-title">
            {t('home.title')}<br />
            <span className="hero-title-accent">{t('home.title_accent')}</span>
          </h1>
          <p className="hero-desc">{t('home.desc')}</p>
          <div className="hero-stats">
            <div className="hero-stat">
              <span className="hero-stat-num">{packages.length}</span>
              <span className="hero-stat-label">{t('home.stat_packages')}</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat">
              <span className="hero-stat-num">
                {packages.filter(p => p.status === 'published').length}
              </span>
              <span className="hero-stat-label">{t('home.stat_published')}</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat">
              <span className="hero-stat-num">
                {packages.filter(p => p.grade === 'A' || p.grade === 'B').length}
              </span>
              <span className="hero-stat-label">{t('home.stat_top_rated')}</span>
            </div>
          </div>
        </div>
      </section>

      <div className="page-container">
        <SearchBar
          query={query}
          activeType={activeType}
          onQueryChange={setQuery}
          onTypeChange={setActiveType}
        />

        {loading && (
          <div className="empty-state">
            <svg className="empty-state-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <h3>{t('home.loading')}</h3>
          </div>
        )}

        {error && (
          <div className="empty-state">
            <svg className="empty-state-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <h3>{t('home.load_error')}</h3>
            <p>{error}</p>
          </div>
        )}

        {!loading && !error && (
          <>
            <p className="results-meta">
              {filtered.length === 1
                ? t('home.results_count', { count: filtered.length })
                : filtered.length}
              {filtered.length !== 1 ? ' packages found' : ''}
            </p>

            {filtered.length === 0 ? (
              <div className="empty-state">
                <svg className="empty-state-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <h3>{t('home.no_results')}</h3>
                <p>{t('home.no_results_hint')}</p>
              </div>
            ) : (
              <div className="package-grid">
                {filtered.map((pkg) => (
                  <PackageCard key={pkg.id} pkg={pkg} />
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}