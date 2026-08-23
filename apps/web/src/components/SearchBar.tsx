'use client';

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { SortField, SortOrder } from '@/data/packages';
import { AnimatePresence, listItem, listStagger, motion, softPanel } from '@/components/Motion';

type MarketView = 'all' | 'low_risk' | 'popular' | 'recent';

interface SearchBarProps {
  query: string;
  activeType: string;
  sortBy: SortField;
  sortOrder: SortOrder;
  category: string;
  client: string;
  tag: string;
  minGrade: string;
  minScore: string;
  maxScore: string;
  updatedDays: string;
  activeMarketView: MarketView;
  onQueryChange: (value: string) => void;
  onTypeChange: (value: string) => void;
  onCategoryChange: (value: string) => void;
  onSortChange: (field: SortField, order: SortOrder) => void;
  onClientChange: (value: string) => void;
  onTagChange: (value: string) => void;
  onMinGradeChange: (value: string) => void;
  onMinScoreChange: (value: string) => void;
  onMaxScoreChange: (value: string) => void;
  onUpdatedDaysChange: (value: string) => void;
  onMarketViewChange: (view: MarketView) => void;
}

const FILTER_KEYS = ['all', 'skill', 'mcp_server', 'plugin', 'command', 'subagent', 'prompt'] as const;

const CLIENT_OPTIONS = ['claude-code', 'cursor', 'claude-code-plugin'] as const;

const GRADE_OPTIONS = ['A', 'B', 'C', 'D', 'E'] as const;

const UPDATED_OPTIONS = ['7', '30', '90'] as const;

const SORT_OPTIONS: { field: SortField; order: SortOrder; key: string }[] = [
  { field: 'updated_at', order: 'desc', key: 'updated' },
  { field: 'install_count', order: 'desc', key: 'installed' },
  { field: 'avg_rating', order: 'desc', key: 'rated' },
  { field: 'name', order: 'asc', key: 'name_asc' },
  { field: 'grade', order: 'asc', key: 'trust' },
];

function SearchGlyph() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function ArrowGlyph() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

export default function SearchBar({
  query,
  activeType,
  sortBy,
  sortOrder,
  category,
  client,
  tag,
  minGrade,
  minScore,
  maxScore,
  updatedDays,
  activeMarketView = 'all',
  onQueryChange,
  onTypeChange,
  onCategoryChange,
  onSortChange,
  onClientChange,
  onTagChange,
  onMinGradeChange,
  onMinScoreChange,
  onMaxScoreChange,
  onUpdatedDaysChange,
  onMarketViewChange,
}: SearchBarProps) {
  const { t } = useTranslation();
  const activeSortKey = `${sortBy}:${sortOrder}`;
  const [isFocused, setIsFocused] = useState(false);
  const [isFiltersOpen, setIsFiltersOpen] = useState(false);
  const hasActiveFilters = Boolean(
    activeType !== 'all' ||
      client ||
      category ||
      tag ||
      minGrade ||
      minScore ||
      maxScore ||
      updatedDays ||
      sortBy !== 'updated_at' ||
      sortOrder !== 'desc',
  );
  const showFilters = isFiltersOpen;
  const normalizedQuery = query.trim();
  const isContextView = activeMarketView !== 'all';
  const showTypeFilters = activeMarketView === 'all' || activeMarketView === 'popular' || activeMarketView === 'recent';
  const showTrustFilters = activeMarketView === 'all' || activeMarketView === 'low_risk';
  const showScoreFilters = activeMarketView === 'all' || activeMarketView === 'low_risk';
  const showFreshnessFilters = activeMarketView === 'all' || activeMarketView === 'recent';
  const showGeneralFilters = activeMarketView === 'all';

  useEffect(() => {
    if (activeMarketView !== 'all') {
      setIsFiltersOpen(true);
    }
  }, [activeMarketView]);

  const suggestionActions = [
    {
      label: t('search.quick_low_risk'),
      description: t('search.quick_low_risk_desc'),
      end: 'Trust',
      onClick: () => onMarketViewChange('low_risk'),
    },
    {
      label: t('search.quick_popular'),
      description: t('search.quick_popular_desc'),
      end: 'Sort',
      onClick: () => onMarketViewChange('popular'),
    },
    {
      label: t('search.quick_recent'),
      description: t('search.quick_recent_desc'),
      end: 'Fresh',
      onClick: () => onMarketViewChange('recent'),
    },
  ];

  return (
    <div className="search-section">
      <div className={`search-command ${isFocused ? 'is-focused' : ''} ${normalizedQuery ? 'has-query' : ''}`}>
        <div className="search-bar">
          <span className="search-icon search-icon-stack" aria-hidden="true">
            <span className={`search-icon-layer ${normalizedQuery ? 'is-hidden' : 'is-visible'}`}>
              <SearchGlyph />
            </span>
            <span className={`search-icon-layer ${normalizedQuery ? 'is-visible' : 'is-hidden'}`}>
              <ArrowGlyph />
            </span>
          </span>
          <input
            type="text"
            className="search-input"
            placeholder={t('search.placeholder')}
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && normalizedQuery) {
                onQueryChange(normalizedQuery);
              }
              if (e.key === 'Escape') {
                setIsFocused(false);
                e.currentTarget.blur();
              }
            }}
            onBlur={() => window.setTimeout(() => setIsFocused(false), 140)}
          />
        </div>

        <AnimatePresence>
          {isFocused && (
            <motion.div
              className="search-suggestions"
              role="listbox"
              aria-label={t('search.quick_filters')}
              variants={softPanel}
              initial="hidden"
              animate="visible"
              exit="exit"
            >
              <div className="search-suggestions__header">
                <span>{t('search.quick_filters')}</span>
                <span>{t('search.enter_hint')}</span>
              </div>
              <motion.div className="search-suggestions__list" variants={listStagger} initial="hidden" animate="visible">
                {normalizedQuery && (
                  <motion.button
                    type="button"
                    className="search-suggestion-item search-suggestion-item--query"
                    aria-label={`搜索 ${normalizedQuery}`}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => onQueryChange(normalizedQuery)}
                    variants={listItem}
                    whileHover={{ x: 2 }}
                    whileTap={{ scale: 0.99 }}
                  >
                    <span className="search-suggestion-icon"><SearchGlyph /></span>
                    <span className="search-suggestion-copy">
                      <strong>{t('search.query_action', { query: normalizedQuery })}</strong>
                      <span>{t('search.query_action_desc')}</span>
                    </span>
                    <span className="search-suggestion-end">Query</span>
                  </motion.button>
                )}
                {suggestionActions.map((action) => (
                  <motion.button
                    type="button"
                    className="search-suggestion-item"
                    key={action.label}
                    aria-label={action.label}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={action.onClick}
                    variants={listItem}
                    whileHover={{ x: 2 }}
                    whileTap={{ scale: 0.99 }}
                  >
                    <span className="search-suggestion-icon"><ArrowGlyph /></span>
                    <span className="search-suggestion-copy">
                      <strong>{action.label}</strong>
                      <span>{action.description}</span>
                    </span>
                    <span className="search-suggestion-end">{action.end}</span>
                  </motion.button>
                ))}
              </motion.div>
              <div className="search-suggestions__footer">
                <span>{t('search.quick_footer')}</span>
                <span>{t('search.esc_hint')}</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="search-controls-row">
        <div className="search-context-bar">
          <div className="search-context-bar__copy">
            <span>{t('search.current_view')}</span>
            <strong>{t(`search.view_${activeMarketView}`)}</strong>
          </div>

          <div className="search-context-bar__actions">
            {isContextView && (
              <button
                type="button"
                className="advanced-filter-toggle"
                onClick={() => onMarketViewChange('all')}
              >
                {t('search.clear_view')}
              </button>
            )}
            <button
              type="button"
              className={`advanced-filter-toggle ${showFilters || hasActiveFilters ? 'active' : ''}`}
              aria-expanded={showFilters}
              onClick={() => setIsFiltersOpen((open) => !open)}
            >
              <span>{t('search.filter_options')}</span>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M3 6h18" />
                <path d="M7 12h10" />
                <path d="M10 18h4" />
              </svg>
            </button>
          </div>
        </div>

        <AnimatePresence initial={false}>
          {showFilters && (
            <motion.div
              className="search-filters-panel is-open"
              initial={{ opacity: 0, height: 0, y: -6 }}
              animate={{ opacity: 1, height: 'auto', y: 0 }}
              exit={{ opacity: 0, height: 0, y: -6 }}
              transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
            >
              {showTypeFilters && (
                <div className="filter-group filter-group--wide">
                  <span className="filter-label">{t('search.type')}</span>
                  <div className="type-filters type-filters--panel">
                    {FILTER_KEYS.map((key) => (
                      <button
                        key={key}
                        className={`type-filter-btn ${activeType === key ? 'active' : ''}`}
                        onClick={() => onTypeChange(key)}
                      >
                        {t(`search.${key}`)}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {showGeneralFilters && (
                <div className="filter-group">
                  <span className="filter-label">{t('search.client')}</span>
                  <select
                    className="sort-select"
                    value={client}
                    onChange={(e) => onClientChange(e.target.value)}
                    aria-label={t('search.client')}
                  >
                    <option value="">{t('search.all_clients')}</option>
                    {CLIENT_OPTIONS.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
              )}

              {showTrustFilters && (
                <div className="filter-group">
                  <span className="filter-label">{t('search.trust_grade')}</span>
                  <select
                    className="sort-select"
                    value={minGrade}
                    onChange={(e) => onMinGradeChange(e.target.value)}
                    aria-label={t('search.trust_grade')}
                  >
                    <option value="">{t('search.any_grade')}</option>
                    {GRADE_OPTIONS.map((g) => (
                      <option key={g} value={g}>{t('search.grade_or_better', { grade: g })}</option>
                    ))}
                  </select>
                </div>
              )}

              {showScoreFilters && (
                <div className="filter-group">
                  <span className="filter-label">{t('search.score_range')}</span>
                  <div className="score-range">
                    <input
                      type="number"
                      className="filter-input"
                      min={0}
                      max={100}
                      placeholder={t('search.min_score')}
                      value={minScore}
                      onChange={(e) => onMinScoreChange(e.target.value)}
                      aria-label={t('search.min_score')}
                      style={{ width: '5.5rem' }}
                    />
                    <span className="score-sep">-</span>
                    <input
                      type="number"
                      className="filter-input"
                      min={0}
                      max={100}
                      placeholder={t('search.max_score')}
                      value={maxScore}
                      onChange={(e) => onMaxScoreChange(e.target.value)}
                      aria-label={t('search.max_score')}
                      style={{ width: '5.5rem' }}
                    />
                  </div>
                </div>
              )}

              {showFreshnessFilters && (
                <div className="filter-group">
                  <span className="filter-label">{t('search.updated_time')}</span>
                  <select
                    className="sort-select"
                    value={updatedDays}
                    onChange={(e) => onUpdatedDaysChange(e.target.value)}
                    aria-label={t('search.updated_time')}
                  >
                    <option value="">{t('search.any_time')}</option>
                    {UPDATED_OPTIONS.map((d) => (
                      <option key={d} value={d}>{t('search.updated_within_days', { days: d })}</option>
                    ))}
                  </select>
                </div>
              )}

              {showGeneralFilters && (
                <div className="filter-group">
                  <span className="filter-label">{t('search.tag')}</span>
                  <input
                    type="text"
                    className="filter-input"
                    placeholder={t('search.tag_placeholder')}
                    value={tag}
                    onChange={(e) => onTagChange(e.target.value)}
                    aria-label={t('search.tag')}
                    style={{ width: '8rem' }}
                  />
                </div>
              )}

              <div className="filter-group">
                <span className="filter-label">{t('search.sort')}</span>
                <select
                  className="sort-select"
                  value={activeSortKey}
                  onChange={(e) => {
                    const [field, order] = e.target.value.split(':') as [SortField, SortOrder];
                    onSortChange(field, order);
                  }}
                  aria-label={t('search.sort')}
                >
                  {SORT_OPTIONS.map((opt) => (
                    <option key={`${opt.field}:${opt.order}`} value={`${opt.field}:${opt.order}`}>
                      {t(`sort.${opt.key}`)}
                    </option>
                  ))}
                </select>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
