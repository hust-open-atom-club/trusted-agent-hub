'use client';

import { useTranslation } from 'react-i18next';
import type { SortField, SortOrder } from '@/data/packages';

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
}

const FILTER_KEYS = ['all', 'skill', 'mcp_server', 'plugin', 'command', 'subagent', 'prompt'] as const;

const CLIENT_OPTIONS = ['claude-code', 'cursor'] as const;

const GRADE_OPTIONS = ['A', 'B', 'C', 'D', 'E'] as const;

const UPDATED_OPTIONS = ['7', '30', '90'] as const;

const SORT_OPTIONS: { field: SortField; order: SortOrder; key: string }[] = [
  { field: 'updated_at', order: 'desc', key: 'updated' },
  { field: 'install_count', order: 'desc', key: 'installed' },
  { field: 'avg_rating', order: 'desc', key: 'rated' },
  { field: 'name', order: 'asc', key: 'name_asc' },
  { field: 'grade', order: 'asc', key: 'trust' },
];

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
}: SearchBarProps) {
  const { t } = useTranslation();
  const activeSortKey = `${sortBy}:${sortOrder}`;

  return (
    <div className="search-section">
      <div className="search-bar">
        <span className="search-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        </span>
        <input
          type="text"
          className="search-input"
          placeholder={t('search.placeholder')}
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
        />
      </div>

      <div className="search-controls-row">
        <div className="type-filters">
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

        <div className="search-filters-panel">
          <div className="filter-group">
            <span className="filter-label">客户端</span>
            <select
              className="sort-select"
              value={client}
              onChange={(e) => onClientChange(e.target.value)}
              aria-label="Filter by client"
            >
              <option value="">全部客户端</option>
              {CLIENT_OPTIONS.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <span className="filter-label">信任等级</span>
            <select
              className="sort-select"
              value={minGrade}
              onChange={(e) => onMinGradeChange(e.target.value)}
              aria-label="Filter by minimum trust grade"
            >
              <option value="">不限等级</option>
              {GRADE_OPTIONS.map((g) => (
                <option key={g} value={g}>{g} 及以上</option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <span className="filter-label">评分范围</span>
            <div className="score-range">
              <input
                type="number"
                className="filter-input"
                min={0}
                max={100}
                placeholder="最低"
                value={minScore}
                onChange={(e) => onMinScoreChange(e.target.value)}
                aria-label="Minimum trust score"
                style={{ width: '5.5rem' }}
              />
              <span className="score-sep">–</span>
              <input
                type="number"
                className="filter-input"
                min={0}
                max={100}
                placeholder="最高"
                value={maxScore}
                onChange={(e) => onMaxScoreChange(e.target.value)}
                aria-label="Maximum trust score"
                style={{ width: '5.5rem' }}
              />
            </div>
          </div>

          <div className="filter-group">
            <span className="filter-label">更新时间</span>
            <select
              className="sort-select"
              value={updatedDays}
              onChange={(e) => onUpdatedDaysChange(e.target.value)}
              aria-label="Filter by last updated"
            >
              <option value="">不限时间</option>
              {UPDATED_OPTIONS.map((d) => (
                <option key={d} value={d}>{d} 天内更新</option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <span className="filter-label">标签</span>
            <input
              type="text"
              className="filter-input"
              placeholder="标签关键词"
              value={tag}
              onChange={(e) => onTagChange(e.target.value)}
              aria-label="Filter by tag"
              style={{ width: '8rem' }}
            />
          </div>

          <div className="filter-group">
            <span className="filter-label">排序</span>
            <select
              className="sort-select"
              value={activeSortKey}
              onChange={(e) => {
                const [field, order] = e.target.value.split(':') as [SortField, SortOrder];
                onSortChange(field, order);
              }}
              aria-label="Sort packages"
            >
              {SORT_OPTIONS.map((opt) => (
                <option key={`${opt.field}:${opt.order}`} value={`${opt.field}:${opt.order}`}>
                  {t(`sort.${opt.key}`)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}
