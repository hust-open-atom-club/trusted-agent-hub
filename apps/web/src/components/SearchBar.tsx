'use client';

import { useTranslation } from 'react-i18next';
import type { SortField, SortOrder } from '@/data/packages';

interface SearchBarProps {
  query: string;
  activeType: string;
  sortBy: SortField;
  sortOrder: SortOrder;
  category: string;
  onQueryChange: (value: string) => void;
  onTypeChange: (value: string) => void;
  onCategoryChange: (value: string) => void;
  onSortChange: (field: SortField, order: SortOrder) => void;
}

const FILTER_KEYS = ['all', 'skill', 'mcp_server', 'plugin', 'command', 'subagent', 'prompt'] as const;

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
  onQueryChange,
  onTypeChange,
  onCategoryChange,
  onSortChange,
}: SearchBarProps) {
  const { t } = useTranslation();
  const activeSortKey = `${sortBy}:${sortOrder}`;

  return (
    <div className="search-section">
      <div className="search-bar">
        <span className="search-icon">&#x1F50D;</span>
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

        <div className="search-extras">
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
  );
}
