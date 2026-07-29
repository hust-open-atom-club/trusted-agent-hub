'use client';

import type { SortField, SortOrder } from '@/data/packages';

const FILTER_OPTIONS = [
  { key: 'all', label: 'All' },
  { key: 'skill', label: 'Skill' },
  { key: 'mcp_server', label: 'MCP Server' },
  { key: 'plugin', label: 'Plugin' },
  { key: 'command', label: 'Command' },
  { key: 'subagent', label: 'Subagent' },
  { key: 'prompt', label: 'Prompt' },
];

const SORT_OPTIONS: { field: SortField; order: SortOrder; label: string }[] = [
  { field: 'updated_at', order: 'desc', label: 'Recently updated' },
  { field: 'install_count', order: 'desc', label: 'Most installed' },
  { field: 'avg_rating', order: 'desc', label: 'Highest rated' },
  { field: 'name', order: 'asc', label: 'Name A–Z' },
  { field: 'grade', order: 'asc', label: 'Trust level' },
];

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
  const activeSortKey = `${sortBy}:${sortOrder}`;

  return (
    <div className="search-section">
      <div className="search-bar">
        <span className="search-icon">&#x1F50D;</span>
        <input
          type="text"
          className="search-input"
          placeholder="Search packages by name, keyword, or description..."
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
        />
      </div>

      <div className="search-controls-row">
        <div className="type-filters">
          {FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.key}
              className={`type-filter-btn ${activeType === opt.key ? 'active' : ''}`}
              onClick={() => onTypeChange(opt.key)}
            >
              {opt.label}
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
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}
