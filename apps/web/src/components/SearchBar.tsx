'use client';

const FILTER_OPTIONS = [
  { key: 'all', label: 'All' },
  { key: 'skill', label: 'Skill' },
  { key: 'mcp_server', label: 'MCP Server' },
  { key: 'plugin', label: 'Plugin' },
  { key: 'command', label: 'Command' },
  { key: 'subagent', label: 'Subagent' },
  { key: 'prompt', label: 'Prompt' },
];

interface SearchBarProps {
  query: string;
  activeType: string;
  onQueryChange: (value: string) => void;
  onTypeChange: (value: string) => void;
}

export default function SearchBar({
  query,
  activeType,
  onQueryChange,
  onTypeChange,
}: SearchBarProps) {
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
    </div>
  );
}
