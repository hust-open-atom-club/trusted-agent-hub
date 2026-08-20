import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import SearchBar from './SearchBar';

function renderSearchBar(overrides: Record<string, unknown> = {}) {
  const props = {
    query: '',
    activeType: 'all',
    sortBy: 'updated_at' as const,
    sortOrder: 'desc' as const,
    category: '',
    client: '',
    tag: '',
    minGrade: '',
    minScore: '',
    maxScore: '',
    updatedDays: '',
    onQueryChange: vi.fn(),
    onTypeChange: vi.fn(),
    onCategoryChange: vi.fn(),
    onSortChange: vi.fn(),
    onClientChange: vi.fn(),
    onTagChange: vi.fn(),
    onMinGradeChange: vi.fn(),
    onMinScoreChange: vi.fn(),
    onMaxScoreChange: vi.fn(),
    onUpdatedDaysChange: vi.fn(),
    ...overrides,
  };
  render(<SearchBar {...props} />);
  return props;
}

describe('SearchBar', () => {
  it('reflects the query value and reports changes', () => {
    const props = renderSearchBar({ query: 'summarize' });
    const input = screen.getByPlaceholderText('按名称、关键词或描述搜索...');
    expect(input).toHaveValue('summarize');

    fireEvent.change(input, { target: { value: 'json' } });
    expect(props.onQueryChange).toHaveBeenCalledWith('json');
  });

  it('switches type filters', () => {
    const props = renderSearchBar();
    fireEvent.click(screen.getByRole('button', { name: 'Skill' }));
    expect(props.onTypeChange).toHaveBeenCalledWith('skill');
  });

  it('marks the active type filter', () => {
    renderSearchBar({ activeType: 'mcp_server' });
    expect(screen.getByRole('button', { name: 'MCP Server' })).toHaveClass(
      'active',
    );
  });

  it('reports client, grade, updated-days and tag filters', () => {
    const props = renderSearchBar();

    fireEvent.change(screen.getByLabelText('Filter by client'), {
      target: { value: 'cursor' },
    });
    expect(props.onClientChange).toHaveBeenCalledWith('cursor');

    fireEvent.change(screen.getByLabelText('Filter by minimum trust grade'), {
      target: { value: 'C' },
    });
    expect(props.onMinGradeChange).toHaveBeenCalledWith('C');

    fireEvent.change(screen.getByLabelText('Filter by last updated'), {
      target: { value: '30' },
    });
    expect(props.onUpdatedDaysChange).toHaveBeenCalledWith('30');

    fireEvent.change(screen.getByLabelText('Filter by tag'), {
      target: { value: 'summary' },
    });
    expect(props.onTagChange).toHaveBeenCalledWith('summary');
  });

  it('reports score range inputs', () => {
    const props = renderSearchBar();

    fireEvent.change(screen.getByLabelText('Minimum trust score'), {
      target: { value: '60' },
    });
    expect(props.onMinScoreChange).toHaveBeenCalledWith('60');

    fireEvent.change(screen.getByLabelText('Maximum trust score'), {
      target: { value: '90' },
    });
    expect(props.onMaxScoreChange).toHaveBeenCalledWith('90');
  });

  it('reports sort field and order from the select', () => {
    const props = renderSearchBar();
    fireEvent.change(screen.getByLabelText('Sort packages'), {
      target: { value: 'grade:asc' },
    });
    expect(props.onSortChange).toHaveBeenCalledWith('grade', 'asc');
  });
});
