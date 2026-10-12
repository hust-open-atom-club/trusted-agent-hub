'use client';

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fadeUp, motion } from '@/components/Motion';
import type { CapabilityHighlight, CapabilityHighlightItem } from './detail-view-model';

export default function CapabilityHighlightCard({
  highlight,
}: {
  highlight: CapabilityHighlight;
}) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  const items = highlight.items ?? [];
  const limit = highlight.collapsedCount ?? items.length;
  const collapsed = items.length > limit;
  const visible = collapsed && !expanded ? items.slice(0, limit) : items;

  const itemText = (item: CapabilityHighlightItem) => {
    if (item.text !== undefined) return item.text;
    const values = { ...item.values };
    if (typeof values.scopeKey === 'string') {
      values.scope = String(t(values.scopeKey));
      delete values.scopeKey;
    }
    return String(t(item.textKey ?? '', values));
  };

  return (
    <motion.article className={`capability-highlight ${highlight.tone}`} variants={fadeUp}>
      <span>{t(highlight.labelKey)}</span>
      {items.length > 0 ? (
        highlight.variant === 'tags' ? (
          <div className="capability-highlight-tags">
            {visible.map((item) => (
              <span className="capability-highlight-tag" key={item.key}>
                {itemText(item)}
              </span>
            ))}
          </div>
        ) : (
          <ul className="capability-highlight-items">
            {visible.map((item) => (
              <li key={item.key}>{itemText(item)}</li>
            ))}
          </ul>
        )
      ) : (
        <strong>{String(t(highlight.textKey ?? '', highlight.values))}</strong>
      )}
      {collapsed && (
        <button
          type="button"
          className="capability-highlight-more"
          aria-expanded={expanded}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded
            ? t('detail.capability.tile.collapse')
            : t('detail.capability.tile.expand', { count: items.length })}
        </button>
      )}
      {highlight.authorDeclared && (
        <em className="capability-highlight-flag">
          {t('detail.capability.tile.author_declared')}
        </em>
      )}
    </motion.article>
  );
}
