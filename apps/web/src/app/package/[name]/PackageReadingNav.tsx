'use client';

import { useEffect, useState } from 'react';
import type { MouseEvent } from 'react';

export interface ReadingNavItem {
  id: string;
  label: string;
}

export default function PackageReadingNav({ items, title }: { items: ReadingNavItem[]; title: string }) {
  const [activeId, setActiveId] = useState(items[0]?.id ?? '');

  const handleNavClick = (event: MouseEvent<HTMLAnchorElement>, id: string) => {
    const target = document.getElementById(id);
    if (!target) {
      return;
    }

    event.preventDefault();
    setActiveId(id);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({
      behavior: prefersReducedMotion ? 'auto' : 'smooth',
      block: 'start',
    });
    window.history.pushState(null, '', `#${id}`);
  };

  useEffect(() => {
    if (!items.length) {
      return;
    }

    let frame = 0;

    const updateActiveSection = () => {
      const sections = items
        .map((item) => ({ ...item, element: document.getElementById(item.id) }))
        .filter((item): item is ReadingNavItem & { element: HTMLElement } => Boolean(item.element));

      if (!sections.length) {
        return;
      }

      const isAtPageEnd = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
      if (isAtPageEnd) {
        setActiveId(sections[sections.length - 1].id);
        return;
      }

      const readingLine = window.innerHeight * 0.3;
      const currentSection = sections.reduce((current, section) => {
        const top = section.element.getBoundingClientRect().top;
        return top <= readingLine ? section : current;
      }, sections[0]);

      setActiveId(currentSection.id);
    };

    const scheduleUpdate = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(updateActiveSection);
    };

    scheduleUpdate();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
    };
  }, [items]);

  if (!items.length) {
    return null;
  }

  return (
    <nav className="detail-reading-nav" aria-label={title}>
      <div className="detail-reading-nav-label">{title}</div>
      <div className="detail-reading-nav-track">
        {items.map((item, index) => {
          const isActive = activeId === item.id;
          return (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={isActive ? 'active' : undefined}
              aria-current={isActive ? 'true' : undefined}
              onClick={(event) => handleNavClick(event, item.id)}
            >
              <span className="detail-reading-nav-index" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
              <span className="detail-reading-nav-text">{item.label}</span>
            </a>
          );
        })}
      </div>
    </nav>
  );
}
