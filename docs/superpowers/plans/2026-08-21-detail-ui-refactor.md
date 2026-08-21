# Package Detail UI Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the package detail page as a marketplace-style two-column detail view with a sticky install and trust rail while preserving TrustedAgentHub safety data.

**Architecture:** Keep the existing package detail data fetching and install helpers unchanged. Extract route-local pure view-model helpers for permission summaries, trust advice, and display labels so the risky data-preservation behavior is testable. Refactor the page JSX into semantic sections and move new layout/styling into `globals.css`.

**Tech Stack:** Next.js 14 client route, React 18, TypeScript, Vitest, existing TrustedAgentHub CSS tokens.

---

### File Structure

- Create: `apps/web/src/app/package/[name]/detail-view-model.ts`
  - Pure helpers for labels, trust advice, permission summaries, and feedback text.
- Create: `apps/web/src/app/package/[name]/detail-view-model.test.ts`
  - Vitest coverage for helper behavior used by the refactored UI.
- Modify: `apps/web/src/app/package/[name]/page.tsx`
  - Keep fetch/state behavior, replace the stacked report layout with hero + left content + right install rail.
- Modify: `apps/web/src/app/globals.css`
  - Replace current `.detail-*` styles with responsive marketplace layout classes.

### Task 1: Add Tested Detail View-Model Helpers

**Files:**
- Create: `apps/web/src/app/package/[name]/detail-view-model.ts`
- Create: `apps/web/src/app/package/[name]/detail-view-model.test.ts`

- [ ] **Step 1: Write failing helper tests**

Create `apps/web/src/app/package/[name]/detail-view-model.test.ts` with tests that define the behavior needed by the new page:

```ts
import { describe, expect, it } from 'vitest';
import {
  formatFeedbackSummary,
  getGradeClass,
  getPermissionSummary,
  getRiskLabel,
  getTrustAdvice,
  getTypeLabel,
} from './detail-view-model';

describe('detail view model helpers', () => {
  it('formats empty and populated feedback counts', () => {
    expect(formatFeedbackSummary(null)).toBe('暂无评分');
    expect(formatFeedbackSummary({ positive: 3, neutral: 1, negative: 2 })).toBe('好评 3 · 差评 2');
  });

  it('maps package grades to rail classes and advice', () => {
    expect(getGradeClass('A')).toBe('trusted');
    expect(getGradeClass('C')).toBe('caution');
    expect(getGradeClass('E')).toBe('danger');
    expect(getGradeClass(null)).toBe('unknown');
    expect(getTrustAdvice('B')).toContain('Review permissions');
    expect(getTrustAdvice(null)).toContain('not been evaluated');
  });

  it('maps risk and type labels with readable fallbacks', () => {
    expect(getRiskLabel('medium_risk')).toBe('Medium Risk');
    expect(getRiskLabel(null)).toBe('Unknown');
    expect(getRiskLabel('custom')).toBe('custom');
    expect(getTypeLabel('mcp_server')).toBe('MCP Server');
    expect(getTypeLabel('custom')).toBe('custom');
  });

  it('summarizes empty permissions as locked down', () => {
    expect(getPermissionSummary(null)).toEqual([
      { label: 'Filesystem', value: 'No read/write/delete access', tone: 'safe' },
      { label: 'Shell', value: 'Not allowed', tone: 'safe' },
      { label: 'Network', value: 'Not allowed', tone: 'safe' },
    ]);
  });

  it('summarizes elevated permissions with caution and danger tones', () => {
    expect(getPermissionSummary({
      filesystem: { read: ['~/src'], write: ['~/.claude'], delete: true },
      shell: { allowed: true, commands: ['npm install'] },
      network: { allowed: true, domains: ['github.com'] },
      environment: { write: ['TOKEN'] },
      credentials: { access: ['github'] },
    })).toEqual([
      { label: 'Filesystem', value: 'Read 1 path · Write 1 path · Delete allowed', tone: 'danger' },
      { label: 'Shell', value: 'Allowed: npm install', tone: 'danger' },
      { label: 'Network', value: 'Allowed: github.com', tone: 'caution' },
      { label: 'Environment', value: 'Write 1 variable', tone: 'caution' },
      { label: 'Credentials', value: 'Access: github', tone: 'caution' },
    ]);
  });
});
```

- [ ] **Step 2: Run helper tests to verify RED**

Run:

```bash
cd apps/web
npm test -- src/app/package/[name]/detail-view-model.test.ts
```

Expected: FAIL because `detail-view-model.ts` does not exist.

- [ ] **Step 3: Implement helper module**

Create `apps/web/src/app/package/[name]/detail-view-model.ts`:

```ts
import type { VersionPermissions } from '@/types';

export const TYPE_LABELS: Record<string, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

export const RISK_LEVEL_LABELS: Record<string, string> = {
  trusted: 'Trusted',
  low_risk: 'Low Risk',
  medium_risk: 'Medium Risk',
  high_risk: 'High Risk',
  untrusted: 'Untrusted',
};

export type PermissionTone = 'safe' | 'caution' | 'danger';

export interface PermissionSummaryItem {
  label: string;
  value: string;
  tone: PermissionTone;
}

export function formatFeedbackSummary(
  counts?: { positive: number; neutral: number; negative: number } | null,
): string {
  if (!counts || counts.positive + counts.neutral + counts.negative === 0) {
    return '暂无评分';
  }
  return `好评 ${counts.positive} · 差评 ${counts.negative}`;
}

export function getGradeClass(grade: string | null): string {
  if (grade === null) return 'unknown';
  const g = grade.toUpperCase();
  if (g === 'A' || g === 'B') return 'trusted';
  if (g === 'C') return 'caution';
  if (g === 'D' || g === 'E') return 'danger';
  return 'unknown';
}

export function getRiskLabel(riskLevel: string | null): string {
  return riskLevel ? (RISK_LEVEL_LABELS[riskLevel] ?? riskLevel) : 'Unknown';
}

export function getTypeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type;
}

export function getTrustAdvice(grade: string | null): string {
  if (grade === null) return 'This package has not been evaluated yet.';
  if (grade === 'A') return 'This package has passed all security scans and is safe to install.';
  if (grade === 'B') return 'Low risk. Review permissions before installing.';
  if (grade === 'C') return 'Medium risk. Review the details and confirm before installing.';
  if (grade === 'D') return 'High risk. Installation is not recommended without thorough review.';
  return 'Untrusted. Installation is blocked by safety policy.';
}

const plural = (count: number, singular: string, pluralLabel = `${singular}s`) =>
  `${count} ${count === 1 ? singular : pluralLabel}`;

export function getPermissionSummary(perms?: VersionPermissions | null): PermissionSummaryItem[] {
  const filesystem = perms?.filesystem;
  const shell = perms?.shell;
  const network = perms?.network;
  const environment = perms?.environment;
  const credentials = perms?.credentials;

  const filesystemParts: string[] = [];
  if (filesystem?.read?.length) filesystemParts.push(`Read ${plural(filesystem.read.length, 'path')}`);
  if (filesystem?.write?.length) filesystemParts.push(`Write ${plural(filesystem.write.length, 'path')}`);
  if (filesystem?.delete) filesystemParts.push('Delete allowed');

  const items: PermissionSummaryItem[] = [
    {
      label: 'Filesystem',
      value: filesystemParts.length ? filesystemParts.join(' · ') : 'No read/write/delete access',
      tone: filesystem?.delete || Boolean(filesystem?.write?.length) ? 'danger' : 'safe',
    },
    {
      label: 'Shell',
      value: shell?.allowed ? `Allowed${shell.commands?.length ? `: ${shell.commands.join(', ')}` : ''}` : 'Not allowed',
      tone: shell?.allowed ? 'danger' : 'safe',
    },
    {
      label: 'Network',
      value: network?.allowed ? `Allowed${network.domains?.length ? `: ${network.domains.join(', ')}` : ''}` : 'Not allowed',
      tone: network?.allowed ? 'caution' : 'safe',
    },
  ];

  if (environment?.read?.length || environment?.write?.length) {
    const envParts: string[] = [];
    if (environment.read?.length) envParts.push(`Read ${plural(environment.read.length, 'variable')}`);
    if (environment.write?.length) envParts.push(`Write ${plural(environment.write.length, 'variable')}`);
    items.push({
      label: 'Environment',
      value: envParts.join(' · '),
      tone: environment.write?.length ? 'caution' : 'safe',
    });
  }

  if (credentials?.access?.length) {
    items.push({
      label: 'Credentials',
      value: `Access: ${credentials.access.join(', ')}`,
      tone: 'caution',
    });
  }

  return items;
}
```

- [ ] **Step 4: Run helper tests to verify GREEN**

Run:

```bash
cd apps/web
npm test -- src/app/package/[name]/detail-view-model.test.ts
```

Expected: PASS for the new helper tests.

### Task 2: Refactor Detail Page Markup

**Files:**
- Modify: `apps/web/src/app/package/[name]/page.tsx`

- [ ] **Step 1: Replace inline helper constants with imports**

Import `formatFeedbackSummary`, `getGradeClass`, `getPermissionSummary`, `getRiskLabel`, `getTrustAdvice`, and `getTypeLabel` from `./detail-view-model`. Remove the duplicate local `TYPE_LABELS`, `RISK_LEVEL_LABELS`, `formatFeedback`, and `getGradeClass`.

- [ ] **Step 2: Update loading skeleton**

Change `DetailSkeleton` to render a hero skeleton plus two-column body skeleton using `.detail-shell`, `.detail-main`, and `.detail-rail`.

- [ ] **Step 3: Build hero and section navigation**

Replace the current `.detail-header` markup with:

```tsx
<section className="detail-hero">
  <div className="detail-identity-mark">{typeLabel.charAt(0)}</div>
  <div className="detail-hero-copy">
    <div className="detail-title-row">
      <h1 className="detail-name">{pkg.name}</h1>
      <TypeBadge type={pkg.type} />
      <StatusBadge status={pkg.status} />
    </div>
    <p className="detail-source-line">...</p>
    <p className="detail-description">{pkg.description}</p>
    <div className="detail-badge-row">...</div>
    <div className="detail-meta-grid">...</div>
  </div>
</section>
```

Then add anchor navigation:

```tsx
<nav className="detail-section-nav" aria-label="Package detail sections">
  <a href="#overview">Overview</a>
  <a href="#trust">Trust Score</a>
  <a href="#permissions">Permissions</a>
  <a href="#installation">Installation</a>
  <a href="#versions">Versions</a>
  <a href="#feedback">Feedback</a>
</nav>
```

- [ ] **Step 4: Build the two-column shell**

Wrap the content in:

```tsx
<div className="detail-shell">
  <main className="detail-main">...</main>
  <aside className="detail-rail" aria-label="Installation and trust summary">...</aside>
</div>
```

Move detailed sections into `.detail-main`. Place install command, target client control, install path, grade summary, permission summary, and source actions in `.detail-rail`.

- [ ] **Step 5: Preserve all existing content categories**

Ensure the refactored page still renders source, compatibility, trust score, trust history, scan findings, permissions, dependencies, entry points, installation, keywords, feedback, and versions. Empty or unavailable sections should show compact local copy rather than disappear when the category is important for safety.

- [ ] **Step 6: Run route helper and install tests**

Run:

```bash
cd apps/web
npm test -- src/app/package/[name]/detail-view-model.test.ts src/lib/install-info.test.ts
```

Expected: PASS.

### Task 3: Add Responsive Detail Styling

**Files:**
- Modify: `apps/web/src/app/globals.css`

- [ ] **Step 1: Replace the existing detail page style block**

Update the `.detail-*` block around the current package detail styles to support:

- max width around 1180px,
- `.detail-hero` as a light surface with compact identity mark,
- `.detail-shell` as `minmax(0, 1fr) 340px`,
- `.detail-rail` sticky on desktop,
- `.rail-card`, `.install-block`, `.permission-summary`, `.detail-table`, `.version-list`, and `.detail-section-nav`.

- [ ] **Step 2: Add mobile rules**

Inside the existing responsive media area, add rules so the layout collapses to one column below 960px and prevents command blocks/tables from overflowing:

```css
@media (max-width: 960px) {
  .detail-shell {
    grid-template-columns: 1fr;
  }

  .detail-rail {
    position: static;
    order: -1;
  }
}
```

- [ ] **Step 3: Run TypeScript build check**

Run:

```bash
cd apps/web
npm run build
```

Expected: Build succeeds or reports only pre-existing monorepo/Docker-context unrelated issues. If a TypeScript or JSX error comes from the refactor, fix it before continuing.

### Task 4: Realtime Preview and Visual Verification

**Files:**
- No source files unless visual QA reveals defects.

- [ ] **Step 1: Start local web dev server**

If Docker web already occupies port 3000, use port 3001:

```bash
cd apps/web
npm run dev -- --port 3001
```

Expected: Next.js dev server prints a local URL.

- [ ] **Step 2: Open live package page**

Open:

```text
http://127.0.0.1:3001/package/superpowers
```

Expected: Page loads against the local TAH API at `http://127.0.0.1:8000` and shows real package data.

- [ ] **Step 3: Verify desktop layout**

Check a desktop viewport around 1365px wide:

- left content column and right install rail are visible,
- install rail is visually prominent and sticky,
- trust score, permissions, install command, versions, and feedback remain visible,
- color tone uses existing paper/accent/ink tokens.

- [ ] **Step 4: Verify mobile layout**

Check a narrow viewport around 390px wide:

- layout collapses to one column,
- install rail appears before long content,
- command blocks and tables scroll within their containers,
- text does not overlap or overflow.

- [ ] **Step 5: Final verification**

Run:

```bash
cd apps/web
npm test -- src/app/package/[name]/detail-view-model.test.ts src/lib/install-info.test.ts
```

Expected: PASS. Then capture `git diff --stat` and summarize changed files.

### Self-Review Checklist

- [ ] Spec coverage: desktop two-column, mobile one-column, sticky install rail, TAH trust/permissions/versions/feedback preserved.
- [ ] Placeholder scan: no `TBD`, `TODO`, or undefined helper names in this plan.
- [ ] Type consistency: helpers import `VersionPermissions` from `@/types`, and page imports helpers from `./detail-view-model`.
- [ ] Preview workflow: local dev server URL is included and does not rely on Docker web rebuild.
