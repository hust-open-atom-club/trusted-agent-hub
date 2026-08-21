# Package Detail UI Refactor Design

## Context

The package detail page currently presents package metadata, trust score,
permissions, installation, feedback, and versions as a single vertical stack of
large sections. The information is complete, but the first viewport feels more
like an internal report than a marketplace detail page.

The target direction is a hybrid upgrade inspired by SkillHub's plugin detail
layout, while keeping TrustedAgentHub's existing product identity and safety
signals.

## Goals

- Rework the package detail page into a professional marketplace layout.
- Use a left main content column plus a right sticky installation/action rail.
- Preserve TrustedAgentHub-specific safety content: trust score, permissions,
  verified source, install method, versions, and feedback.
- Keep the visual tone aligned with the current frontend palette rather than
  fully copying SkillHub.
- Make local development previewable in real time while implementing.

## Non-Goals

- Do not change package, version, install manifest, trust score, or feedback API
  contracts.
- Do not redesign the home page, review pages, admin pages, or submit flow.
- Do not add new package data fields.
- Do not implement real tabs with routing unless the existing data shape makes
  that cheap; section anchors are acceptable.

## Layout Direction

The approved direction is "Option C: hybrid upgrade."

The page uses a two-column desktop layout:

- Left column: package identity, overview/readme-style content, trust details,
  permissions, install details, versions, and feedback.
- Right column: sticky action rail with install command, target client,
  install path, grade summary, permission summary, and source actions.

The first viewport should include:

- Breadcrumb back to package browsing.
- Package type mark, using an existing icon style or a simple generated mark.
- Package name.
- Package slug/source line, including GitHub/source and owner where available.
- Description.
- Status/type/version/client/risk badges.
- Compact metadata row for version, license, installs, and feedback.
- Right-side installation card with the generated CLI command.
- Right-side trust summary card with grade, recommendation, shell/network/file
  permission summary, and verified source state.

The main content below the hero is organized as marketplace-style sections:

- Overview
- Trust Score
- Permissions
- Installation
- Versions
- Feedback

These sections may be navigated by inline tabs/anchor links. The page should not
hide content that exists today; it should reorganize it.

## Visual Tone

The refactor should stay visually consistent with the current TrustedAgentHub
frontend:

- Keep the warm brand accent used by the current logo/navigation.
- Use a light neutral page background and white/near-white surfaces.
- Use dark primary action buttons for install/copy actions.
- Use blue accents for installability and link affordances.
- Use green/amber/red only for trust and risk states.
- Avoid fully adopting SkillHub's black-and-white minimalism.
- Avoid making the page read as one beige/yellow theme; the brand accent should
  be present but restrained.

Cards should be flatter and less nested than the current detail page. Use section
surfaces only where they help scanning: hero panel, install rail cards, trust
summary, permission summaries, and repeated version/feedback rows.

## Component Shape

The current detail page file is large, so the implementation should introduce
small presentational helpers where useful:

- Detail hero/identity block.
- Metadata/badge row.
- Sticky install rail.
- Trust summary rail card.
- Section navigation.
- Permission summary blocks.

These helpers may live in the same route file initially if that keeps scope
small, but extracting route-local components is preferred if it makes the page
easier to read. Shared components should only be created when reusable outside
this page.

## Data Flow

Keep the existing data loading behavior:

- `fetchPackage(name)` loads the package summary.
- `fetchPackageVersion(name, latest_version)` loads version detail.
- `fetchPackageVersions(name)` loads published versions.
- `fetchTrustHistory(name)` loads trust history.
- Feedback remains handled by the existing `FeedbackSection`.

The install command continues to use `buildInstallCommand`, `getSelectableClients`,
`getClientLabel`, and `getClientTargetPath`.

If version detail fails to load, the page should still show package summary
information and avoid rendering misleading install/trust details. Empty states
should be compact and local to the affected section.

## Responsive Behavior

Desktop:

- Use the two-column layout.
- Right rail is sticky below the navigation.
- Main content width remains comfortable for reading and tables.

Tablet/mobile:

- Collapse to one column.
- Install card moves near the top, after the package identity and before long
  overview content.
- Section navigation can wrap horizontally.
- Tables and command blocks must not overflow the viewport.

## Real-Time Preview Workflow

Implementation should run from branch `detail-ui-refactor`.

During implementation:

- Run the web app in development mode so changes can be viewed immediately.
- Use the current local API at `http://127.0.0.1:8000`.
- Preview at least one real plugin page, such as
  `http://127.0.0.1:3000/package/superpowers`.
- Keep the preview URL available to the user while iterating.
- Use browser screenshots to validate desktop and narrow viewport layout before
  calling the work complete.

## Acceptance Criteria

- The package detail page uses the approved left-content/right-install-rail
  layout on desktop.
- The page preserves all currently visible detail categories: source,
  compatibility, trust score, trust history, permissions, dependencies,
  installation, keywords, feedback, and versions.
- The install command, selected client behavior, and target path remain correct.
- The visual tone remains aligned with the current frontend brand.
- The layout works without text overlap or horizontal scrolling on desktop and
  mobile widths.
- The page is verified against live local data.

## Open Implementation Notes

- The existing `apps/web` Docker build currently cannot resolve the monorepo
  `packages/schema/constants` import from its Docker build context. For live
  UI iteration, prefer the local Next dev server rather than Docker web rebuild
  unless that build context issue is separately addressed.
- The detail route currently has substantial inline style usage. The refactor
  should move new page styling into `globals.css` or route-local class names
  rather than adding more large inline style blocks.
