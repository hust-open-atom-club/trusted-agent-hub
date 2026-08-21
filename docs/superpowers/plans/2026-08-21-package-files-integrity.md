# Package Files And Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add package file browsing, source preview, and visible integrity/signature information to the public package detail page.

**Architecture:** Reuse the existing `VersionDetail` response and enrich it with scan report file contents when available. Convert `scan_file_contents` into a typed tree for a reusable file-tree component, then render a detail-page section alongside an integrity panel that exposes SHA-256, commit hash, signatures, attestation, SBOM, and artifact size.

**Tech Stack:** Next.js 14 app router, React 18, TypeScript, Vitest, FastAPI/Pydantic, SQLAlchemy, existing global CSS. This repo does not use shadcn or Tailwind; the file tree reference will be adapted to `apps/web/src/components/ui/file-tree.tsx` with project-local CSS classes.

---

### Task 1: View Model Helpers

**Files:**
- Modify: `apps/web/src/app/package/[name]/detail-view-model.ts`
- Modify: `apps/web/src/app/package/[name]/detail-view-model.test.ts`

- [ ] Write failing tests for building a nested file tree from `scan_file_contents`, default file selection, byte-size formatting, and integrity row extraction.
- [ ] Run `npm test -- "src/app/package/[name]/detail-view-model.test.ts"` and confirm the new tests fail.
- [ ] Implement `buildFileTree`, `getFileEntries`, `getDefaultSelectedPath`, `formatByteSize`, and `getIntegrityRows`.
- [ ] Re-run the same test and confirm it passes.

### Task 2: File Tree Component

**Files:**
- Create: `apps/web/src/components/ui/file-tree.tsx`
- Create: `apps/web/src/components/ui/file-tree.test.tsx`

- [ ] Write failing tests for rendering folder/file nodes and selecting a file.
- [ ] Run `npm test -- src/components/ui/file-tree.test.tsx` and confirm failure.
- [ ] Implement a Tailwind-free React file tree component with folder toggles, selected state, file sizes, and ARIA tree roles.
- [ ] Re-run the test and confirm it passes.

### Task 3: Detail Page Sections

**Files:**
- Modify: `apps/web/src/app/package/[name]/page.tsx`
- Modify: `apps/web/src/app/package/[name]/detail-i18n.test.ts`
- Modify: `apps/web/src/i18n/locales/zh/common.json`
- Modify: `apps/web/src/i18n/locales/en/common.json`
- Modify: `apps/web/src/app/globals.css`

- [ ] Add i18n keys for `detail.nav.files`, `detail.nav.integrity`, file browser labels, empty states, and integrity labels.
- [ ] Render a `files` section from `scan_file_contents`, with file tree on the left and code preview on the right.
- [ ] Render an `integrity` section from `source` and `integrity` data.
- [ ] Add CSS matching the current TAH palette and responsive layout.

### Task 4: Public API File Contents

**Files:**
- Modify: `apps/api/src/models/packages.py`
- Modify: `apps/api/src/repositories/sqlalchemy.py`
- Modify: `apps/api/src/services/packages.py`
- Modify: `apps/api/tests/test_packages_contract.py`

- [ ] Write a failing API/service test showing a public version includes `scan_file_contents` from scan reports.
- [ ] Add `scan_file_contents` to the public `VersionDetail` model.
- [ ] Add read-only `get_scan_report` to the consumer SQLAlchemy repository.
- [ ] Enrich public version responses with `scan_json.file_contents` when the repository supports scan reports.

### Task 5: Verification

**Files:**
- No new files.

- [ ] Run focused web tests for detail helpers, file tree, i18n, and install command.
- [ ] Run focused API package contract tests.
- [ ] Run `npm run build`.
- [ ] Restart the web dev server on port 3001 after build.
- [ ] Verify `http://127.0.0.1:3001/package/superpowers` in the browser.
- [ ] Run `git diff --check`.
