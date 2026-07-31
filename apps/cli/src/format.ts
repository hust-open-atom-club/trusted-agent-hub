import chalk from 'chalk';
import {
  PACKAGE_TYPE_LABELS,
  VERSION_STATUS_LABELS,
  RISK_LEVEL_LABELS,
  INSTALL_RECOMMENDATION_LABELS,
  GRADE_LABELS,
  RISK_LEVEL_TO_GRADE,
  GRADE_TO_RISK_LEVEL,
  GRADE_TO_RECOMMENDATION,
} from '../../../packages/schema/constants';
import type {
  PackageType,
  VersionStatus,
  RiskLevel,
  InstallRecommendation,
  Grade,
} from '../../../packages/schema/constants';
import type { PackageSummary, VersionDetail } from './api-client';

// ── Color helpers ───────────────────────────────────────────────────────

/** Return a chalk colour for a risk level string. */
function riskLevelColor(level: string | null): chalk.Chalk {
  if (level === null) return chalk.gray;
  switch (level) {
    case 'trusted':    return chalk.green;
    case 'low_risk':   return chalk.blue;
    case 'medium_risk':return chalk.yellow;
    case 'high_risk':  return chalk.red;
    case 'untrusted':  return chalk.redBright;
    default:           return chalk.gray;
  }
}

/** Return a chalk colour for a version status string. */
function statusColor(status: string): chalk.Chalk {
  switch (status) {
    case 'published':     return chalk.green;
    case 'approved':      return chalk.greenBright;
    case 'pending_review':return chalk.yellow;
    case 'scanning':      return chalk.blue;
    case 'submitted':     return chalk.blue;
    case 'draft':         return chalk.dim;
    case 'rejected':      return chalk.red;
    case 'error':         return chalk.redBright;
    case 'yanked':        return chalk.magenta;
    case 'resubmitted':   return chalk.yellow;
    default:              return chalk.gray;
  }
}

/** Return a chalk colour for a grade value (A-E). */
function gradeColor(grade: string | null): chalk.Chalk {
  if (grade === null) return chalk.gray;
  switch (grade) {
    case 'A': return chalk.greenBright;
    case 'B': return chalk.blue;
    case 'C': return chalk.yellow;
    case 'D': return chalk.red;
    case 'E': return chalk.redBright;
    default:  return chalk.gray;
  }
}

/** Resolve grade from version detail, preferring effective_grade.
 *
 * Resolution order:
 * 1. version.effective_grade (manual_grade or auto_grade from backend)
 * 2. pkg.grade (already enriched from effective_grade)
 * 3. version.trust_score.risk_summary.grade (auto grade fallback)
 * 4. risk_level → grade mapping (legacy data)
 */
function resolveGrade(pkg: PackageSummary, version: VersionDetail | null): string | null {
  // Prefer effective_grade from version (reflects manual override)
  if (version?.effective_grade) {
    return version.effective_grade;
  }
  if (pkg.grade) return pkg.grade;
  // Fallback: auto grade from risk_summary
  if (version?.trust_score?.risk_summary?.grade) {
    return version.trust_score.risk_summary.grade;
  }
  // Legacy: map risk_level → grade
  const level = pkg.risk_level || version?.trust_score?.risk_summary?.level;
  if (level && level in RISK_LEVEL_TO_GRADE) {
    return RISK_LEVEL_TO_GRADE[level];
  }
  return null;
}

// ── Public formatters ───────────────────────────────────────────────────

/**
 * Compact single-package card used in search result listings.
 */
export function formatPackageCard(pkg: PackageSummary): string {
  const typeLabel = PACKAGE_TYPE_LABELS[pkg.type as PackageType] || pkg.type;
  const statusLabel =
    VERSION_STATUS_LABELS[pkg.status as VersionStatus] || pkg.status;
  const effectiveRiskLevel = pkg.grade
    ? GRADE_TO_RISK_LEVEL[pkg.grade as Grade]
    : null;
  const displayRiskLevel = effectiveRiskLevel || pkg.risk_level;
  const riskLabel = displayRiskLevel
    ? RISK_LEVEL_LABELS[displayRiskLevel as RiskLevel]
    : 'N/A';

  const lines: string[] = [];

  // Name + type badge
  lines.push(
    `  ${chalk.bold.cyan(pkg.name)}  ${chalk.dim(`[${typeLabel}]`)}`,
  );

  // Description
  lines.push(`    ${chalk.dim(pkg.description)}`);

  // Grade
  const gradeVal = pkg.grade || null;
  const gradeStr = gradeVal ? `${gradeColor(gradeVal)(gradeVal)}` : '';

  // Stats row
  const stats = [
    gradeStr ? `${chalk.dim('Grade:')} ${gradeStr}` : null,
    `${chalk.dim('Risk:')} ${riskLevelColor(displayRiskLevel)(riskLabel)}`,
    `${chalk.dim('Status:')} ${statusColor(pkg.status)(statusLabel)}`,
    `${chalk.dim('v')}${pkg.latest_version}`,
    `${chalk.dim('Installs:')} ${pkg.install_count.toLocaleString()}`,
    `${chalk.dim('Rating:')} ${pkg.avg_rating != null ? pkg.avg_rating.toString() : 'N/A'}`,
  ].filter(Boolean) as string[];
  lines.push(`    ${stats.join('  ')}`);

  // Keywords
  if (pkg.keywords.length > 0) {
    lines.push(
      `    ${chalk.dim('Keywords:')} ${pkg.keywords.map((k) => chalk.dim(k)).join(', ')}`,
    );
  }

  return lines.join('\n');
}

/**
 * Detailed single-package display used by the `info` command.
 */
export function formatPackageDetail(
  pkg: PackageSummary,
  version: VersionDetail | null,
): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(
    `  ${chalk.bold.cyan(pkg.name)}  ${chalk.dim(`v${pkg.latest_version}`)}`,
  );
  lines.push(`  ${chalk.dim('─'.repeat(58))}`);

  // Basic metadata
  lines.push(
    `  ${chalk.dim('Type:')}        ${PACKAGE_TYPE_LABELS[pkg.type as PackageType] || pkg.type}`,
  );
  lines.push(`  ${chalk.dim('Description:')} ${pkg.description}`);
  lines.push(`  ${chalk.dim('License:')}     ${pkg.license}`);

  if (version?.author) {
    const a = version.author;
    const authorStr = [a.name, a.email ? `<${a.email}>` : '', a.url ? a.url : '']
      .filter(Boolean)
      .join(' ');
    lines.push(`  ${chalk.dim('Author:')}      ${authorStr}`);
  }

  lines.push(
    `  ${chalk.dim('Homepage:')}    ${pkg.homepage || 'N/A'}`,
  );

  // Trust & risk section
  lines.push('');
  const gradeVal = resolveGrade(pkg, version);
  if (gradeVal) {
    const gradeLabel = GRADE_LABELS[gradeVal as Grade] || gradeVal;
    lines.push(
      `  ${chalk.dim('Grade:')}        ${gradeColor(gradeVal)(gradeLabel)}`,
    );
  }
  const effectiveRiskLevel = gradeVal
    ? GRADE_TO_RISK_LEVEL[gradeVal as Grade]
    : null;
  const displayRiskLevel = effectiveRiskLevel || pkg.risk_level;
  const riskLabel = displayRiskLevel
    ? RISK_LEVEL_LABELS[displayRiskLevel as RiskLevel]
    : 'N/A';
  lines.push(
    `  ${chalk.dim('Risk Level:')}  ${riskLevelColor(displayRiskLevel)(riskLabel)}`,
  );
  const statusLabel =
    VERSION_STATUS_LABELS[pkg.status as VersionStatus] || pkg.status;
  lines.push(
    `  ${chalk.dim('Status:')}      ${statusColor(pkg.status)(statusLabel)}`,
  );

  // Install recommendation (from effective_grade)
  {
    const rec = gradeVal
      ? GRADE_TO_RECOMMENDATION[gradeVal as Grade]
      : version?.trust_score?.risk_summary?.install_recommendation;
    if (rec) {
      const recLabel =
        INSTALL_RECOMMENDATION_LABELS[rec as InstallRecommendation] || rec;
      lines.push(
        `  ${chalk.dim('Recommend:')}   ${recLabel}`,
      );
    }
  }

  // Stats
  lines.push('');
  lines.push(
    `  ${chalk.dim('Installs:')}    ${pkg.install_count.toLocaleString()}`,
  );
  lines.push(
    `  ${chalk.dim('Rating:')}      ${pkg.avg_rating != null ? '★'.repeat(Math.round(pkg.avg_rating)) + ` (${pkg.avg_rating})` : 'N/A'}`,
  );

  // Keywords
  if (pkg.keywords.length > 0) {
    lines.push(
      `  ${chalk.dim('Keywords:')}   ${pkg.keywords.join(', ')}`,
    );
  }

  // Client compatibility (from version file)
  if (version?.compatibility && version.compatibility.length > 0) {
    lines.push(
      `  ${chalk.dim('Clients:')}     ${version.compatibility.join(', ')}`,
    );
  }

  // Owner
  const ownerStr = pkg.owner
    ? pkg.owner.display_name
    : 'N/A';
  lines.push(
    `  ${chalk.dim('Owner:')}       ${ownerStr}`,
  );

  // Permissions summary (from version)
  if (version?.permissions) {
    const perms: string[] = [];
    const p = version.permissions as Record<string, unknown>;
    if (p.filesystem) perms.push('filesystem');
    if (p.shell) perms.push('shell');
    if (p.network) perms.push('network');
    if (p.environment) perms.push('environment');
    if (p.credentials) perms.push('credentials');
    if (perms.length > 0) {
      lines.push(
        `  ${chalk.dim('Permissions:')} ${perms.join(', ')}`,
      );
    }
  }

  // Top risks
  if (version?.trust_score?.risk_summary?.top_risks?.length) {
    lines.push('');
    lines.push(`  ${chalk.yellow('Top risks:')}`);
    for (const risk of version.trust_score.risk_summary.top_risks) {
      lines.push(`    ${chalk.dim('•')} ${risk}`);
    }
  }

  lines.push(`  ${chalk.dim('─'.repeat(58))}`);
  lines.push('');

  return lines.join('\n');
}
