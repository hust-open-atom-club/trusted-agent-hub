#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { formatPackageCard, formatPackageDetail } from './format';
import { checkInstall } from './grade-gate';
import { client, ApiError } from './api-client';
import type { PackageSummary, VersionDetail } from './api-client';
import {
  PACKAGE_TYPE_LABELS,
  GRADE_LABELS,
} from '../../../packages/schema/constants';
import type { PackageType, Grade } from '../../../packages/schema/constants';

// ── Helpers ──────────────────────────────────────────────────────────────

/** Display an error and exit. */
function fatal(message: string, exitCode = 1): never {
  console.error('');
  console.error(chalk.red(`  ${message}`));
  console.error('');
  process.exit(exitCode);
}

/** Format an ApiError for the user. */
function handleApiError(err: unknown): never {
  if (err instanceof ApiError) {
    if (err.statusCode === 404) {
      fatal('Package not found.');
    }
    fatal(err.message);
  }
  fatal(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
}

// ── Program setup ───────────────────────────────────────────────────────

const program = new Command();

program
  .name('trusted-agent-hub')
  .description(
    chalk.bold('TrustedAgentHub CLI — AI agent capability package registry'),
  )
  .version('0.1.0');

// ── search ──────────────────────────────────────────────────────────────

program
  .command('search <keyword>')
  .description('Search packages by keyword (server-side filtering via API)')
  .option('-t, --type <type>', 'Filter by package type')
  .option('-c, --client <client>', 'Filter by client compatibility')
  .option('--category <category>', 'Filter by package category')
  .option('--page <page>', 'Page number (1-based)', '1')
  .option('--page-size <size>', 'Results per page (1-100)', '20')
  .action(async (keyword: string, options: {
    type?: string;
    client?: string;
    category?: string;
    page?: string;
    pageSize?: string;
  }) => {
    const pageRaw = parseInt(options.page || '1', 10);
    if (!Number.isFinite(pageRaw) || pageRaw < 1) {
      fatal(`Invalid --page value: "${options.page}". Must be a positive integer.`);
    }
    const page = pageRaw;
    const pageSizeRaw = parseInt(options.pageSize || '20', 10);
    if (!Number.isFinite(pageSizeRaw) || pageSizeRaw < 1 || pageSizeRaw > 100) {
      fatal(`Invalid --page-size value: "${options.pageSize}". Must be between 1 and 100.`);
    }
    const pageSize = pageSizeRaw;

    let result: { items: PackageSummary[]; total: number; total_pages: number };
    try {
      result = await client.searchPackages({
        q: keyword,
        type: options.type,
        client: options.client,
        category: options.category,
        page,
        page_size: pageSize,
      });
    } catch (err) {
      handleApiError(err);
    }

    console.log('');
    if (result.items.length === 0) {
      const filters: string[] = [];
      if (options.type) filters.push(`type="${options.type}"`);
      if (options.client) filters.push(`client="${options.client}"`);
      if (options.category) filters.push(`category="${options.category}"`);
      const suffix = filters.length > 0 ? ` with ${filters.join(', ')}` : '';
      console.log(chalk.yellow(`  No packages found for "${keyword}"${suffix}.`));
    } else {
      const filterDesc: string[] = [];
      if (options.type) filterDesc.push(`type: ${options.type}`);
      if (options.client) filterDesc.push(`client: ${options.client}`);
      if (options.category) filterDesc.push(`category: ${options.category}`);
      const suffix = filterDesc.length > 0 ? ` (filtered: ${filterDesc.join(', ')})` : '';
      console.log(
        chalk.bold(`  Found ${result.total} package(s) matching "${keyword}"${suffix}:`),
      );
      if (result.total_pages > 1) {
        console.log(chalk.dim(`  Page ${page}/${result.total_pages} (${result.items.length} shown)`));
      }
      console.log('');
      result.items.forEach((pkg, idx) => {
        console.log(formatPackageCard(pkg));
        if (idx < result.items.length - 1) console.log('');
      });
    }
    console.log('');
  });

// ── info ────────────────────────────────────────────────────────────────

program
  .command('info <name>')
  .description('Show detailed information about a package')
  .action(async (name: string) => {
    let pkg: PackageSummary;
    let version: VersionDetail | null = null;

    try {
      pkg = await client.getPackage(name);
    } catch (err) {
      handleApiError(err);
    }

    try {
      version = await client.getVersionDetail(name, pkg!.latest_version);
    } catch (err) {
      // Only 404 is acceptable for version detail (package exists but version file missing)
      if (!(err instanceof ApiError && err.statusCode === 404)) {
        handleApiError(err);
      }
    }

    console.log(formatPackageDetail(pkg!, version));
  });

// ── install ─────────────────────────────────────────────────────────────

program
  .command('install <name>')
  .description('Install a package with grade-based safety gating')
  .option('-y, --yes', 'Skip confirmation prompts (Grade C)')
  .option('-f, --force', 'First explicit consent for high-risk installs (Grade D)')
  .option('--accept-high-risk', 'Second explicit consent for high-risk installs (Grade D, required with --force)')
  .action(async (name: string, options: { yes?: boolean; force?: boolean; acceptHighRisk?: boolean }) => {
    let pkg: PackageSummary;
    let version: VersionDetail | null = null;

    const spinner = ora('Looking up package details…').start();
    try {
      pkg = await client.getPackage(name);
    } catch (err) {
      spinner.stop();
      handleApiError(err);
    }

    try {
      version = await client.getVersionDetail(name, pkg!.latest_version);
    } catch (err) {
      if (!(err instanceof ApiError && err.statusCode === 404)) {
        spinner.stop();
        handleApiError(err);
      }
    }
    spinner.stop();

    // ── Resolve grade and check install ──
    const gateResult = checkInstall(
      {
        grade: version?.trust_score?.risk_summary?.grade || pkg!.grade || null,
        riskLevel: pkg!.risk_level || null,
        versionLevel: version?.trust_score?.risk_summary?.level || null,
      },
      { yes: options.yes, force: options.force, acceptHighRisk: options.acceptHighRisk },
    );

    const grade = gateResult.grade;
    const rec = version?.trust_score?.risk_summary?.install_recommendation || null;
    const topRisks = version?.trust_score?.risk_summary?.top_risks || [];
    const trustScore = pkg!.trust_score;

    // ── Display summary ──
    console.log('');
    console.log(
      `  ${chalk.dim('Package:')}  ${chalk.cyan(pkg!.name)}  ${chalk.dim('v' + pkg!.latest_version)}`,
    );
    console.log(
      `  ${chalk.dim('Type:')}     ${PACKAGE_TYPE_LABELS[pkg!.type as PackageType] || pkg!.type}`,
    );

    if (grade && grade !== 'unknown') {
      const gradeLabel = GRADE_LABELS[grade as Grade] || grade;
      const policy = (gateResult as any).policy || 'block';
      const policyIcon =
        policy === 'allow' ? chalk.green('✓')
        : policy === 'warn' ? chalk.yellow('⚠')
        : policy === 'confirm' ? chalk.yellow('⚠')
        : chalk.red('✗');
      console.log(
        `  ${chalk.dim('Grade:')}     ${chalk.bold(gradeLabel)}  ${policyIcon} ${
          policy === 'allow' ? chalk.green('允许自动安装')
          : policy === 'warn' ? chalk.yellow('展示权限声明')
          : policy === 'confirm' ? chalk.yellow('需确认后安装')
          : chalk.red('禁止安装')}`,
      );
    }

    if (trustScore !== null) console.log(`  ${chalk.dim('Trust:')}    ${trustScore}/100`);
    if (rec) console.log(`  ${chalk.dim('Recommend:')} ${rec}`);

    if (topRisks.length > 0) {
      console.log('');
      console.log(`  ${chalk.yellow('Top risks:')}`);
      for (const risk of topRisks.slice(0, 5)) {
        console.log(`    ${chalk.dim('•')} ${risk}`);
      }
    }

    console.log('');

    if (!gateResult.allowed) {
      const reason = 'reason' in gateResult ? gateResult.reason : 'Installation blocked by safety policy.';
      const header =
        grade === 'E' ? chalk.red.bold('  ✗ Installation blocked')
        : grade === 'D' ? chalk.yellow.bold('  ⚠ Grade D — High Risk')
        : grade === 'C' ? chalk.yellow.bold('  ⚠ Installation requires confirmation')
        : chalk.red.bold('  ✗ Installation blocked');
      console.log(header);
      console.log(chalk.yellow(`    ${reason}`));
      console.log('');
      return;
    }

    if (grade === 'D') {
      console.log(chalk.yellow.bold('  ⚠ Forcing install of Grade D package'));
      console.log(chalk.yellow('    You have confirmed twice (--force + --accept-high-risk).'));
    }

    if (grade === 'B' && version?.permissions) {
      console.log(chalk.blue('  ℹ Grade B — Low Risk'));
      console.log(chalk.blue('    Review the permission declarations:'));
      const perms = version.permissions;
      if (perms.filesystem) console.log(chalk.dim(`      filesystem: ${JSON.stringify(perms.filesystem)}`));
      if (perms.shell) console.log(chalk.dim(`      shell: ${JSON.stringify(perms.shell)}`));
      if (perms.network) console.log(chalk.dim(`      network: ${JSON.stringify(perms.network)}`));
      if (perms.environment) console.log(chalk.dim(`      environment: ${JSON.stringify(perms.environment)}`));
    }

    if (version?.installation?.targets) {
      console.log(`  ${chalk.dim('Targets:')}`);
      for (const t of version.installation.targets) {
        console.log(`    ${chalk.dim('•')} ${t.client}: ${t.destination}`);
      }
    }

    if (version?.installation?.post_install_message) {
      console.log('');
      console.log(chalk.cyan(`  ℹ ${version.installation.post_install_message}`));
    }

    console.log('');
    console.log(chalk.green('  ✓ Ready to install'));
    console.log(chalk.dim('  Install execution pending backend API integration.'));
    console.log('');
  });

// ── Parse ───────────────────────────────────────────────────────────────

program.parse();
