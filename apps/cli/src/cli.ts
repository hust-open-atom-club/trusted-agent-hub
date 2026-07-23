#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { formatPackageCard, formatPackageDetail } from './format';
import { InstallExecutor, InstallBlockedError, InstallError } from './install-executor';
import { VerifyExecutor } from './verify-executor';
import type { VerifyResult } from './verify-executor';
import { UninstallExecutor } from './uninstall-executor';
import type { UninstallResult } from './uninstall-executor';
import { createTerminalConfirm } from './confirm';
import { validateManifest, ManifestValidationError } from './manifest-types';
import type { InstallManifest } from './manifest-types';
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

// Allow subcommands to define options that shadow root-level options
// (e.g. install --version <version> vs root --version).
program.enablePositionalOptions();

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
  .option('-c, --client <client>', 'Target client (e.g. claude-code)', 'claude-code')
  .option('--version <version>', 'Specific version to install (default: latest)')
  .option('-y, --yes', 'Skip confirmation prompts (Grade C)')
  .option('-f, --force', 'First explicit consent for high-risk installs (Grade D)')
  .option('--accept-high-risk', 'Second explicit consent for high-risk installs (Grade D, required with --force)')
  .action(async (name: string, options: {
    client?: string;
    version?: string;
    yes?: boolean;
    force?: boolean;
    acceptHighRisk?: boolean;
  }) => {
    const clientType = options.client || 'claude-code';
    const executor = new InstallExecutor(client);

    // ── Display intent ──
    console.log('');
    console.log(`  ${chalk.dim('Package:')}  ${chalk.cyan(name)}`);
    console.log(`  ${chalk.dim('Client:')}   ${chalk.cyan(clientType)}`);
    if (options.version) {
      console.log(`  ${chalk.dim('Version:')}  ${chalk.cyan(options.version)}`);
    }
    console.log('');

    // ── Phase 1: Fetch manifest ──
    const fetchSpinner = ora('Fetching install manifest…').start();
    let manifestRaw: unknown;
    try {
      manifestRaw = await client.getInstallManifest(name, clientType, options.version || undefined);
    } catch (err) {
      fetchSpinner.stop();
      if (err instanceof ApiError && err.statusCode === 404) {
        fatal('Package not found or no published version available.');
      }
      if (err instanceof ApiError && err.statusCode === 409) {
        fatal(
          `Install manifest unavailable for "${name}" with client "${clientType}".\n` +
          `    This package may not support this client, or installation is blocked by the server.`,
        );
      }
      handleApiError(err);
    }
    fetchSpinner.stop();

    // ── Phase 2: Validate manifest (client-side) ──
    let manifest: InstallManifest;
    try {
      manifest = validateManifest(manifestRaw);
    } catch (err: unknown) {
      if (err instanceof ManifestValidationError) {
        fatal(
          `Invalid install manifest received from server.\n` +
          `    ${err.message}\n` +
          `    This is a server-side issue — please report it to the package maintainer.`,
        );
      }
      throw err;
    }

    // ── Display package info ──
    console.log(`  ${chalk.dim('Package:')}  ${chalk.cyan(manifest.name)}  ${chalk.dim('v' + manifest.version)}`);
    console.log(`  ${chalk.dim('Type:')}     ${PACKAGE_TYPE_LABELS[manifest.type as PackageType] || manifest.type}`);
    const gradeVal = manifest.risk_summary.grade || null;
    if (gradeVal) {
      const gradeLabel = GRADE_LABELS[gradeVal as Grade] || gradeVal;
      const policy = gradeVal === 'A' ? 'allow' : gradeVal === 'B' ? 'warn' : gradeVal === 'C' ? 'confirm' : gradeVal === 'D' ? 'confirm' : 'block';
      const policyIcon =
        policy === 'allow' ? chalk.green('✓')
        : policy === 'warn' ? chalk.yellow('⚠')
        : policy === 'confirm' ? chalk.yellow('⚠')
        : chalk.red('✗');
      console.log(
        `  ${chalk.dim('Grade:')}     ${chalk.bold(gradeLabel)}  ${policyIcon}`,
      );
    }
    console.log(`  ${chalk.dim('Source:')}   ${manifest.source.type} · ${manifest.source.repository_url}`);
    const rec = manifest.risk_summary.install_recommendation;
    if (rec) console.log(`  ${chalk.dim('Recommend:')} ${rec}`);

    // Top risks
    if (manifest.risk_summary.top_risks && manifest.risk_summary.top_risks.length > 0) {
      console.log('');
      console.log(`  ${chalk.yellow('Top risks:')}`);
      for (const risk of manifest.risk_summary.top_risks.slice(0, 5)) {
        console.log(`    ${chalk.dim('•')} ${risk}`);
      }
    }

    // Permissions for Grade B
    if (gradeVal === 'B' && manifest.permissions) {
      console.log('');
      console.log(chalk.blue('  ℹ Grade B — Review permissions:'));
      const p = manifest.permissions;
      if (p.filesystem) console.log(chalk.dim(`    filesystem: ${JSON.stringify(p.filesystem)}`));
      if (p.shell) console.log(chalk.dim(`    shell: ${JSON.stringify(p.shell)}`));
      if (p.network) console.log(chalk.dim(`    network: ${JSON.stringify(p.network)}`));
      if (p.environment) console.log(chalk.dim(`    environment: ${JSON.stringify(p.environment)}`));
    }

    console.log('');

    // ── Phase 3: Execute install (reuse pre-fetched manifest) ──
    const installSpinner = ora('Installing…').start();
    try {
      const result = await executor.installWithManifest(
        manifest,
        clientType,
        {
          yes: options.yes,
          force: options.force,
          acceptHighRisk: options.acceptHighRisk,
        },
      );

      installSpinner.succeed(chalk.green('Installation complete'));

      console.log('');
      console.log(`  ${chalk.dim('Installed to:')} ${chalk.cyan(result.targetDir)}`);
      console.log(`  ${chalk.dim('SHA-256:')}      ${chalk.dim(result.sha256.slice(0, 16))}…`);
      console.log(`  ${chalk.dim('Record:')}       ${chalk.dim('~/.trusted-agent-hub/installs.json')}`);

      // Post-install message
      if (manifest.installation.post_install_message) {
        console.log('');
        console.log(chalk.cyan(`  ℹ ${manifest.installation.post_install_message}`));
      }

      console.log('');
    } catch (err: unknown) {
      installSpinner.stop();

      if (err instanceof InstallBlockedError) {
        const header =
          err.grade === 'E' ? chalk.red.bold('  ✗ Installation blocked (Grade E)')
          : err.grade === 'D' ? chalk.yellow.bold('  ⚠ Grade D — requires --force + --accept-high-risk')
          : err.grade === 'C' ? chalk.yellow.bold('  ⚠ Grade C — requires --yes')
          : chalk.red.bold('  ✗ Installation blocked');
        console.log(header);
        console.log(chalk.yellow(`    ${err.message}`));
        console.log('');
        process.exit(1);
      }

      if (err instanceof InstallError) {
        console.log('');
        console.log(chalk.red.bold(`  ✗ Installation failed (${err.code})`));
        console.log(chalk.red(`    ${err.message}`));
        console.log('');
        process.exit(1);
      }

      // Unexpected errors
      console.log('');
      console.log(chalk.red.bold('  ✗ Installation failed'));
      console.log(chalk.red(`    ${err instanceof Error ? err.message : String(err)}`));
      console.log('');
      process.exit(1);
    }
  });

// ── verify ──────────────────────────────────────────────────────────────

/**
 * Print a verify result with a stable, machine-parseable status line.
 * Never leaks file content, tokens, or response bodies.
 */
function printVerifyResult(result: VerifyResult): void {
  const icon =
    result.status === 'valid' ? chalk.green('✓')
    : result.status === 'remote_unavailable' ? chalk.yellow('⚠')
    : chalk.red('✗');

  console.log('');
  console.log(`  ${icon} ${chalk.bold(result.packageName)}${result.version ? chalk.dim(' v' + result.version) : ''}  ${chalk.dim(`[${result.status}]`)}`);
  console.log(`  ${chalk.dim('Client:')}       ${result.client}`);
  if (result.installPath) {
    console.log(`  ${chalk.dim('Install path:')} ${result.installPath}`);
  }
  if (result.artifactSha256) {
    console.log(`  ${chalk.dim('Artifact SHA:')} ${result.artifactSha256.slice(0, 16)}…`);
  }
  if (result.expectedContentSha256) {
    console.log(`  ${chalk.dim('Expected content:')} ${result.expectedContentSha256.slice(0, 16)}…`);
  }
  if (result.actualContentSha256) {
    const match = result.expectedContentSha256 === result.actualContentSha256;
    const color = match ? chalk.dim : chalk.red;
    console.log(`  ${chalk.dim('Actual content:')}   ${color(result.actualContentSha256.slice(0, 16) + '…')}`);
  }
  console.log('');
  console.log(`  ${result.status === 'valid' ? chalk.green(result.message) : chalk.yellow(result.message)}`);
  console.log('');
}

program
  .command('verify <name>')
  .description('Verify an installed package against its local record and registry manifest')
  .option('-c, --client <client>', 'Installed client', 'claude-code')
  .action(async (name: string, options: { client: string }) => {
    const result = await new VerifyExecutor(client).verify(name, options.client);
    printVerifyResult(result);
    if (!result.ok) process.exitCode = 1;
  });

// ── uninstall ────────────────────────────────────────────────────────────

/**
 * Print an uninstall result with a stable, machine-parseable status line.
 * Never leaks file content, tokens, or response bodies.
 */
function printUninstallResult(result: UninstallResult): void {
  const icon =
    result.ok ? chalk.green('✓')
    : result.status === 'cancelled' ? chalk.green('✓')
    : chalk.red('✗');

  console.log('');
  console.log(
    `  ${icon} ${chalk.bold(result.packageName)}  ${chalk.dim(`[${result.status}]`)}`,
  );
  if (result.version) {
    console.log(`  ${chalk.dim('Version:')}       ${result.version}`);
  }
  console.log(`  ${chalk.dim('Client:')}        ${result.client}`);
  if (result.installPath) {
    console.log(`  ${chalk.dim('Install path:')}  ${result.installPath}`);
  }
  if (result.quarantinePath) {
    console.log(`  ${chalk.dim('Recovery path:')} ${result.quarantinePath}`);
  }
  console.log('');
  console.log(`  ${result.ok ? chalk.green(result.message) : chalk.yellow(result.message)}`);
  console.log('');
}

program
  .command('uninstall <name>')
  .description('Safely uninstall a locally installed package')
  .option('-c, --client <client>', 'Installed client', 'claude-code')
  .option('-y, --yes', 'Skip the confirmation prompt')
  .option('-f, --force', 'Allow modified or legacy content to be removed')
  .action(async (
    name: string,
    options: { client: string; yes?: boolean; force?: boolean },
  ) => {
    const confirm = options.yes ? undefined : createTerminalConfirm();
    const result = await new UninstallExecutor().uninstall(name, options.client, {
      yes: options.yes,
      force: options.force,
      confirm,
    });
    printUninstallResult(result);
    if (!result.ok) process.exitCode = 1;
  });

// ── Parse ───────────────────────────────────────────────────────────────

program.parse();
