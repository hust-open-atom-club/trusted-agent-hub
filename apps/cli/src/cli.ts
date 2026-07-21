#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { loadPackages, loadVersionForPackage } from './mock-loader';
import { formatPackageCard, formatPackageDetail } from './format';
import { checkInstall, resolveGrade } from './grade-gate';
import {
  PACKAGE_TYPE_LABELS,
  CLIENT_LABELS,
  GRADE_LABELS,
} from '../../../packages/schema/constants';
import type { PackageType, Client, Grade } from '../../../packages/schema/constants';

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
  .description('Search packages by keyword (matches name, description, and keywords)')
  .option(
    '-t, --type <type>',
    'Filter by package type: skill, mcp_server, plugin, subagent, command, prompt',
  )
  .option(
    '-c, --client <client>',
    'Filter by client compatibility (e.g. claude-code, cursor, vscode)',
  )
  .action(
    (
      keyword: string,
      options: { type?: string; client?: string },
    ) => {
      const packages = loadPackages();
      const kw = keyword.toLowerCase().trim();

      // Keyword matching on name, description, and keyword tags
      let results = packages.filter((pkg) => {
        if (pkg.name.toLowerCase().includes(kw)) return true;
        if (pkg.description.toLowerCase().includes(kw)) return true;
        if (pkg.keywords.some((k) => k.toLowerCase().includes(kw))) return true;
        return false;
      });

      // Type filter
      if (options.type) {
        const before = results.length;
        results = results.filter((pkg) => pkg.type === options.type);
      }

      // Client compatibility filter
      if (options.client) {
        results = results.filter((pkg) => {
          const version = loadVersionForPackage(pkg);
          if (!version || !version.compatibility) return false;
          return version.compatibility.includes(options.client!);
        });
      }

      // Output
      console.log('');
      if (results.length === 0) {
        const filters: string[] = [];
        if (options.type) filters.push(`type="${options.type}"`);
        if (options.client) filters.push(`client="${options.client}"`);
        const suffix = filters.length > 0 ? ` with ${filters.join(', ')}` : '';
        console.log(
          chalk.yellow(`  No packages found for "${keyword}"${suffix}.`),
        );
      } else {
        const filterDesc: string[] = [];
        if (options.type) filterDesc.push(`type: ${options.type}`);
        if (options.client) filterDesc.push(`client: ${options.client}`);
        const suffix =
          filterDesc.length > 0 ? `  (filtered: ${filterDesc.join(', ')})` : '';

        console.log(
          chalk.bold(
            `  Found ${results.length} package(s) matching "${keyword}"${suffix}:`,
          ),
        );
        console.log('');
        results.forEach((pkg, idx) => {
          console.log(formatPackageCard(pkg));
          if (idx < results.length - 1) console.log('');
        });
      }
      console.log('');
    },
  );

// ── info ────────────────────────────────────────────────────────────────

program
  .command('info <name>')
  .description('Show detailed information about a package')
  .action((name: string) => {
    const packages = loadPackages();
    const pkg = packages.find((p) => p.name === name);

    if (!pkg) {
      console.log('');
      console.log(chalk.red(`  Package "${name}" not found.`));
      console.log(
        chalk.dim(`  Use "${chalk.cyan('trusted-agent-hub search <keyword>')}" to discover packages.`),
      );
      console.log('');
      return;
    }

    const version = loadVersionForPackage(pkg);
    console.log(formatPackageDetail(pkg, version));
  });

// ── install ─────────────────────────────────────────────────────────────

program
  .command('install <name>')
  .description('Install a package with grade-based safety gating')
  .option('-y, --yes', 'Skip confirmation prompts (Grade C)')
  .option('-f, --force', 'First explicit consent for high-risk installs (Grade D)')
  .option('--accept-high-risk', 'Second explicit consent for high-risk installs (Grade D, required with --force)')
  .action(async (name: string, options: { yes?: boolean; force?: boolean; acceptHighRisk?: boolean }) => {
    const packages = loadPackages();
    const pkg = packages.find((p) => p.name === name);

    if (!pkg) {
      console.log('');
      console.log(chalk.red(`  Package "${name}" not found.`));
      console.log(
        chalk.dim(`  Use "${chalk.cyan('trusted-agent-hub search <keyword>')}" to discover packages.`),
      );
      console.log('');
      return;
    }

    const spinner = ora('Looking up package details…').start();
    const version = loadVersionForPackage(pkg);
    await new Promise((resolve) => setTimeout(resolve, 400));
    spinner.stop();

    // ── Resolve grade and check install ──
    const gateResult = checkInstall(
      {
        grade: version?.trust_score?.risk_summary?.grade || pkg.grade || null,
        riskLevel: pkg.risk_level || null,
        versionLevel: version?.trust_score?.risk_summary?.level || null,
      },
      { yes: options.yes, force: options.force, acceptHighRisk: options.acceptHighRisk },
    );

    const grade = gateResult.grade;
    const rec = version?.trust_score?.risk_summary?.install_recommendation || null;
    const topRisks = version?.trust_score?.risk_summary?.top_risks || [];
    const trustScore = pkg.trust_score;

    // ── Display summary ──
    console.log('');
    console.log(
      `  ${chalk.dim('Package:')}  ${chalk.cyan(pkg.name)}  ${chalk.dim('v' + pkg.latest_version)}`,
    );
    console.log(
      `  ${chalk.dim('Type:')}     ${PACKAGE_TYPE_LABELS[pkg.type as PackageType] || pkg.type}`,
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
        `  ${chalk.dim('Grade:')}     ${chalk.bold(gradeLabel)}  ${policyIcon} ${policy === 'allow' ? chalk.green('允许自动安装')
          : policy === 'warn' ? chalk.yellow('展示权限声明')
          : policy === 'confirm' ? chalk.yellow('需确认后安装')
          : chalk.red('禁止安装')}`,
      );
    }

    if (trustScore !== null) {
      console.log(`  ${chalk.dim('Trust:')}    ${trustScore}/100`);
    }
    if (rec) {
      console.log(`  ${chalk.dim('Recommend:')} ${rec}`);
    }

    // ── Top risks ──
    if (topRisks.length > 0) {
      console.log('');
      console.log(`  ${chalk.yellow('Top risks:')}`);
      for (const risk of topRisks.slice(0, 5)) {
        console.log(`    ${chalk.dim('•')} ${risk}`);
      }
    }

    console.log('');

    // ── Gating result ──
    if (!gateResult.allowed) {
      const reason = 'reason' in gateResult ? gateResult.reason : 'Installation blocked by safety policy.';
      if (grade === 'E') {
        console.log(chalk.red.bold('  ✗ Installation blocked'));
      } else if (grade === 'D') {
        console.log(chalk.yellow.bold('  ⚠ Grade D — High Risk'));
      } else if (grade === 'C') {
        console.log(chalk.yellow.bold('  ⚠ Installation requires confirmation'));
      } else {
        console.log(chalk.red.bold('  ✗ Installation blocked'));
      }
      console.log(chalk.yellow(`    ${reason}`));
      console.log('');
      return;
    }

    // Grade D allowed (both flags provided)
    if (grade === 'D') {
      console.log(chalk.yellow.bold('  ⚠ Forcing install of Grade D package'));
      console.log(chalk.yellow('    You have confirmed twice (--force + --accept-high-risk).'));
      console.log(chalk.yellow('    Please review the risks above carefully.'));
    }

    // Grade B: show permissions but allow
    if (grade === 'B') {
      console.log(chalk.blue('  ℹ Grade B — Low Risk'));
      console.log(chalk.blue('    Review the permission declarations:'));
      if (version?.permissions) {
        const perms = version.permissions as Record<string, unknown>;
        if (perms.filesystem) console.log(chalk.dim(`      filesystem: ${JSON.stringify(perms.filesystem)}`));
        if (perms.shell) console.log(chalk.dim(`      shell: ${JSON.stringify(perms.shell)}`));
        if (perms.network) console.log(chalk.dim(`      network: ${JSON.stringify(perms.network)}`));
        if (perms.environment) console.log(chalk.dim(`      environment: ${JSON.stringify(perms.environment)}`));
      }
    }

    // ── Install targets (informational — actual install is pending API) ──
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

    if (version?.installation?.command) {
      console.log(
        `  ${chalk.dim('Setup:')}    ${version.installation.command}`,
      );
    }

    console.log('');
    console.log(chalk.green('  ✓ Ready to install'));
    console.log(chalk.dim('  Install execution pending backend API integration.'));
    console.log('');
  });

// ── Parse ───────────────────────────────────────────────────────────────

program.parse();
