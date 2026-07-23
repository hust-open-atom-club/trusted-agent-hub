/**
 * Safe terminal confirmation for destructive operations.
 *
 * Provides a TTY-aware confirmation callback that displays a sanitized
 * summary and waits for a `y`/`yes` response.  In non-interactive
 * environments the factory returns `undefined` — callers must handle the
 * `confirmation_required` state themselves.
 *
 * This module is responsible ONLY for input/output.  It contains no
 * uninstall strategy, business logic, or policy decisions.
 */

import type { Readable, Writable } from 'stream';
import * as readline from 'readline/promises';
import { sanitizeOutput } from './safe-output';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Summary shown to the user before they confirm. */
export interface ConfirmSummary {
  packageName: string;
  version: string;
  client: string;
  installPath: string;
  contentState: string;
}

/** Callback the caller invokes to request confirmation. */
export type ConfirmCallback = (summary: ConfirmSummary) => Promise<boolean>;

/** Pluggable I/O for testing. */
export interface ConfirmIO {
  input: Readable & { isTTY?: boolean };
  output: Writable & { isTTY?: boolean };
}

// ---------------------------------------------------------------------------
// Default I/O (process stdio)
// ---------------------------------------------------------------------------

const defaultIo: ConfirmIO = {
  input: process.stdin,
  output: process.stdout,
};

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function formatSanitizedSummary(summary: ConfirmSummary): string {
  return [
    `Package:   ${sanitizeOutput(summary.packageName)}`,
    `Version:   ${sanitizeOutput(summary.version)}`,
    `Client:    ${sanitizeOutput(summary.client)}`,
    `Path:      ${sanitizeOutput(summary.installPath)}`,
    `Content:   ${sanitizeOutput(summary.contentState)}`,
    '',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a terminal confirmation callback.
 *
 * Returns `undefined` when stdin or stdout is not a TTY — callers must
 * handle this as a `confirmation_required` state rather than blocking
 * or defaulting to "yes".
 */
export function createTerminalConfirm(io: ConfirmIO = defaultIo): ConfirmCallback | undefined {
  if (!io.input.isTTY || !io.output.isTTY) return undefined;

  return async (summary: ConfirmSummary): Promise<boolean> => {
    const rl = readline.createInterface({ input: io.input, output: io.output });
    try {
      io.output.write(formatSanitizedSummary(summary));
      const answer = (await rl.question('Continue uninstall? [y/N] ')).trim().toLowerCase();
      return answer === 'y' || answer === 'yes';
    } finally {
      rl.close();
    }
  };
}
