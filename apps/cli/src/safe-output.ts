/**
 * Shared terminal output sanitization.
 *
 * Strips ANSI escape codes, OSC sequences, C0/C1 control characters, CR, LF,
 * and truncates to a maximum length.  Prevents terminal injection via crafted
 * package names, client identifiers, paths, or server responses.
 *
 * Used by both `verify-executor` and `uninstall-executor` — all untrusted
 * strings that reach the terminal must pass through this function.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_OUTPUT_LENGTH = 200;

// C0: U+0000–U+001F, C1: U+0080–U+009F, plus DEL (U+007F)
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f\x80-\x9f]/g;
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;
const OSC_RE = /\x1b\].*?(\x07|\x1b\\)/g;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function sanitizeOutput(input: string): string {
  let out = input
    .replace(OSC_RE, '')
    .replace(ANSI_RE, '')
    .replace(CONTROL_RE, '');
  if (out.length > MAX_OUTPUT_LENGTH) {
    out = out.slice(0, MAX_OUTPUT_LENGTH - 1) + '…';
  }
  return out;
}
