# TrustedAgentHub AI Install Guide

Use this guide when a user asks you to install a TrustedAgentHub capability package, including a skill, plugin, MCP server, command, prompt, or subagent.

The safe installation path is the TrustedAgentHub CLI. Do not manually download, extract, copy, or execute package contents. Do not run package-provided scripts unless the `tah` CLI selects an installation method that explicitly requires confirmation.

## Hub Setup

Before installing packages from this deployment, make sure the TrustedAgentHub CLI is available.

If `tah` is not installed or not available on PATH, install it first:

```bash
npm install -g trusted-agent-hub@latest
```

Then configure this Hub once:

```bash
tah use http://140.143.119.142:8000 --allow-http
```

If global npm install is unavailable, use `npx trusted-agent-hub@latest ...` for the same commands.

This stores the Hub API address locally. After this step, package installation can use short commands such as `tah install <package> --client <client>`.

## Required Flow

1. Identify the requested package name exactly as written by the user, such as `code-review-skill` or `@user_741dc82b/dev-expert`.
2. Identify the target client. If the user did not specify one, infer it from the current AI environment when it is obvious. Otherwise ask before installing.
3. Inspect the package before installation:

   ```bash
   tah info <package>
   ```

   If `tah` is not installed or not available on PATH, install it with `npm install -g trusted-agent-hub@latest`, or use `npx trusted-agent-hub@latest ...` for the same commands.

4. Preview the install manifest before installing. Use the same API base configured for the CLI. If the current deployment still uses this temporary IP, use `http://140.143.119.142:8000`.

   ```bash
   API_BASE="${TRUSTED_AGENT_HUB_API_URL:-http://140.143.119.142:8000}"
   ENCODED_PACKAGE=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "<package>")
   curl "$API_BASE/api/v0/packages/$ENCODED_PACKAGE/install-manifest?client=<client>"
   ```

   Keep `<package>` unencoded in the Node command above; it handles namespaced or scoped package names before `curl` runs.

5. Before installing, show the user the package name, version, type, target client, install path, risk grade, top risks, permissions, and install method from `tah info` and the `install-manifest`. If the install manifest cannot be fetched, do not guess the install path or method; explain the blocker and ask how to proceed.
6. Install only through the CLI:

   ```bash
   tah install <package> --client <client>
   ```

   Or, when using `npx`:

   ```bash
   npx trusted-agent-hub@latest install <package> --client <client>
   ```

7. The CLI fetches the package `install-manifest`, validates the manifest, applies the risk gate, downloads and verifies artifacts, installs into the client directory, and writes the local install record.
8. After installation, report the result and target path to the user. For Claude Code plugins, tell the user to start a new session and check `/plugin` if needed.

## Supported Clients

- `claude-code`: installs skills and compatible capability packages into `~/.claude/skills/`.
- `claude-code-plugin`: installs plugin packages into `~/.claude/skills/`; Claude Code discovers plugins that include `.claude-plugin/plugin.json`.
- `cursor`: installs compatible skill packages into `~/.cursor/skills/`.

If the package type and client are incompatible, do not improvise another destination. Report the incompatibility and stop.

## Risk Gate

Preserve TrustedAgentHub's grade policy exactly:

- Grade A: installation may proceed after showing the summary.
- Grade B: show permissions before installation.
- Grade C: ask the user for explicit confirmation, or pass `--yes` only after the user has confirmed.
- Grade D: ask for high-risk confirmation twice, then install only with both `--force` and `--accept-high-risk`.
- Grade E: do not install. The CLI must not be bypassed.

If a package has an unknown grade, missing `install-manifest`, failed integrity data, or an unsafe target path, stop and explain the blocker.

## Examples

Install a skill into Claude Code:

```bash
tah install code-review-skill --client claude-code
```

Install a plugin into Claude Code:

```bash
tah install demo-claude-plugin --client claude-code-plugin
```

Install a namespaced package:

```bash
tah install @user_741dc82b/dev-expert --client claude-code
```

## User Prompt Template

The user can ask:

```text
Please follow http://140.143.119.142:3000/install/tah.md and install @user_741dc82b/dev-expert for my current AI client. If `tah` is not available, install the TrustedAgentHub CLI globally first. Configure this Hub, show the risk grade, permissions, and target path before installing, and install only through the CLI.
```

If this guide is hosted on a different TrustedAgentHub domain, use that domain's `/install/tah.md` URL.
