# Real-World Capability Packages

This directory vendors **real, installable capability packages** from well-known open-source projects. They complement the `examples/` demo packages with production-grade content and are ready to be scanned, reviewed, published, and installed through Trusted Agent Hub.

## Package List

| Package | Type | Upstream Source | License | Version |
|---|---|---|---|---|
| `anthropic-skill-creator` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/skill-creator) | Apache-2.0 | 1.0.0 |
| `anthropic-mcp-builder` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/mcp-builder) | Apache-2.0 | 1.0.0 |
| `anthropic-algorithmic-art` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/algorithmic-art) | Apache-2.0 | 1.0.0 |
| `anthropic-brand-guidelines` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/brand-guidelines) | Apache-2.0 | 1.0.0 |
| `anthropic-webapp-testing` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/webapp-testing) | Apache-2.0 | 1.0.0 |
| `anthropic-theme-factory` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/theme-factory) | Apache-2.0 | 1.0.0 |
| `anthropic-frontend-design` | Skill | [anthropics/skills](https://github.com/anthropics/skills/tree/main/skills/frontend-design) | Apache-2.0 | 1.0.0 |
| `mcp-server-filesystem` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | Apache-2.0 | 0.6.3 |
| `mcp-server-memory` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/memory) | Apache-2.0 | 0.6.3 |
| `mcp-server-sequential-thinking` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking) | Apache-2.0 | 0.6.2 |
| `mcp-server-everything` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/everything) | Apache-2.0 | 2.0.0 |
| `anthropic-skills-plugin` | Plugin | [anthropics/skills](https://github.com/anthropics/skills) (Claude Code plugin structure) | Apache-2.0 | 1.0.0 |
| `anthropic-web-skills-plugin` | Plugin | [anthropics/skills](https://github.com/anthropics/skills) (Claude Code plugin structure) | Apache-2.0 | 1.0.0 |
| `superpowers` | Plugin | [obra/superpowers](https://github.com/obra/superpowers) | MIT | 6.2.0 |

## Vendored Commits

- `anthropics/skills` @ `b29e7cf65e5cb78a5ac33d582270551bc74a14eb` (2026-07-24)
- `modelcontextprotocol/servers` @ `76d64c822f5125032f89eb71dbdb94e42b434821` (2026-07-29)
- `obra/superpowers` @ `44c9b2d6e889982ac18c27d05a19fefe335194e1` (2026-07-28)

## Integrity

Each `manifest.json` contains a `sha256` digest computed with a deterministic tree hash:

```text
sha256(path\0<file bytes>\0 for every file, sorted by relative path)
```

`manifest.json` itself is excluded from the digest. Text files (no NUL byte) are
canonicalized to LF line endings before hashing, so digests are identical on
Windows and Linux checkouts. To reproduce:

```powershell
python scripts/compute_package_hash.py examples/real-world/skills/skill-creator
```

## Notes

- Only Apache-2.0 skills from `anthropics/skills` are vendored. The `docx`/`pdf`/`pptx`/`xlsx` document skills are source-available rather than open source and are intentionally **not** included.
- MCP server source code is provided as reference; the recommended runtime uses the official npm packages (`@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-memory`).
- `superpowers` is vendored wholesale from its upstream MIT-licensed repository.
- See `mcp-servers/LICENSE` (Apache-2.0, with MCP project relicensing notice) and the per-skill `LICENSE.txt` files.
