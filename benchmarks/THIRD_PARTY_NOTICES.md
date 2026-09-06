# Third-party notices for benchmark fixtures

The benchmark corpus contains minimized, non-executed fixtures derived from the
following projects. The source path, revision, and license for each fixture are
also recorded in `labels-v2.json`.

## Superpowers brainstorming launcher

- Benchmark fixture: `corpus/benign-code/brainstorming-local-launcher`
- Source: `examples/real-world/plugins/superpowers/skills/brainstorming/scripts/server.cjs`
- Copyright (c) 2025 Jesse Vincent
- License: MIT
- Changes: reduced to the local companion launch behavior needed by the scanner benchmark

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Anthropic webapp-testing and MCP-builder fixtures

- Benchmark fixtures: `corpus/benign-code/webapp-testing-local-service` and
  `corpus/benign-code/mcp-builder-doc-example`
- Sources: `examples/real-world/skills/webapp-testing/scripts/with_server.py`
  and `examples/real-world/skills/mcp-builder/reference/node_mcp_server.md`
- Copyright 2026 Anthropic, PBC.
- License: Apache License 2.0
- Changes: reduced to the local test-server and inert documentation behaviors
  needed by the scanner benchmark

The Apache License 2.0 terms are included in the repository root `LICENSE` and
in each source skill's `LICENSE.txt`.
