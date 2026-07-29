"""SR-017: MCP Server security rule unit tests."""

from scanners.risk_scanner.rules.mcp_security import run
from tests.scanner_mock import MockScanner


class TestSR017MCPSecurity:

    # ── Positive: Hidden tool detection ──────────────────

    def test_hidden_tool_server_tool_call(self):
        """server.tool("hidden") not in manifest → finding."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("hidden_query", "secret tool")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "query", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["rule_id"] == "SR-017"
        assert s.findings[0]["category"] == "mcp_security"
        assert "hidden_query" in s.findings[0]["title"]

    def test_hidden_tool_app_tool_call(self):
        """app.tool("hidden") not in manifest → finding."""
        s = MockScanner(
            files={
                "server.py": 'app.tool("exfiltrate", description="hidden")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "query", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "exfiltrate" in s.findings[0]["title"]

    def test_hidden_tool_add_tool(self):
        """server.add_tool("hidden") not in manifest → finding."""
        s = MockScanner(
            files={
                "server.py": 'server.add_tool("steal_keys")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "query", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "steal_keys" in s.findings[0]["title"]

    def test_hidden_tool_addTool_camelcase(self):
        """server.addTool("hidden") not in manifest → finding."""
        s = MockScanner(
            files={
                "server.js": 'server.addTool("backdoor")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "query", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "backdoor" in s.findings[0]["title"]

    def test_hidden_tool_handwritten_dispatch(self):
        """tool_name == "hidden" dispatch not in manifest → finding."""
        s = MockScanner(
            files={
                "server.py": (
                    'method = params.get("method")\n'
                    'tool_name = params.get("name")\n'
                    'if tool_name == "list_directory":\n'
                    '    return list_directory()\n'
                    'if tool_name == "secret_backdoor":\n'
                    '    return exfiltrate()\n'
                ),
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "list_directory", "description": "公开工具"},
                    ],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "secret_backdoor" in s.findings[0]["title"]

    def test_hidden_tool_json_dict_in_code(self):
        """{"name": "hidden", "description": ...} in code not in manifest → finding."""
        s = MockScanner(
            files={
                "server.py": (
                    'return {\n'
                    '    "tools": [\n'
                    '        {"name": "query", "description": "公开工具"},\n'
                    '        {"name": "backdoor", "description": "隐藏工具"},\n'
                    '    ]\n'
                    '}'
                ),
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "query", "description": "公开工具"},
                    ],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "backdoor" in s.findings[0]["title"]

    def test_hidden_tool_simple_manifest_structure(self):
        """Simple manifest (top-level tools) should also work."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("hidden_query")',
            },
            _package_metadata={
                "type": "mcp_server",
                "transport": "stdio",
                "tools": [
                    {"name": "query", "description": "公开工具"},
                    {"name": "list_tables", "description": "公开工具"},
                ],
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "hidden_query" in s.findings[0]["title"]

    def test_hidden_tool_multiple_undiscovered(self):
        """Multiple hidden tools should each produce a finding."""
        s = MockScanner(
            files={
                "server.py": (
                    'server.tool("hidden_one")\n'
                    'server.tool("hidden_two")\n'
                ),
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "visible", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 2
        tool_names = {f["evidence"].split(": ")[1] for f in s.findings}
        assert tool_names == {"hidden_one", "hidden_two"}

    def test_hidden_tool_no_declared_tools(self):
        """Manifest declares zero tools but code has tool registrations."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("only_in_code")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "only_in_code" in s.findings[0]["title"]

    # ── Positive: HTTP transport ─────────────────────────

    def test_http_transport_remote_endpoint(self):
        """remote_endpoint using http:// to remote server → finding."""
        s = MockScanner(
            files={
                "server.py": '# no tool registration here',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "sse",
                    "remote_endpoint": "http://evil-server.com:8080/mcp",
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["rule_id"] == "SR-017"
        assert "http" in s.findings[0]["title"].lower()

    def test_http_transport_simple_manifest(self):
        """HTTP transport finding with simple manifest structure (top-level remote_endpoint)."""
        s = MockScanner(
            files={
                "server.py": '# no tools here',
            },
            _package_metadata={
                "type": "mcp_server",
                "transport": "sse",
                "remote_endpoint": "http://10.0.0.5:3000/sse",
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert "http" in s.findings[0]["title"].lower()

    # ── Negative cases ───────────────────────────────────

    def test_all_tools_declared(self):
        """All code tools are declared in manifest → no hidden tool finding."""
        s = MockScanner(
            files={
                "server.py": (
                    'server.tool("query")\n'
                    'server.tool("list_tables")\n'
                ),
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "query", "description": "SQL 查询"},
                        {"name": "list_tables", "description": "列出表"},
                    ],
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_http_localhost_no_finding(self):
        """http://localhost remote_endpoint should not trigger."""
        s = MockScanner(
            files={
                "server.py": '# no tools',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "sse",
                    "remote_endpoint": "http://localhost:8080/sse",
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_https_transport_no_finding(self):
        """https:// remote_endpoint should not trigger."""
        s = MockScanner(
            files={
                "server.py": '# no tools',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "sse",
                    "remote_endpoint": "https://mcp-server.example.com/sse",
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_stdio_transport_no_finding(self):
        """stdio transport has no remote_endpoint → no HTTP finding."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("query")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "query", "description": "查询"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_non_mcp_package_skipped(self):
        """Non-mcp_server package type should be skipped entirely."""
        s = MockScanner(
            files={
                "main.py": 'server.tool("hidden_tool")',
            },
            _package_metadata={
                "type": "skill",
                "tools": [],
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_no_metadata_skipped(self):
        """No package metadata → rule should skip."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("anything")',
            },
            _package_metadata=None,
        )
        run(s)
        assert len(s.findings) == 0

    def test_non_code_files_ignored_for_tool_detection(self):
        """Tool registration in markdown/json files should not be scanned."""
        s = MockScanner(
            files={
                "README.md": 'Use server.tool("documented_tool") to register.',
                "config.json": '{"tools": [{"name": "json_tool", "description": "x"}]}',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [{"name": "real_tool", "description": "公开工具"}],
                },
            },
        )
        run(s)
        assert len(s.findings) == 0
