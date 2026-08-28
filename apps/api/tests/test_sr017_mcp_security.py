"""SR-017: MCP Server security rule unit tests."""

import sys
from types import ModuleType

import pytest

from scanners.risk_scanner.rules import mcp_security
from scanners.risk_scanner.rules.mcp_security import run
from tests.scanner_mock import MockScanner


_REAL_LOAD_SEMANTIC_MODEL = mcp_security._load_semantic_model


@pytest.fixture(autouse=True)
def _no_real_model(monkeypatch):
    """All SR-017 unit tests must not load the real embedding model."""
    monkeypatch.setattr(mcp_security, "_load_semantic_model", lambda: None)


class FakeModel:
    """Fake embedding model producing a controllable cosine similarity."""

    def __init__(self, similarity: float = 0.9):
        import math

        self._sim = max(-1.0, min(1.0, similarity))
        self._sin_theta = math.sin(math.acos(self._sim))

    def embed(self, texts):
        import numpy as np

        return [np.array([1.0, 0.0]), np.array([self._sim, self._sin_theta])]


def test_semantic_model_uses_configured_cache_directory(monkeypatch, tmp_path):
    captured: dict[str, object] = {}
    fake_fastembed = ModuleType("fastembed")

    class FakeTextEmbedding:
        def __init__(self, model_name, *, cache_dir=None):
            captured["model_name"] = model_name
            captured["cache_dir"] = cache_dir

    fake_fastembed.TextEmbedding = FakeTextEmbedding
    cache_dir = tmp_path / "fastembed-cache"
    monkeypatch.setitem(sys.modules, "fastembed", fake_fastembed)
    monkeypatch.setenv("FASTEMBED_CACHE_PATH", str(cache_dir))
    monkeypatch.setattr(mcp_security, "_SEMANTIC_MODEL", None)

    model = _REAL_LOAD_SEMANTIC_MODEL()

    assert isinstance(model, FakeTextEmbedding)
    assert captured == {
        "model_name": "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
        "cache_dir": str(cache_dir),
    }


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


# ── Tool description poisoning detection ────────────────────────────────

class TestSR017ToolDescriptionPoisoning:

    def _patch_model(self, monkeypatch, similarity: float):
        monkeypatch.setattr(
            mcp_security, "_load_semantic_model", lambda: FakeModel(similarity)
        )

    # ── ① Keyword + permission contradiction (deterministic) ──

    def test_poisoning_keyword_contradiction_high(self, monkeypatch):
        """Description claims shell capability, permissions deny it -> high."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "get_weather", "description": "获取天气信息，可执行任意 shell 命令"},
                    ],
                },
                "permissions": {
                    "shell": {"allowed": False},
                    "network": {"allowed": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-017"
        assert f["category"] == "mcp_security"
        assert f["severity"] == "high"
        assert "投毒" in f["title"]

    def test_poisoning_credential_contradiction(self, monkeypatch):
        """Description claims credential access, permissions deny -> high."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "list_tables", "description": "列出数据库表并读取环境变量"},
                    ],
                },
                "permissions": {
                    "environment": {"read": [], "write": []},
                    "network": {"allowed": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_poisoning_no_finding_when_permission_granted(self, monkeypatch):
        """Same risky capability but permission explicitly granted -> no finding."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "run_shell", "description": "在沙箱中执行 shell 命令"},
                    ],
                },
                "permissions": {
                    "shell": {"allowed": True},
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_poisoning_without_permissions_low(self, monkeypatch):
        """Risky description but no permissions section -> low hint only."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "get_weather", "description": "获取天气信息，可执行任意 shell 命令"},
                    ],
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "low"

    def test_poisoning_multi_tools_critical(self, monkeypatch):
        """>=2 tools with keyword contradiction -> critical."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "get_weather", "description": "获取天气信息，可执行任意 shell 命令"},
                        {"name": "get_time", "description": "获取时间，支持删除所有文件"},
                    ],
                },
                "permissions": {
                    "shell": {"allowed": False},
                    "filesystem": {"read": [], "write": [], "delete": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 2
        assert all(f["severity"] == "critical" for f in s.findings)

    # ── ② Semantic drift (desc vs permissions) ──

    def test_semantic_drift_low(self, monkeypatch):
        """No keywords but low desc-perm similarity -> low hint."""
        self._patch_model(monkeypatch, similarity=0.2)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "query", "description": "处理用户请求"},
                    ],
                },
                "permissions": {
                    "filesystem": {"read": ["./"], "write": [], "delete": False},
                    "shell": {"allowed": False},
                    "network": {"allowed": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "low"
        assert "语义漂移" in s.findings[0]["title"]

    def test_semantic_no_drift_no_finding(self, monkeypatch):
        """High desc-perm similarity and no keywords -> no finding."""
        self._patch_model(monkeypatch, similarity=0.9)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "list_directory", "description": "列出指定目录内容"},
                    ],
                },
                "permissions": {
                    "filesystem": {"read": ["./"], "write": [], "delete": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_semantic_keyword_dual_signal_critical(self, monkeypatch):
        """① + ② on the same tool -> critical."""
        self._patch_model(monkeypatch, similarity=0.2)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "get_weather", "description": "获取天气信息，可执行任意 shell 命令"},
                    ],
                },
                "permissions": {
                    "filesystem": {"read": ["./"], "write": [], "delete": False},
                    "shell": {"allowed": False},
                    "network": {"allowed": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "critical"

    def test_semantic_model_unavailable_fallback(self, monkeypatch):
        """fastembed unavailable -> only keyword rule (①) runs, no crash."""
        monkeypatch.setattr(mcp_security, "_load_semantic_model", lambda: None)
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "get_weather", "description": "获取天气信息，可执行任意 shell 命令"},
                        {"name": "list_tables", "description": "列出所有表"},
                    ],
                },
                "permissions": {
                    "shell": {"allowed": False},
                    "network": {"allowed": False},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    # ── Code-side description mismatch ──

    def test_code_desc_mismatch_high(self, monkeypatch):
        """Code-registered desc has risky keywords, manifest desc does not."""
        s = MockScanner(
            files={
                "server.py": (
                    'server.tool("query", description="执行任意 shell 命令，删除所有文件")'
                ),
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "query", "description": "执行只读 SQL 查询"},
                    ],
                },
                "permissions": {
                    "shell": {"allowed": False},
                    "database": {"allowed": True, "drivers": ["postgresql"]},
                },
            },
        )
        run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-017"
        assert f["severity"] == "high"
        assert "代码注册描述" in f["title"]

    def test_code_desc_consistent_no_finding(self, monkeypatch):
        """Code-registered desc matches manifest desc -> no mismatch finding."""
        s = MockScanner(
            files={
                "server.py": 'server.tool("query", description="执行只读 SQL 查询")',
            },
            _package_metadata={
                "type": "mcp_server",
                "mcp_server_config": {
                    "transport": "stdio",
                    "tools": [
                        {"name": "query", "description": "执行只读 SQL 查询"},
                    ],
                },
                "permissions": {
                    "database": {"allowed": True, "drivers": ["postgresql"]},
                },
            },
        )
        run(s)
        assert len(s.findings) == 0
