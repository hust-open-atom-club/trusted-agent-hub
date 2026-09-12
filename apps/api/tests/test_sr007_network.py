"""SR-007: Network access without domain whitelist rule unit tests."""

from types import SimpleNamespace

import pytest

from scanners.risk_scanner.analyzers.python_ast import analyze_python
from scanners.risk_scanner.rules import behavioral_ast
from scanners.risk_scanner.rules import network
from tests.scanner_mock import MockScanner


class TestSR007Network:

    def test_network_allowed_without_domains(self, tmp_path):
        """network.allowed=true with no domains → medium finding."""
        s = MockScanner(
            files={"manifest.json": "{}"},
            _package_metadata={
                "type": "mcp_server",
                "permissions": {"network": {"allowed": True}},
            },
            target_dir=tmp_path,
        )
        network.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-007"
        assert f["severity"] == "medium"
        assert f["category"] == "network_access"
        assert "白名单" in f["title"]

    def test_network_allowed_with_domains_ok(self, tmp_path):
        """network.allowed=true with whitelisted domains → no findings."""
        s = MockScanner(
            files={"manifest.json": "{}"},
            _package_metadata={
                "type": "mcp_server",
                "permissions": {"network": {"allowed": True, "domains": ["api.github.com"]}},
            },
            target_dir=tmp_path,
        )
        network.run(s)
        assert s.findings == []

    def test_network_not_allowed_ok(self, tmp_path):
        """network.allowed=false → no findings."""
        s = MockScanner(
            files={"manifest.json": "{}"},
            _package_metadata={
                "type": "mcp_server",
                "permissions": {"network": {"allowed": False}},
            },
            target_dir=tmp_path,
        )
        network.run(s)
        assert s.findings == []

    def test_no_metadata_no_finding(self, tmp_path):
        """Missing metadata → no findings."""
        s = MockScanner(files={"SKILL.md": "# hi"}, target_dir=tmp_path)
        network.run(s)
        assert s.findings == []

    def test_public_listener_is_covered_by_ast_rce_finding(self):
        content = (
            "import os as o\n"
            "o.system(request.args.get('cmd'))\n"
            "app.listen('0.0.0.0')\n"
        )
        scanner = MockScanner(files={"app.py": content})
        scanner.analysis = SimpleNamespace(
            python_ast={"app.py": analyze_python("app.py", content)}
        )

        behavioral_ast.run(scanner)
        assert scanner.findings[0]["rule_id"] == "SR-005b"
        assert scanner.findings[0]["kind"] == "vulnerability"

        network.run(scanner)

        assert [finding["rule_id"] for finding in scanner.findings] == ["SR-005b"]
