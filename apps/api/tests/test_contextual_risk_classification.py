"""Regression tests for capability-versus-vulnerability classification."""

from __future__ import annotations

import json
from pathlib import Path

from scanners.risk_scanner.analyzers.url_context import (
    URL_USAGE_COMPARISON,
    URL_USAGE_LOCAL_REFERENCE,
    URL_USAGE_STATIC_ASSET,
    classify_url_usage,
)
from scanners.risk_scanner.scanner import RiskScanner


def _scan(tmp_path: Path, filename: str, content: str) -> dict:
    manifest = {
        "name": "context-regression",
        "version": "1.0.0",
        "type": "mcp_server",
        "description": "Context classification regression fixture.",
        "author": "TrustedAgentHub",
        "license": "Apache-2.0",
        "permissions": {},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / filename).write_text(content, encoding="utf-8")
    return RiskScanner(tmp_path).scan()


def test_url_classifier_distinguishes_non_network_uses() -> None:
    assert classify_url_usage('return origin === "http://" + host;', 1, "http://") == (
        URL_USAGE_COMPARISON
    )
    assert classify_url_usage(
        'const image = "https://cdn.invalid/logo.png";',
        1,
        "https://cdn.invalid/logo.png",
    ) == URL_USAGE_STATIC_ASSET
    assert classify_url_usage(
        'const url = "http://localhost:4317/session";',
        1,
        "http://localhost:4317/session",
    ) == URL_USAGE_LOCAL_REFERENCE


def test_local_launcher_is_capability_without_vulnerability(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "launcher.js",
        """const childProcess = require("child_process");
const url = `http://localhost:${port}/session`;
childProcess.execFile("xdg-open", [url], { shell: false });
""",
    )

    assert not {"SR-005", "SR-008", "SR-014"}.intersection(
        finding["rule_id"] for finding in report["findings"]
    )
    assert {"network.local_service", "shell.execute"} <= set(
        report["structural_analysis"]["capability_graph"]["observed"]
    )


def test_request_origin_fetch_is_confirmed_ssrf(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "origin.js",
        """async function proxyOrigin(request) {
  const origin = request.headers.origin;
  return fetch(origin);
}
""",
    )

    finding = next(item for item in report["findings"] if item["rule_id"] == "SR-014")
    assert finding["effective_severity"] == "high"
    assert finding["kind"] == "vulnerability"
    assert finding["disposition"] == "confirmed_vulnerability"
    assert finding["source_control"] == "remote_attacker"


def test_public_listener_requires_context(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "server.js",
        'http.createServer(handler).listen(4317, "0.0.0.0");\n',
    )

    finding = next(item for item in report["findings"] if item["rule_id"] == "SR-007")
    assert finding["effective_severity"] == "medium"
    assert finding["kind"] == "context_dependent"
    assert finding["disposition"] == "needs_context"
    assert finding["requires_manual_review"] is True
    assert "network.listen_public" in report["structural_analysis"]["capability_graph"]["observed"]


def test_fixed_python_argv_is_process_capability_only(tmp_path: Path) -> None:
    report = _scan(
        tmp_path,
        "preview.py",
        """import subprocess
subprocess.Popen(["python", "-m", "http.server", "4317", "--bind", "127.0.0.1"], shell=False)
""",
    )

    assert not any(item["rule_id"] == "SR-005" for item in report["findings"])
    capabilities = set(report["structural_analysis"]["capability_graph"]["observed"])
    assert {"network.local_service", "process.spawn"} <= capabilities
