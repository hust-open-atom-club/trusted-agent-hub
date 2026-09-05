"""SR-014: SSRF rule unit tests."""

import pytest

from scanners.risk_scanner.rules import ssrf
from tests.scanner_mock import MockScanner


class TestSR014SSRF:

    def test_aws_metadata_endpoint(self):
        """169.254.169.254 → critical finding."""
        s = MockScanner(files={
            "main.py": 'requests.get("http://169.254.169.254/latest/meta-data/")\n',
        })
        ssrf.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-014"
        assert f["severity"] == "critical"
        assert f["category"] == "ssrf"

    def test_internal_ip(self):
        """An internal URL literal alone does not prove a request."""
        s = MockScanner(files={
            "main.py": 'url = "http://192.168.1.1/admin"\n',
        })
        ssrf.run(s)
        assert s.findings == []

    def test_localhost(self):
        """A fixed localhost request is a local capability, not SSRF."""
        s = MockScanner(files={
            "main.py": 'fetch("http://localhost:8080/api")\n',
        })
        ssrf.run(s)
        assert s.findings == []

    def test_dynamic_url_concat(self):
        """requests.get(base + user_input) → medium finding."""
        s = MockScanner(files={
            "main.py": 'requests.get(base_url + user_input)\n',
        })
        ssrf.run(s)
        assert len(s.findings) >= 1

    def test_defensive_context_downgraded_to_info(self):
        """Defensive prose without a request sink is not a finding."""
        s = MockScanner(files={
            "main.py": (
                "# WARNING: do not connect to internal IPs\n"
                "# Access to http://192.168.1.1 is forbidden in production\n"
                "def docs():\n"
                "    pass\n"
            ),
        })
        ssrf.run(s)
        assert s.findings == []

    def test_markdown_files_skipped(self):
        """.md files are excluded from this rule."""
        s = MockScanner(files={
            "README.md": "See http://localhost/docs for details\n",
        })
        ssrf.run(s)
        assert s.findings == []

    def test_benign_code_no_finding(self):
        """Public HTTPS URLs → no findings."""
        s = MockScanner(files={
            "main.py": 'requests.get("https://api.github.com/repos/x")\n',
        })
        ssrf.run(s)
        assert s.findings == []
