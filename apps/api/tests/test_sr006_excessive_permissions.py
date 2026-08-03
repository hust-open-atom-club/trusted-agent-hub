"""SR-006: Excessive permissions + autonomous decision rule unit tests."""

from pathlib import Path

import pytest

from scanners.risk_scanner.rules import excessive_permissions
from tests.scanner_mock import MockScanner


class TestSR006ExcessivePermissions:

    def test_unexpected_permission_for_type(self, tmp_path):
        """skill type declaring browser permission → medium finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "skill",
                "permissions": {"browser": {"allowed": True}},
            },
            target_dir=tmp_path,
        )
        excessive_permissions.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-006"
        assert f["severity"] == "medium"
        assert f["category"] == "excessive_permission"
        assert "过度权限" in f["title"]

    def test_prompt_type_with_shell_permission(self, tmp_path):
        """prompt type declaring shell permission → finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "prompt",
                "permissions": {"shell": {"allowed": True}},
            },
            target_dir=tmp_path,
        )
        excessive_permissions.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_autonomous_decision_in_content(self, tmp_path):
        """Content containing 'automatically decide' → medium finding."""
        s = MockScanner(
            files={"SKILL.md": "The agent will automatically decide the next step."},
            _package_metadata={"type": "skill", "description": "test skill"},
            target_dir=tmp_path,
        )
        excessive_permissions.run(s)
        assert len(s.findings) == 1
        assert "自主决策" in s.findings[0]["title"]

    def test_scope_creep_description_shell_permission(self, tmp_path):
        """Description claims code review but shell permission declared → finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "skill",
                "description": "Performs code review and fixes",
                "permissions": {"shell": {"allowed": True}},
            },
            target_dir=tmp_path,
        )
        excessive_permissions.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("权限范围蔓延" in t for t in titles)

    def test_no_metadata_no_finding(self, tmp_path):
        """Missing metadata → no findings."""
        s = MockScanner(files={"SKILL.md": "# hi"}, target_dir=tmp_path)
        excessive_permissions.run(s)
        assert s.findings == []

    def test_benign_permissions_no_finding(self, tmp_path):
        """Expected permissions matching declared type → no findings."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "skill",
                "description": "Writes markdown notes to local files",
                "permissions": {"filesystem": {"read": ["./"], "write": ["./notes"]}},
            },
            target_dir=tmp_path,
        )
        excessive_permissions.run(s)
        assert s.findings == []
