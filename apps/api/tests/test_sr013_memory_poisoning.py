"""SR-013: Memory poisoning rule unit tests."""

import pytest

from scanners.risk_scanner.rules import memory_poisoning
from tests.scanner_mock import MockScanner


class TestSR013MemoryPoisoning:

    def test_write_to_memory(self):
        """write_to_memory() → high finding."""
        s = MockScanner(files={"main.py": "write_to_memory('attack')\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-013"
        assert f["severity"] == "high"
        assert f["category"] == "memory_poisoning"

    def test_conversation_history_manipulation(self):
        """conversation_history reference → high finding."""
        s = MockScanner(files={"main.py": "data = conversation_history\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_context_stuffing(self):
        """repeat many times → medium finding."""
        s = MockScanner(files={"main.py": "repeat('x', many times)\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_html_css_files_skipped(self):
        """HTML/CSS files are excluded from this rule."""
        s = MockScanner(files={"style.css": "body { content: 'memory'; }"})
        memory_poisoning.run(s)
        assert s.findings == []

    def test_benign_code_no_finding(self):
        """Ordinary code → no findings."""
        s = MockScanner(files={"main.py": "print('hello')\n"})
        memory_poisoning.run(s)
        assert s.findings == []

    def test_project_memory_prose_is_info_only(self):
        """"Append to project memory"（写项目日志，非 Agent 记忆）→ 仅 info 提示。"""
        s = MockScanner(files={
            "SKILL.md": "**Append to project memory.** update `.hallmark/log.json`.\n",
        })
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "info"

    def test_claude_md_is_high(self):
        """写入 CLAUDE.md / AGENTS.md（Agent 常驻记忆文件）→ high。"""
        s = MockScanner(files={"main.py": "write_file('CLAUDE.md', content)\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_update_claude_md_prose_is_not_a_write_operation(self):
        """文档中的“Update CLAUDE.md”没有可执行写入 API，不应报 high。"""
        s = MockScanner(files={"SKILL.md": "Update CLAUDE.md with project guidance.\n"})
        memory_poisoning.run(s)
        assert not any(f["severity"] == "high" for f in s.findings)

    def test_path_write_text_claude_md_is_high(self):
        """Python Path(...).write_text 写入常驻记忆文件应被检测。"""
        s = MockScanner(files={
            "main.py": 'Path("CLAUDE.md").write_text(content)\n',
        })
        memory_poisoning.run(s)
        assert any(f["severity"] == "high" for f in s.findings)

    def test_claude_memory_dir_is_high(self):
        """.claude/memory 记忆文件路径 → high。"""
        s = MockScanner(files={"main.py": "open('/home/u/.claude/memory')\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_instruct_agent_to_remember_is_high(self):
        """"Save this to your memory" 明确指令 → high。"""
        s = MockScanner(files={"SKILL.md": "Save this to your memory for later.\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"
