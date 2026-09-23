import json
from datetime import date

import pytest

from scanners.risk_scanner.dependency_parsers import (
    parse_dependencies,
    parse_dependency_sources,
)
from scanners.risk_scanner.registry_policy import (
    RegistryClassification,
    RegistryEntry,
    RegistryPolicy,
)


def test_dependency_parsers_normalize_manifest_and_lockfiles():
    records = parse_dependencies({
        "package.json": '{"dependencies":{"lodash":"^4.17.0"}}',
        "package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21","integrity":"sha512-x"}}}',
        "requirements.txt": "requests==2.31.0\nflask\n",
        "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
    })
    assert any(r.name == "lodash" and r.ecosystem == "npm" for r in records)
    assert any(r.name == "flask" and r.version is None for r in records)
    assert any(r.name == "serde" and r.ecosystem == "crates.io" for r in records)


def test_dependency_parsers_preserve_registry_source_and_usage():
    records = parse_dependencies({
        "package-lock.json": (
            '{"lockfileVersion":3,"packages":{'
            '"node_modules/demo":{"version":"1.0.0",'
            '"resolved":"https://registry.npmmirror.com/demo/-/demo-1.0.0.tgz",'
            '"integrity":"sha512-demo"}}}'
        ),
        "Cargo.lock": (
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "abc"\n'
        ),
    })

    npm = next(record for record in records if record.name == "demo")
    cargo = next(record for record in records if record.name == "serde")
    assert npm.registry == "https://registry.npmmirror.com/demo/-/demo-1.0.0.tgz"
    assert npm.registry_usage == "resolved_download"
    assert cargo.registry == "registry+https://github.com/rust-lang/crates.io-index"
    assert cargo.registry_usage == "registry_api"
    assert cargo.integrity == "abc"


@pytest.mark.parametrize(
    "lock",
    [
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/demo": {
                    "version": "1.0.0",
                    "resolved": {"unexpected": "object"},
                }
            },
        },
        {
            "lockfileVersion": 1,
            "dependencies": {
                "demo": {
                    "version": "1.0.0",
                    "resolved": ["unexpected", "array"],
                }
            },
        },
    ],
)
def test_npm_lock_parser_ignores_non_string_resolved_values(lock):
    records = parse_dependencies({"package-lock.json": json.dumps(lock)})

    assert len(records) == 1
    assert records[0].name == "demo"
    assert records[0].registry is None
    assert records[0].registry_usage is None


def test_python_lock_parsers_preserve_configured_sources():
    pipfile = {
        "_meta": {
            "sources": [
                {"name": "corp", "url": "https://pypi.corp.example/simple"}
            ]
        },
        "default": {
            "requests": {"version": "==2.31.0", "index": "corp"}
        },
    }
    records = parse_dependencies({
        "Pipfile.lock": json.dumps(pipfile),
        "poetry.lock": (
            '[[package]]\nname = "flask"\nversion = "3.0.0"\n'
            '[package.source]\ntype = "legacy"\n'
            'url = "https://poetry.corp.example/simple"\n'
        ),
    })

    requests = next(record for record in records if record.name == "requests")
    flask = next(record for record in records if record.name == "flask")
    assert requests.registry == "https://pypi.corp.example/simple"
    assert flask.registry == "https://poetry.corp.example/simple"
    assert requests.registry_usage == flask.registry_usage == "registry_api"


def test_dependency_source_discovery_covers_manager_configuration():
    files = {
        ".npmrc": "registry=https://npm.corp.example/\n",
        "requirements-dev.txt": (
            "--extra-index-url https://python.corp.example/simple\npytest==8.0.0\n"
        ),
        "pyproject.toml": (
            '[[tool.poetry.source]]\nname = "corp"\n'
            'url = "https://poetry.corp.example/simple"\n'
        ),
        ".cargo/config.toml": (
            '[registries.corp]\nindex = "sparse+https://cargo.corp.example/"\n'
        ),
        "pnpm-lock.yaml": (
            "resolution:\n  tarball: https://npm.corp.example/pkg.tgz\n"
        ),
    }

    observations = parse_dependency_sources(files)
    observed = {(item.ecosystem, item.url, item.usage) for item in observations}

    assert ("npm", "https://npm.corp.example/", "registry_api") in observed
    assert (
        "pypi",
        "https://python.corp.example/simple",
        "registry_api",
    ) in observed
    assert (
        "pypi",
        "https://poetry.corp.example/simple",
        "registry_api",
    ) in observed
    assert (
        "cargo",
        "sparse+https://cargo.corp.example/",
        "registry_api",
    ) in observed
    assert (
        "npm",
        "https://npm.corp.example/pkg.tgz",
        "resolved_download",
    ) in observed


@pytest.mark.parametrize(
    "index_directive",
    [
        "-i https://python.corp.example/simple",
        "-i=https://python.corp.example/simple",
    ],
)
def test_requirements_registry_observation_is_not_counted_twice(
    index_directive,
):
    files = {
        "requirements.txt": (
            f"{index_directive}\nrequests==2.31.0\n"
        )
    }
    records = parse_dependencies(files)

    observations = parse_dependency_sources(files, records)
    matching = [
        observation
        for observation in observations
        if observation.url == "https://python.corp.example/simple"
    ]

    assert len(matching) == 1
    assert matching[0].dependency_name == "requests"


def test_yarn_selector_name_extraction_handles_scoped_and_unscoped_names():
    records = parse_dependencies({
        "yarn.lock": (
            'lodash@^4.17.0:\n  version "4.17.21"\n\n'
            '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n'
        )
    })

    assert {(record.name, record.version) for record in records} == {
        ("lodash", "4.17.21"),
        ("@scope/pkg", "1.2.3"),
    }


def test_yarn_resolved_fragment_is_separated_from_source_url():
    fragment = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    files = {
        "yarn.lock": (
            "lodash@^4.17.0:\n"
            '  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/'
            f'lodash-4.17.21.tgz#{fragment}"\n'
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert len(records) == 1
    assert records[0].registry == (
        "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
    )
    assert records[0].integrity == fragment
    assert len(observations) == 1
    assert observations[0].url == records[0].registry


def test_requirements_strips_version_fragment_but_preserves_url_fragment():
    records = parse_dependencies({
        "requirements.txt": (
            "requests==2.31.0#sha256=deadbeef\n"
            "demo @ https://packages.example/demo.whl#sha256=cafebabe\n"
        )
    })

    requests = next(record for record in records if record.name == "requests")
    demo = next(record for record in records if record.name == "demo")

    assert requests.version == "2.31.0"
    assert demo.version is None
    assert demo.registry == (
        "https://packages.example/demo.whl#sha256=cafebabe"
    )


def test_npm_and_python_git_sources_are_observed_and_rejected():
    files = {
        "package.json": json.dumps({
            "dependencies": {
                "npm-ssh-demo": "git+ssh://git@github.com/example/npm-demo.git",
                "npm-github-demo": "github:example/github-demo#v1.0.0",
                "npm-shortcut-demo": "example/shortcut-demo",
            }
        }),
        "requirements.txt": (
            "python-ssh-demo[security] @ "
            "git+ssh://git@gitlab.com/example/python-demo.git\n"
            "--editable git+ssh://git@gitlab.com/example/editable.git"
            "#egg=python-editable-demo\n"
            "git+ssh://git@gitlab.com/example/unnamed.git\n"
        ),
    }

    observations = parse_dependency_sources(files)
    by_url = {item.url: item for item in observations}
    expected_sources = {
        "git+ssh://git@github.com/example/npm-demo.git",
        "git+https://github.com/example/github-demo.git#v1.0.0",
        "git+https://github.com/example/shortcut-demo.git",
        "git+ssh://git@gitlab.com/example/python-demo.git",
        "git+ssh://git@gitlab.com/example/editable.git#egg=python-editable-demo",
        "git+ssh://git@gitlab.com/example/unnamed.git",
    }

    assert set(by_url) == expected_sources
    python_extra = next(
        record for record in parse_dependencies(files)
        if record.name == "python-ssh-demo"
    )
    assert python_extra.registry == (
        "git+ssh://git@gitlab.com/example/python-demo.git"
    )
    assert all(
        not RegistryPolicy([]).evaluate(
            item.ecosystem, item.url, item.usage
        ).allowed
        for item in observations
    )
    assert {
        RegistryPolicy([]).evaluate(
            item.ecosystem, item.url, item.usage
        ).reason
        for item in observations
    } == {"non_registry_source", "unknown_host"}


@pytest.mark.parametrize("option", ["--find-links", "-f"])
@pytest.mark.parametrize("separator", [" ", "="])
@pytest.mark.parametrize(
    ("allow_download", "expected_allowed"),
    [(False, False), (True, True)],
)
def test_find_links_requires_resolved_download_approval(
    option, separator, allow_download, expected_allowed
):
    source = "https://files.corp.example/wheels/demo.whl"
    observations = parse_dependency_sources({
        "requirements.txt": f"{option}{separator}{source}\n"
    })
    entry = RegistryEntry(
        ecosystem="pypi",
        exact_host="files.corp.example",
        classification=RegistryClassification.APPROVED_PRIVATE,
        evidence_url="https://security.corp.example/pypi",
        allow_as_resolved_download=allow_download,
        note="Test private Python source.",
        reviewed_at=date(2026, 9, 22),
    )

    assert len(observations) == 1
    assert observations[0].usage == "resolved_download"
    decision = RegistryPolicy([entry]).evaluate(
        observations[0].ecosystem,
        observations[0].url,
        observations[0].usage,
    )
    assert decision.allowed is expected_allowed
    assert decision.reason == (
        "matched" if expected_allowed else "usage_not_allowed"
    )


def test_bare_http_requirements_are_observed_without_inventing_names():
    observations = parse_dependency_sources({
        "requirements.txt": (
            "https://packages.example/demo-1.0-py3-none-any.whl"
            "#sha256=cafebabe # verified artifact\n"
            "http://packages.example/source-demo-1.0.tar.gz?download=1\n"
            "-e https://packages.example/editable#egg=editable-demo\n"
            "./local-demo-1.0-py3-none-any.whl\n"
        )
    })

    assert len(observations) == 3
    assert {
        (item.url, item.usage, item.dependency_name)
        for item in observations
    } == {
        (
            "https://packages.example/demo-1.0-py3-none-any.whl"
            "#sha256=cafebabe",
            "resolved_download",
            None,
        ),
        (
            "http://packages.example/source-demo-1.0.tar.gz?download=1",
            "resolved_download",
            None,
        ),
        (
            "https://packages.example/editable#egg=editable-demo",
            "resolved_download",
            "editable-demo",
        ),
    }


@pytest.mark.parametrize(
    "command",
    [
        "pip install --find-links https://registry.example/wheels demo",
        "pip install --find-links=https://registry.example/wheels demo",
        "pip install -f https://registry.example/wheels demo",
        "pip install -f=https://registry.example/wheels demo",
    ],
)
def test_find_links_is_not_classified_as_a_registry_api_in_inline_rules(
    command,
):
    from scanners.risk_scanner.rules.supply_chain import (
        _dependency_usage_near_line,
    )

    assert _dependency_usage_near_line(
        [command], 1
    ) == "resolved_download"


def test_npm_force_is_not_classified_as_pip_find_links():
    from scanners.risk_scanner.rules.supply_chain import (
        _dependency_usage_near_line,
    )

    assert _dependency_usage_near_line(
        ["npm install -f --registry https://mirror.internal/ demo"], 1
    ) == "registry_api"


def test_dependency_scan_reports_osv_query_failures(tmp_path):
    from scanners.risk_scanner.scanner import RiskScanner

    (tmp_path / "package.json").write_text(
        '{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}',
        encoding="utf-8",
    )
    scanner = RiskScanner(tmp_path)

    class FailedClient:
        max_queries = 10
        queried = 1

        def query(self, dependency):
            from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
            return OSVQueryResult([], "TimeoutError")

    scanner.osv_client = FailedClient()
    report = scanner.scan()
    assert report["dependency_scan"]["status"] == "partial"
    assert report["dependency_scan"]["dependencies_found"] == 1
    assert report["dependency_scan"]["query_failures"] == 1
    assert report["scan_status"]["state"] == "partial"


def test_osv_query_limit_comes_from_scan_policy(tmp_path):
    from scanners.risk_scanner.policy import ScanPolicy
    from scanners.risk_scanner.scanner import RiskScanner

    scanner = RiskScanner(tmp_path, policy=ScanPolicy(max_osv_queries=3))

    assert scanner.osv_client.max_queries == 3
    assert scanner.policy.as_dict()["max_osv_queries"] == 3


@pytest.mark.parametrize("query_limit", [0, -1])
def test_scan_policy_rejects_invalid_osv_query_limits(query_limit):
    from scanners.risk_scanner.policy import ScanPolicy

    with pytest.raises(ValueError, match="max_osv_queries must be at least 1"):
        ScanPolicy(max_osv_queries=query_limit)


def test_scan_policy_accepts_one_osv_query():
    from scanners.risk_scanner.policy import ScanPolicy

    policy = ScanPolicy(max_osv_queries=1)

    assert policy.max_osv_queries == 1
