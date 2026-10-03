import json
from datetime import date

import pytest

from scanners.risk_scanner.dependency_parsers import (
    parse_dependencies,
    parse_dependency_sources,
)
from scanners.risk_scanner.dependency_parsers.python import (
    iter_requirement_options,
    parse_requirements,
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


@pytest.mark.parametrize(
    ("file_name", "expected_scope"),
    [
        ("requirements-latest.txt", "runtime"),
        ("fastest.txt", "runtime"),
        ("tests/requirements.txt", "runtime"),
        ("requirements-dev.txt", "dev"),
        ("requirements-tests.txt", "test"),
    ],
)
def test_requirement_scope_matches_filename_tokens(file_name, expected_scope):
    records = parse_requirements("demo==1.0.0\n", file_name)
    assert records[0].scope == expected_scope


@pytest.mark.parametrize(
    ("file_name", "expected_scope"),
    [
        ("requirements.txt", "runtime"),
        ("requirements-dev.txt", "dev"),
        ("requirements-tests.txt", "test"),
    ],
)
def test_requirement_source_observations_match_filename_scope(
    file_name,
    expected_scope,
):
    observations = parse_dependency_sources({
        file_name: (
            "-f https://unapproved.example/wheels\n"
            "https://unapproved.example/demo.whl\n"
        )
    })

    assert len(observations) == 2
    assert {item.scope for item in observations} == {expected_scope}


def test_npm_lock_scope_distinguishes_dev_optional_from_dev_optional_subtree():
    records = parse_dependencies({"package-lock.json": json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/shared": {"version": "1.0.0", "devOptional": True},
            "node_modules/dev-subtree": {"version": "1.0.0", "dev": True, "optional": True},
        },
    })})
    assert {record.name: record.scope for record in records} == {
        "shared": "mixed", "dev-subtree": "dev",
    }


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


@pytest.mark.parametrize(
    ("groups", "category", "expected_scope"),
    [
        (["dev"], None, "dev"),
        (["test"], None, "test"),
        (["main"], None, "runtime"),
        (["main", "dev"], None, "mixed"),
        (["dev", "docs"], None, "unknown"),
        (None, "dev", "dev"),
        (None, "main", "runtime"),
    ],
)
def test_poetry_lock_scope_uses_groups_then_legacy_category(groups, category, expected_scope):
    group_line = f"groups = {json.dumps(groups)}\n" if groups is not None else ""
    category_line = f'category = "{category}"\n' if category else ""
    records = parse_dependencies({
        "poetry.lock": (
            '[[package]]\nname = "demo"\nversion = "1.0.0"\n'
            f"{group_line}{category_line}"
        ),
    })
    assert len(records) == 1
    assert records[0].scope == expected_scope


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
    ("option", "usage"),
    [
        ("--index-url", "registry_api"),
        ("--extra-index-url", "registry_api"),
        ("-i", "registry_api"),
        ("--find-links", "resolved_download"),
        ("-f", "resolved_download"),
    ],
)
@pytest.mark.parametrize("separator", [" \\\n  \\\n  ", "=\\\r\n"])
def test_requirements_continued_source_options_keep_usage(
    option, usage, separator
):
    url = "https://packages.example/simple#fragment"
    files = {
        "requirements.txt": (
            f"{option}{separator}{url} # source comment\n"
            "requests==\\\n2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert [(record.name, record.version) for record in records] == [
        ("requests", "2.31.0"),
    ]
    expected_index = url if option in {"--index-url", "-i"} else None
    assert records[0].registry == expected_index
    assert records[0].registry_usage == (
        "registry_api" if expected_index else None
    )
    assert [(item.url, item.usage) for item in observations] == [(url, usage)]


@pytest.mark.parametrize(
    "option", ["--index-url", "--extra-index-url", "-i", "--find-links", "-f"]
)
def test_requirements_empty_continued_option_retains_download_only(option):
    url = "https://packages.example/demo.whl#sha256=deadbeef"
    files = {
        "requirements.txt": (
            f"{option}=\\\n    {url} # trailing URL for review\n"
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert [(record.name, record.registry) for record in records] == [
        ("requests", None),
    ]
    assert [
        (item.url, item.usage, item.dependency_name) for item in observations
    ] == [(url, "resolved_download", None)]


def test_requirements_multiple_continued_source_options_share_logical_line():
    files = {
        "requirements.txt": (
            '--index-url \\\n  "https://pypi.org/simple" \\\n'
            '  --extra-index-url="https://mirror.example/simple" \\\n'
            '  --find-links \\\n  "https://files.example/wheels/"\n'
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert records[0].registry == "https://pypi.org/simple"
    assert {(item.url, item.usage) for item in observations} == {
        ("https://pypi.org/simple", "registry_api"),
        ("https://mirror.example/simple", "registry_api"),
        ("https://files.example/wheels/", "resolved_download"),
    }


def test_requirements_continued_references_preserve_names_and_fragments():
    files = {
        "requirements.txt": (
            "demo[security] \\\n  @ \\\n"
            "  https://packages.example/demo.whl#sha256=cafebabe\n"
            "-e \\\n  git+https://git.example/demo.git#egg=editable-demo\n"
            "https://packages.example/\\\n"
            "bare.whl#sha256=deadbeef # artifact comment\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert {record.name for record in records} == {"demo", "editable-demo"}
    assert all(record.registry_usage == "resolved_download" for record in records)
    assert {(item.url, item.usage, item.dependency_name) for item in observations} == {
        (
            "https://packages.example/demo.whl#sha256=cafebabe",
            "resolved_download", "demo",
        ),
        (
            "git+https://git.example/demo.git#egg=editable-demo",
            "resolved_download", "editable-demo",
        ),
        (
            "https://packages.example/bare.whl#sha256=deadbeef",
            "resolved_download", None,
        ),
    }


@pytest.mark.parametrize("configured_index", [None, "https://pypi.org/simple"])
@pytest.mark.parametrize(
    ("requirement", "direct_url"),
    [
        (
            "demo-git @ git+https://git.example/demo.git#egg=demo-git "
            "--index-url https://evil.example/simple",
            "git+https://git.example/demo.git#egg=demo-git",
        ),
        (
            "requests==2.31.0 --index-url https://evil.example/simple",
            None,
        ),
        (
            "demo-wheel @ https://packages.example/demo.whl#sha256=cafebabe "
            "-f https://evil.example/wheels",
            "https://packages.example/demo.whl#sha256=cafebabe",
        ),
    ],
    ids=["direct-git", "ordinary-requirement", "direct-wheel"],
)
def test_requirement_trailing_source_options_do_not_change_registry(
    configured_index, requirement, direct_url
):
    prefix = f"--index-url {configured_index}\n" if configured_index else ""
    files = {
        "requirements.txt": (
            f"{prefix}{requirement}\n"
            "urllib3==2.0.0\n"
            "requests==2.32.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    ordinary = [
        record for record in records if record.name in {"urllib3", "requests"}
    ]
    assert {record.name for record in ordinary} == {"urllib3", "requests"}
    assert all(record.registry == configured_index for record in ordinary)
    assert all(
        record.registry_usage == ("registry_api" if configured_index else None)
        for record in ordinary
    )
    expected_sources = (
        {(configured_index, "registry_api")} if configured_index else set()
    )
    if direct_url:
        expected_sources.add((direct_url, "resolved_download"))
        direct = next(
            record for record in records if record.name.startswith("demo-")
        )
        assert direct.registry == direct_url
        assert direct.registry_usage == "resolved_download"
    assert {(item.url, item.usage) for item in observations} == expected_sources


def test_quoted_option_value_does_not_inject_requirement_source():
    files = {
        "requirements.txt": (
            '--trusted-host "host --index-url https://evil.example/simple" '
            "--extra-index-url https://mirror.example/simple\n"
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert [
        (record.name, record.registry, record.registry_usage) for record in records
    ] == [("requests", None, None)]
    assert [(item.url, item.usage) for item in observations] == [
        ("https://mirror.example/simple", "registry_api"),
    ]


def test_source_option_before_editable_retains_explicit_observation():
    files = {
        "requirements.txt": (
            "--index-url https://pypi.org/simple -e ./local-project\n"
        )
    }

    observations = parse_dependency_sources(files)

    assert [(item.url, item.usage, item.dependency_name) for item in observations] == [
        ("https://pypi.org/simple", "registry_api", None),
    ]


@pytest.mark.parametrize("invalid_value", ["=", "= https://evil.example/simple"])
def test_non_url_source_option_value_does_not_replace_configured_registry(
    invalid_value
):
    files = {
        "requirements.txt": (
            "--index-url https://pypi.org/simple\n"
            f"--index-url {invalid_value}\n"
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert records[0].registry == "https://pypi.org/simple"
    assert records[0].registry_usage == "registry_api"
    assert {(item.url, item.usage) for item in observations} == {
        ("https://pypi.org/simple", "registry_api"),
    }


@pytest.mark.parametrize(
    ("filename", "scope"),
    [
        ("requirements.txt", "runtime"),
        ("requirements-dev.txt", "dev"),
        ("requirements-tests.txt", "test"),
    ],
)
def test_continued_requirements_preserve_record_location_and_scope(filename, scope):
    files = {
        filename: (
            "# configuration\n"
            "--index-url \\\n  https://pypi.org/simple\n"
            "requests==\\\n2.31.0\n"
            "demo \\\n  @ https://packages.example/demo.whl#sha256=cafebabe\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert [
        (record.name, record.line, record.source_ref, record.scope)
        for record in records
    ] == [
        ("requests", 4, "L4", scope),
        ("demo", 6, "L6", scope),
    ]
    assert [
        (item.dependency_name, item.line, item.source_ref, item.scope)
        for item in observations
    ] == [
        ("requests", 4, "L4", scope),
        ("demo", 6, "L6", scope),
    ]


def test_continued_source_observations_use_url_physical_line():
    files = {
        "requirements.txt": (
            "# source declarations\n"
            "--extra-index-url \\\n  https://mirror.example/simple\n"
            "--find-links \\\n  https://files.example/wheels/\n"
            "https://packages.example/\\\n"
            "bare.whl#sha256=deadbeef\n"
            "--index-url=\\\n  https://packages.example/review.whl\n"
        )
    }

    observations = parse_dependency_sources(files)

    assert {(item.url, item.usage, item.line) for item in observations} == {
        ("https://mirror.example/simple", "registry_api", 3),
        ("https://files.example/wheels/", "resolved_download", 5),
        (
            "https://packages.example/bare.whl#sha256=deadbeef",
            "resolved_download", 6,
        ),
        ("https://packages.example/review.whl", "resolved_download", 9),
    }
    assert all(item.dependency_name is None for item in observations)


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
        _dependency_usage_for_url,
    )

    assert _dependency_usage_for_url(
        command, command.index("https://")
    ) == "resolved_download"


def test_dequoted_source_url_does_not_borrow_a_later_occurrence_line():
    observations = parse_dependency_sources({
        "requirements.txt": (
            '--index-url="https://co""rp.example/simple" \\\n'
            '  --extra-index-url https://corp.example/simple\n'
        )
    })

    assert [(item.url, item.source_ref, item.line) for item in observations] == [
        ("https://corp.example/simple", "L1", 1),
        ("https://corp.example/simple", "L2", 2),
    ]


def test_npm_force_is_not_classified_as_pip_find_links():
    from scanners.risk_scanner.rules.supply_chain import (
        _dependency_usage_for_url,
    )

    command = "npm install -f --registry https://mirror.internal/ demo"
    assert _dependency_usage_for_url(
        command, command.index("https://")
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
            return OSVQueryResult(
                [], status="failed", failure_reason="TimeoutError"
            )

    scanner.osv_client = FailedClient()
    report = scanner.scan()
    assert report["dependency_scan"]["status"] == "failed"
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

@pytest.mark.parametrize(
    ("option", "usage"),
    [
        ("--index-url", "registry_api"),
        ("--extra-index-url", "registry_api"),
        ("-i", "registry_api"),
        ("--find-links", "resolved_download"),
        ("-f", "resolved_download"),
    ],
)
@pytest.mark.parametrize("separator", [" \\\n  \\\n  ", "=\\\r\n"])
def test_requirements_continued_options_keep_their_usage(option, usage, separator):
    url = "https://packages.example/simple#fragment"
    files = {
        "requirements.txt": (
            f"{option}{separator}{url} # source comment\n"
            "requests==\\\n2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert len(records) == 1
    assert (records[0].name, records[0].version) == ("requests", "2.31.0")
    if option in {"--index-url", "-i"}:
        assert records[0].registry == url
        assert records[0].registry_usage == "registry_api"
    assert [(item.url, item.usage) for item in observations] == [(url, usage)]

@pytest.mark.parametrize(
    "option", ["--index-url", "--extra-index-url", "-i", "--find-links", "-f"]
)
@pytest.mark.parametrize("separator", ["=\\\n    ", "=\\\r\n\t"])
def test_requirements_incomplete_source_option_retains_trailing_url(
    option, separator
):
    url = "https://packages.example/demo.whl#sha256=deadbeef"
    files = {
        "requirements.txt": (
            f"{option}{separator}{url} # trailing URL for review\n"
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert [(record.name, record.registry) for record in records] == [
        ("requests", None),
    ]
    assert [
        (item.url, item.usage, item.dependency_name) for item in observations
    ] == [(url, "resolved_download", None)]

def test_incomplete_source_option_does_not_consume_next_source_option():
    observations = parse_dependency_sources({
        "requirements.txt": (
            "--index-url=\\\n    --extra-index-url https://packages.example/simple\n"
        )
    })

    assert [(item.url, item.usage) for item in observations] == [
        ("https://packages.example/simple", "registry_api"),
    ]

def test_requirements_commented_continuation_does_not_consume_bare_url():
    observations = parse_dependency_sources({
        "requirements.txt": (
            "# --index-url \\\n"
            "https://packages.example/demo.whl#sha256=deadbeef\n"
        )
    })

    assert [(item.url, item.usage) for item in observations] == [
        ("https://packages.example/demo.whl#sha256=deadbeef", "resolved_download"),
    ]

def test_requirements_multiple_continued_options_share_one_logical_line():
    files = {
        "requirements.txt": (
            '--index-url \\\n  "https://pypi.org/simple" \\\n'
            '  --extra-index-url="https://mirror.example/simple" \\\n'
            '  --find-links \\\n  "https://files.example/wheels/"\n'
            "requests==2.31.0\n"
        )
    }

    records = parse_dependencies(files)
    observations = parse_dependency_sources(files, records)

    assert records[0].registry == "https://pypi.org/simple"
    assert {(item.url, item.usage) for item in observations} == {
        ("https://pypi.org/simple", "registry_api"),
        ("https://mirror.example/simple", "registry_api"),
        ("https://files.example/wheels/", "resolved_download"),
    }

@pytest.mark.parametrize("editable", ["-e ./pkg", "--editable ./pkg", "--editable=./pkg"])
def test_editable_keeps_preceding_source_declaration_for_review(editable):
    url = "https://private.example/simple"
    content = f"--index-url {url} {editable}\nrequests==2.31.0\n"
    files = {"requirements.txt": content}

    assert list(iter_requirement_options(content)) == [("--index-url", url, 1)]
    records = parse_dependencies(files)
    assert [(record.name, record.registry) for record in records] == [
        ("requests", url),
    ]
    assert [(item.url, item.usage) for item in parse_dependency_sources(files, records)] == [
        (url, "registry_api"),
    ]

@pytest.mark.parametrize("configured_index", [None, "https://pypi.org/simple"])
def test_separate_equals_token_does_not_become_a_registry(configured_index):
    prefix = f"--index-url {configured_index}\n" if configured_index else ""
    malformed = "--index-url = https://private.example/simple\n"
    files = {"requirements.txt": f"{prefix}{malformed}requests==2.31.0\n"}

    assert list(iter_requirement_options(malformed)) == []
    records = parse_dependencies(files)
    assert [(record.name, record.registry) for record in records] == [
        ("requests", configured_index),
    ]
    assert [(item.url, item.usage) for item in parse_dependency_sources(files, records)] == (
        [(configured_index, "registry_api")] if configured_index else []
    )

@pytest.mark.parametrize("separator", ["\r", "\f", "\v", "\x1c"])
def test_requirements_preserve_existing_line_separator_behavior(separator):
    records = parse_dependencies({
        "requirements.txt": f"requests==2.31.0{separator}flask==3.0.0"
    })

    assert {(record.name, record.version) for record in records} == {
        ("requests", "2.31.0"), ("flask", "3.0.0"),
    }

def test_logical_requirements_preserve_original_line_numbers():
    from scanners.risk_scanner.logical_lines import iter_logical_lines

    lines = list(iter_logical_lines(
        "# source configuration\r\n"
        "--index-url \\\r\n  \\\r\n  https://pypi.org/simple\r\n"
        "demo @ \\\r\n  https://packages.example/demo.whl\r\n"
        "requests==2.31.0",
        requirement_comments=True,
    ))

    assert [line.start_line for line in lines] == [1, 2, 5, 7]
    assert lines[1].source_line(lines[1].text.index("https://")) == 4
    assert lines[2].source_line(lines[2].text.index("https://")) == 6
