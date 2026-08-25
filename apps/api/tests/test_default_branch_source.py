"""Regression tests for default-branch-only repository acquisition."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from src.routers import producer as producer_router
from src.routers import trust
from src.services import producer as producer_service
from src.services.producer import ProducerService


class _JsonResponse:
    def __init__(self, payload: object) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "_JsonResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def test_resolve_default_branch_from_github_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_urlopen(request, timeout: int):
        observed["url"] = request.full_url
        observed["timeout"] = timeout
        return _JsonResponse(
            {"full_name": "acme/demo", "default_branch": "master"}
        )

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)

    resolved = trust._resolve_default_branch_source(
        trust._parse_github_url("https://github.com/acme/demo")
    )

    assert observed == {
        "url": "https://api.github.com/repos/acme/demo",
        "timeout": 20,
    }
    assert resolved["ref"] == "master"
    assert resolved["subdir"] is None
    assert resolved["repository_resolved"] is True


def test_default_branch_with_slash_keeps_its_subdirectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        trust,
        "_fetch_repository_default_branch",
        lambda _parsed: "release/main",
    )

    resolved = trust._resolve_default_branch_source(
        trust._parse_github_url(
            "https://github.com/acme/demo/tree/release/main/skills/hello"
        )
    )

    assert resolved["ref"] == "release/main"
    assert resolved["subdir"] == "skills/hello"


def test_non_default_tree_path_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        trust,
        "_fetch_repository_default_branch",
        lambda _parsed: "main",
    )

    with pytest.raises(HTTPException) as raised:
        trust._resolve_default_branch_source(
            trust._parse_github_url(
                "https://github.com/acme/demo/tree/feature-x"
            )
        )

    assert raised.value.status_code == 400
    assert "default branch" in str(raised.value.detail)


def test_scan_endpoint_rejects_non_default_branch_before_enqueueing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        trust,
        "_fetch_repository_default_branch",
        lambda _parsed: "main",
    )
    background_tasks = BackgroundTasks()

    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            background_tasks,
            repo_url="https://github.com/acme/demo/tree/feature-x",
            _user=SimpleNamespace(id="user-1"),
        )

    assert raised.value.status_code == 400
    assert background_tasks.tasks == []


def test_producer_endpoint_rejects_non_default_branch_before_state_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Repository:
        update_calls: list[object] = []

        @staticmethod
        def get_version(_version_id: str) -> dict[str, object]:
            return {
                "id": "version-1",
                "package_id": None,
                "source": {
                    "repository_url": (
                        "https://github.com/acme/demo/tree/feature-x"
                    )
                },
            }

    repository = Repository()
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_default_branch",
        lambda _parsed: "main",
    )

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            "version-1",
            BackgroundTasks(),
            _user=SimpleNamespace(id="user-1"),
        )

    assert raised.value.status_code == 400
    assert repository.update_calls == []


def test_git_clone_explicitly_uses_resolved_default_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(trust, "_is_github_reachable", lambda: True)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(trust.subprocess, "run", fake_run)

    assert trust._git_clone_with_retries(
        {"owner": "acme", "repo": "demo", "ref": "master"},
        "unused-clone-directory",
        max_attempts=1,
    )

    command = commands[0]
    assert command[command.index("--branch") + 1] == "master"
    assert "--single-branch" in command


def test_zipball_uses_the_same_resolved_default_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    requested_urls: list[str] = []

    def fake_urlopen(request, timeout: int):
        requested_urls.append(request.full_url)
        raise OSError("network unavailable")

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)

    assert not trust._download_zipball(
        {"owner": "acme", "repo": "demo", "ref": "master"},
        "unused-zip-directory",
        max_attempts=1,
    )
    assert requested_urls == [
        "https://api.github.com/repos/acme/demo/zipball/master"
    ]


def test_acquisition_metadata_overrides_repository_claims() -> None:
    metadata = {
        "source": {
            "repository_url": "https://github.com/untrusted/other",
            "ref": "feature-x",
            "commit_hash": "b" * 40,
            "subdirectory": "wrong/path",
        }
    }
    facts = {
        "source": {
            "repository_url": "https://github.com/acme/demo",
            "ref": "a" * 40,
            "commit_hash": "a" * 40,
            "type": "github",
            "owner": "acme",
            "repo": "demo",
            "ref_type": "commit",
        },
        "integrity": {
            "sha256": "c" * 64,
            "hash_scope": "scanned_source",
            "is_complete": True,
        },
    }

    safe = trust._apply_acquisition_facts(metadata, facts)

    assert safe["source"] == {
        "repository_url": "https://github.com/acme/demo",
        "ref": "a" * 40,
        "commit_hash": "a" * 40,
        "type": "github",
        "owner": "acme",
        "repo": "demo",
        "ref_type": "commit",
    }
    assert safe["integrity"] == facts["integrity"]
    assert metadata["source"]["repository_url"].endswith("untrusted/other")


class _ProducerRepository:
    def __init__(self) -> None:
        self.version: dict[str, object] = {
            "id": "version-1",
            "package_id": "package-1",
            "version": "1.0.0",
            "source": {
                "type": "github",
                "repository_url": "https://github.com/acme/demo/tree/feature-x",
                "ref": "feature-x",
            },
            "integrity": {
                "sha256": "f" * 64,
                "signature": "package-authored-signature",
                "sbom_url": "https://attacker.example/sbom.json",
            },
            "installation": {"method": "npm_install"},
        }

    def get_version(self, _version_id: str) -> dict[str, object]:
        return self.version

    def get_package(self, _package_id: str) -> dict[str, str]:
        return {"name": "demo"}

    def update_version_data(self, _version_id: str, data: dict[str, object]) -> None:
        self.version.update(data)

    def save_scan_report(self, **_kwargs: object) -> None:
        return None

    def update_version_status(self, _version_id: str, status: str) -> None:
        self.version["status"] = status

    def create_audit_log(self, **_kwargs: object) -> None:
        return None


@pytest.mark.parametrize(
    "install_method",
    ["npm_install", "pip_install", "docker_run", "manual_steps"],
)
def test_producer_persists_acquired_source_and_clears_untrusted_integrity(
    monkeypatch: pytest.MonkeyPatch,
    install_method: str,
) -> None:
    repo = _ProducerRepository()
    repo.version["installation"] = {"method": install_method}
    service = ProducerService(repo)  # type: ignore[arg-type]
    monkeypatch.setattr(
        service,
        "_apply_installation_steps_to_version",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        producer_service,
        "_backfill_author_license",
        lambda *_args, **_kwargs: None,
    )
    commit_hash = "a" * 40

    service.handle_scan_complete(
        "version-1",
        {
            "scan_id": "scan-default-branch",
            "scan_report": {"summary": {"total": 0}},
            "trust_score": {},
            "commit_hash": commit_hash,
            "source_subdirectory": None,
            "local_source_dir": None,
            "package_claims": {
                "integrity": {
                    "sha256": "f" * 64,
                    "signature": "package-authored-signature",
                    "sbom_url": "https://attacker.example/sbom.json",
                },
            },
            "package_metadata": {
                "source": {
                    "type": "github",
                    "repository_url": "https://github.com/acme/demo",
                    "owner": "acme",
                    "repo": "demo",
                    "ref_type": "branch",
                    "ref": "master",
                    "commit_hash": commit_hash,
                }
            },
        },
    )

    source = repo.version["source"]
    assert isinstance(source, dict)
    assert source["repository_url"] == "https://github.com/acme/demo"
    assert source["ref"] == "master"
    assert source["commit_hash"] == commit_hash
    assert repo.version["integrity"] is None
    assert repo.version["provenance_claims"] == {
        "integrity": {
            "sha256": "f" * 64,
            "signature": "package-authored-signature",
            "sbom_url": "https://attacker.example/sbom.json",
        },
    }
