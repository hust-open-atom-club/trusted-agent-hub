"""Artifact packaging must honor an explicit source subdirectory."""

from pathlib import Path
from zipfile import ZipFile

import pytest

from src.routers import trust
from src.services import artifacts
from src.services.producer import ProducerService


class _RebuildRepository:
    def __init__(self) -> None:
        self.version = {
            "id": "version-rebuild",
            "package_id": "package-rebuild",
            "version": "1.0.0",
            "source": {
                "repository_url": "https://github.com/acme/demo",
                "commit_hash": "A" * 40,
                "subdirectory": "skills/demo",
            },
        }

    def get_version(self, _version_id: str) -> dict[str, object]:
        return self.version

    def get_package(self, _package_id: str) -> dict[str, object]:
        return {"name": "demo", "type": "skill"}


def test_build_artifact_uses_explicit_nested_subdirectory(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    skill = repo / "skills" / "demo"
    skill.mkdir(parents=True)
    (repo / "manifest.json").write_text("{}\n", encoding="utf-8")
    (repo / "README.md").write_text("whole repository\n", encoding="utf-8")
    (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (repo / "skills" / "NOTICE").write_text("Shared notice\n", encoding="utf-8")
    (skill / "SKILL.md").write_text("# demo\n", encoding="utf-8")

    monkeypatch.setattr(artifacts, "ARTIFACTS_ROOT", tmp_path / "artifacts")
    result = artifacts.build_artifact(
        repo_url="https://example.invalid/demo",
        commit_hash="a" * 40,
        package_name="demo",
        version="1.0.0",
        local_source_dir=str(repo),
        source_subdirectory="skills/demo",
    )

    archive = artifacts.ARTIFACTS_ROOT / Path(str(result["download_url"])).name
    with ZipFile(archive) as handle:
        assert handle.namelist() == [
            "demo/SKILL.md",
            "demo/NOTICE",
            "demo/LICENSE",
        ]


def test_build_artifact_rejects_missing_or_escaping_subdirectory(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(artifacts, "ARTIFACTS_ROOT", tmp_path / "artifacts")

    for subdirectory in ("missing", "../outside"):
        with pytest.raises(artifacts.ArtifactError):
            artifacts.build_artifact(
                repo_url="https://example.invalid/demo",
                commit_hash="b" * 40,
                package_name=f"demo-{subdirectory.replace('/', '-')}",
                version="1.0.0",
                local_source_dir=str(repo),
                source_subdirectory=subdirectory,
            )


def test_build_artifact_never_falls_back_to_url_only_clone(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(artifacts, "ARTIFACTS_ROOT", tmp_path / "artifacts")

    with pytest.raises(
        artifacts.ArtifactError,
        match="bounded local source snapshot is required",
    ):
        artifacts.build_artifact(
            repo_url="https://example.invalid/private",
            commit_hash="c" * 40,
            package_name="no-clone-fallback",
            version="1.0.0",
        )


def test_publish_rebuild_acquires_pinned_source_and_cleans_it(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _RebuildRepository()
    service = ProducerService(repository)  # type: ignore[arg-type]
    acquired: dict[str, object] = {}
    source_dir = tmp_path / "tah_repo_rebuild"

    def acquire_source(parsed: dict[str, object]) -> tuple[str, str, str]:
        acquired["parsed"] = parsed
        (source_dir / "skills" / "demo").mkdir(parents=True)
        return str(source_dir), "github_api", "a" * 40

    def build(**kwargs: object) -> dict[str, object]:
        acquired["build_kwargs"] = kwargs
        assert Path(str(kwargs["local_source_dir"])).is_dir()
        return {
            "download_url": "/api/v0/artifacts/demo.zip",
            "sha256": "b" * 64,
            "download_size_bytes": 10,
        }

    monkeypatch.setattr(trust, "_acquire_repo_source", acquire_source)
    monkeypatch.setattr(artifacts, "build_artifact", build)
    applied: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        service,
        "_apply_artifact_to_version",
        lambda *args: applied.append(args),
    )

    assert service._try_rebuild_artifact("version-rebuild") is True
    parsed = acquired["parsed"]
    assert isinstance(parsed, dict)
    assert parsed["ref"] == "a" * 40
    assert parsed["commit_hash"] == "a" * 40
    assert parsed["subdir"] == "skills/demo"
    build_kwargs = acquired["build_kwargs"]
    assert isinstance(build_kwargs, dict)
    assert build_kwargs["local_source_dir"] == str(source_dir)
    assert build_kwargs["source_subdirectory"] == "skills/demo"
    assert not source_dir.exists()
    assert applied
