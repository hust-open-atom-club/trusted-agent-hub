"""Artifact packaging must honor an explicit source subdirectory."""

from pathlib import Path
from zipfile import ZipFile

import pytest

from src.services import artifacts


def test_build_artifact_uses_explicit_nested_subdirectory(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    skill = repo / "skills" / "demo"
    skill.mkdir(parents=True)
    (repo / "manifest.json").write_text("{}\n", encoding="utf-8")
    (repo / "README.md").write_text("whole repository\n", encoding="utf-8")
    (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
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
        assert handle.namelist() == ["SKILL.md", "LICENSE"]


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
