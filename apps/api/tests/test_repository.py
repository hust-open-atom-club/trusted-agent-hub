"""Tests for the strict JSON-backed package repository."""

import json
from pathlib import Path

import pytest

from src.repositories.base import RepositoryDataError
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


def _write_repository(
    root: Path,
    packages: list[dict[str, object]],
    versions: list[dict[str, object]],
) -> tuple[Path, Path]:
    packages_path = root / "packages.json"
    versions_dir = root / "versions"
    versions_dir.mkdir()
    packages_path.write_text(json.dumps(packages), encoding="utf-8")
    for index, version in enumerate(versions):
        (versions_dir / f"version-{index}.json").write_text(
            json.dumps(version), encoding="utf-8"
        )
    return packages_path, versions_dir


def _package(**overrides: object) -> dict[str, object]:
    package: dict[str, object] = {
        "id": "p1",
        "name": "example",
        "description": "x",
        "type": "skill",
        "latest_version": "1.0.0",
        "status": "published",
    }
    package.update(overrides)
    return package


def _version(**overrides: object) -> dict[str, object]:
    version: dict[str, object] = {
        "id": "v1",
        "package_id": "p1",
        "version": "1.0.0",
        "status": "published",
    }
    version.update(overrides)
    return version


def test_repository_loads_explicit_version() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    version = repo.get_version("code-review-skill", "1.0.0")

    assert version is not None
    assert version.id == "ver-001"


def test_repository_never_synthesizes_unknown_version() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")

    assert repo.get_version("code-review-skill", "9.9.9") is None


def test_repository_exposes_indexed_records_as_immutable_sequences() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")

    packages = repo.list_packages()
    versions = repo.list_versions("code-review-skill")

    assert isinstance(packages, tuple)
    assert isinstance(versions, tuple)
    assert repo.get_package("code-review-skill") == packages[0]
    assert repo.get_package("missing") is None
    assert repo.get_version_by_id("ver-001") == versions[0]
    assert repo.get_version_by_id("missing") is None
    assert repo.list_versions("missing") == ()


def test_get_package_returns_an_independent_deep_copy() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    package = repo.get_package("code-review-skill")
    assert package is not None

    package.name = "mutated"
    package.keywords.append("mutated")

    stored = repo.get_package("code-review-skill")
    assert stored is not None
    assert stored.name == "code-review-skill"
    assert "mutated" not in stored.keywords


def test_list_packages_returns_independent_deep_copies() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    package = repo.list_packages()[0]

    package.name = "mutated"
    package.keywords.append("mutated")

    stored = repo.list_packages()[0]
    assert stored.name == "code-review-skill"
    assert "mutated" not in stored.keywords


def test_get_version_returns_an_independent_deep_copy() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    version = repo.get_version("code-review-skill", "1.0.0")
    assert version is not None

    version.version = "9.9.9"
    version.compatibility.append("mutated")

    stored = repo.get_version("code-review-skill", "1.0.0")
    assert stored is not None
    assert stored.version == "1.0.0"
    assert "mutated" not in stored.compatibility


def test_get_version_by_id_returns_an_independent_deep_copy() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    version = repo.get_version_by_id("ver-001")
    assert version is not None

    version.version = "9.9.9"
    version.compatibility.append("mutated")

    stored = repo.get_version_by_id("ver-001")
    assert stored is not None
    assert stored.version == "1.0.0"
    assert "mutated" not in stored.compatibility


def test_list_versions_returns_independent_deep_copies() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    version = repo.list_versions("code-review-skill")[0]

    version.version = "9.9.9"
    version.compatibility.append("mutated")

    stored = repo.list_versions("code-review-skill")[0]
    assert stored.version == "1.0.0"
    assert "mutated" not in stored.compatibility


def test_invalid_latest_version_relationship_is_reported(tmp_path: Path) -> None:
    packages = tmp_path / "packages.json"
    versions = tmp_path / "versions"
    versions.mkdir()
    packages.write_text(
        '[{"id":"p1","name":"broken","description":"x",'
        '"type":"skill","latest_version":"1.0.0","status":"published"}]',
        encoding="utf-8",
    )

    with pytest.raises(RepositoryDataError, match="latest_version"):
        JsonPackageRepository(packages, versions)


def test_unexpected_top_level_field_is_reported(tmp_path: Path) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package(unexpected=True)],
        [_version()],
    )

    with pytest.raises(RepositoryDataError, match="Invalid mock repository data"):
        JsonPackageRepository(packages, versions)


def test_unexpected_nested_field_is_reported(tmp_path: Path) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package()],
        [
            _version(
                source={
                    "type": "github",
                    "repository_url": "https://example.com/repository",
                    "ref": "v1.0.0",
                    "commit_hash": "abc123",
                    "unexpected": True,
                }
            )
        ],
    )

    with pytest.raises(RepositoryDataError, match="Invalid mock repository data"):
        JsonPackageRepository(packages, versions)


def test_coercible_wrong_type_is_reported(tmp_path: Path) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package(install_count="12")],
        [_version()],
    )

    with pytest.raises(RepositoryDataError, match="Invalid mock repository data"):
        JsonPackageRepository(packages, versions)


@pytest.mark.parametrize(
    ("second_package", "message"),
    [
        (_package(id="p2"), "package name"),
        (_package(name="other"), "package id"),
    ],
)
def test_duplicate_packages_are_reported(
    tmp_path: Path, second_package: dict[str, object], message: str
) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package(), second_package],
        [_version()],
    )

    with pytest.raises(RepositoryDataError, match=message):
        JsonPackageRepository(packages, versions)


@pytest.mark.parametrize(
    ("second_version", "message"),
    [
        (_version(package_id="p2", version="2.0.0"), "version id"),
        (_version(id="v2"), "version key"),
    ],
)
def test_duplicate_versions_are_reported(
    tmp_path: Path, second_version: dict[str, object], message: str
) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package(), _package(id="p2", name="other", latest_version="2.0.0")],
        [_version(), second_version],
    )

    with pytest.raises(RepositoryDataError, match=message):
        JsonPackageRepository(packages, versions)


def test_version_referencing_unknown_package_is_reported(tmp_path: Path) -> None:
    packages, versions = _write_repository(
        tmp_path,
        [_package()],
        [_version(package_id="missing")],
    )

    with pytest.raises(RepositoryDataError, match="unknown package"):
        JsonPackageRepository(packages, versions)
