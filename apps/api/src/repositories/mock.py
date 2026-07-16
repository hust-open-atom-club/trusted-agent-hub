"""Strict JSON-backed repository for the checked-in mock package data."""

import json
from pathlib import Path
from typing import Sequence

from pydantic import TypeAdapter, ValidationError

from src.models.packages import PackageSummary, VersionDetail

from .base import RepositoryDataError


class JsonPackageRepository:
    """Load explicit package and version records from JSON files."""

    def __init__(self, packages_path: Path, versions_dir: Path) -> None:
        try:
            packages = TypeAdapter(list[PackageSummary]).validate_json(
                packages_path.read_text(encoding="utf-8"), strict=True
            )
            versions = [
                VersionDetail.model_validate_json(
                    path.read_text(encoding="utf-8"), strict=True
                )
                for path in sorted(versions_dir.glob("*.json"))
            ]
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise RepositoryDataError(f"Invalid mock repository data: {exc}") from exc

        self._packages = tuple(packages)
        self._versions = tuple(versions)
        self._packages_by_name: dict[str, PackageSummary] = {}
        package_name_by_id: dict[str, str] = {}

        for package in self._packages:
            if package.name in self._packages_by_name:
                raise RepositoryDataError(f"Duplicate package name: {package.name}")
            if package.id in package_name_by_id:
                raise RepositoryDataError(f"Duplicate package id: {package.id}")
            self._packages_by_name[package.name] = package
            package_name_by_id[package.id] = package.name

        self._versions_by_key: dict[tuple[str, str], VersionDetail] = {}
        self._versions_by_id: dict[str, VersionDetail] = {}
        for version in self._versions:
            if version.id in self._versions_by_id:
                raise RepositoryDataError(f"Duplicate version id: {version.id}")

            name = package_name_by_id.get(version.package_id)
            if name is None:
                raise RepositoryDataError(
                    f"Version {version.id} references unknown package {version.package_id}"
                )

            key = (name, version.version)
            if key in self._versions_by_key:
                raise RepositoryDataError(
                    f"Duplicate version key: {name}@{version.version}"
                )
            self._versions_by_id[version.id] = version
            self._versions_by_key[key] = version

        for package in self._packages:
            if (package.name, package.latest_version) not in self._versions_by_key:
                raise RepositoryDataError(
                    f"Package {package.name} latest_version {package.latest_version} "
                    "has no explicit version record"
                )

    def list_packages(self) -> Sequence[PackageSummary]:
        return tuple(package.model_copy(deep=True) for package in self._packages)

    def get_package(self, name: str) -> PackageSummary | None:
        package = self._packages_by_name.get(name)
        return None if package is None else package.model_copy(deep=True)

    def list_versions(self, name: str) -> Sequence[VersionDetail]:
        return tuple(
            version.model_copy(deep=True)
            for (package_name, _), version in self._versions_by_key.items()
            if package_name == name
        )

    def get_version(self, name: str, version: str) -> VersionDetail | None:
        detail = self._versions_by_key.get((name, version))
        return None if detail is None else detail.model_copy(deep=True)

    def get_version_by_id(self, version_id: str) -> VersionDetail | None:
        detail = self._versions_by_id.get(version_id)
        return None if detail is None else detail.model_copy(deep=True)
