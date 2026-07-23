"""Safe Install Manifest v1.0 construction service."""

import math
import posixpath
import re

from pydantic import TypeAdapter, ValidationError

from src.errors import ConsumerAPIError
from src.models.install import (
    CopyInstallationStep,
    DownloadInstallationStep,
    ExtractInstallationStep,
    HttpsUrl,
    InstallManifest,
    ManifestInstallation,
    ManifestInstallationStep,
    ManifestIntegrity,
    ManifestSource,
    VerifyInstallationStep,
)
from src.models.packages import Dependencies
from src.repositories.base import PackageRepository

from .packages import PackageService


SUPPORTED_SOURCE_TYPES = {"github", "npm", "pypi", "docker", "local_upload"}
SUPPORTED_INSTALL_METHODS = {
    "copy_directory",
    "npm_install",
    "pip_install",
    "docker_run",
    "manual_steps",
}
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
HTTPS_URL_ADAPTER = TypeAdapter(HttpsUrl)
CLIENT_INSTALL_ROOTS = {
    "claude-code": "~/.claude/skills/",
    "cursor": "~/.cursor/skills/",
}


class InstallManifestService:
    """Build manifests only from explicit, published, install-safe records."""

    def __init__(self, repository: PackageRepository) -> None:
        self.packages = PackageService(repository)

    def get_manifest(
        self,
        name: str,
        client: str,
        version: str | None = None,
    ) -> InstallManifest:
        package = self.packages.get_public_package(name)
        selected_version = version or package.latest_version
        record = self.packages.get_public_version(name, selected_version)

        invalid_fields: list[str] = []
        source = record.source
        if source is None:
            invalid_fields.append("source.download_url")
        else:
            if source.type not in SUPPORTED_SOURCE_TYPES:
                invalid_fields.append("source.type")
            if not self._is_https_url(source.repository_url):
                invalid_fields.append("source.repository_url")
            if not self._is_https_url(source.download_url):
                invalid_fields.append("source.download_url")
            if not source.ref:
                invalid_fields.append("source.ref")
            if not COMMIT_PATTERN.fullmatch(source.commit_hash):
                invalid_fields.append("source.commit_hash")

        integrity = record.integrity
        if integrity is None:
            invalid_fields.append("integrity.sha256")
        else:
            if not SHA256_PATTERN.fullmatch(integrity.sha256):
                invalid_fields.append("integrity.sha256")
            if (
                integrity.download_size_bytes is None
                or integrity.download_size_bytes < 0
            ):
                invalid_fields.append("integrity.download_size_bytes")

        if client not in record.compatibility:
            invalid_fields.append("compatibility")

        installation = record.installation
        validated_steps: list[ManifestInstallationStep] | None = None
        if installation is None or not installation.steps:
            invalid_fields.append("installation.steps")
        else:
            try:
                validated_steps = [
                    ManifestInstallationStep.model_validate(step.model_dump())
                    for step in installation.steps
                ]
            except ValidationError:
                invalid_fields.append("installation.steps")
            else:
                actions = [step.root.action for step in validated_steps]
                download_steps = [
                    (index, step.root)
                    for index, step in enumerate(validated_steps)
                    if isinstance(step.root, DownloadInstallationStep)
                ]
                verify_steps = [
                    (index, step.root)
                    for index, step in enumerate(validated_steps)
                    if isinstance(step.root, VerifyInstallationStep)
                ]
                copy_steps = [
                    step.root
                    for step in validated_steps
                    if isinstance(step.root, CopyInstallationStep)
                ]
                consuming_indices = [
                    index
                    for index, step in enumerate(validated_steps)
                    if isinstance(
                        step.root,
                        (ExtractInstallationStep, CopyInstallationStep),
                    )
                ]
                valid_identity = (
                    len(download_steps) == 1
                    and len(verify_steps) == 1
                    and download_steps[0][0] < verify_steps[0][0]
                    and source is not None
                    and integrity is not None
                    and self._canonical_https_url(
                        str(download_steps[0][1].url)
                    )
                    == self._canonical_https_url(source.download_url)
                    and verify_steps[0][1].algorithm == "sha256"
                    and verify_steps[0][1].checksum == integrity.sha256
                )
                if valid_identity:
                    verify_index = verify_steps[0][0]
                    if installation.method == "copy_directory":
                        valid_identity = actions == [
                            "download",
                            "verify",
                            "extract",
                            "copy",
                        ]
                    else:
                        valid_identity = (
                            len(actions) == len(set(actions))
                            and all(
                                index > verify_index
                                for index in consuming_indices
                            )
                        )

                if valid_identity and copy_steps:
                    client_root = CLIENT_INSTALL_ROOTS.get(
                        installation.target_client or ""
                    )
                    valid_identity = client_root is not None and all(
                        self._is_strict_child_path(
                            step.destination,
                            client_root,
                        )
                        for step in copy_steps
                    )
                if not valid_identity:
                    invalid_fields.append("installation.steps")
        if installation is None or installation.target_client != client:
            invalid_fields.append("installation.target_client")
        if (
            installation is None
            or installation.method not in SUPPORTED_INSTALL_METHODS
        ):
            invalid_fields.append("installation.method")

        if record.permissions is None:
            invalid_fields.append("permissions")

        trust_score = record.trust_score
        risk_summary = None if trust_score is None else trust_score.risk_summary
        if (
            trust_score is None
            or risk_summary is None
            or risk_summary.grade is None
        ):
            invalid_fields.append("trust_score")
        if (
            risk_summary is not None
            and risk_summary.install_recommendation == "blocked"
        ):
            invalid_fields.append("risk_summary.install_recommendation")

        if invalid_fields:
            raise ConsumerAPIError(
                status_code=409,
                code="install_manifest_unavailable",
                message=(
                    f"Install manifest for '{name}@{selected_version}' "
                    "is unavailable."
                ),
                details={"invalid_fields": invalid_fields},
            )

        assert source is not None
        assert integrity is not None
        assert installation is not None
        assert validated_steps is not None
        assert record.permissions is not None
        assert trust_score is not None
        assert risk_summary is not None

        return InstallManifest(
            name=package.name,
            version=record.version,
            type=package.type,
            description=package.description,
            source=ManifestSource(
                type=source.type,
                repository_url=source.repository_url,
                download_url=source.download_url,
                ref=source.ref,
                commit_hash=source.commit_hash,
            ),
            integrity=ManifestIntegrity(
                sha256=integrity.sha256,
                download_size_bytes=integrity.download_size_bytes,
            ),
            installation=ManifestInstallation(
                method=installation.method,
                target_client=installation.target_client,
                steps=validated_steps,
                pre_install_message=installation.pre_install_message,
                post_install_message=installation.post_install_message,
            ),
            permissions=record.permissions,
            risk_summary=risk_summary,
            compatibility=record.compatibility,
            dependencies=record.dependencies or Dependencies(),
        )

    @staticmethod
    def _canonical_https_url(value: str | None) -> str | None:
        if value is None:
            return None
        try:
            url = HTTPS_URL_ADAPTER.validate_python(value)
        except ValidationError:
            return None
        return str(url)

    @classmethod
    def _is_https_url(cls, value: str | None) -> bool:
        return cls._canonical_https_url(value) is not None

    @staticmethod
    def _is_strict_child_path(path: str, root: str) -> bool:
        normalized_path = posixpath.normpath(path)
        normalized_root = posixpath.normpath(root)
        return (
            normalized_path != normalized_root
            and normalized_path.startswith(f"{normalized_root}/")
        )
