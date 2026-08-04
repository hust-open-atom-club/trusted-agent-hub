"""Safe Install Manifest v1.0 construction service."""

import posixpath
import re

from pydantic import TypeAdapter, ValidationError

from schema.constants import (
    GRADE_TO_RECOMMENDATION,
    GRADE_TO_RISK_LEVEL,
    PACKAGE_TYPE_INSTALL_CLIENTS,
)
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
from src.models.packages import Dependencies, Grade, RiskSummary
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
    "claude-code-plugin": "~/.claude/plugins/",
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
        installation = record.installation
        method = installation.method if installation is not None else None

        if source is None:
            invalid_fields.append("source.repository_url")
        else:
            if source.type not in SUPPORTED_SOURCE_TYPES:
                invalid_fields.append("source.type")
            if not self._is_https_url(source.repository_url):
                invalid_fields.append("source.repository_url")
            if not source.ref:
                invalid_fields.append("source.ref")

        integrity = record.integrity

        allowed_clients = PACKAGE_TYPE_INSTALL_CLIENTS.get(package.type, ())
        if client not in allowed_clients or client not in record.compatibility:
            invalid_fields.append("compatibility")

        # 目标客户端解析：同一个包可通过 installation.targets 显式声明
        # 多个客户端的安装目标（client -> destination）。声明了 targets 时
        # 必须存在匹配请求 client 的条目；未声明时保持原契约
        # （installation.target_client 必须等于请求客户端）。
        target_dest: str | None = None
        targets = (installation.targets or []) if installation is not None else []
        steps_client = installation.target_client if installation is not None else ""
        for target in targets:
            if target.client == client:
                target_dest = target.destination
                steps_client = client
                break

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
                # 按请求客户端覆盖 copy destination（支持多客户端安装）
                for step in validated_steps:
                    if step.root.action == "copy" and target_dest is not None:
                        step.root.destination = target_dest
                if not self._validate_steps_for_method(
                    method,
                    validated_steps,
                    source,
                    integrity,
                    steps_client,
                ):
                    invalid_fields.append("installation.steps")
        if installation is None:
            invalid_fields.append("installation.target_client")
        elif targets:
            if target_dest is None:
                invalid_fields.append("installation.target_client")
        elif installation.target_client != client:
            invalid_fields.append("installation.target_client")
        if method not in SUPPORTED_INSTALL_METHODS:
            invalid_fields.append("installation.method")

        # 目录复制必须携带可下载制品与完整性摘要；npm/pip/docker/manual
        # 由各自 step 内容承载，不强制 ZIP 制品字段。
        if method == "copy_directory":
            if source is None or not self._is_https_url(source.download_url):
                invalid_fields.append("source.download_url")
            if source is None or not COMMIT_PATTERN.fullmatch(
                source.commit_hash or ""
            ):
                invalid_fields.append("source.commit_hash")
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

        if record.permissions is None:
            invalid_fields.append("permissions")

        # ── Grade resolution ──────────────────────────────────────
        auto_grade: Grade | None = None
        original_risk_summary = (
            record.trust_score.risk_summary
            if record.trust_score is not None
            else None
        )
        if original_risk_summary is not None:
            auto_grade = original_risk_summary.grade

        effective_grade: Grade | None = record.manual_grade or auto_grade

        if effective_grade is None:
            invalid_fields.append("risk_summary.grade")

        # Only block on effective_grade == E
        if effective_grade == "E":
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
        assert installation is not None
        assert validated_steps is not None
        assert record.permissions is not None
        assert effective_grade is not None

        # Build final risk summary from effective_grade
        recommendation = GRADE_TO_RECOMMENDATION.get(
            str(effective_grade), "caution"
        )
        level = GRADE_TO_RISK_LEVEL.get(
            str(effective_grade), "medium_risk"
        )
        final_risk_summary = RiskSummary(
            level=level,
            grade=effective_grade,
            top_risks=(
                original_risk_summary.top_risks
                if original_risk_summary is not None
                else []
            ),
            install_recommendation=recommendation,
            auto_grade=auto_grade,
            manual_grade=record.manual_grade,
            effective_grade=effective_grade,
        )

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
            integrity=(
                ManifestIntegrity(
                    sha256=integrity.sha256,
                    download_size_bytes=integrity.download_size_bytes,
                )
                if integrity is not None
                else None
            ),
            installation=ManifestInstallation(
                method=installation.method,
                target_client=client,
                steps=validated_steps,
                pre_install_message=installation.pre_install_message,
                post_install_message=installation.post_install_message,
            ),
            permissions=record.permissions,
            risk_summary=final_risk_summary,
            compatibility=record.compatibility,
            dependencies=record.dependencies or Dependencies(),
        )

    @staticmethod
    def _validate_steps_for_method(
        method: str | None,
        steps: list[ManifestInstallationStep],
        source,
        integrity,
        target_client: str,
    ) -> bool:
        """按安装方式校验步骤序列与制品字段的一致性。"""
        actions = [step.root.action for step in steps]

        if method == "copy_directory":
            if actions != ["download", "verify", "extract", "copy"]:
                return False
            download_step = steps[0].root
            verify_step = steps[1].root
            copy_step = steps[3].root
            if (
                source is None
                or integrity is None
                or InstallManifestService._canonical_https_url(
                    str(download_step.url)
                )
                != InstallManifestService._canonical_https_url(
                    source.download_url
                )
                or verify_step.algorithm != "sha256"
                or verify_step.checksum != integrity.sha256
            ):
                return False
            client_root = CLIENT_INSTALL_ROOTS.get(target_client)
            return (
                client_root is not None
                and InstallManifestService._is_strict_child_path(
                    copy_step.destination,
                    client_root,
                )
            )

        if method == "npm_install":
            return (
                len(steps) == 1
                and steps[0].root.action == "npm_install"
            )

        if method == "pip_install":
            return (
                len(steps) == 1
                and steps[0].root.action == "pip_install"
            )

        if method == "docker_run":
            return (
                len(steps) == 1
                and steps[0].root.action == "docker_run"
            )

        if method == "manual_steps":
            return (
                len(steps) == 1
                and steps[0].root.action == "manual_steps"
            )

        return False

    _LOCALHOST_ORIGINS = {"localhost", "127.0.0.1", "[::1]"}

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
        if value is None:
            return False
        # Accept HTTPS URLs
        if cls._canonical_https_url(value) is not None:
            return True
        # Allow localhost HTTP for development
        try:
            from urllib.parse import urlparse
            parsed = urlparse(value)
            return parsed.scheme == "http" and parsed.hostname in cls._LOCALHOST_ORIGINS
        except Exception:
            return False

    @staticmethod
    def _is_strict_child_path(path: str, root: str) -> bool:
        normalized_path = posixpath.normpath(path)
        normalized_root = posixpath.normpath(root)
        return (
            normalized_path != normalized_root
            and normalized_path.startswith(f"{normalized_root}/")
        )
