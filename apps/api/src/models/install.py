"""Strict Install Manifest v1.0 Consumer API models."""

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, HttpUrl, RootModel

from .common import PackageType, StrictContractModel
from .packages import (
    Dependencies,
    Permissions,
    RiskSummary,
)


SEMANTIC_VERSION_PATTERN = (
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _require_https(url: HttpUrl) -> HttpUrl:
    if url.scheme != "https":
        raise ValueError("URL must use HTTPS")
    return url


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("value must contain a non-whitespace character")
    return value


def _require_safe_install_path(value: str) -> str:
    if "\x00" in value or "\\" in value:
        raise ValueError("install path contains an unsafe character")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("install path must not be absolute")
    if ".." in value.split("/"):
        raise ValueError("install path must not traverse parent directories")
    return value


HttpsUrl = Annotated[HttpUrl, AfterValidator(_require_https)]
NonBlankString = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_require_non_blank),
]
SafeInstallPath = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_require_safe_install_path),
]
SourceType = Literal["github", "npm", "pypi", "docker", "local_upload"]
InstallMethod = Literal[
    "copy_directory",
    "npm_install",
    "pip_install",
    "docker_run",
    "manual_steps",
]


class InstallManifestQuery(StrictContractModel):
    """Exact accepted query parameters for install manifest requests."""

    client: NonBlankString
    version: str | None = Field(
        default=None,
        pattern=SEMANTIC_VERSION_PATTERN,
    )


class ManifestSource(StrictContractModel):
    type: SourceType
    repository_url: HttpsUrl
    download_url: HttpsUrl
    ref: str = Field(min_length=1)
    commit_hash: str = Field(pattern=r"^[a-f0-9]{40}$")


class ManifestIntegrity(StrictContractModel):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    download_size_bytes: int = Field(ge=0)


class DownloadInstallationStep(StrictContractModel):
    action: Literal["download"]
    url: HttpsUrl


class VerifyInstallationStep(StrictContractModel):
    action: Literal["verify"]
    algorithm: Literal["sha256"]
    checksum: str = Field(pattern=r"^[a-f0-9]{64}$")


class ExtractInstallationStep(StrictContractModel):
    action: Literal["extract"]
    archive: SafeInstallPath


class CopyInstallationStep(StrictContractModel):
    action: Literal["copy"]
    source: SafeInstallPath
    destination: SafeInstallPath


StepVariant = Annotated[
    DownloadInstallationStep
    | VerifyInstallationStep
    | ExtractInstallationStep
    | CopyInstallationStep,
    Field(discriminator="action"),
]


class ManifestInstallationStep(RootModel[StepVariant]):
    """A closed, discriminated Install Manifest v1.0 step."""


class ManifestInstallation(StrictContractModel):
    method: InstallMethod
    target_client: str
    steps: list[ManifestInstallationStep] = Field(min_length=1)
    pre_install_message: str | None = None
    post_install_message: str | None = None


class InstallManifest(StrictContractModel):
    manifest_version: Literal["1.0"] = "1.0"
    name: str
    version: str = Field(pattern=SEMANTIC_VERSION_PATTERN)
    type: PackageType
    description: str
    source: ManifestSource
    integrity: ManifestIntegrity
    installation: ManifestInstallation
    permissions: Permissions
    risk_summary: RiskSummary
    compatibility: list[str]
    dependencies: Dependencies
