"""Canonical package and version models for the Consumer API."""

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field

from .common import Owner, PackageType, Page, StrictContractModel

# Valid LLM review labels as defined by scan-report.schema.json
LLM_LABEL = Literal[
    "llm:suspected-malicious",
    "llm:suspected-negligent",
    "llm:likely-benign",
    "llm:uncertain",
    "llm:unavailable",
]


class Author(StrictContractModel):
    name: str
    email: str
    url: str | None = None


class Source(StrictContractModel):
    type: str
    repository_url: str
    owner: str | None = None
    repo: str | None = None
    ref_type: str | None = None
    ref: str
    commit_hash: str
    verified_owner: bool = False
    stars: int | None = None
    last_commit_at: str | None = None
    download_url: str | None = None


class Integrity(StrictContractModel):
    sha256: str
    signature: str | None = None
    attestation_url: str | None = None
    sbom_url: str | None = None
    download_size_bytes: int | None = None


class FilesystemPermissions(StrictContractModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)
    delete: bool = False


class ShellPermissions(StrictContractModel):
    allowed: bool = False
    commands: list[str] = Field(default_factory=list)
    description: str | None = None


class NetworkPermissions(StrictContractModel):
    allowed: bool = False
    domains: list[str] = Field(default_factory=list)
    description: str | None = None


class EnvironmentPermissions(StrictContractModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)


class CredentialsPermissions(StrictContractModel):
    access: list[str] = Field(default_factory=list)
    description: str | None = None


class Permissions(StrictContractModel):
    filesystem: FilesystemPermissions | None = None
    shell: ShellPermissions | None = None
    network: NetworkPermissions | None = None
    environment: EnvironmentPermissions | None = None
    credentials: CredentialsPermissions | None = None
    database: dict[str, object] | None = None
    browser: dict[str, object] | None = None
    external_services: list[object] | None = None


class InstallTarget(StrictContractModel):
    client: str
    destination: str
    config_template: str | None = None


class InstallationStep(StrictContractModel):
    """An action-specific installation step with extensible parameters."""

    model_config = ConfigDict(extra="allow")

    action: str


class Installation(StrictContractModel):
    method: str
    targets: list[InstallTarget] = Field(default_factory=list)
    steps: list[InstallationStep] = Field(default_factory=list)
    target_client: str | None = None
    command: str | None = None
    pre_install_message: str | None = None
    post_install_message: str | None = None


class Dependencies(StrictContractModel):
    npm: list[dict[str, str]] | None = None
    pip: list[dict[str, str]] | None = None
    system: list[str] | None = None
    docker: list[dict[str, str]] | None = None
    mcp_servers: list[dict[str, str]] | None = None


class EntryPoints(StrictContractModel):
    main: str | None = None
    config: str | None = None
    scripts: list[str] | None = None


class TrustScoreDimension(StrictContractModel):
    model_config = ConfigDict(extra="ignore")  # accept but do not expose legacy DB fields
    weight: float
    details: dict[str, object] | None = None


class TrustScoreExplanation(StrictContractModel):
    dimension: str
    message: str
    deduction: float | None = None
    evidence: str | None = None


class Grade(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"


class RiskSummary(StrictContractModel):
    level: str
    grade: Grade | None = None
    top_risks: list[str] = Field(default_factory=list)
    install_recommendation: str


class TrustScore(StrictContractModel):
    model_config = ConfigDict(extra="ignore")  # accept but do not expose legacy DB fields
    model_version: str | None = None
    dimensions: dict[str, TrustScoreDimension] | None = None
    explanations: list[TrustScoreExplanation] | None = None
    risk_summary: RiskSummary | None = None
    calculated_at: str | None = None


class ScanFinding(StrictContractModel):
    id: str
    rule_id: str | None = None
    severity: str
    category: str
    title: str
    description: str
    location: dict[str, object] | None = None
    evidence: str | None = None
    llm_label: LLM_LABEL | None = None
    remediation: str | None = None
    cwe_id: str | None = None


class LLMReviewLabelsSummary(StrictContractModel):
    suspected_malicious: int = Field(default=0, ge=0)
    suspected_negligent: int = Field(default=0, ge=0)
    likely_benign: int = Field(default=0, ge=0)
    uncertain: int = Field(default=0, ge=0)
    unavailable: int = Field(default=0, ge=0)


class LLMReview(StrictContractModel):
    triggered: bool = False
    findings_reviewed: int = 0
    labels_summary: LLMReviewLabelsSummary | None = None
    error: str | None = None
    fallback: str | None = None


class ScanReport(StrictContractModel):
    scan_id: str
    package_name: str | None = None
    version: str | None = None
    scanner_version: str
    duration_ms: int | None = None
    summary: dict[str, object] | None = None
    findings: list[ScanFinding] | None = None
    metadata_validation: dict[str, object] | None = None
    structure_check: dict[str, object] | None = None
    dependency_check: dict[str, object] | None = None
    llm_review: LLMReview | None = None
    scanned_at: str | None = None


class PackageSummary(StrictContractModel):
    id: str
    name: str
    description: str
    type: PackageType
    license: str | None = None
    keywords: list[str] = Field(default_factory=list)
    category: str | None = None
    homepage: str | None = None
    icon_url: str | None = None
    owner: Owner | None = None
    latest_version: str
    status: str
    risk_level: str | None = None
    grade: Grade | None = None
    install_count: int = 0
    avg_rating: float | None = None
    created_at: str | None = None
    updated_at: str | None = None


class VersionSummary(StrictContractModel):
    id: str
    version: str
    status: str
    submitted_at: str | None = None
    created_at: str | None = None


class VersionDetail(StrictContractModel):
    id: str
    package_id: str
    version: str
    status: str
    author: Author | None = None
    source: Source | None = None
    integrity: Integrity | None = None
    compatibility: list[str] = Field(default_factory=list)
    permissions: Permissions | None = None
    installation: Installation | None = None
    type_config: dict[str, object] | None = None
    dependencies: Dependencies | None = None
    entry_points: EntryPoints | None = None
    submitted_at: str | None = None
    published_at: str | None = None
    created_at: str | None = None
    trust_score: TrustScore | None = None
    scan_report: ScanReport | None = None


class PackageDetail(PackageSummary):
    latest_version_detail: VersionSummary


class PackagePage(Page[PackageSummary]):
    pass


class PackageStats(StrictContractModel):
    package_name: str
    install_count: int
    avg_rating: float | None
    total_versions: int
    latest_version: str
    status: str
