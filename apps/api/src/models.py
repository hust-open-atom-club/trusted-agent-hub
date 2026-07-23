"""Pydantic models for API responses.

These models define the shape of data returned by the Consumer-side (分发侧)
endpoints.  They are derived from the shared agent-package schema and adapted
for API presentation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Any, Optional, Generic, TypeVar

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared sub-models
# ---------------------------------------------------------------------------


class Owner(BaseModel):
    """Package owner / author summary."""

    id: str
    username: str
    display_name: str
    role: str


class Author(BaseModel):
    """Detailed author information (from version detail)."""

    name: str
    email: str
    url: Optional[str] = None


class Source(BaseModel):
    """Source repository reference."""

    type: str
    repository_url: str
    owner: Optional[str] = None
    repo: Optional[str] = None
    ref_type: Optional[str] = None
    ref: str
    commit_hash: str
    verified_owner: bool = False
    stars: Optional[int] = None
    last_commit_at: Optional[str] = None


class Integrity(BaseModel):
    """Integrity / verification information."""

    sha256: str
    signature: Optional[str] = None
    attestation_url: Optional[str] = None
    sbom_url: Optional[str] = None


class FilesystemPermissions(BaseModel):
    read: List[str] = Field(default_factory=list)
    write: List[str] = Field(default_factory=list)
    delete: bool = False


class ShellPermissions(BaseModel):
    allowed: bool = False
    commands: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class NetworkPermissions(BaseModel):
    allowed: bool = False
    domains: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class EnvironmentPermissions(BaseModel):
    read: List[str] = Field(default_factory=list)
    write: List[str] = Field(default_factory=list)


class CredentialsPermissions(BaseModel):
    access: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class Permissions(BaseModel):
    filesystem: Optional[FilesystemPermissions] = None
    shell: Optional[ShellPermissions] = None
    network: Optional[NetworkPermissions] = None
    environment: Optional[EnvironmentPermissions] = None
    credentials: Optional[CredentialsPermissions] = None
    database: Optional[Dict[str, Any]] = None
    browser: Optional[Dict[str, Any]] = None
    external_services: Optional[List[Any]] = None


class InstallTarget(BaseModel):
    client: str
    destination: str
    config_template: Optional[str] = None


class Installation(BaseModel):
    method: str
    targets: List[InstallTarget] = Field(default_factory=list)
    command: Optional[str] = None
    pre_install_message: Optional[str] = None
    post_install_message: Optional[str] = None


class Dependencies(BaseModel):
    npm: Optional[List[Dict[str, str]]] = None
    pip: Optional[List[Dict[str, str]]] = None
    system: Optional[List[str]] = None
    docker: Optional[List[Dict[str, str]]] = None
    mcp_servers: Optional[List[Dict[str, str]]] = None


class EntryPoints(BaseModel):
    main: Optional[str] = None
    config: Optional[str] = None
    scripts: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Trust score
# ---------------------------------------------------------------------------


class TrustScoreDimension(BaseModel):
    weight: float
    details: Optional[Dict[str, Any]] = None


class TrustScoreExplanation(BaseModel):
    dimension: str
    message: str
    deduction: Optional[float] = None
    evidence: Optional[str] = None


class RiskSummary(BaseModel):
    level: str
    grade: Optional[str] = None
    top_risks: List[str] = Field(default_factory=list)
    install_recommendation: str


class TrustScore(BaseModel):
    model_version: Optional[str] = None
    dimensions: Optional[Dict[str, TrustScoreDimension]] = None
    explanations: Optional[List[TrustScoreExplanation]] = None
    risk_summary: Optional[RiskSummary] = None
    calculated_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Scan report
# ---------------------------------------------------------------------------


class ScanFinding(BaseModel):
    id: str
    rule_id: Optional[str] = None
    severity: str
    category: str
    title: str
    description: str
    location: Optional[Dict[str, Any]] = None
    evidence: Optional[str] = None
    llm_label: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None


class ScanReport(BaseModel):
    scan_id: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    scanner_version: str
    duration_ms: Optional[int] = None
    summary: Optional[Dict[str, Any]] = None
    findings: Optional[List[ScanFinding]] = None
    metadata_validation: Optional[Dict[str, Any]] = None
    structure_check: Optional[Dict[str, Any]] = None
    dependency_check: Optional[Dict[str, Any]] = None
    llm_review: Optional[Dict[str, Any]] = None
    scanned_at: Optional[str] = None


# ---------------------------------------------------------------------------
# API response models
# ---------------------------------------------------------------------------


class PackageSummary(BaseModel):
    """Lightweight package row for list views."""

    id: str
    name: str
    description: str
    type: str
    license: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    category: Optional[str] = None
    homepage: Optional[str] = None
    icon_url: Optional[str] = None
    owner: Optional[Owner] = None
    latest_version: str
    status: str
    risk_level: Optional[str] = None
    install_count: int = 0
    avg_rating: Optional[float] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PackageDetail(BaseModel):
    """Full package detail including metadata fields."""

    id: str
    name: str
    description: str
    type: str
    license: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    category: Optional[str] = None
    homepage: Optional[str] = None
    icon_url: Optional[str] = None
    owner: Optional[Owner] = None
    latest_version: str
    status: str
    risk_level: Optional[str] = None
    install_count: int = 0
    avg_rating: Optional[float] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class VersionSummary(BaseModel):
    """Summary row for a package version listing."""

    id: str
    version: str
    status: str
    submitted_at: Optional[str] = None
    created_at: Optional[str] = None


class VersionDetail(BaseModel):
    """Full version detail including trust scores, scan report, etc."""

    id: str
    package_id: str
    version: str
    author: Optional[Author] = None
    source: Optional[Source] = None
    integrity: Optional[Integrity] = None
    compatibility: List[str] = Field(default_factory=list)
    permissions: Optional[Permissions] = None
    installation: Optional[Installation] = None
    type_config: Optional[Dict[str, Any]] = None
    dependencies: Optional[Dependencies] = None
    entry_points: Optional[EntryPoints] = None
    status: str
    submitted_at: Optional[str] = None
    published_at: Optional[str] = None
    created_at: Optional[str] = None
    trust_score: Optional[TrustScore] = None
    scan_report: Optional[ScanReport] = None


class InstallManifest(BaseModel):
    """Installation manifest returned to the consumer."""

    package_name: str
    version: str
    method: str
    targets: List[InstallTarget] = Field(default_factory=list)
    command: Optional[str] = None
    dependencies: Optional[Dependencies] = None
    compatibility: List[str] = Field(default_factory=list)
    pre_install_warnings: List[str] = Field(default_factory=list)
    pre_install_message: Optional[str] = None
    post_install_message: Optional[str] = None
    trust_score: Optional[TrustScoreResponse] = None


class TrustScoreResponse(BaseModel):
    """Trust score data returned to the consumer."""

    version_id: str
    level: Optional[str] = None
    grade: Optional[str] = None
    recommendation: Optional[str] = None
    dimensions: Optional[Dict[str, Any]] = None
    explanations: Optional[List[Dict[str, Any]]] = None
    calculated_at: Optional[str] = None


class PackageStats(BaseModel):
    """Install / download statistics for a package."""

    package_name: str
    install_count: int = 0
    avg_rating: Optional[float] = None
    total_versions: int = 0
    latest_version: Optional[str] = None
    status: Optional[str] = None


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list wrapper."""

    items: List[T] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    limit: int = 20
