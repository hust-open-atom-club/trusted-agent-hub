"""Canonical package and version models for the Consumer API."""

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_serializer

from .common import Owner, PackageType, Page, SafeSourceSubdirectory, StrictContractModel

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
    commit_hash: str | None = None
    verified_owner: bool = False
    stars: int | None = None
    last_commit_at: str | None = None
    download_url: str | None = None
    subdirectory: SafeSourceSubdirectory | None = None


class Integrity(StrictContractModel):
    sha256: str
    hash_scope: Literal["scanned_source", "artifact_archive"] | None = None
    is_complete: bool | None = None
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
    package: str | None = None
    targets: list[InstallTarget] | None = None
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
    mcp_servers: list[dict[str, object]] | None = None


class EntryPoints(StrictContractModel):
    main: str | None = None
    config: str | None = None
    scripts: list[str] | None = None


class TrustScoreDimension(StrictContractModel):
    model_config = ConfigDict(extra="allow")  # allow legacy "score" field in DB
    weight: float
    details: dict[str, object] | None = None

    @model_serializer(mode="wrap")
    def _drop_legacy_numeric_score(self, handler):
        """legacy 'score' 字段仅用于兼容历史数据，不进入 public 输出。"""
        data = handler(self)
        if isinstance(data, dict):
            data.pop("score", None)
        return data


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
    requires_confirmation: bool = False
    auto_grade: Grade | None = None
    manual_grade: Grade | None = None
    effective_grade: Grade | None = None


class TrustScore(StrictContractModel):
    model_config = ConfigDict(extra="allow")  # allow legacy "score" field in DB
    model_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    model_version: str | None = None
    dimensions: dict[str, TrustScoreDimension] | None = None
    explanations: list[TrustScoreExplanation] | None = None
    risk_summary: RiskSummary | None = None
    calculated_at: str | None = None

    @model_serializer(mode="wrap")
    def _drop_legacy_numeric_score(self, handler):
        """legacy 'score' 字段仅用于兼容历史数据，不进入 public 输出。"""
        data = handler(self)
        if isinstance(data, dict):
            data.pop("score", None)
        return data


class FindingOccurrence(StrictContractModel):
    file: str
    line: int | None = Field(default=None, ge=1)


class FindingOccurrences(StrictContractModel):
    count: int = Field(ge=1)
    items: list[FindingOccurrence] = Field(default_factory=list)
    truncated: bool = False


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
    downgraded: str | None = None
    remediation: str | None = None
    cwe_id: str | None = None
    requires_confirmation: bool | None = None
    occurrences: FindingOccurrences | None = None


class PermissionEvidence(StrictContractModel):
    capability: str
    status: Literal["observed", "declared", "conditional", "mentioned", "inferred"]
    confidence: float = Field(ge=0, le=1)
    source: Literal["code", "manifest", "frontmatter", "docs"]
    file: str | None = None
    evidence: str = Field(max_length=240)


class LLMReviewLabelsSummary(StrictContractModel):
    suspected_malicious: int = Field(default=0, ge=0)
    suspected_negligent: int = Field(default=0, ge=0)
    likely_benign: int = Field(default=0, ge=0)
    uncertain: int = Field(default=0, ge=0)
    unavailable: int = Field(default=0, ge=0)


class LLMReview(StrictContractModel):
    triggered: bool = False
    findings_reviewed: int = 0
    findings_skipped: int = 0
    findings_pending: int = 0
    status: Literal[
        "not_triggered",
        "not_required",
        "not_configured",
        "completed",
        "call_failed",
    ] | None = None
    attempts: int = 0
    labels: dict[str, LLM_LABEL] = Field(default_factory=dict)
    labels_summary: LLMReviewLabelsSummary | None = None
    error: str | None = None
    fallback: str | None = None


class ScanStatus(StrictContractModel):
    state: Literal["complete", "partial", "failed"]
    conclusion: Literal["risks_found", "no_risks_found", "inconclusive"]
    complete: bool
    reasons: list[str] = Field(default_factory=list)


class ScanLimitsConfigured(StrictContractModel):
    max_file_bytes: int | None = None
    max_total_bytes: int | None = None
    max_files: int | None = None
    max_depth: int | None = None
    max_findings: int | None = None
    max_osv_queries: int | None = None
    max_skipped_samples: int | None = None


class ScanLimitsObserved(StrictContractModel):
    discovered_files: int | None = None
    discovered_count: int | None = None
    discovered_at_least: bool | None = None
    analyzed_files: int | None = None
    discovered_bytes: int | None = None
    analyzed_bytes: int | None = None


class ScanLimitsSkipped(StrictContractModel):
    count: int = 0
    by_reason: dict[str, int] = Field(default_factory=dict)
    samples: list[str] = Field(default_factory=list)


class ScanLimits(StrictContractModel):
    configured: ScanLimitsConfigured | None = None
    observed: ScanLimitsObserved | None = None
    exceeded: list[str] = Field(default_factory=list)
    skipped: ScanLimitsSkipped | None = None


class RuleExecutionResult(StrictContractModel):
    rule_id: str
    status: str
    duration_ms: int = 0
    findings_added: int = 0
    error_type: str | None = None
    error_message: str | None = None


class RuleExecution(StrictContractModel):
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[RuleExecutionResult] = Field(default_factory=list)


class ScannerError(StrictContractModel):
    phase: str
    rule_id: str | None = None
    error_type: str
    message: str
    recoverable: bool


class ScanSummary(StrictContractModel):
    total: int = 0
    effective_total: int = 0
    occurrences_total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    pass_rate: float | None = None


class CapabilityGraphSummary(StrictContractModel):
    declared: list[str] = Field(default_factory=list)
    observed: list[str] = Field(default_factory=list)
    undeclared_observed: list[str] = Field(default_factory=list)
    edge_count: int = 0


class StructuralAnalysis(StrictContractModel):
    python_files: int = 0
    javascript_files: int = 0
    shell_files: int = 0
    structured_documents: int = 0
    parse_errors: int = 0
    capability_graph: CapabilityGraphSummary = Field(default_factory=CapabilityGraphSummary)


class ProvenanceSource(StrictContractModel):
    """Server-established source facts recorded alongside a scan report."""

    type: str | None = None
    repository_url: str | None = None
    owner: str | None = None
    repo: str | None = None
    ref_type: str | None = None
    ref: str | None = None
    commit_hash: str | None = Field(
        default=None,
        pattern=r"^(?:[a-f0-9]{40})?$",
    )
    verified_owner: bool = False
    subdirectory: str | None = None


class ProvenanceIntegrity(StrictContractModel):
    """Server-computed content integrity facts."""

    sha256: str | None = Field(
        default=None,
        pattern=r"^(?:[a-f0-9]{64})?$",
    )
    hash_scope: Literal["scanned_source"] | None = None
    is_complete: bool | None = None


class ProvenanceVerification(StrictContractModel):
    """Independent verification results for provenance claims."""

    repository: bool = False
    owner: bool
    signature: bool
    attestation: bool
    sbom: bool


class AcquisitionFacts(StrictContractModel):
    source: ProvenanceSource
    integrity: ProvenanceIntegrity
    verification: ProvenanceVerification
    acquisition_method: str


class PackageProvenanceClaims(StrictContractModel):
    """Redacted package-authored provenance claims retained for audit."""

    source: dict[str, object] = Field(default_factory=dict)
    integrity: dict[str, object] = Field(default_factory=dict)


class ScanProvenance(StrictContractModel):
    acquisition_facts: AcquisitionFacts
    package_claims: PackageProvenanceClaims


class ScanReport(StrictContractModel):
    """Consumer-facing projection of the scanner report.

    Scanner-internal source contents and implementation details are not part
    of this model; completeness, limits, rule execution and structural
    analysis are explicitly declared so extra=forbid catches contract drift.
    """

    scan_id: str
    package_name: str | None = None
    version: str | None = None
    scanner_version: str
    duration_ms: int | None = None
    scan_status: ScanStatus | None = None
    scan_limits: ScanLimits | None = None
    rule_execution: RuleExecution | None = None
    scanner_errors: list[ScannerError] = Field(default_factory=list)
    source_snapshot_id: str | None = None
    source_snapshot_sha256: str | None = None
    source_snapshot_created_at: int | None = None
    source_snapshot_expires_at: int | None = None
    summary: ScanSummary | None = None
    findings: list[ScanFinding] | None = None
    permission_evidence: list[PermissionEvidence] = Field(default_factory=list)
    metadata_validation: dict[str, object] | None = None
    structure_check: dict[str, object] | None = None
    dependency_check: dict[str, object] | None = None
    dependency_scan: dict[str, object] | None = None
    structural_analysis: StructuralAnalysis | None = None
    llm_review: LLMReview | None = None
    scanned_at: str | None = None
    provenance: ScanProvenance | None = None


class FeedbackCounts(StrictContractModel):
    """用户反馈等级计数（positive / neutral / negative）。"""

    positive: int = 0
    neutral: int = 0
    negative: int = 0


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
    feedback_counts: FeedbackCounts | None = None
    created_at: str | None = None
    updated_at: str | None = None


class VersionSummary(StrictContractModel):
    id: str
    version: str
    status: str
    submitted_at: str | None = None
    created_at: str | None = None


class TrustHistoryPoint(StrictContractModel):
    """One point in a package's version-level trust-score history."""

    version: str
    score: float | None = None
    grade: Grade | None = None
    calculated_at: str | None = None


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
    scan_file_contents: dict[str, str] | None = None
    auto_grade: Grade | None = None
    manual_grade: Grade | None = None
    effective_grade: Grade | None = None
    manual_grade_by: str | None = None
    manual_grade_reason: str | None = None
    manual_grade_at: str | None = None


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
