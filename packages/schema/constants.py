"""
Trusted Agent Hub — 共享常量定义 (Python)

本文件定义所有枚举值、状态转换规则和常量映射。
API (FastAPI) 和 扫描器 (scanner) 均引用此文件。

版本: v0.1
冻结时间: 第 2 周末
"""

from enum import StrEnum
from typing import Final

# Integrity hashes are produced for different byte domains.  Keep the scope
# explicit so a bounded scan-tree digest cannot be confused with the archive
# hash used by the installation manifest.
HASH_SCOPE_SCANNED_SOURCE: Final[str] = "scanned_source"
HASH_SCOPE_ARTIFACT_ARCHIVE: Final[str] = "artifact_archive"

# ============================================================
# 能力包类型
# ============================================================
PACKAGE_TYPES: Final[tuple[str, ...]] = (
    "skill",
    "mcp_server",
    "plugin",
    "subagent",
    "command",
    "prompt",
)

PACKAGE_TYPE_LABELS: Final[dict[str, str]] = {
    "skill": "Skill",
    "mcp_server": "MCP Server",
    "plugin": "Plugin",
    "subagent": "Subagent",
    "command": "Command",
    "prompt": "Prompt",
}


# ============================================================
# 版本状态
# ============================================================
class VersionStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    SCANNING = "scanning"
    ERROR = "error"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"
    YANKED = "yanked"
    RESUBMITTED = "resubmitted"
    CHANGES_REQUESTED = "changes_requested"


VERSION_STATUS_LABELS: Final[dict[str, str]] = {
    "draft": "草稿",
    "submitted": "已提交",
    "scanning": "扫描中",
    "error": "扫描失败",
    "pending_review": "待审核",
    "approved": "已通过",
    "rejected": "已驳回",
    "published": "已发布",
    "yanked": "已下架",
    "resubmitted": "已重新提交",
    "changes_requested": "需修改",
}

# 状态转换规则
STATUS_TRANSITIONS: Final[dict[str, list[str]]] = {
    "draft": ["submitted"],
    "submitted": ["scanning"],
    "scanning": ["pending_review", "error"],
    "error": ["submitted"],
    "pending_review": ["approved", "rejected", "changes_requested"],
    "approved": ["published", "rejected"],
    "rejected": ["resubmitted"],
    "published": ["yanked", "pending_review"],
    "yanked": ["published"],
    "resubmitted": ["scanning"],
    "changes_requested": ["scanning"],
}

PUBLISHABLE_STATUSES: Final[tuple[str, ...]] = ("approved",)
VISIBLE_STATUSES: Final[tuple[str, ...]] = ("published",)
PUBLIC_VISIBLE_STATUSES: Final[tuple[str, ...]] = ("published", "yanked")


# ============================================================
# 审核结论
# ============================================================
class ReviewConclusion(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


REVIEW_CONCLUSION_LABELS: Final[dict[str, str]] = {
    "approved": "通过",
    "rejected": "驳回",
    "changes_requested": "要求修改",
}


# ============================================================
# 用户角色
# ============================================================
class UserRole(StrEnum):
    USER = "user"
    SUBMITTER = "submitter"
    REVIEWER = "reviewer"
    ADMIN = "admin"


USER_ROLE_LABELS: Final[dict[str, str]] = {
    "user": "普通用户",
    "submitter": "提交者",
    "reviewer": "审核员",
    "admin": "管理员",
}


# ============================================================
# 扫描发现严重程度
# ============================================================
class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


FINDING_SEVERITY_ORDER: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

FINDING_SEVERITY_LABELS: Final[dict[str, str]] = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


# ============================================================
# 扫描发现分类
# ============================================================
class FindingCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    DANGEROUS_SHELL = "dangerous_shell"
    CREDENTIAL_ACCESS = "credential_access"
    HARDCODED_SECRET = "hardcoded_secret"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    EXCESSIVE_PERMISSION = "excessive_permission"
    NETWORK_ACCESS = "network_access"
    DEPENDENCY_RISK = "dependency_risk"
    SOURCE_INTEGRITY = "source_integrity"
    METADATA_QUALITY = "metadata_quality"
    SUPPLY_CHAIN = "supply_chain"
    OUTPUT_HANDLING = "output_handling"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    MEMORY_POISONING = "memory_poisoning"
    SSRF = "ssrf"
    AGENT_SNOOPING = "agent_snooping"
    TOOL_MISUSE = "tool_misuse"
    MCP_SECURITY = "mcp_security"
    PLUGIN_SECURITY = "plugin_security"
    SUBAGENT_SECURITY = "subagent_security"
    INSTALLATION_SECURITY = "installation_security"


FINDING_CATEGORY_LABELS: Final[dict[str, str]] = {
    "prompt_injection": "提示注入",
    "dangerous_shell": "危险 Shell",
    "credential_access": "凭据访问",
    "hardcoded_secret": "硬编码密钥",
    "remote_code_execution": "远程代码执行",
    "excessive_permission": "过度权限",
    "network_access": "网络访问",
    "dependency_risk": "依赖风险",
    "source_integrity": "来源完整性",
    "metadata_quality": "元数据质量",
    "supply_chain": "供应链风险",
    "output_handling": "输出处理风险",
    "system_prompt_leakage": "系统提示泄露",
    "memory_poisoning": "记忆投毒",
    "ssrf": "SSRF 服务端请求伪造",
    "agent_snooping": "Agent 窥探",
    "tool_misuse": "工具滥用",
    "mcp_security": "MCP安全",
    "plugin_security": "插件安全",
    "subagent_security": "子Agent安全",
    "installation_security": "安装器安全",
}


# ============================================================
# 评分策略：发现类别对应的自动 veto 严重度
# ============================================================
# Values are the severities that make a finding in the category eligible for
# the trust-score dangerous/veto path. An empty set is intentional: the
# category still contributes to score and review signals, but does not by
# itself force an untrusted result.
_VETO_SEVERITIES: Final[frozenset[str]] = frozenset({
    FindingSeverity.CRITICAL.value,
    FindingSeverity.HIGH.value,
})

FINDING_CATEGORY_POLICY: Final[dict[str, frozenset[str]]] = {
    "prompt_injection": _VETO_SEVERITIES,
    "dangerous_shell": _VETO_SEVERITIES,
    "credential_access": _VETO_SEVERITIES,
    "hardcoded_secret": _VETO_SEVERITIES,
    "remote_code_execution": _VETO_SEVERITIES,
    "excessive_permission": _VETO_SEVERITIES,
    "network_access": _VETO_SEVERITIES,
    "dependency_risk": frozenset(),
    "source_integrity": _VETO_SEVERITIES,
    "metadata_quality": frozenset(),
    "supply_chain": _VETO_SEVERITIES,
    "installation_security": _VETO_SEVERITIES,
    "output_handling": _VETO_SEVERITIES,
    "system_prompt_leakage": _VETO_SEVERITIES,
    "memory_poisoning": _VETO_SEVERITIES,
    "ssrf": _VETO_SEVERITIES,
    "agent_snooping": _VETO_SEVERITIES,
    "tool_misuse": _VETO_SEVERITIES,
    "mcp_security": _VETO_SEVERITIES,
    "plugin_security": _VETO_SEVERITIES,
    "subagent_security": _VETO_SEVERITIES,
}


# ============================================================
# 审计操作
# ============================================================
class AuditAction(StrEnum):
    SUBMIT = "submit"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"
    PUBLISH = "publish"
    YANK = "yank"
    UNYANK = "unyank"
    RESUBMIT = "resubmit"


# ============================================================
# 风险标签
# ============================================================
RISK_TAGS: Final[tuple[str, ...]] = (
    "prompt-injection-suspect",
    "dangerous-shell",
    "reads-credentials",
    "hardcoded-secret",
    "remote-code-exec",
    "excessive-filesystem-read",
    "excessive-filesystem-write",
    "network-external",
    "unlocked-dependency",
    "suspicious-dependency",
    "unverified-source",
    "missing-integrity",
    "no-license",
    "incomplete-metadata",
    "undocumented-permission",
    "supply-chain-risk",
    "output-handling-risk",
    "system-prompt-leakage",
    "memory-poisoning",
    "ssrf",
    "agent-snooping",
    "tool-misuse",
)

RISK_TAG_LEVELS: Final[dict[str, str]] = {
    "prompt-injection-suspect": "high",
    "dangerous-shell": "high",
    "reads-credentials": "high",
    "hardcoded-secret": "high",
    "remote-code-exec": "high",
    "excessive-filesystem-read": "medium",
    "excessive-filesystem-write": "medium",
    "network-external": "medium",
    "unlocked-dependency": "medium",
    "suspicious-dependency": "medium",
    "unverified-source": "medium",
    "missing-integrity": "low",
    "no-license": "low",
    "incomplete-metadata": "low",
    "undocumented-permission": "low",
    "supply-chain-risk": "high",
    "output-handling-risk": "medium",
    "system-prompt-leakage": "high",
    "memory-poisoning": "high",
    "ssrf": "high",
    "agent-snooping": "high",
    "tool-misuse": "medium",
}


# ============================================================
# 客户端兼容性
# ============================================================
CLIENTS: Final[tuple[str, ...]] = (
    "claude-code",
    "claude-code-plugin",
    "claude-ai",
    "cursor",
    "vscode",
    "mcp-client-generic",
    "openai-agents",
    "github-copilot",
    "windsurf",
    "cline",
)

CLIENT_LABELS: Final[dict[str, str]] = {
    "claude-code": "Claude Code",
    "claude-code-plugin": "Claude Code 插件",
    "claude-ai": "claude.ai",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "mcp-client-generic": "通用 MCP 客户端",
    "openai-agents": "OpenAI Agents SDK",
    "github-copilot": "GitHub Copilot",
    "windsurf": "Windsurf",
    "cline": "Cline",
}


# 包类型允许安装到的客户端。
# 详情页的安装目标选择与后端校验都以该映射为唯一依据。
PACKAGE_TYPE_INSTALL_CLIENTS: Final[dict[str, tuple[str, ...]]] = {
    "skill": ("claude-code", "cursor"),
    "mcp_server": ("claude-code", "cursor"),
    "plugin": ("claude-code-plugin",),
    "subagent": ("claude-code",),
    "command": ("claude-code",),
    "prompt": ("claude-code",),
}


# ============================================================
# 安装方式
# ============================================================
INSTALL_METHODS: Final[tuple[str, ...]] = (
    "copy_directory",
    "npm_install",
    "pip_install",
    "docker_run",
    "manual_steps",
)


# ============================================================
# 风险等级（安装建议）
# ============================================================
class RiskLevel(StrEnum):
    TRUSTED = "trusted"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    UNTRUSTED = "untrusted"


class InstallRecommendation(StrEnum):
    SAFE = "safe"
    REVIEW_RECOMMENDED = "review_recommended"
    CAUTION = "caution"
    NOT_RECOMMENDED = "not_recommended"
    BLOCKED = "blocked"


# ============================================================
# 信任评分等级
# ============================================================
GRADES: Final[list[str]] = ["A", "B", "C", "D", "E"]

# effective_grade → risk_level (唯一映射源)
GRADE_TO_RISK_LEVEL: Final[dict[str, str]] = {
    "A": "trusted",
    "B": "low_risk",
    "C": "medium_risk",
    "D": "high_risk",
    "E": "untrusted",
}

# effective_grade → install_recommendation (唯一映射源)
GRADE_TO_RECOMMENDATION: Final[dict[str, str]] = {
    "A": "safe",
    "B": "review_recommended",
    "C": "caution",
    "D": "not_recommended",
    "E": "blocked",
}


# ============================================================
# 角色权限矩阵
# ============================================================
ROLE_PERMISSIONS: Final[dict] = {
    "user": {
        "browse": True,
        "submit": False,
        "review": False,
        "publish": False,
        "yank": False,
        "view_audit_log": False,
        "manage_users": False,
    },
    "submitter": {
        "browse": True,
        "submit": True,
        "review": False,
        "publish": False,
        "yank": False,
        "view_audit_log": False,
        "manage_users": False,
    },
    "reviewer": {
        "browse": True,
        "submit": False,
        "review": True,
        "publish": False,
        "yank": False,
        "view_audit_log": False,
        "manage_users": False,
    },
    "admin": {
        "browse": True,
        "submit": True,
        "review": True,
        "publish": True,
        "yank": True,
        "view_audit_log": True,
        "manage_users": True,
    },
}


# ============================================================
# Helper 函数
# ============================================================
def can_transition(from_status: str, to_status: str) -> bool:
    """检查状态是否可以转换"""
    allowed = STATUS_TRANSITIONS.get(from_status, [])
    return to_status in allowed


def is_status_visible_to_public(status: str) -> bool:
    """检查状态是否对普通用户可见"""
    return status in PUBLIC_VISIBLE_STATUSES


def get_risk_tag_level(tag: str) -> str | None:
    """获取风险标签的等级"""
    return RISK_TAG_LEVELS.get(tag)
