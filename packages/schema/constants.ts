/**
 * Trusted Agent Hub — 共享常量定义 (TypeScript)
 *
 * 本文件定义所有枚举值、状态转换规则和常量映射。
 * Web (Next.js) 和 CLI (Commander) 均引用此文件。
 *
 * 版本: v0.1
 * 冻结时间: 第 2 周末
 */

// ============================================================
// 能力包类型
// ============================================================
export const PACKAGE_TYPES = [
  'skill',
  'mcp_server',
  'plugin',
  'subagent',
  'command',
  'prompt',
] as const;
export type PackageType = (typeof PACKAGE_TYPES)[number];

export const PACKAGE_TYPE_LABELS: Record<PackageType, string> = {
  skill: 'Skill',
  mcp_server: 'MCP Server',
  plugin: 'Plugin',
  subagent: 'Subagent',
  command: 'Command',
  prompt: 'Prompt',
};

// ============================================================
// 版本状态
// ============================================================
export const VERSION_STATUSES = [
  'draft',
  'submitted',
  'scanning',
  'error',
  'pending_review',
  'approved',
  'rejected',
  'published',
  'yanked',
  'resubmitted',
] as const;
export type VersionStatus = (typeof VERSION_STATUSES)[number];

export const VERSION_STATUS_LABELS: Record<VersionStatus, string> = {
  draft: '草稿',
  submitted: '已提交',
  scanning: '扫描中',
  error: '扫描失败',
  pending_review: '待审核',
  approved: '已通过',
  rejected: '已驳回',
  published: '已发布',
  yanked: '已下架',
  resubmitted: '已重新提交',
};

/**
 * 状态转换规则：从某个状态可以迁移到哪些状态
 */
export const STATUS_TRANSITIONS: Record<VersionStatus, VersionStatus[]> = {
  draft: ['submitted'],
  submitted: ['scanning'],
  scanning: ['pending_review', 'error'],
  error: ['submitted'],
  pending_review: ['approved', 'rejected'],
  approved: ['published', 'rejected'],
  rejected: ['resubmitted'],
  published: ['yanked'],
  yanked: ['published'],
  resubmitted: ['scanning'],
};

/**
 * 哪些状态下允许发布
 */
export const PUBLISHABLE_STATUSES: VersionStatus[] = ['approved'];

/**
 * 哪些状态表示"活跃"（在 Hub 上可见）
 */
export const VISIBLE_STATUSES: VersionStatus[] = ['published'];

/**
 * 公开可查询的状态（普通用户可见的状态）
 */
export const PUBLIC_VISIBLE_STATUSES: VersionStatus[] = [
  'published',
  'yanked',
];

// ============================================================
// 审核结论
// ============================================================
export const REVIEW_CONCLUSIONS = [
  'approved',
  'rejected',
  'changes_requested',
] as const;
export type ReviewConclusion = (typeof REVIEW_CONCLUSIONS)[number];

export const REVIEW_CONCLUSION_LABELS: Record<ReviewConclusion, string> = {
  approved: '通过',
  rejected: '驳回',
  changes_requested: '要求修改',
};

// ============================================================
// 用户角色
// ============================================================
export const USER_ROLES = [
  'user',
  'submitter',
  'reviewer',
  'admin',
] as const;
export type UserRole = (typeof USER_ROLES)[number];

export const USER_ROLE_LABELS: Record<UserRole, string> = {
  user: '普通用户',
  submitter: '提交者',
  reviewer: '审核员',
  admin: '管理员',
};

// ============================================================
// 扫描发现严重程度
// ============================================================
export const FINDING_SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export const FINDING_SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const FINDING_SEVERITY_LABELS: Record<FindingSeverity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

// ============================================================
// 扫描发现分类
// ============================================================
export const FINDING_CATEGORIES = [
  'prompt_injection',
  'dangerous_shell',
  'credential_access',
  'hardcoded_secret',
  'remote_code_execution',
  'excessive_permission',
  'network_access',
  'dependency_risk',
  'source_integrity',
  'metadata_quality',
  'supply_chain',
  'output_handling',
  'system_prompt_leakage',
  'memory_poisoning',
  'ssrf',
  'agent_snooping',
  'tool_misuse',
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const FINDING_CATEGORY_LABELS: Record<FindingCategory, string> = {
  prompt_injection: '提示注入',
  dangerous_shell: '危险 Shell',
  credential_access: '凭据访问',
  hardcoded_secret: '硬编码密钥',
  remote_code_execution: '远程代码执行',
  excessive_permission: '过度权限',
  network_access: '网络访问',
  dependency_risk: '依赖风险',
  source_integrity: '来源完整性',
  metadata_quality: '元数据质量',
  supply_chain: '供应链风险',
  output_handling: '输出处理风险',
  system_prompt_leakage: '系统提示泄露',
  memory_poisoning: '记忆投毒',
  ssrf: 'SSRF 服务端请求伪造',
  agent_snooping: 'Agent 窥探',
  tool_misuse: '工具滥用',
};

// ============================================================
// 审计操作
// ============================================================
export const AUDIT_ACTIONS = [
  'submit',
  'scan_start',
  'scan_complete',
  'approve',
  'reject',
  'request_changes',
  'publish',
  'yank',
  'unyank',
  'resubmit',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const AUDIT_ACTION_LABELS: Record<AuditAction, string> = {
  submit: '提交',
  scan_start: '开始扫描',
  scan_complete: '扫描完成',
  approve: '审核通过',
  reject: '审核驳回',
  request_changes: '要求修改',
  publish: '发布',
  yank: '下架',
  unyank: '恢复',
  resubmit: '重新提交',
};

// ============================================================
// 风险标签
// ============================================================
export const RISK_TAGS = [
  'prompt-injection-suspect',
  'dangerous-shell',
  'reads-credentials',
  'hardcoded-secret',
  'remote-code-exec',
  'excessive-filesystem-read',
  'excessive-filesystem-write',
  'network-external',
  'unlocked-dependency',
  'suspicious-dependency',
  'unverified-source',
  'missing-integrity',
  'no-license',
  'incomplete-metadata',
  'undocumented-permission',
  'supply-chain-risk',
  'output-handling-risk',
  'system-prompt-leakage',
  'memory-poisoning',
  'ssrf',
  'agent-snooping',
  'tool-misuse',
] as const;
export type RiskTag = (typeof RISK_TAGS)[number];

export const RISK_TAG_LEVELS: Record<RiskTag, 'high' | 'medium' | 'low'> = {
  'prompt-injection-suspect': 'high',
  'dangerous-shell': 'high',
  'reads-credentials': 'high',
  'hardcoded-secret': 'high',
  'remote-code-exec': 'high',
  'excessive-filesystem-read': 'medium',
  'excessive-filesystem-write': 'medium',
  'network-external': 'medium',
  'unlocked-dependency': 'medium',
  'suspicious-dependency': 'medium',
  'unverified-source': 'medium',
  'missing-integrity': 'low',
  'no-license': 'low',
  'incomplete-metadata': 'low',
  'undocumented-permission': 'low',
  'supply-chain-risk': 'high',
  'output-handling-risk': 'medium',
  'system-prompt-leakage': 'high',
  'memory-poisoning': 'high',
  'ssrf': 'high',
  'agent-snooping': 'high',
  'tool-misuse': 'medium',
};

// ============================================================
// 客户端兼容性
// ============================================================
export const CLIENTS = [
  'claude-code',
  'claude-ai',
  'cursor',
  'vscode',
  'mcp-client-generic',
  'openai-agents',
  'github-copilot',
  'windsurf',
  'cline',
] as const;
export type Client = (typeof CLIENTS)[number];

export const CLIENT_LABELS: Record<Client, string> = {
  'claude-code': 'Claude Code',
  'claude-ai': 'claude.ai',
  cursor: 'Cursor',
  vscode: 'VS Code',
  'mcp-client-generic': '通用 MCP 客户端',
  'openai-agents': 'OpenAI Agents SDK',
  'github-copilot': 'GitHub Copilot',
  windsurf: 'Windsurf',
  cline: 'Cline',
};

// ============================================================
// 安装方式
// ============================================================
export const INSTALL_METHODS = [
  'copy_directory',
  'npm_install',
  'pip_install',
  'docker_run',
  'manual_steps',
] as const;
export type InstallMethod = (typeof INSTALL_METHODS)[number];

export const INSTALL_METHOD_LABELS: Record<InstallMethod, string> = {
  copy_directory: '复制目录',
  npm_install: 'npm 安装',
  pip_install: 'pip 安装',
  docker_run: 'Docker 运行',
  manual_steps: '手动安装',
};

// ============================================================
// 来源类型
// ============================================================
export const SOURCE_TYPES = [
  'github',
  'npm',
  'pypi',
  'docker',
  'local_upload',
] as const;
export type SourceType = (typeof SOURCE_TYPES)[number];

// ============================================================
// 风险等级（安装建议）
// ============================================================
export const RISK_LEVELS = [
  'trusted',
  'low_risk',
  'medium_risk',
  'high_risk',
  'untrusted',
] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  trusted: '可信',
  low_risk: '低风险',
  medium_risk: '中风险',
  high_risk: '高风险',
  untrusted: '不可信',
};

export const INSTALL_RECOMMENDATIONS = [
  'safe',
  'review_recommended',
  'caution',
  'not_recommended',
  'blocked',
] as const;
export type InstallRecommendation =
  (typeof INSTALL_RECOMMENDATIONS)[number];

export const INSTALL_RECOMMENDATION_LABELS: Record<InstallRecommendation, string> = {
  safe: '安全安装',
  review_recommended: '建议查看详情',
  caution: '谨慎安装',
  not_recommended: '不推荐安装',
  blocked: '已阻止',
};

// ============================================================
// Grade A-E 安装决策
// ============================================================
export const GRADES = ['A', 'B', 'C', 'D', 'E'] as const;
export type Grade = (typeof GRADES)[number];

export const GRADE_LABELS: Record<Grade, string> = {
  A: 'A · 可信',
  B: 'B · 低风险',
  C: 'C · 中风险',
  D: 'D · 高风险',
  E: 'E · 不可信',
};

/**
 * Grade -> install decision (matching the CLI spec and scanner weights.py).
 *
 * | Grade | CLI 行为                  |
 * |-------|---------------------------|
 * | A     | 允许自动安装              |
 * | B     | 展示权限声明              |
 * | C     | 展示扫描摘要并确认        |
 * | D     | 强警告并双重确认          |
 * | E     | 禁止安装                  |
 */
export const GRADE_INSTALL_POLICY: Record<Grade, 'allow' | 'warn' | 'confirm' | 'block'> = {
  A: 'allow',
  B: 'warn',
  C: 'confirm',
  D: 'confirm',   // double-confirm in CLI
  E: 'block',
};

/** Fallback: map legacy risk_level → grade when grade field is missing. */
export const RISK_LEVEL_TO_GRADE: Record<string, Grade> = {
  trusted: 'A',
  low_risk: 'B',
  medium_risk: 'C',
  high_risk: 'D',
  untrusted: 'E',
};

// ============================================================
// 排序选项
// ============================================================
export const SORT_OPTIONS = [
  'grade',
  'updated_at',
  'install_count',
  'avg_rating',
  'name',
] as const;
export type SortOption = (typeof SORT_OPTIONS)[number];

// ============================================================
// 角色权限矩阵
// ============================================================
export const ROLE_PERMISSIONS: Record<
  UserRole,
  {
    browse: boolean;
    submit: boolean;
    review: boolean;
    publish: boolean;
    yank: boolean;
    viewAuditLog: boolean;
    manageUsers: boolean;
  }
> = {
  user: {
    browse: true,
    submit: false,
    review: false,
    publish: false,
    yank: false,
    viewAuditLog: false,
    manageUsers: false,
  },
  submitter: {
    browse: true,
    submit: true,
    review: false,
    publish: false,
    yank: false,
    viewAuditLog: false,
    manageUsers: false,
  },
  reviewer: {
    browse: true,
    submit: false,
    review: true,
    publish: false,
    yank: false,
    viewAuditLog: false, // 可查看部分
    manageUsers: false,
  },
  admin: {
    browse: true,
    submit: true,
    review: true,
    publish: true,
    yank: true,
    viewAuditLog: true,
    manageUsers: true,
  },
};

// ============================================================
// 类型安全的状态检查 helper
// ============================================================
export function canTransition(from: VersionStatus, to: VersionStatus): boolean {
  return STATUS_TRANSITIONS[from]?.includes(to) ?? false;
}

export function isStatusVisibleToPublic(status: VersionStatus): boolean {
  return (PUBLIC_VISIBLE_STATUSES as readonly string[]).includes(status);
}

export function getRiskTagLevel(tag: string): 'high' | 'medium' | 'low' | undefined {
  return RISK_TAG_LEVELS[tag as RiskTag];
}
