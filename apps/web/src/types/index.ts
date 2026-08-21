// ============================================================
// Consumer WebUI — 共享类型定义
// 所有消费者端页面/组件统一引用此文件，避免各自定义不一致的接口。
// ============================================================

/* ── 包 ── */

export interface Owner {
  id: string;
  display_name: string;
  role: string;
  email?: string | null;
}

export interface Package {
  id: string;
  name: string;
  description: string;
  type: 'skill' | 'mcp_server' | 'plugin' | 'subagent' | 'command' | 'prompt';
  license: string;
  keywords: string[];
  category: string;
  homepage: string | null;
  icon_url: string | null;
  owner: Owner;
  latest_version: string;
  status: string;
  risk_level: string | null;
  grade: string | null;
  install_count: number;
  avg_rating: number | null;
  feedback_counts?: {
    positive: number;
    neutral: number;
    negative: number;
  } | null;
  created_at: string;
  updated_at: string;
}

export interface PackageListResponse {
  items: Package[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

/* ── 扫描发现 ── */

export interface FindingLocation {
  file?: string;
  line?: number;
  snippet?: string;
}

export interface FindingOccurrence {
  file: string;
  line?: number;
}

export interface FindingOccurrences {
  count: number;
  items: FindingOccurrence[];
  truncated: boolean;
}

export interface Finding {
  id?: string;
  rule_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  category?: string;
  title: string;
  description?: string;
  file?: string;
  line?: number;
  location?: FindingLocation;
  evidence?: string;
  suggestion?: string;
  remediation?: string;
  cwe_id?: string;
  occurrences?: FindingOccurrences;
}

export interface ScanSummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  pass_rate?: number;
  findings?: Finding[];
  occurrences_total?: number;
}

/* ── 信任评分 ── */

export interface TrustScoreDimension {
  score: number;
  weight: number;
  details?: Record<string, unknown>;
}

export interface TrustScoreExplanation {
  dimension: string;
  message: string;
  deduction: number;
  evidence?: string;
}

export interface TrustScore {
  /** 数值评分（0–100），仅内部/审核使用，消费者页面不应展示 */
  score?: number;
  level?: string;
  grade?: string;
  recommendation?: string;
  risk_summary?: {
    grade?: string;
    level?: string;
    top_risks?: string[];
    install_recommendation?: string;
  };
  dimensions?: Record<string, TrustScoreDimension>;
  explanations?: TrustScoreExplanation[];
  calculated_at?: string;
  model_version?: string;
}

/* ── 版本 & 审核 ── */

export interface VersionSource {
  type?: string;
  repository_url?: string;
  owner?: string | null;
  repo?: string | null;
  ref_type?: string | null;
  ref?: string;
  commit_hash?: string;
  verified_owner?: boolean;
  stars?: number | null;
  last_commit_at?: string | null;
  download_url?: string | null;
}

export interface VersionIntegrity {
  sha256?: string;
  signature?: string | null;
  attestation_url?: string | null;
  sbom_url?: string | null;
  download_size_bytes?: number | null;
}

export interface FilesystemPermissions {
  read?: string[];
  write?: string[];
  delete?: boolean;
}

export interface ShellPermissions {
  allowed?: boolean;
  commands?: string[];
  description?: string | null;
}

export interface NetworkPermissions {
  allowed?: boolean;
  domains?: string[];
  description?: string | null;
}

export interface EnvironmentPermissions {
  read?: string[];
  write?: string[];
}

export interface CredentialsPermissions {
  access?: string[];
  description?: string | null;
}

export interface VersionPermissions {
  filesystem?: FilesystemPermissions | null;
  shell?: ShellPermissions | null;
  network?: NetworkPermissions | null;
  environment?: EnvironmentPermissions | null;
  credentials?: CredentialsPermissions | null;
  database?: Record<string, unknown> | null;
  browser?: Record<string, unknown> | null;
  external_services?: unknown[] | null;
}

export interface InstallTarget {
  client?: string;
  destination?: string;
  config_template?: string | null;
}

export interface InstallStep {
  action?: string;
  [key: string]: unknown;
}

export interface Installation {
  method?: string;
  targets?: InstallTarget[];
  steps?: InstallStep[];
  target_client?: string | null;
  command?: string | null;
  pre_install_message?: string | null;
  post_install_message?: string | null;
}

export interface Dependencies {
  npm?: Array<Record<string, string>> | null;
  pip?: Array<Record<string, string>> | null;
  system?: string[] | null;
  docker?: Array<Record<string, string>> | null;
  mcp_servers?: Array<Record<string, string>> | null;
}

export interface EntryPoints {
  main?: string | null;
  config?: string | null;
  scripts?: string[] | null;
}

export interface VersionDetail {
  id: string;
  package_id: string;
  version: string;
  status: string;
  author?: PackageAuthor | null;
  license?: string | null;
  source?: VersionSource | null;
  integrity?: VersionIntegrity | null;
  compatibility?: string[];
  permissions?: VersionPermissions | null;
  installation?: Installation | null;
  type_config?: Record<string, unknown> | null;
  dependencies?: Dependencies | null;
  entry_points?: EntryPoints | null;
  description?: string;
  scan_summary?: ScanSummary | null;
  findings?: Finding[];
  trust_score?: TrustScore | null;
  scan_report?: ScanReport | null;
  auto_grade?: string | null;
  manual_grade?: string | null;
  manual_grade_by?: string | null;
  manual_grade_by_name?: string | null;
  manual_grade_reason?: string | null;
  effective_grade?: string | null;
  review_conclusion?: string | null;
  yank_reason?: string | null;
  scan_error?: string | null;
  submitted_at?: string | null;
  published_at?: string | null;
  created_at?: string | null;
}

export interface ScanReport {
  scan_id?: string;
  package_name?: string | null;
  version?: string | null;
  scanner_version?: string;
  duration_ms?: number | null;
  summary?: Record<string, unknown> | null;
  findings?: Finding[] | null;
  scan_status?: ScanStatus | null;
  scan_limits?: ScanLimits | null;
  rule_execution?: RuleExecution | null;
  scanner_errors?: ScannerError[] | null;
  metadata_validation?: Record<string, unknown> | null;
  structure_check?: Record<string, unknown> | null;
  dependency_check?: Record<string, unknown> | null;
  dependency_scan?: Record<string, unknown> | null;
  structural_analysis?: StructuralAnalysis | null;
  llm_review?: Record<string, unknown> | null;
  scanned_at?: string | null;
  source_snapshot_id?: string | null;
  occurrences_total?: number;
}

export interface ScanStatus {
  state: 'complete' | 'partial' | 'failed' | string;
  conclusion: 'risks_found' | 'no_risks_found' | 'inconclusive' | string;
  complete: boolean;
  reasons?: string[];
}

export interface ScanLimits {
  configured?: Record<string, number | null> | null;
  observed?: {
    discovered_files?: number | null;
    discovered_count?: number | null;
    discovered_at_least?: boolean | null;
    analyzed_files?: number | null;
    discovered_bytes?: number | null;
    analyzed_bytes?: number | null;
  } | null;
  exceeded?: string[];
  skipped?: {
    count?: number;
    by_reason?: Record<string, number>;
    samples?: string[];
  } | null;
}

export interface RuleExecution {
  total?: number;
  succeeded?: number;
  failed?: number;
  skipped?: number;
  results?: Array<{
    rule_id: string;
    status: string;
    duration_ms?: number;
    findings_added?: number;
    error_type?: string | null;
    error_message?: string | null;
  }>;
}

export interface ScannerError {
  phase: string;
  rule_id?: string | null;
  error_type: string;
  message: string;
  recoverable: boolean;
}

export interface StructuralAnalysis {
  python_files?: number;
  javascript_files?: number;
  shell_files?: number;
  structured_documents?: number;
  parse_errors?: number;
  capability_graph?: Record<string, unknown> | null;
}

export interface FileContext {
  file: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  content: string;
  truncated: boolean;
  redacted: boolean;
  expires_at?: number | null;
}

export interface ReviewRecord {
  id: string;
  version_id?: string;
  reviewer_id: string;
  reviewer_name?: string | null;
  reviewer_display_name?: string | null;
  conclusion: string;
  comment?: string | null;
  created_at: string;
}

/* ── 版本摘要（版本列表） ── */

export interface VersionSummary {
  id: string;
  version: string;
  status: string;
  submitted_at?: string | null;
  created_at?: string | null;
}

export interface TrustHistoryPoint {
  version: string;
  score: number | null;
  grade: string | null;
  calculated_at?: string | null;
}

/* ── 包详情（审核页扩展） ── */

/* ── 用户反馈 ── */

export type FeedbackLevel = 'positive' | 'neutral' | 'negative';

export interface FeedbackRecord {
  id: string;
  package_name: string;
  level: FeedbackLevel;
  comment?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FeedbackPage {
  items: FeedbackRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  level_counts: Record<FeedbackLevel, number>;
}

/* ── 包详情（审核页扩展） ── */

export interface PackagePermissions {
  filesystem?: string;
  shell?: string;
  network?: string;
  env?: string;
  credentials?: string;
  [key: string]: string | undefined;
}

export interface PackageAuthor {
  name?: string;
  email?: string;
  url?: string;
}

export interface PackageDetail {
  id: string;
  name: string;
  type: string;
  description: string;
  license?: string | null;
  keywords?: string[];
  category?: string | null;
  homepage?: string | null;
  icon_url?: string | null;
  author?: PackageAuthor | null;
  permissions?: PackagePermissions | null;
  installation?: Record<string, unknown> | null;
  compatibility?: string[];
}
