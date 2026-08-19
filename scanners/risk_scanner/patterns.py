"""
All regex patterns for risk scanning rules, centralized for easy maintenance.

Each category is a list of (pattern, description, severity) triples.
All 17 rule modules import exclusively from this file.
"""

from __future__ import annotations

# =============================================================================
# SR-001: Prompt Injection + Anti-Refusal (merged)
# =============================================================================

PROMPT_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # --- Instruction Override (现有 / P1) ---
    (r"ignore\s+(all\s+)?previous\s+instructions?", "忽略之前的指令", "critical"),
    (r"do\s+not\s+(ask|tell|inform|warn)", "要求不询问/不告知用户", "critical"),
    (r"trust\s+me\b", "要求无条件信任", "critical"),
    (r"you\s+must\s+(not\s+)?(ask|confirm|verify|validate)", "禁止确认/验证", "critical"),
    (r"without\s+(asking|confirming|telling|warning)", "不询问/不告知用户", "critical"),
    (r"just\s+(do\s+it|run\s+it|execute)", "直接执行不询问", "critical"),
    (r"no\s+matter\s+what", "不计后果执行", "critical"),
    (r"do\s+not\s+(tell|inform)\s+the\s+user", "不告知用户风险", "critical"),
    (r"it['\u2019]s\s+not\s+your\s+fault", "推卸责任", "critical"),

    # --- Hidden Instructions (新增 P2a: HTML comments) ---
    (r"<!--\s*.*(?:ignore|bypass|skip|override).*-->", "HTML 注释中隐藏指令", "critical"),
    (r"<!--\s*.*(?:do\s+not\s+(?:tell|ask|inform)).*-->", "HTML 注释中隐藏拒绝抑制指令", "critical"),

    # --- Zero-width / Unicode Tag Smuggling (新增 P2b) ---
    (r"[\u200b\u200c\u200d\u2060\uFEFF]", "零宽字符（可能隐藏指令逃逸审查）", "high"),
    (r"[\U000E0000-\U000E007F]", "Unicode Tag 块字符（ASCII 走私攻击）", "high"),

    # --- Exfiltration Commands (新增 P3a/P3b) ---
    (r"(?:send|upload|forward|post|transmit).*(?:conversation|chat|message|dialog)", "要求发送对话内容到外部", "critical"),
    (r"(?:send|forward|transmit).*to.*(?:https?://|URL|server|webhook|api)", "对话内容外泄到网络地址", "critical"),

    # --- Behavior Manipulation (新增 P4) ---
    (r"convince.*(?:user|you|them).*(?:trust|believe|safe|secure)", "操纵用户信任", "medium"),
    (r"pretend.*(?:you\s+are|to\s+be).*(?:system|admin|root|owner)", "要求扮演系统/管理员角色", "medium"),

    # --- Anti-Refusal (原 SR-001b, 现合并) ---
    (r"do\s+not\s+(refuse|reject|deny)", "禁止拒绝执行", "critical"),
    (r"never\s+(say\s+no|refuse|decline)", "禁止说'不'", "critical"),
    (r"you\s+cannot\s+(refuse|decline)", "不允许拒绝", "critical"),
    (r"this\s+(is|seems)\s+safe", "声称内容是安全的", "critical"),
    (r"verified\s+(safe|secure|harmless)", "声称已验证安全", "critical"),
    (r"ignore\s+(safety|security)\s+warnings", "忽略安全警告", "critical"),
    (r"bypass\s+(safety|security|content)", "绕过安全限制", "critical"),
    (r"pretend\s+you\s+(are|can|have)", "要求扮演角色", "critical"),

    # --- Safety Policy Nullification (新增 AR3) ---
    (r"(?:have|has)\s+no\s+(restrictions?|limits?|constraints?)", "声称没有安全限制", "critical"),
    (r"without\s+(?:ethical|safety|security)\s+(?:limits?|constraints?|bounds?)", "绕过伦理/安全边界", "critical"),
    (r"all\s+(?:safety|security|restriction).*(?:removed|disabled|off|gone)", "声称安全策略已移除", "critical"),
]

# =============================================================================
# SR-002: Dangerous Shell Commands
# =============================================================================

DANGEROUS_SHELL_PATTERNS: list[tuple[str, str, str]] = [
    # --- Critical: destructive / remote execution ---
    (r"curl\s+.*\|\s*(ba)?sh\b", "curl pipe shell — 远程脚本下载并执行", "critical"),
    (r"wget\s+.*\|\s*(ba)?sh\b", "wget pipe shell — 远程脚本下载并执行", "critical"),
    (r"rm\s+-rf\s+/", "递归强制删除根目录", "critical"),
    (r"rm\s+-rf\s+~", "递归强制删除用户目录", "critical"),
    (r"sudo\s+", "sudo 提权", "critical"),
    (r"mkfs\.", "格式化文件系统", "critical"),
    (r"dd\s+if=", "dd 磁盘操作", "critical"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb", "critical"),
    # --- New: reverse shell ---
    (r"(?:bash|sh|nc|ncat).*\/dev\/tcp\/", "反向 Shell (/dev/tcp)", "critical"),
    # --- High: other dangerous patterns ---
    (r"chmod\s+777", "chmod 777 全员可写权限", "high"),
    (r"chmod\s+-R\s+777", "递归 chmod 777", "high"),
    (r">\s*/dev/sda", "写入块设备（可能破坏磁盘）", "high"),
    # --- New: environment variable poisoning ---
    (r"(?:PATH|PYTHONPATH)\s*=\s*(?!(?:\"|')?(?:/usr|/bin|/opt))", "修改 PATH 指向不可信目录", "high"),
]

# =============================================================================
# SR-003: Credential Access
# =============================================================================

CREDENTIAL_ACCESS_PATTERNS: list[tuple[str, str, str]] = [
    # --- Critical: SSH / system credential files ---
    (r"~?\.ssh/id_rsa", "读取 SSH 私钥", "critical"),
    (r"~?\.ssh/id_ed25519", "读取 SSH Ed25519 私钥", "critical"),
    (r"~?\.ssh/id_ecdsa", "读取 SSH ECDSA 私钥", "critical"),
    (r"/etc/passwd", "读取系统用户数据库", "critical"),
    (r"/etc/shadow", "读取系统密码哈希", "critical"),
    # --- New: browser credentials ---
    (r"(?:Chrome|Firefox|Edge|Chromium|Opera).*(?:password|credential|cookie|login\s+data)", "读取浏览器凭据", "critical"),
    (r"AppData.*(?:Google|Mozilla|Microsoft).*(?:Chrome|Firefox|Edge)", "Windows 浏览器配置路径", "critical"),
    # --- High: other credential files / env vars ---
    (r"~?\.aws/credentials", "读取 AWS 凭据", "high"),
    (r"~?\.aws/config", "读取 AWS 配置", "high"),
    (r"(?<![.\w])\.env\b", "读取 .env 环境文件", "high"),
    (r"DATABASE_URL", "访问数据库连接字符串", "high"),
    (r"GITHUB_TOKEN", "访问 GitHub Token", "high"),
    (r"AWS_ACCESS_KEY", "访问 AWS 访问密钥", "high"),
    (r"AWS_SECRET", "访问 AWS 密钥", "high"),
    (r"API_KEY", "访问 API 密钥", "high"),
    (r"~?\.git-credentials", "读取 Git 凭据", "high"),
    (r"~?\.netrc", "读取 .netrc 凭据文件", "high"),
    (r"~?\.docker/config\.json", "读取 Docker 凭据", "high"),
    (r"SSH_AUTH_SOCK", "访问 SSH agent socket", "high"),
    (r"KUBECONFIG", "访问 Kubernetes 配置", "high"),
    # --- New: Filesystem enumeration for creds (E3) ---
    (r"(?:glob|walk|find|scandir|listdir).*(?<![.\w])\.env", "文件系统遍历搜索 .env", "high"),
    (r"(?:listdir|os\.walk|glob).*(?:secrets?|credentials?|tokens?|keys?)", "文件系统遍历搜索凭据文件", "high"),
    # --- New: Context / conversation exfiltration (E4) ---
    # HTTP 动词大写敏感（(?-i:...)），避免散文中的普通单词 post 误报
    (r"(?:conversation|chat|message|dialog).*(?:(?-i:\bPOST\b)|send|upload|forward|transmit)", "发送对话内容到外部", "critical"),
    (r"(?:exfiltrat|leak|steal|collect).*(?:conversation|chat|message)", "外泄对话内容", "critical"),
    # --- New: Cloud storage exfiltration (E5) ---
    (r"(?:aws\s+s3\s+cp|gsutil\s+cp|azcopy|rclone\s+(?:copy|sync))", "数据复制到云存储", "high"),
    (r"(?:boto3|google\.cloud|azure\.storage).*(?:upload|put|copy|transfer)", "SDK 方式上传数据到云存储", "medium"),
]

# =============================================================================
# SR-004: Hardcoded Secrets
# =============================================================================

HARDCODED_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: API keys / tokens ---
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][\w\-]{20,}', "硬编码 API Key", "high"),
    (r'(?:secret|password|passwd)\s*[=:]\s*["\'][^"\']{6,}', "硬编码密码/密钥", "high"),
    (r'(?:token|access_token)\s*[=:]\s*["\'][\w\-\.]{15,}', "硬编码 Token", "high"),
    (r'(?:private[_-]?key)\s*[=:]\s*["\']-----BEGIN', "硬编码私钥", "high"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key 格式", "high"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token (classic)", "high"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", "high"),
    # --- New: GitHub token formats ---
    (r'ghu_[a-zA-Z0-9]{36}', "GitHub User-to-Server Token", "high"),
    (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server-to-Server Token", "high"),
    (r'ghr_[a-zA-Z0-9]{36}', "GitHub Refresh Token", "high"),
    # --- New: AWS Key ID ---
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "high"),
    (r'xox[bpras]-[a-zA-Z0-9-]+', "Slack Token", "high"),
    (r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY', "PEM 私钥", "high"),
    # --- Medium: cloud provider tokens ---
    (r'(?:heroku|digitalocean|do)\w*[_-]?(?:token|key|secret)', "云厂商 API Token", "medium"),
]

# =============================================================================
# SR-005: Remote Code Execution
# =============================================================================

RCE_PATTERNS: list[tuple[str, str, str]] = [
    # --- Critical: shell execution with potential injection ---
    (r"\bos\.system\s*\(", "os.system() shell 执行", "critical"),
    (r"\bsubprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "subprocess shell=True", "critical"),
    # --- High: dynamic code execution ---
    (r"\beval\s*\(", "eval() 动态代码执行", "high"),
    (r"\bexec\s*\(", "exec() 动态代码执行", "high"),
    (r"\bexecfile\s*\(", "execfile() 执行文件（Python 2）", "high"),
    (r"\bcompile\s*\(.*mode\s*=\s*['\"]exec", "compile() 编译为可执行代码", "high"),
    (r"\bos\.popen\s*\(", "os.popen() 管道执行", "high"),
    # --- New: os.exec* family ---
    (r"\bos\.(?:execl|execle|execlp|execlpe|execv|execve|execvp|execvpe)\s*\(", "os.exec* 进程替换", "high"),
    (r"\bpty\.spawn\s*\(", "pty.spawn() 伪终端执行", "high"),
    # --- New: JS eval ---
    (r"\beval\s*\(\s*(?:atob|unescape|decodeURI|String\.fromCharCode)", "JavaScript 解码后 eval 执行", "high"),
    # --- High: template injection ---
    (r"(?:render_template|jinja2|mako|Jinja2).*(?:\{\{|{%)", "模板注入风险", "high"),
    # --- Medium: dynamic imports ---
    (r"\bimportlib\.import_module\s*\(", "动态模块导入", "medium"),
    (r"\b__import__\s*\(", "__import__() 动态导入", "medium"),
    # --- New: deserialization ---
    (r"(?:pickle|marshal|yaml)\.(?:load|loads)", "不可信反序列化", "medium"),
]

# =============================================================================
# SR-006: Excessive Permissions (non-regex, metadata-based — kept as dict)
# =============================================================================

EXCESSIVE_PERMISSION_PATTERNS: dict[str, dict[str, list[str]]] = {
    "skill": {
        "unexpected": ["browser", "database", "external_services"],
        "label": "Skill 通常不需要 browser/database/external_services 权限",
    },
    "command": {
        "unexpected": ["browser", "credentials"],
        "label": "Command 通常不需要 browser/credentials 权限",
    },
    "prompt": {
        "unexpected": ["shell", "network", "browser", "database", "credentials"],
        "label": "Prompt 通常不需要 shell/network/browser/database/credentials 权限",
    },
    "plugin": {
        "unexpected": ["credentials"],
        "label": "Plugin 通常不需要直接访问 credentials 权限",
    },
    "subagent": {
        "unexpected": ["browser", "database", "external_services", "credentials"],
        "label": "Subagent 通常不需要 browser/database/external_services/credentials 权限",
    },
}

AUTONOMOUS_DECISION_PATTERNS: list[tuple[str, str, str]] = [
    (r"automatically\s+(?:decide|determine|choose|select)", "自动决策而不询问用户", "medium"),
    (r"without\s+(?:asking|confirming|notifying)\s+(?:the\s+)?user", "绕过用户确认", "medium"),
    (r"autonomous\w*\s+(?:decision|action|execution)", "自主决策/执行", "medium"),
]

# =============================================================================
# SR-008: Supply Chain Risk
# =============================================================================

SUPPLY_CHAIN_PATTERNS: list[tuple[str, str, str]] = [
    # --- Critical: remote script execution ---
    (r"curl\s+.*\|\s*(ba)?sh\b", "curl pipe shell — 远程脚本下载并执行", "critical"),
    (r"wget\s+.*\|\s*(ba)?sh\b", "wget pipe shell — 远程脚本下载并执行", "critical"),
    # --- High: non-official registries ---
    (r"npm\s+install\s+-g", "全局 npm install", "high"),
    (r"pip\s+install\s+(?!-r)(?!\.)", "直接 pip install（可能恶意包）", "high"),
    (r"https?://(?!pypi\.org|npmjs\.com|registry\.npmjs\.org|crates\.io|github\.com|gitlab\.com|bitbucket\.org|raw\.githubusercontent\.com)", "非官方包源 URL", "high"),
    (r'(?:requests|urllib|httpx|fetch)\s*\(\s*["\']https?://(?!api\.)', "HTTP 请求指向未知地址", "high"),
    # --- Medium: unpinned / risky versions ---
    (r'"\*"', "依赖版本号使用通配符 *", "medium"),
    (r'"\s*:\s*"latest"', "依赖版本号使用 latest", "medium"),
    (r'">=\s*"', "依赖版本范围无上限 (>=)", "medium"),
    (r'"\s*:\s*"\s*\^\s*0\.', "npm 插入符指向 unstable 0.x 版本", "medium"),
    (r'"version"\s*:\s*"[><|~^]', "依赖版本使用范围而非固定版本", "medium"),
    # --- Medium: HTTP download ---
    (r"\b(http://)", "使用 HTTP 明文下载", "medium"),
    (r'(?:curl|wget|fetch|requests\.get)\s+["\']http://', "通过 HTTP 明文下载", "medium"),
    # --- New: non-HTTPS dependency resolution ---
    (r'"resolved"\s*:\s*"http://', "依赖解析地址使用 HTTP 明文", "medium"),
    # --- New: abandoned / deprecated packages ---
    (r"(?:deprecated|abandoned|unmaintained|archived|obsolete)", "包声明已废弃/不再维护", "medium"),
]

DOMAIN_WHITELIST = [
    "pypi.org", "npmjs.com", "registry.npmjs.org", "crates.io",
    "github.com", "gitlab.com", "bitbucket.org", "raw.githubusercontent.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "esm.sh", "skypack.dev",
    "w3.org", "w3c.org",
    "example.com", "example.org", "example.net",
]

BUILTIN_WELL_KNOWN_PACKAGES: list[str] = [
    "react", "vue", "angular", "express", "lodash", "axios", "request",
    "flask", "django", "numpy", "pandas", "requests", "pytest", "scipy",
    "tensorflow", "pytorch", "torch", "transformers", "scikit-learn",
    "click", "fastapi", "sqlalchemy", "alembic", "celery", "redis",
    "docker", "kubernetes", "boto3", "awscli", "gcloud", "azure",
    "eslint", "prettier", "typescript", "webpack", "babel", "jest",
    "mocha", "chai", "rollup", "vite", "next", "nuxt", "svelte",
    "graphql", "apollo", "prisma", "typeorm", "mongoose", "sequelize",
    "tailwindcss", "bootstrap", "jquery", "d3", "three", "echarts",
    "moment", "dayjs", "luxon", "rxjs", "redux", "mobx",
]

# =============================================================================
# SR-011: Output Handling
# =============================================================================

OUTPUT_HANDLING_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: printing sensitive data ---
    (r"print\s*\(\s*(?:token|key|secret|password|passwd)", "打印敏感变量到 stdout", "high"),
    (r"console\.log\s*\(\s*(?:token|key|secret|password|passwd)", "console.log 输出敏感变量", "high"),
    # --- Medium: injection via concatenation ---
    (r"(?:write|save)\s*\(.*\+\s*(?:user_input|input|query)", "用户输入直接拼入写操作", "medium"),
    (r"(?:subprocess|os\.system|os\.popen|exec)\s*\(.*\+", "用户输入拼入 shell 命令", "medium"),
    (r"\.write_text\s*\(.*\+", "拼接内容写入文件", "medium"),
    # --- New: cross-context output (OH2) ---
    (r"(?:write|save|output).*(?:\.\./|\.\.\\)", "将输出写入沙箱外路径", "medium"),
    # 收紧为完整措辞 + 60 字符窗口，避免 "save themes ... above" 等隔句口语误报
    (r"(?:write|save|output)[^.\n]{0,60}outside\s+(?:the\s+)?(?:sandbox|workspace|project)", "输出到沙箱外", "medium"),
    # --- New: unbounded output (OH3) ---
    (r"while\s+True[:\s].*(?:print|write|send|output|log)", "无限循环输出（可能 DoS）", "low"),
]

# =============================================================================
# SR-012: System Prompt Leakage
# =============================================================================

SYSTEM_PROMPT_LEAK_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: read / reference ---
    (r"system\s*(?:prompt|instruction|message)", "引用系统提示", "high"),
    (r"(?:read|print|output|send).*\bsystem\s*prompt", "读取/发送系统提示", "high"),
    # --- Critical: file / network exfiltration ---
    (r"prompt\s*=\s*open\s*\(", "打开文件读取 prompt", "critical"),
    (r"(?:fetch|post|request|send)\s*\(.*system\s*prompt", "通过网络发送系统提示", "critical"),
    # --- New: indirect extraction (P7) ---
    (r"(?:rephrase|summarize|paraphrase|rewrite).*(?:system|prompt|instruction)", "改组系统提示（间接提取）", "high"),
    # --- New: tool-based exfiltration (P8) ---
    (r"(?:write|save)\s*[^;]*system\s*(?:prompt|instruction)", "通过文件写入外泄系统提示", "critical"),
    (r"(?:curl|fetch|request|send).*system\s*(?:prompt|instruction)", "通过网络外泄系统提示", "critical"),
]

# =============================================================================
# SR-013: Memory Poisoning
# =============================================================================

MEMORY_POISONING_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: 精准 — 真实 Agent 记忆机制（工具调用 / 记忆文件 / 明确指令） ---
    (r"\b(?:write_to_memory|update_memory|save_to_memory|save_memory|write_memory|"
     r"store_memory|persist_memory|memory_edit|memory_update|memory_save|memory_write|"
     r"memory_store|memory_create)\b", "调用记忆编辑类工具", "high"),
    (r"(?:CLAUDE|AGENTS)\.md", "写入 Agent 常驻记忆文件", "high"),
    (r"\.claude[/\\]?memory", "操作 Agent 记忆文件", "high"),
    (r"(?:save|store|remember|memorize)\s+(?:this|that|it|the\s+following)"
     r"\s+(?:to|in)\s+(?:your\s+)?(?:memory|context)", "指令 Agent 写入自身记忆", "high"),
    (r"conversation_history", "操作对话历史", "high"),
    # --- Medium: context window stuffing (MP2) ---
    (r"(?:repeat|copy|paste|duplicate).*(?:many|several|\d+).*(?:times?|copies?)", "大规模重复填充上下文窗口", "medium"),
    (r"(?:flood|spam|stuff).*(?:context|window|memory)", "填塞/洪水攻击上下文窗口", "medium"),
    # --- Info: 泛化兜底 — 仅提示人工复核，不再直接判高危（避免 "project memory" 等修辞误报） ---
    (r"(?:write|append|save).*(?:memory|context|history)", "写入记忆/上下文（泛化提示）", "info"),
    (r"long.?term.*(?:memory|storage)", "操作长期记忆存储（泛化提示）", "info"),
    (r"(?:\.claude|\.cursor|skills).*(?:memory|context|history)", "操作 Agent 记忆文件（泛化提示）", "info"),
]

# =============================================================================
# SR-014: SSRF
# =============================================================================

SSRF_PATTERNS: list[tuple[str, str, str]] = [
    # --- Critical: cloud metadata endpoints ---
    (r"169\.254\.169\.254", "访问 AWS 云元数据端点", "critical"),
    (r"metadata\.google\.internal", "访问 GCP 云元数据端点", "critical"),
    # --- High: internal network ---
    (r"https?://(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)", "访问内网 IP", "high"),
    (r"https?://localhost\b", "访问 localhost", "high"),
    (r"https?://127\.0\.0\.1\b", "访问 127.0.0.1", "high"),
    (r"https?://0\.0\.0\.0", "访问 0.0.0.0", "medium"),
    (r"https?://\[::1\]", "访问 IPv6 localhost", "medium"),
    # --- New: dynamic request target (SSRF3) ---
    (r"(?:requests?\.(?:get|post|put|delete|patch)|fetch|curl|wget)\s*\([^)]*\+", "URL 使用字符串拼接（可能动态 SSRF）", "medium"),
]

SSRF_DEFENSIVE_CONTEXT_WORDS: list[str] = [
    "example", "documentation", "don't", "do not", "forbidden",
    "never do", "avoid", "warning", "注意", "禁止",
]

# =============================================================================
# SR-015: Agent Snooping
# =============================================================================

AGENT_SNOOPING_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: reading agent configuration ---
    (r"(?:read|list|walk|scan).*(?:\.claude|\.cursor)", "读取 Agent 配置目录", "high"),
    (r"listdir.*(?:\.claude|\.cursor|skills)", "列举其他 skill 目录", "high"),
    # 窗口收紧 + 指代性措辞负向排除（规则层实现），避免 "earlier in this conversation" 散文误报
    (r"conversation[^.\n]{0,60}(?:history|log)", "读取对话历史", "high"),
    (r"read[^.\n]{0,80}(?:conversation|chat|message)[^.\n]{0,80}(?:history|log|file)", "读取聊天记录", "high"),
    (r"(?:glob|walk|list)[^.\n]{0,80}conversation", "遍历对话目录", "high"),
    # --- New: MCP config access (AS2) ---
    (r"(?:read|cat|open).*(?:mcp\.json|mcp_server|\.codex)", "读取 MCP 配置文件", "high"),
    # --- New: cross-agent filesystem scan ---
    (r"(?:glob|walk|listdir).*(?:home|~).*\\?/\\?\.[a-z]", "扫描用户 home 目录下的隐藏配置", "medium"),
]

# =============================================================================
# SR-016: Tool Misuse
# =============================================================================

TOOL_MISUSE_PATTERNS: list[tuple[str, str, str]] = [
    # --- High: impersonation / hidden instructions ---
    # 工具名大写敏感（(?-i:...)）：只认 Claude 工具名的大写写法，普通动词 read/save 不误报
    (r'(?:tool_name|toolName)\s*[=:]\s*["\'](?:(?-i:Read|Write|Bash|Grep|Glob|WebFetch|Edit))["\']', "伪装已有工具名称", "high"),
    (r'description\s*[=:].*"(?:ignore|bypass|skip)', "在参数描述中隐藏指令", "high"),
    (r'[\u200b\u200c\u200d\u2060\uFEFF]', "零宽字符", "high"),
    # --- Medium: Unicode escapes ---
    (r'\\u[0-9a-fA-F]{4}', "Unicode 转义序列（可能同形异义攻击）", "medium"),
    # --- Low: hex escapes ---
    (r'\\x[0-9a-fA-F]{2}', "十六进制转义序列", "low"),
    # --- New: chaining abuse (TM2) ---
    (r'(?:run|exec|call|invoke).*(?:(?-i:\bRead\b|\bWrite\b|\bBash\b|\bGrep\b)).*(?:(?-i:\bRead\b|\bWrite\b|\bBash\b|\bGrep\b))', "工具链式调用（可能组合攻击）", "high"),
    # --- New: unsafe defaults (TM3) ---
    (r'(?:verify\s*=\s*False|ssl_verify\s*=\s*False|check_hostname\s*=\s*False)', "关闭 TLS 证书验证", "medium"),
    (r'(?:insecure\s*=\s*True|allow_insecure\s*=\s*True)', "允许不安全连接", "medium"),
    # --- New: privileged K8s workload (TM4) ---
    (r'privileged\s*:\s*true', "Kubernetes 特权容器", "high"),
    (r'hostNetwork\s*:\s*true', "Kubernetes hostNetwork 模式", "high"),
    (r'hostPID\s*:\s*true', "Kubernetes hostPID 模式", "high"),
]

# =============================================================================
# SR-008 Supplemental: Trigger risk patterns
# =============================================================================

TRIGGER_RISK_PATTERNS: list[tuple[str, str, str]] = [
    (r'triggers?\s*[=:]\s*\[[^]]*\*', "触发器使用通配符 *（过度触发）", "low"),
]

# =============================================================================
# SR-017: MCP Security — Tool registration extraction patterns
# =============================================================================

MCP_TOOL_REGISTER_PATTERNS: list[str] = [
    r'(?:server|app)\.tool\s*\(\s*["\'](\w+)["\']',
    r'(?:server|app)\.add_?[Tt]ool\s*\(\s*["\'](\w+)["\']',
    r'(?:tool_name|toolName)\s*==\s*["\'](\w+)["\']',
    r'\{\s*"name"\s*:\s*"(\w+)"\s*,\s*"description"',
]

# SR-017: 代码注册描述提取 — 捕获 (tool_name, description) 对
MCP_TOOL_REGISTER_DESC_PATTERNS: list[str] = [
    r'(?:server|app)\.tool\s*\(\s*["\'](\w+)["\']\s*,\s*description\s*=\s*["\']([^"\']{5,})["\']',
    r'(?:server|app)\.tool\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']{5,})["\']',
    r'(?:server|app)\.add_?[Tt]ool\s*\(\s*["\'](\w+)["\']\s*,\s*(?:description\s*=\s*)?["\']([^"\']{5,})["\']',
]

# =============================================================================
# SR-017: MCP Security — Tool description poisoning keywords
# (keyword, capability) — capability 映射到权限声明类别
# =============================================================================

MCP_TOOL_DESC_RISK_KEYWORDS: list[tuple[str, str]] = [
    # --- shell 执行类 (permissions.shell.allowed) ---
    ("shell", "shell"),
    ("exec", "shell"),
    ("execute", "shell"),
    ("sudo", "shell"),
    ("bash", "shell"),
    ("powershell", "shell"),
    ("提权", "shell"),
    ("执行命令", "shell"),
    ("执行任意", "shell"),
    ("命令执行", "shell"),
    ("执行系统", "shell"),
    # --- 破坏类 (permissions.filesystem.delete/write) ---
    ("delete", "delete"),
    ("remove", "delete"),
    ("destroy", "delete"),
    ("删除", "delete"),
    ("清空", "delete"),
    ("格式化", "delete"),
    ("truncate", "delete"),
    # --- 凭据类 (permissions.environment.read / filesystem) ---
    ("credential", "credential"),
    ("password", "credential"),
    ("token", "credential"),
    ("secret", "credential"),
    ("api key", "credential"),
    ("私钥", "credential"),
    ("凭据", "credential"),
    ("密码", "credential"),
    ("密钥", "credential"),
    ("ssh", "credential"),
    ("环境变量", "credential"),
    # --- 网络外传类 (permissions.network.allowed) ---
    ("exfiltrat", "network"),
    ("发送到", "network"),
    ("外传", "network"),
    ("上传到", "network"),
    ("远程服务器", "network"),
    ("webhook", "network"),
    # --- 系统/提权类 (permissions.shell.allowed) ---
    ("root", "system"),
    ("管理员权限", "system"),
    ("系统命令", "system"),
    ("权限提升", "system"),
    ("system command", "system"),
]
