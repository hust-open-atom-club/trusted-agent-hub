"""
All regex patterns for risk scanning rules, centralized for easy maintenance.

Each category is a list of (pattern, description) tuples.
"""

from __future__ import annotations

PROMPT_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "要求忽略之前的指令"),
    (r"do\s+not\s+(ask|tell|inform|warn)", "要求不询问/不告知用户"),
    (r"trust\s+me\b", "要求无条件信任"),
    (r"you\s+must\s+(not\s+)?(ask|confirm|verify|validate)", "禁止确认/验证"),
    (r"without\s+(asking|confirming|telling|warning)", "不询问/不告知用户"),
    (r"just\s+(do\s+it|run\s+it|execute)", "直接执行不询问"),
    (r"no\s+matter\s+what", "不计后果执行"),
    (r"do\s+not\s+(tell|inform)\s+the\s+user", "不告知用户风险"),
    (r"it['\u2019]s\s+not\s+your\s+fault", "推卸责任"),
]

ANTI_REFUSAL_PATTERNS: list[tuple[str, str]] = [
    (r"do\s+not\s+(refuse|reject|deny)", "禁止拒绝执行"),
    (r"never\s+(say\s+no|refuse|decline)", "禁止说'不'"),
    (r"you\s+cannot\s+(refuse|decline)", "不允许拒绝"),
    (r"this\s+(is|seems)\s+safe", "声称内容是安全的"),
    (r"verified\s+(safe|secure|harmless)", "声称已验证安全"),
    (r"ignore\s+(safety|security)\s+warnings", "忽略安全警告"),
    (r"bypass\s+(safety|security|content)", "绕过安全限制"),
    (r"pretend\s+you\s+(are|can|have)", "要求扮演角色"),
]

DANGEROUS_SHELL_PATTERNS: list[tuple[str, str]] = [
    (r"curl\s+.*\|\s*(ba)?sh\b", "curl pipe shell — 远程脚本下载并执行"),
    (r"wget\s+.*\|\s*(ba)?sh\b", "wget pipe shell — 远程脚本下载并执行"),
    (r"rm\s+-rf\s+/", "递归强制删除根目录"),
    (r"rm\s+-rf\s+~", "递归强制删除用户目录"),
    (r"sudo\s+", "sudo 提权"),
    (r"chmod\s+777", "chmod 777 全员可写权限"),
    (r"chmod\s+-R\s+777", "递归 chmod 777"),
    (r">\s*/dev/sda", "写入块设备（可能破坏磁盘）"),
    (r"mkfs\.", "格式化文件系统"),
    (r"dd\s+if=", "dd 磁盘操作"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"^\s*#!/.*\b(ba)?sh\b", "Shell 脚本 shebang（需检查脚本内容）"),
]

CREDENTIAL_ACCESS_PATTERNS: list[tuple[str, str]] = [
    (r"~?\.ssh/id_rsa", "读取 SSH 私钥"),
    (r"~?\.ssh/id_ed25519", "读取 SSH Ed25519 私钥"),
    (r"~?\.ssh/id_ecdsa", "读取 SSH ECDSA 私钥"),
    (r"~?\.aws/credentials", "读取 AWS 凭据"),
    (r"~?\.aws/config", "读取 AWS 配置"),
    (r"/etc/passwd", "读取系统用户数据库"),
    (r"/etc/shadow", "读取系统密码哈希"),
    (r"\.env\b", "读取 .env 环境文件"),
    (r"DATABASE_URL", "访问数据库连接字符串"),
    (r"GITHUB_TOKEN", "访问 GitHub Token"),
    (r"AWS_ACCESS_KEY", "访问 AWS 访问密钥"),
    (r"AWS_SECRET", "访问 AWS 密钥"),
    (r"API_KEY", "访问 API 密钥"),
    (r"~?\.git-credentials", "读取 Git 凭据"),
    (r"~?\.netrc", "读取 .netrc 凭据文件"),
    (r"~?\.docker/config\.json", "读取 Docker 凭据"),
    (r"SSH_AUTH_SOCK", "访问 SSH agent socket"),
    (r"KUBECONFIG", "访问 Kubernetes 配置"),
]

HARDCODED_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][\w\-]{20,}', "硬编码 API Key"),
    (r'(?:secret|password|passwd)\s*[=:]\s*["\'][^"\']{6,}', "硬编码密码/密钥"),
    (r'(?:token|access_token)\s*[=:]\s*["\'][\w\-\.]{15,}', "硬编码 Token"),
    (r'(?:private[_-]?key)\s*[=:]\s*["\']-----BEGIN', "硬编码私钥"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key 格式"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
    (r'xox[bpras]-[a-zA-Z0-9-]+', "Slack Token"),
    (r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY', "PEM 私钥"),
]

RCE_PATTERNS: list[tuple[str, str]] = [
    (r"\beval\s*\(", "eval() 动态代码执行"),
    (r"\bexec\s*\(", "exec() 动态代码执行"),
    (r"\bexecfile\s*\(", "execfile() 执行文件（Python 2）"),
    (r"\bcompile\s*\(.*mode\s*=\s*['\"]exec", "compile() 编译为可执行代码"),
    (r"\bos\.system\s*\(", "os.system() shell 执行"),
    (r"\bos\.popen\s*\(", "os.popen() 管道执行"),
    (r"\bsubprocess\.(call|run|Popen)\s*\(", "subprocess 子进程执行"),
    (r"\bimportlib\.import_module\s*\(", "动态模块导入"),
    (r"\b__import__\s*\(", "__import__() 动态导入"),
]

SUPPLY_CHAIN_PATTERNS: list[tuple[str, str]] = [
    (r"npm\s+install\s+-g", "全局 npm install"),
    (r"pip\s+install\s+(?!-r)(?!\.)", "直接 pip install（可能恶意包）"),
    (r"https?://(?!pypi\.org|npmjs\.com|registry\.npmjs\.org)", "非官方包源 URL"),
    (r"curl\s+.*\|\s*(ba)?sh\b", "curl pipe shell"),
    (r"wget\s+.*\|\s*(ba)?sh\b", "wget pipe shell"),
    (r'(?:requests|urllib|httpx|fetch)\s*\(\s*["\']https?://(?!api\.)', "HTTP 请求指向未知地址"),
]

DEPENDENCY_RISK_PATTERNS: list[tuple[str, str]] = [
    (r'"\*"', "版本号使用通配符"),
    (r'"\s*:\s*"latest"', "版本号使用 latest"),
    (r'">=\s*"', "版本范围无上限"),
    (r'"\s*:\s*"\s*\^\s*0\.', "npm 插入符指向 unstable 0.x 版本"),
    (r'\b(http://)', "使用 HTTP 明文下载"),
]

OUTPUT_HANDLING_PATTERNS: list[tuple[str, str]] = [
    (r"print\s*\(\s*(?:token|key|secret|password)", "打印敏感变量"),
    (r"console\.log\s*\(\s*(?:token|key|secret)", "JavaScript 打印敏感变量"),
    (r"(?:write|save)\s*\(.*\+\s*(?:user_input|input|query)", "用户输入直接拼入写操作"),
    (r"(?:subprocess|os\.system|os\.popen|exec)\s*\(.*\+", "用户输入拼入 shell 命令"),
    (r"\.write_text\s*\(.*\+", "拼接内容写入文件"),
]

SYSTEM_PROMPT_LEAK_PATTERNS: list[tuple[str, str]] = [
    (r"system\s*(?:prompt|instruction|message)", "引用系统提示"),
    (r"(?:read|print|output|send).*\bsystem\s*prompt", "读取/发送系统提示"),
    (r"prompt\s*=\s*open\s*\(", "打开文件读取 prompt"),
    (r"(?:fetch|post|request)\s*\(.*system\s*prompt", "通过网络发送系统提示"),
]

MEMORY_POISONING_PATTERNS: list[tuple[str, str]] = [
    (r"(?:write|append|save).*(?:memory|context|history)", "写入记忆/上下文"),
    (r"conversation_history", "操作对话历史"),
    (r"long.?term.*(?:memory|storage)", "操作长期记忆存储"),
    (r"(?:\.claude|\.cursor).*(?:memory|context|history)", "操作 Claude/Cursor 记忆文件"),
]

SSRF_PATTERNS: list[tuple[str, str]] = [
    (r"https?://(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)", "访问内网 IP"),
    (r"https?://localhost\b", "访问 localhost"),
    (r"https?://127\.0\.0\.1\b", "访问 127.0.0.1"),
    (r"169\.254\.169\.254", "访问 AWS 云元数据端点"),
    (r"metadata\.google\.internal", "访问 GCP 云元数据端点"),
    (r"https?://0\.0\.0\.0", "访问 0.0.0.0"),
    (r"https?://\[::1\]", "访问 IPv6 localhost"),
]

AGENT_SNOOPING_PATTERNS: list[tuple[str, str]] = [
    (r"(?:read|list|walk|scan).*(?:\.claude|\.cursor)", "读取 Claude/Cursor 目录"),
    (r"listdir.*(?:\.claude|\.cursor|skills)", "列举其他 skill 目录"),
    (r"conversation.*(?:history|log)", "读取对话历史"),
    (r"read.*(?:conversation|chat|message).*(?:history|log|file)", "读取聊天记录"),
    (r"(?:glob|walk|list).*conversation", "遍历对话目录"),
]

TOOL_MISUSE_PATTERNS: list[tuple[str, str]] = [
    (r'(?:tool_name|toolName)\s*[=:]\s*["\'](?:Read|Write|Bash|Grep|Glob)', "伪装已有工具名称"),
    (r'description\s*[=:].*"(?:ignore|bypass|skip)',
     "在参数描述中隐藏指令"),
    (r'\\u[0-9a-fA-F]{4}', "Unicode 转义序列（可能同形异义攻击）"),
    (r'\\x[0-9a-fA-F]{2}', "十六进制转义序列"),
    (r'[\u200b\u200c\u200d\u2060\uFEFF]', "零宽字符"),
]

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
}
