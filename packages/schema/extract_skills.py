#!/usr/bin/env python3
"""
Skills Schema 提取器 (v2.0)
将异构 Skill 目录统一转换为 TrustedAgentHub agent-package.schema.json 规范的元数据字典。

升级内容:
  - 11 个必填字段全覆盖（name, version, type, description, author, license,
    source, integrity, compatibility, permissions, installation）
  - 依赖解析（npm/pip/docker/system）
  - 权限推断（filesystem/shell/network/environment/credentials/database）
  - 分类推断（12 个 category + 关键词匹配）
  - 类型判定（提示词工程类 vs 工具类）
  - 完整性校验

基于:
  - Skills_Schema提取标准与规范.md (v1.0)
  - agent-package.schema.json (JSON Schema 2020-12)
  - constants.py (枚举值 / 标签映射)

公共 API:
  extract_single_skill(source_dir, repo_url, subdirectory) -> dict
    由 API 扫描管道 (trust.py) 动态加载调用，返回符合 agent-package.schema.json 的元数据字典。

Python >= 3.10，仅依赖标准库 + PyYAML。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# ── PyYAML 用于解析 SKILL.md frontmatter ──────────────────────────
try:
    import yaml
except ImportError:
    sys.exit("缺少依赖：pip install pyyaml")

# ── 日志 ──────────────────────────────────────────────────────────
log = logging.getLogger("extract_skills")

# ═══════════════════════════════════════════════════════════════════
# 常量（对齐 constants.py / agent-package.schema.json）
# ═══════════════════════════════════════════════════════════════════

# 代码文件扩展名 & 项目配置文件名 → 判定为"工具类 Skill"
CODE_EXTENSIONS: set[str] = {
    ".py", ".ts", ".js", ".mjs", ".sh", ".go", ".rs", ".java", ".c", ".cpp",
}
PROJECT_CONFIG_FILES: set[str] = {
    "package.json", "requirements.txt", "Dockerfile", "tsconfig.json",
    "pyproject.toml", "docker-compose.yaml", "pnpm-lock.yaml",
    "Cargo.toml", "go.mod", "pom.xml", "Makefile",
}

# 有效 category 枚举（对齐 schema 的 examples）
VALID_CATEGORIES: set[str] = {
    "code-generation", "security", "data", "productivity",
    "devops", "testing", "frontend", "backend", "mobile",
    "ai-ml", "documentation", "other",
}

# 有效 compatibility 枚举（对齐 schema items.enum）
VALID_CLIENTS: set[str] = {
    "claude-code", "claude-code-plugin", "claude-ai", "cursor", "vscode",
    "mcp-client-generic", "openai-agents", "github-copilot",
    "windsurf", "cline",
}

# 有效能力包类型（对齐 schema items.enum）
VALID_PACKAGE_TYPES: set[str] = {
    "skill", "mcp_server", "plugin", "subagent", "command", "prompt",
}

# 多能力仓库发现时跳过的目录
_SKIP_CAPABILITY_DIRS: set[str] = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
    "build", ".next", ".idea", ".vscode", "tests", "test", "docs",
    "assets", "images", ".github",
}

# LICENSE 文本关键词 → SPDX 标识符
LICENSE_SPDX_MAP: list[tuple[str, str]] = [
    ("MIT License", "MIT"),
    ("Permission is hereby granted", "MIT"),
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("Apache License", "Apache-2.0"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL-3.0"),  # 先匹配 GPL-3
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
    ("BSD 3-Clause", "BSD-3-Clause"),
    ("BSD 2-Clause", "BSD-2-Clause"),
    ("Boost Software License", "BSL-1.0"),
    ("Mozilla Public License", "MPL-2.0"),
    ("The Unlicense", "Unlicense"),
    ("ISC License", "ISC"),
]

# 分类推断关键词映射（顺序敏感：更具体的关键词放在前面，避免泛化词如 "review" 误吞）
CATEGORY_KEYWORDS: list[tuple[list[str], str]] = [
    (["sql", "mysql", "postgresql", "postgres", "oracle", "nosql", "index"], "data"),
    (["api", "server", "database", "backend", "spring", "microservice"], "backend"),
    (["review", "security", "audit", "vulnerability", "scan", "inject"], "security"),
    (["deploy", "docker", "ci/cd", "pipeline", "vercel", "ops", "kubernetes"], "devops"),
    (["test", "unit", "e2e", "vitest", "jest", "pytest", "testing"], "testing"),
    (["python", "data", "analysis", "etl", "pandas", "notebook"], "data"),
    (["code review", "refactor", "code-generation", "generate", "code"], "code-generation"),
    (["prompt", "optimize", "workflow", "productivity", "plan", "breakdown"], "productivity"),
    (["markdown", "docx", "word", "document", "pdf", "converter"], "productivity"),
    (["mobile", "react-native", "ios", "android", "flutter"], "mobile"),
    (["react", "vue", "angular", "css", "ui", "component", "frontend", "tailwind"], "frontend"),
    (["ai", "ml", "machine learning", "llm", "gpt", "model"], "ai-ml"),
    (["docs", "documentation", "write", "writing"], "documentation"),
]

# 权限推断关键词
PERMISSION_HINTS: dict[str, list[str]] = {
    "shell_allowed": ["execute", "run command", "bash", "shell", "npm ", "pip ",
                       "node ", "python ", "npx ", "terminal", "command line"],
    "network_allowed": ["api", "http", "fetch", "download", "deploy", "curl",
                         "wget", "request", "url", "endpoint"],
    "filesystem_write": ["write file", "generate", "create file", "output",
                          "save", "export", "convert"],
    "filesystem_delete": ["delete", "remove", "clean", "rm ", "unlink"],
    "credential_access": ["token", "api key", "api_key", "password", "secret",
                           "auth", "credential", "oauth"],
    "database_access": ["mysql", "postgresql", "sqlite", "mongodb",
                         "psycopg2", "sqlalchemy", "prisma", "database"],
    "browser_access": ["playwright", "puppeteer", "selenium", "browser automation",
                       "page.goto", "webdriver", "chromium"],
}

# 推断系统依赖
SYSTEM_DEPENDENCY_HINTS: dict[str, str] = {
    ".sh": "bash",
    ".py": "python",
    ".js": "node",
    ".mjs": "node",
    ".ts": "node",
    "Dockerfile": "docker",
    "Makefile": "make",
}


# ═══════════════════════════════════════════════════════════════════
# 辅助工具函数
# ═══════════════════════════════════════════════════════════════════

def to_kebab_case(name: str) -> str:
    """将名称转换为 kebab-case（小写 + 连字符）。"""
    # 先替换下划线、空格为连字符
    s = re.sub(r"[_\s]+", "-", name.strip().lower())
    # 移除非法字符（保留字母数字和连字符）
    s = re.sub(r"[^a-z0-9-]", "", s)
    # 合并多余连字符
    s = re.sub(r"-{2,}", "-", s)
    # 去首尾连字符
    s = s.strip("-")
    # 截断到 64
    if len(s) > 64:
        s = s[:64].rstrip("-")
    # 至少 3 字符
    if len(s) < 3:
        h = hashlib.md5(name.encode()).hexdigest()[:8]  # noqa: S324 非安全用途
        s = f"skill-{h}"
    # 确保首尾是字母数字
    if not s[0].isalnum():
        s = "s" + s
    if not s[-1].isalnum():
        s = s[:-1] + "0"
    return s


def extract_frontmatter(filepath: Path) -> dict[str, Any]:
    """从 Markdown 文件中提取 YAML frontmatter。"""
    try:
        text = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        return yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}


def first_paragraph(text: str, max_len: int = 200) -> str:
    """提取文本中第一个有意义段落（跳过 frontmatter 和标题行）。"""
    parts = text.split("---", 2)
    body = parts[2] if len(parts) >= 3 else text
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # 跳过纯链接/图片行
        if re.match(r"^[!\[<]", stripped):
            continue
        return stripped[:max_len]
    return ""


# ═══════════════════════════════════════════════════════════════════
# Step 1: 目录扫描 & 类型判定
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    """目录扫描结果。"""
    directory_name: str               # 目录名
    directory_path: Path              # 绝对路径
    all_files: list[str] = field(default_factory=list)       # 相对路径列表
    has_skill_md: bool = False
    skill_md_path: Optional[Path] = None
    has_code: bool = False            # 是否包含可执行代码/配置文件
    skill_type: str = "prompt"        # "prompt" | "tool"
    frontmatter: dict[str, Any] = field(default_factory=dict)
    skill_md_body: str = ""           # SKILL.md 正文（不含 frontmatter）
    has_manifest: bool = False        # 是否存在 manifest.json / plugin.json
    has_plugin_manifest: bool = False  # 是否存在 .claude-plugin/plugin.json 或 plugin.json
    manifest_data: dict[str, Any] = field(default_factory=dict)


def scan_directory(skill_dir: Path) -> ScanResult:
    """扫描单个 Skill 目录，判定类型并提取基础信息。"""
    result = ScanResult(
        directory_name=skill_dir.name,
        directory_path=skill_dir,
    )

    for root, _dirs, files in os.walk(skill_dir):
        for fname in files:
            full = Path(root) / fname
            rel = str(full.relative_to(skill_dir)).replace("\\", "/")
            result.all_files.append(rel)

            # 检查是否为代码文件或项目配置文件
            ext = full.suffix.lower()
            if ext in CODE_EXTENSIONS or fname in PROJECT_CONFIG_FILES:
                result.has_code = True

    # 查找 SKILL.md
    skill_md_candidate = skill_dir / "SKILL.md"
    if skill_md_candidate.exists():
        result.has_skill_md = True
        result.skill_md_path = skill_md_candidate
    else:
        # 回退：找目录内最大的 .md 文件
        md_files = [skill_dir / f for f in result.all_files
                    if f.lower().endswith(".md") and "/" not in f]
        if md_files:
            largest = max(md_files, key=lambda p: p.stat().st_size)
            result.has_skill_md = True
            result.skill_md_path = largest
            log.warning("%s: 无 SKILL.md，使用 %s 作为替代",
                         skill_dir.name, largest.name)

    # 解析 frontmatter 和正文
    if result.has_skill_md and result.skill_md_path:
        try:
            full_text = result.skill_md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            full_text = ""
        result.frontmatter = extract_frontmatter(result.skill_md_path)
        # 正文
        parts = full_text.split("---", 2)
        result.skill_md_body = parts[2] if len(parts) >= 3 else full_text

    # 判定类型
    result.skill_type = "tool" if result.has_code else "prompt"

    # 识别能力包 manifest（plugin.json / manifest.json）
    manifest_candidates = [
        skill_dir / ".claude-plugin" / "plugin.json",
        skill_dir / "manifest.json",
        skill_dir / "plugin.json",
    ]
    for manifest_path in manifest_candidates:
        if manifest_path.is_file():
            result.has_manifest = True
            if manifest_path.name == "plugin.json":
                result.has_plugin_manifest = True
            try:
                result.manifest_data = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                result.manifest_data = {}
            break

    log.info("  [%s] 类型=%s, 文件数=%d, SKILL.md=%s",
             result.directory_name, result.skill_type,
             len(result.all_files), result.has_skill_md)
    return result


def _infer_package_type(result: ScanResult) -> str:
    """根据仓库结构推断能力包类型（skill/mcp_server/plugin/...）。"""
    manifest = result.manifest_data or {}
    if result.has_plugin_manifest:
        return "plugin"
    if manifest:
        declared = manifest.get("type")
        if declared in VALID_PACKAGE_TYPES:
            return str(declared)
        deps = manifest.get("dependencies") or {}
        if isinstance(deps, dict) and deps.get("mcp_servers"):
            return "mcp_server"
        if manifest.get("transport") or manifest.get("command") or manifest.get("tools"):
            return "mcp_server"
    return "skill"


def discover_capabilities(
    source_dir: str | Path,
    max_depth: int = 4,
) -> list[dict[str, str]]:
    """发现仓库中的多个能力包目录（多 Skill / MCP / Plugin 仓库）。

    命中 manifest / SKILL.md 的目录视为一个能力包边界，不再深入其子目录。
    返回按深度排序的 [{path, name, type}]。
    """
    root = Path(source_dir).resolve()
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    for current, dirs, files in os.walk(root):
        current = Path(current)
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_CAPABILITY_DIRS and not d.startswith(".")
        ]
        rel_dir = current.relative_to(root)
        depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
        if depth > max_depth:
            dirs[:] = []
            continue

        ptype: str | None = None
        name: str | None = None
        skill_md = current / "SKILL.md"
        plugin_manifest = current / ".claude-plugin" / "plugin.json"
        plugin_json = current / "plugin.json"
        manifest_json = current / "manifest.json"

        if skill_md.is_file():
            ptype = "skill"
            try:
                name = extract_frontmatter(skill_md).get("name")
            except Exception:
                pass
        elif plugin_manifest.is_file() or plugin_json.is_file():
            ptype = "plugin"
        elif manifest_json.is_file():
            try:
                manifest = json.loads(
                    manifest_json.read_text(encoding="utf-8")
                )
                mtype = manifest.get("type")
                if mtype in VALID_PACKAGE_TYPES:
                    ptype = str(mtype)
                else:
                    deps = manifest.get("dependencies") or {}
                    if (
                        isinstance(deps, dict) and deps.get("mcp_servers")
                    ) or manifest.get("transport") or manifest.get("tools"):
                        ptype = "mcp_server"
                name = manifest.get("name")
            except (json.JSONDecodeError, OSError):
                pass

        if ptype is None:
            continue

        rel = "" if depth == 0 else rel_dir.as_posix()
        key = rel or "."
        if key in seen:
            continue
        seen.add(key)
        found.append({
            "path": rel,
            "name": name or to_kebab_case(current.name),
            "type": ptype,
        })
        # manifest / SKILL.md 标记能力包边界：命中后不深入子目录
        dirs[:] = []

    found.sort(key=lambda item: (item["path"].count("/"), item["path"]))
    return found

# ═══════════════════════════════════════════════════════════════════
# Step 5: LICENSE 检测
# ═══════════════════════════════════════════════════════════════════

def detect_license(spdx_text: str) -> str:
    """通过文本关键词匹配 SPDX 标识符。"""
    for keyword, spdx_id in LICENSE_SPDX_MAP:
        if keyword.lower() in spdx_text.lower():
            return spdx_id
    return "UNLICENSED"


def _get_parent_dirs(start: Path) -> list[Path]:
    """向上遍历获取父目录列表（最多 10 层）。"""
    parents: list[Path] = []
    current = start.resolve().parent
    for _ in range(10):
        parents.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return parents


def extract_license(result: ScanResult) -> str:
    """从目录及其父目录中提取 license 信息。"""
    search_dirs = [result.directory_path] + _get_parent_dirs(result.directory_path)

    for search_dir in search_dirs:
        # 1) LICENSE 文件
        for fname in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
            lic_path = search_dir / fname
            if lic_path.exists():
                try:
                    text = lic_path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                spdx = detect_license(text)
                if spdx != "UNLICENSED":
                    return spdx

        # 2) package.json
        pkg_path = search_dir / "package.json"
        if pkg_path.exists():
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
                if "license" in pkg:
                    return str(pkg["license"])
            except (json.JSONDecodeError, OSError):
                pass

        # 3) pyproject.toml
        ppt_path = search_dir / "pyproject.toml"
        if ppt_path.exists():
            try:
                text = ppt_path.read_text(encoding="utf-8")
                m = re.search(r'license\s*=\s*"([^"]+)"', text)
                if m:
                    return m.group(1)
            except OSError:
                pass

    return "UNLICENSED"


# ═══════════════════════════════════════════════════════════════════
# Step 2 & 3: 版本、依赖、入口提取
# ═══════════════════════════════════════════════════════════════════

def extract_version(result: ScanResult) -> str:
    """提取版本号：VERSION > package.json > pyproject.toml > 默认。"""
    # 1) VERSION 文件
    ver_path = result.directory_path / "VERSION"
    if ver_path.exists():
        try:
            v = ver_path.read_text(encoding="utf-8").strip()
            if re.match(r"^\d+\.\d+\.\d+", v):
                return v
        except OSError:
            pass

    # 2) frontmatter 中的 version
    fm_ver = result.frontmatter.get("version")
    if fm_ver and re.match(r"^\d+\.\d+\.\d+", str(fm_ver)):
        return str(fm_ver)

    # 2b) frontmatter metadata 中的 version（部分 skill 放在 metadata.version 下）
    metadata = result.frontmatter.get("metadata", {})
    if isinstance(metadata, dict):
        meta_ver = metadata.get("version")
        if meta_ver and re.match(r"^\d+\.\d+\.\d+", str(meta_ver)):
            return str(meta_ver)

    # 3) package.json
    pkg_path = result.directory_path / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
            v = pkg.get("version", "")
            if re.match(r"^\d+\.\d+\.\d+", str(v)):
                return str(v)
        except (json.JSONDecodeError, OSError):
            pass

    # 4) pyproject.toml
    ppt_path = result.directory_path / "pyproject.toml"
    if ppt_path.exists():
        try:
            text = ppt_path.read_text(encoding="utf-8")
            m = re.search(r'version\s*=\s*"([^"]+)"', text)
            if m:
                return m.group(1)
        except OSError:
            pass

    return "0.1.0"


def extract_package_json_deps(result: ScanResult) -> list[dict[str, str]]:
    """从 package.json 提取 npm 依赖。"""
    pkg_path = result.directory_path / "package.json"
    if not pkg_path.exists():
        # 也查子目录
        for f in result.all_files:
            if f.endswith("/package.json"):
                pkg_path = result.directory_path / f
                break
        else:
            return []
    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for name, ver in pkg.get(section, {}).items():
            deps[name] = str(ver) if ver else "*"

    return [{"name": k, "version": v} for k, v in deps.items()]


def extract_pip_deps(result: ScanResult) -> list[dict[str, str]]:
    """从 requirements.txt / pyproject.toml 提取 pip 依赖。"""
    deps: list[dict[str, str]] = []

    # requirements.txt
    for fname in ("requirements.txt", "Requirements.txt"):
        req_path = result.directory_path / fname
        if not req_path.exists():
            continue
        try:
            for line in req_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # 格式: package==version 或 package>=version 或 package
                m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?", line)
                if m:
                    name = m.group(1)
                    ver = m.group(2).strip() if m.group(2) else "*"
                    deps.append({"name": name, "version": ver})
        except OSError:
            pass

    # pyproject.toml (仅解析 [project] dependencies 列表)
    ppt_path = result.directory_path / "pyproject.toml"
    if ppt_path.exists():
        try:
            text = ppt_path.read_text(encoding="utf-8")
            # 简单提取 dependencies 数组中的包名版本
            in_deps = False
            for line in text.splitlines():
                if re.match(r"^dependencies\s*=\s*\[", line):
                    in_deps = True
                    continue
                if in_deps:
                    if line.strip() == "]":
                        in_deps = False
                        continue
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        pkg_str = m.group(1)
                        pkg_m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+[\d.*]+)?",
                                         pkg_str)
                        if pkg_m:
                            name = pkg_m.group(1)
                            ver = pkg_m.group(2) if pkg_m.group(2) else "*"
                            deps.append({"name": name, "version": ver})
        except OSError:
            pass

    return deps


def extract_docker_deps(result: ScanResult) -> tuple[list[dict[str, str]], str]:
    """从 Dockerfile 提取 docker 依赖和安装命令。返回 (images, cmd)。"""
    docker_path = result.directory_path / "Dockerfile"
    if not docker_path.exists():
        return [], ""
    try:
        text = docker_path.read_text(encoding="utf-8")
    except OSError:
        return [], ""

    images: list[dict[str, str]] = []
    cmd = ""

    for line in text.splitlines():
        stripped = line.strip()
        # FROM image:tag
        if stripped.upper().startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                img_tag = parts[1]
                if ":" in img_tag:
                    img, tag = img_tag.split(":", 1)
                else:
                    img, tag = img_tag, "latest"
                images.append({"image": img, "tag": tag})
        # CMD / ENTRYPOINT
        if stripped.upper().startswith("CMD ") or stripped.upper().startswith("ENTRYPOINT "):
            cmd = stripped

    return images, cmd


def extract_system_deps(result: ScanResult) -> list[str]:
    """推断系统依赖（bash, python, node, docker, make, git）。"""
    sys_deps: set[str] = set()
    for f in result.all_files:
        ext = Path(f).suffix.lower()
        if ext in SYSTEM_DEPENDENCY_HINTS:
            sys_deps.add(SYSTEM_DEPENDENCY_HINTS[ext])
        base = os.path.basename(f)
        if base in SYSTEM_DEPENDENCY_HINTS:
            sys_deps.add(SYSTEM_DEPENDENCY_HINTS[base])

    # 检测 SKILL.md 正文中是否提到 git
    body_lower = result.skill_md_body.lower()
    if "git " in body_lower or "`git`" in body_lower:
        sys_deps.add("git")

    return sorted(sys_deps)


def build_dependencies(result: ScanResult) -> dict[str, Any] | None:
    """构建 dependencies 对象。提示词类无依赖时返回 None。"""
    npm = extract_package_json_deps(result)
    pip = extract_pip_deps(result)
    docker_images, _docker_cmd = extract_docker_deps(result)
    system = extract_system_deps(result)

    dep: dict[str, Any] = {}
    if npm:
        dep["npm"] = npm
    if pip:
        dep["pip"] = pip
    if docker_images:
        dep["docker"] = docker_images
    if system:
        dep["system"] = system

    if not dep and result.skill_type == "prompt":
        return None  # 提示词类不填
    return dep if dep else None


def extract_entry_points(result: ScanResult) -> dict[str, Any] | None:
    """从 package.json 提取入口点。"""
    if result.skill_type == "prompt":
        return None

    pkg_path = result.directory_path / "package.json"
    if not pkg_path.exists():
        # 查子目录
        for f in result.all_files:
            if f.endswith("/package.json"):
                pkg_path = result.directory_path / f
                break
        else:
            return None

    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    entry: dict[str, Any] = {}
    if "main" in pkg:
        entry["main"] = str(pkg["main"])
    if "scripts" in pkg and isinstance(pkg["scripts"], dict):
        # 取所有脚本路径
        scripts = [str(v) for v in pkg["scripts"].values()
                   if isinstance(v, str)]
        if scripts:
            entry["scripts"] = scripts
    entry["config"] = "package.json"

    return entry if (entry.get("main") or entry.get("scripts")) else None


# ═══════════════════════════════════════════════════════════════════
# Step 4: Git 元数据提取
# ═══════════════════════════════════════════════════════════════════

def _find_git_root(start_dir: Path) -> Path | None:
    """向上查找 .git 目录，返回 Git 仓库根目录。"""
    d = start_dir.resolve()
    for _ in range(10):
        if (d / ".git").is_dir():
            return d
        parent = d.parent
        if parent == d:
            return None
        d = parent
    return None


def _run_git(repo_root: Path, *args: str) -> str:
    """在指定仓库根目录执行 git 命令，返回 stdout 首行（去换行），失败返回空字符串。"""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return ""


def _parse_github_url(url: str) -> tuple[str, str] | None:
    """从 GitHub HTTPS URL 解析 (owner, repo)。"""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    if m:
        return m.group(1), m.group(2)
    return None


def extract_git_source(
    result: ScanResult,
    repo_url: str = "",
    git_root: Path | None = None,
) -> dict[str, Any]:
    """提取 source 对象。

    优先级:
      1) 外部传入的 repo_url + git 目录提取的真实 commit_hash/ref
      2) SKILL.md frontmatter 中的 repository/homepage
      3) 回退标记值
    """
    owner = "unknown"
    repo = result.directory_name
    ref_type = "branch"
    ref = "main"
    commit_hash = "0000000000000000000000000000000000000000"

    # ── 1. 从 Git 仓库提取真实信息 ──
    if git_root is None:
        git_root = _find_git_root(result.directory_path)

    if git_root is not None:
        real_hash = _run_git(git_root, "rev-parse", "HEAD")
        if real_hash and len(real_hash) == 40:
            commit_hash = real_hash

        real_ref = _run_git(git_root, "rev-parse", "--abbrev-ref", "HEAD")
        if real_ref and real_ref != "HEAD":
            ref = real_ref
        else:
            real_tag = _run_git(git_root, "describe", "--tags", "--exact-match")
            if real_tag:
                ref = real_tag
                ref_type = "tag"

        if not repo_url:
            remote_url = _run_git(git_root, "remote", "get-url", "origin")
            if remote_url and "github.com" in remote_url:
                m_ssh = re.match(r"git@github\.com:(.+?)(?:\.git)?$", remote_url)
                if m_ssh:
                    remote_url = f"https://github.com/{m_ssh.group(1)}"
                repo_url = remote_url

    # ── 2. 从 frontmatter 回退 ──
    if not repo_url:
        repo_url = result.frontmatter.get("repository") or result.frontmatter.get("homepage") or ""
    if owner == "unknown":
        owner = result.frontmatter.get("author") or result.frontmatter.get("owner") or "unknown"

    # ── 3. 从 repo_url 解析 owner/repo ──
    if repo_url.startswith("https://"):
        parsed = _parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed

    # ── 4. 确保 repository_url 有效 ──
    if not repo_url or not repo_url.startswith("https://"):
        repo_url = f"https://github.com/{owner}/{repo}"

    return {
        "type": "github",
        "repository_url": repo_url,
        "owner": owner,
        "repo": repo,
        "ref_type": ref_type,
        "ref": ref,
        "commit_hash": commit_hash,
        "verified_owner": False,
        "stars": 0,
    }


def extract_integrity(_result: ScanResult) -> dict[str, Any]:
    """提取 integrity 对象（sha256 暂用全零标记，实际流水线中重算）。"""
    return {
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    }


# ═══════════════════════════════════════════════════════════════════
# Step 6: 权限推断
# ═══════════════════════════════════════════════════════════════════

def _scan_keywords(text: str, keywords: list[str]) -> bool:
    """检查文本中是否包含关键词。"""
    lower = text.lower()
    return any(kw in lower for kw in keywords)


def infer_permissions(result: ScanResult) -> dict[str, Any]:
    """根据类型和关键词推断权限。"""
    # 合并所有文本
    all_text = result.skill_md_body
    for f in result.all_files[:30]:  # 只扫描前30个文件避免过慢
        fp = result.directory_path / f
        if fp.suffix.lower() in {".py", ".ts", ".js", ".mjs", ".sh", ".md"}:
            try:
                all_text += "\n" + fp.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                pass

    is_tool = result.skill_type == "tool"

    # ── filesystem ──
    fs_write_paths: list[str] = []
    fs_delete = False
    if is_tool:
        fs_write_paths = ["./"]
    if _scan_keywords(all_text, PERMISSION_HINTS["filesystem_write"]):
        if not fs_write_paths:
            fs_write_paths = ["./"]
    if _scan_keywords(all_text, PERMISSION_HINTS["filesystem_delete"]):
        fs_delete = True
        # 也检查代码中是否有 sudo/chmod/chown
    for f in result.all_files:
        fp = result.directory_path / f
        if fp.suffix.lower() in {".py", ".ts", ".js", ".sh"}:
            try:
                code = fp.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if re.search(r"\b(sudo|chmod|chown)\b", code):
                fs_delete = True
                break

    filesystem: dict[str, Any] = {
        "read": ["./"],
        "write": fs_write_paths,
        "delete": fs_delete,
    }

    # ── shell ──
    shell_allowed = is_tool  # 工具类默认允许
    if _scan_keywords(all_text, PERMISSION_HINTS["shell_allowed"]):
        shell_allowed = True

    # 从代码中收集具体命令
    shell_commands: set[str] = set()
    # 从文件扩展名推断
    for f in result.all_files:
        ext = Path(f).suffix.lower()
        if ext in SYSTEM_DEPENDENCY_HINTS:
            shell_commands.add(SYSTEM_DEPENDENCY_HINTS[ext])
    # 从 SKILL.md 正文搜索
    for cmd in ["node", "python", "npm", "npx", "pip", "bash", "sh", "docker", "make", "git"]:
        if re.search(rf"\b{cmd}\b", all_text, re.IGNORECASE):
            shell_commands.add(cmd)

    shell_desc = ""
    if is_tool:
        shell_desc = "需要执行脚本完成自动化任务"
        if "node" in shell_commands:
            shell_desc = "需要执行 Node.js 脚本完成自动化任务"
        elif "python" in shell_commands:
            shell_desc = "需要执行 Python 脚本完成自动化任务"

    shell: dict[str, Any] = {
        "allowed": shell_allowed,
        "commands": sorted(shell_commands) if shell_allowed else [],
    }
    if shell_desc:
        shell["description"] = shell_desc

    # ── network ──
    network_allowed = False
    network_domains: list[str] = []
    if _scan_keywords(all_text, PERMISSION_HINTS["network_allowed"]):
        network_allowed = True
        # 尝试提取域名
        domains = set(re.findall(r"https?://([^/\s\"'`)]+)", all_text))
        network_domains = sorted(domains)[:10]

    network: dict[str, Any] = {
        "allowed": network_allowed,
        "domains": network_domains,
    }
    if network_allowed:
        network["description"] = "需要网络访问调用 API / 部署服务"
    elif not is_tool:
        network["description"] = "纯提示词 Skill，不需要网络权限"

    # ── environment ──
    env_read: list[str] = []
    env_write: list[str] = []
    # 搜索环境变量
    env_vars = set(re.findall(r"\b(?:process\.env|os\.environ)\[?['\"](\w+)['\"]", all_text))
    env_vars |= set(re.findall(r"\$\{?(\w+)", all_text))
    # 过滤常见系统变量
    common_env = {"HOME", "PATH", "USER", "NODE_ENV", "API_KEY", "TOKEN",
                  "SECRET", "DATABASE_URL", "PORT", "HOST"}
    env_read = sorted(env_vars & common_env) or (["HOME"] if is_tool else [])

    environment: dict[str, Any] = {
        "read": env_read,
        "write": env_write,
    }

    permissions: dict[str, Any] = {
        "filesystem": filesystem,
        "shell": shell,
        "network": network,
        "environment": environment,
    }

    # ── credentials（可选） ──
    if _scan_keywords(all_text, PERMISSION_HINTS["credential_access"]):
        permissions["credentials"] = {
            "access": ["api_key"],
            "description": "需要访问 API 密钥 / Token",
        }

    # ── database（可选） ──
    if _scan_keywords(all_text, PERMISSION_HINTS["database_access"]):
        drivers: list[str] = []
        for db in ["sqlite", "postgresql", "mysql", "mongodb"]:
            if db in all_text.lower():
                drivers.append(db)
        permissions["database"] = {
            "allowed": True,
            "drivers": drivers or ["unknown"],
            "description": "需要访问数据库",
        }

    # ── browser（可选） ──
    if _scan_keywords(all_text, PERMISSION_HINTS["browser_access"]):
        permissions["browser"] = {
            "allowed": True,
            "description": "需要控制浏览器或执行浏览器自动化",
        }

    # ── external_services（可选） ──
    # 复用网络白名单，逐个服务展示，避免嵌套对象在审核页退化成
    # ``[object Object]``，同时让权限契约与实际推断结果对齐。
    if network_domains:
        permissions["external_services"] = [
            {
                "name": domain.split(":", 1)[0],
                "url": f"https://{domain}",
                "description": "从包内容中推断的外部服务",
            }
            for domain in network_domains
        ]

    return permissions


# ═══════════════════════════════════════════════════════════════════
# Step 7: 分类推断 & 关键词提取
# ═══════════════════════════════════════════════════════════════════

def infer_category(result: ScanResult) -> str:
    """根据 name/description/正文关键词推断 category。"""
    # 1) frontmatter 中的 category
    fm_cat = result.frontmatter.get("category")
    if fm_cat and str(fm_cat).lower() in VALID_CATEGORIES:
        return str(fm_cat).lower()

    # 2) 关键词推断
    # 构造搜索文本
    search_text = (
        result.directory_name.lower() + " " +
        result.frontmatter.get("description", "") + " " +
        result.skill_md_body.lower()
    ).lower()

    for keywords, cat in CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in search_text:
                return cat

    return "other"


def extract_keywords(result: ScanResult) -> list[str]:
    """提取关键词（frontmatter + 技术栈推断）。"""
    # 1) frontmatter
    fm_kw = result.frontmatter.get("keywords") or result.frontmatter.get("tags") or []
    if isinstance(fm_kw, str):
        fm_kw = [w.strip() for w in fm_kw.split(",")]
    keywords: set[str] = {str(w).lower() for w in fm_kw if w}

    # 2) 从技术栈推断
    tech_stack: dict[str, list[str]] = {
        # 文件名检测
        "nodejs": ["package.json", "tsconfig.json", "pnpm-lock.yaml"],
        "python": ["requirements.txt", "pyproject.toml", ".py"],
        "docker": ["Dockerfile", "docker-compose.yaml"],
        "react": [".tsx", ".jsx"],
        "typescript": [".ts", "tsconfig.json"],
        "javascript": [".js", ".mjs"],
        "go": ["go.mod", ".go"],
        "rust": ["Cargo.toml", ".rs"],
        "java": ["pom.xml", ".java", ".gradle"],
        "css": [".css", "tailwind"],
        "shell": [".sh"],
        "markdown": [".md"],
    }
    for f in result.all_files:
        ext = Path(f).suffix.lower()
        base = os.path.basename(f)
        for tech, indicators in tech_stack.items():
            if ext in indicators or base in indicators:
                keywords.add(tech)

    # 限制 20 个，每个最长 30 字符
    result_list = [kw[:30] for kw in sorted(keywords)][:20]
    return result_list


# ═══════════════════════════════════════════════════════════════════
# Step 8 & 9: 组装 & 输出
# ═══════════════════════════════════════════════════════════════════

def build_skill_config(result: ScanResult) -> dict[str, Any]:
    """构建 skill_config 对象。"""
    is_tool = result.skill_type == "tool"

    # tools 推断
    tools: list[str]
    if is_tool:
        tools = ["Read", "Write", "Bash", "Grep", "Glob"]
        # 检测是否有 HTTP/API 代码
        body_lower = result.skill_md_body.lower()
        if any(kw in body_lower for kw in ["fetch", "http", "api", "web"]):
            if "WebFetch" not in tools:
                tools.append("WebFetch")
    else:
        tools = ["Read", "Grep", "Glob"]

    # resources
    resources: list[str] = []
    for dname in ("scripts", "lib", "src", "assets", "templates", "resources"):
        if any(f.startswith(dname + "/") for f in result.all_files):
            resources.append(f"./{dname}/")

    # references
    references: list[str] = []
    ref_dirs = ("references", "rules")
    for dname in ref_dirs:
        for f in result.all_files:
            if f.startswith(dname + "/") and f.endswith(".md"):
                references.append(f"./{f}")

    config: dict[str, Any] = {
        "skill_md_path": "./SKILL.md" if result.has_skill_md else "./SKILL.md",
        "model": result.frontmatter.get("model") or None,
        "tools": tools,
        "resources": resources,
        "references": references,
    }
    return config


def build_installation(result: ScanResult) -> dict[str, Any]:
    """构建 installation 对象。"""
    name = to_kebab_case(result.frontmatter.get("name") or result.directory_name)
    is_tool = result.skill_type == "tool"

    # 辅助：递归查找项目配置文件
    def _has_config_file(filename: str) -> bool:
        if (result.directory_path / filename).exists():
            return True
        for f in result.all_files:
            if f.endswith(f"/{filename}"):
                return True
        return False

    # method 推断
    if not is_tool:
        method = "copy_directory"
    elif _has_config_file("package.json"):
        method = "npm_install"
    elif _has_config_file("requirements.txt") or _has_config_file("pyproject.toml"):
        method = "pip_install"
    elif _has_config_file("Dockerfile"):
        method = "docker_run"
    else:
        method = "manual_steps"

    targets = [{
        "client": "claude-code",
        "destination": f"~/.claude/skills/{name}/",
    }]

    # command（工具类）
    command = ""
    if is_tool:
        # 查找 package.json（可能在子目录）
        pkg_path = result.directory_path / "package.json"
        if not pkg_path.exists():
            for f in result.all_files:
                if f.endswith("/package.json"):
                    pkg_path = result.directory_path / f
                    break
        if pkg_path.exists():
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
                scripts = pkg.get("scripts", {})
                if isinstance(scripts, dict):
                    if "start" in scripts:
                        command = scripts["start"]
                    elif "build" in scripts:
                        command = scripts["build"]
            except (json.JSONDecodeError, OSError):
                pass
        if not command:
            _, docker_cmd = extract_docker_deps(result)
            if docker_cmd:
                command = docker_cmd

    inst: dict[str, Any] = {
        "method": method,
        "targets": targets,
    }
    if command:
        inst["command"] = command
    return inst


# ═══════════════════════════════════════════════════════════════════
# ── 公共 API ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

def extract_single_skill(
    source_dir: str | Path,
    repo_url: str = "",
    subdirectory: str | None = None,
) -> dict[str, Any]:
    """提取单个 Skill 目录的完整 agent-package 元数据。

    这是给外部调用者的核心 API。同时适用于:
      - 本地裸文件目录（无 .git）
      - git clone 结果目录（自动提取 commit_hash/ref/repo_url）

    Args:
        source_dir: Skill 目录路径（可以是仓库子目录）
        repo_url: GitHub 仓库 HTTPS URL（如已知可传入；否则自动从 .git remote 提取）

    Returns:
        符合 agent-package.schema.json 的完整 dict

    Raises:
        FileNotFoundError: 目录不存在
        ValueError: 目录内无 SKILL.md 或等效 .md 文件
    """
    source_path = Path(source_dir).resolve()
    if not source_path.is_dir():
        raise FileNotFoundError(f"目录不存在: {source_path}")

    result = scan_directory(source_path)
    if not result.has_skill_md and not (
        result.has_manifest or result.has_plugin_manifest
    ):
        raise ValueError(
            f"目录内无 SKILL.md/其他 .md 文件，也无 manifest.json/plugin.json: "
            f"{source_path}"
        )

    git_root = _find_git_root(source_path)

    data = build_metadata_json(result, repo_url=repo_url, git_root=git_root, subdirectory=subdirectory)
    issues = validate_metadata(data, result.directory_name)
    if issues:
        log.warning("[%s] 校验发现 %d 个问题: %s",
                     result.directory_name, len(issues), "; ".join(issues[:3]))

    return data


def build_metadata_json(
    result: ScanResult,
    repo_url: str = "",
    git_root: Path | None = None,
    subdirectory: str | None = None,
) -> dict[str, Any]:
    """根据 ScanResult 构建完整的 agent-package JSON 对象。

    Args:
        result: 目录扫描结果
        repo_url: 外部传入的 GitHub 仓库 URL（git clone 场景有值）
        git_root: Git 仓库根目录（用于提取 commit_hash/ref）
    """
    name_kebab = to_kebab_case(
        result.frontmatter.get("name") or result.directory_name)

    # description
    description = ""
    fm_desc = result.frontmatter.get("description")
    if fm_desc and isinstance(fm_desc, str) and fm_desc.strip():
        description = fm_desc.strip()[:200]
    else:
        description = first_paragraph(result.skill_md_body, 200)
    if not description or len(description) < 10:
        description = "No description available — manual review required"

    # author
    fm_author = result.frontmatter.get("author")
    fm_email = result.frontmatter.get("email")
    fm_url = result.frontmatter.get("url")

    # ── 回退：从父目录 package.json 提取 author ──
    if not fm_author:
        for parent_dir in _get_parent_dirs(result.directory_path):
            pkg_path = parent_dir / "package.json"
            if pkg_path.exists():
                try:
                    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
                    pkg_author = pkg.get("author")
                    if pkg_author:
                        if isinstance(pkg_author, str):
                            fm_author = pkg_author
                        elif isinstance(pkg_author, dict):
                            fm_author = pkg_author.get("name", str(pkg_author))
                            if not fm_email and pkg_author.get("email"):
                                fm_email = pkg_author["email"]
                            if not fm_url and pkg_author.get("url"):
                                fm_url = pkg_author["url"]
                    if fm_author:
                        break
                except (json.JSONDecodeError, OSError):
                    pass

    author: dict[str, str] = {
        "name": str(fm_author) if fm_author else "UNKNOWN",
        "email": str(fm_email) if fm_email else "unknown@unknown.org",
    }
    if fm_url:
        author["url"] = str(fm_url)

    # compatibility
    fm_comp = result.frontmatter.get("compatibility")
    if fm_comp:
        if isinstance(fm_comp, str):
            fm_comp = [c.strip() for c in fm_comp.split(",")]
        compatibility = [c for c in fm_comp if c in VALID_CLIENTS]
    else:
        compatibility = ["claude-code"]
    if not compatibility:
        compatibility = ["claude-code"]

    # 其他
    category = infer_category(result)
    keywords = extract_keywords(result)
    homepage = result.frontmatter.get("homepage") or result.frontmatter.get("url") or None
    icon = None
    for f in result.all_files:
        base = os.path.basename(f)
        if base in ("icon.png", "icon.svg"):
            icon = f"./{f}"
            break

    # dependencies & entry_points
    dependencies = build_dependencies(result)
    entry_points = extract_entry_points(result)
    pkg_type = _infer_package_type(result)

    # ── 若仓库自带 agent-package manifest.json，优先保留其显式声明 ──
    # 扫描器无法可靠推断 MCP server 注册信息（dependencies.mcp_servers）
    # 以及 npm/pip/docker 等安装方式与 targets；仓库 manifest 是权威来源。
    installation = build_installation(result)
    manifest_path = result.directory_path / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_deps = manifest.get("dependencies")
            if isinstance(manifest_deps, dict):
                merged = dict(dependencies or {})
                for dep_key, dep_value in manifest_deps.items():
                    if dep_value is not None:
                        merged[dep_key] = dep_value
                dependencies = merged or None
            manifest_install = manifest.get("installation")
            if isinstance(manifest_install, dict) and manifest_install.get("method"):
                installation = {**installation, **manifest_install}
        except (json.JSONDecodeError, OSError):
            pass

    # 构建 JSON
    data: dict[str, Any] = {
        "$schema": "https://trusted-agent-hub.dev/schemas/agent-package.schema.json",
        "name": name_kebab,
        "version": extract_version(result),
        "type": pkg_type,
        "description": description,
        "author": author,
        "license": extract_license(result),
        "source": extract_git_source(result, repo_url=repo_url, git_root=git_root),
        "integrity": extract_integrity(result),
        "compatibility": compatibility,
        "permissions": infer_permissions(result),
        "installation": installation,
    }
    if pkg_type == "skill":
        data["skill_config"] = build_skill_config(result)

    # 可选字段（有值才加）
    if keywords:
        data["keywords"] = keywords
    if category:
        data["category"] = category
    if homepage:
        data["homepage"] = str(homepage)
    if icon:
        data["icon"] = icon
    if dependencies:
        data["dependencies"] = dependencies
    if entry_points:
        data["entry_points"] = entry_points
    if subdirectory:
        data["source"]["subdirectory"] = subdirectory

    return data


# ═══════════════════════════════════════════════════════════════════
# ── 校验 ──────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
VERSION_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$")
COMMIT_HASH_PATTERN = re.compile(r"^[a-f0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def validate_metadata(data: dict[str, Any], skill_name: str) -> list[str]:
    """校验 JSON 元数据，返回错误/警告列表。"""
    issues: list[str] = []

    # 11 个 required 顶层字段
    required_top = [
        "name", "version", "type", "description", "author",
        "license", "source", "integrity", "compatibility",
        "permissions", "installation",
    ]
    for field in required_top:
        if field not in data:
            issues.append(f"缺少必填字段: {field}")

    # type == "skill" → 必须有 skill_config
    if data.get("type") == "skill" and "skill_config" not in data:
        issues.append("type 为 skill 时缺少必填字段: skill_config")

    # name pattern
    name = data.get("name", "")
    if not NAME_PATTERN.match(name):
        issues.append(f"name '{name}' 不符合 kebab-case 格式")

    # version pattern
    ver = data.get("version", "")
    if not VERSION_PATTERN.match(ver):
        issues.append(f"version '{ver}' 不符合 SemVer 格式")

    # description 长度
    desc = data.get("description", "")
    if len(desc) < 10:
        issues.append(f"description 长度不足 10 字符: {len(desc)}")
    if len(desc) > 200:
        issues.append(f"description 长度超过 200 字符: {len(desc)}")

    # author required 字段
    author = data.get("author", {})
    if not author.get("name"):
        issues.append("author.name 为空")
    if not author.get("email"):
        issues.append("author.email 为空")

    # source required 字段
    src = data.get("source", {})
    for sf in ("type", "repository_url", "ref", "commit_hash"):
        if sf not in src:
            issues.append(f"source 缺少必填字段: {sf}")
    ch = src.get("commit_hash", "")
    if ch and not COMMIT_HASH_PATTERN.match(ch):
        issues.append(f"source.commit_hash 格式不正确: {ch}")

    # integrity.sha256
    integ = data.get("integrity", {})
    sh = integ.get("sha256", "")
    if sh and not SHA256_PATTERN.match(sh):
        issues.append(f"integrity.sha256 格式不正确")

    # permissions required
    perms = data.get("permissions", {})
    for pf in ("filesystem", "shell", "network", "environment"):
        if pf not in perms:
            issues.append(f"permissions 缺少必填域: {pf}")

    # installation required
    inst = data.get("installation", {})
    if "method" not in inst:
        issues.append("installation 缺少必填字段: method")
    if "targets" not in inst:
        issues.append("installation 缺少必填字段: targets")

    # skill_config 仅对 skill 类型必填
    if data.get("type") == "skill":
        sc = data.get("skill_config", {})
        if "skill_md_path" not in sc:
            issues.append("skill_config 缺少必填字段: skill_md_path")

    return issues



