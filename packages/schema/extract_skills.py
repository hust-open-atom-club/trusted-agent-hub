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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from scanners.risk_scanner.inventory import (
    ScanInventory,
    build_inventory,
    load_text_files,
)
from scanners.risk_scanner.policy import ScanPolicy

# ── 共享 YAML frontmatter 解析器 ─────────────────────────────────
try:
    from packages.schema.frontmatter import split_frontmatter
except ModuleNotFoundError:  # 允许直接执行本文件
    from frontmatter import split_frontmatter

# ── 日志 ──────────────────────────────────────────────────────────
log = logging.getLogger("extract_skills")

# ═══════════════════════════════════════════════════════════════════
# 常量（对齐 constants.py / agent-package.schema.json）
# ═══════════════════════════════════════════════════════════════════

# 代码文件扩展名 & 项目配置文件名 → 判定为"工具类 Skill"
CODE_EXTENSIONS: set[str] = {
    ".py", ".pyw",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1",
    ".go", ".rs", ".java", ".kt", ".swift", ".scala",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm",
    ".rb", ".php", ".pl", ".lua",
}
PERMISSION_INFERENCE_MAX_CODE_FILES = 128
PERMISSION_INFERENCE_MAX_FILE_BYTES = 512 * 1024
PERMISSION_INFERENCE_MAX_TOTAL_BYTES = 4 * 1024 * 1024
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

# 推断系统依赖
SYSTEM_DEPENDENCY_HINTS: dict[str, str] = {
    ".sh": "bash",
    ".py": "python",
    ".js": "node",
    ".jsx": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".tsx": "node",
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


def _parse_json_object(text: str, source: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        log.warning("无法解析 JSON 对象 %s: %s", source, exc)
        return {}
    if not isinstance(value, dict):
        log.warning("JSON 根节点必须是对象: %s", source)
        return {}
    return value


def _require_safe_source_subdirectory(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source subdirectory must be a non-blank string")
    if "\x00" in value or "\\" in value:
        raise ValueError("source subdirectory must use safe POSIX path syntax")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("source subdirectory must be relative")
    if value != "." and any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("source subdirectory must not contain empty or traversal segments")
    return value


def first_paragraph(text: str, max_len: int = 200) -> str:
    """提取文本中第一个有意义段落（跳过 frontmatter 和标题行）。"""
    _parsed, body = split_frontmatter(text)
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
    permission_evidence: list[dict[str, Any]] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict, repr=False)
    inventory: ScanInventory | None = field(default=None, repr=False)

    def text(self, relative_path: str | Path) -> str | None:
        """Return text from the bounded scan snapshot, never from disk."""
        key = Path(relative_path).as_posix()
        if key.startswith("./"):
            key = key[2:]
        return self.file_contents.get(key)

    def json_object(self, relative_path: str | Path) -> dict[str, Any]:
        text = self.text(relative_path)
        if text is None:
            return {}
        return _parse_json_object(text, relative_path)

    def has_file(self, relative_path: str | Path) -> bool:
        key = Path(relative_path).as_posix()
        if key.startswith("./"):
            key = key[2:]
        return key in self.all_files


def scan_directory(
    skill_dir: Path,
    *,
    policy: ScanPolicy | None = None,
    inventory: ScanInventory | None = None,
    file_contents: dict[str, str] | None = None,
) -> ScanResult:
    """扫描单个 Skill 目录，判定类型并提取基础信息。

    All discovery and reads use one bounded inventory.  Callers that already
    scanned the directory can pass the scanner's inventory and text snapshot
    to avoid a second traversal and, critically, to preserve the same budget.
    """
    skill_dir = skill_dir.resolve()
    effective_policy = (
        policy or (inventory.policy if inventory else None) or ScanPolicy()
    )
    if (
        policy is not None
        and inventory is not None
        and inventory.policy not in {None, policy}
    ):
        raise ValueError("inventory policy does not match extraction policy")
    if inventory is None:
        inventory = build_inventory(skill_dir, effective_policy)
    if file_contents is None:
        file_contents = load_text_files(inventory, policy=effective_policy)

    for record in inventory.files:
        try:
            record.absolute_path.relative_to(skill_dir)
        except ValueError as exc:
            raise ValueError("inventory is outside the extraction root") from exc

    inventory_paths = {record.relative_path for record in inventory.files}
    result = ScanResult(
        directory_name=skill_dir.name,
        directory_path=skill_dir,
        all_files=[record.relative_path for record in inventory.files],
        file_contents={
            path: content for path, content in file_contents.items()
            if path in inventory_paths
        },
        inventory=inventory,
    )

    for rel in result.all_files:
        path = Path(rel)
        if path.suffix.lower() in CODE_EXTENSIONS or path.name in PROJECT_CONFIG_FILES:
            result.has_code = True

    # 查找 SKILL.md
    skill_md_candidate = skill_dir / "SKILL.md"
    if result.text("SKILL.md") is not None:
        result.has_skill_md = True
        result.skill_md_path = skill_md_candidate
    else:
        # 回退：找目录内最大的 .md 文件
        md_records = [
            record for record in inventory.files
            if record.relative_path.lower().endswith(".md")
            and "/" not in record.relative_path
            and record.relative_path in result.file_contents
        ]
        if md_records:
            largest_record = max(md_records, key=lambda item: item.size_bytes)
            largest = skill_dir / largest_record.relative_path
            result.has_skill_md = True
            result.skill_md_path = largest
            log.warning("%s: 无 SKILL.md，使用 %s 作为替代",
                         skill_dir.name, largest.name)

    # 解析 frontmatter 和正文
    if result.has_skill_md and result.skill_md_path:
        relative_skill_path = result.skill_md_path.relative_to(skill_dir).as_posix()
        full_text = result.text(relative_skill_path) or ""
        parsed, body = split_frontmatter(full_text)
        result.frontmatter = parsed.data
        result.skill_md_body = body

    # 判定类型
    result.skill_type = "tool" if result.has_code else "prompt"

    # 识别能力包 manifest（plugin.json / manifest.json）
    manifest_candidates = [
        skill_dir / ".claude-plugin" / "plugin.json",
        skill_dir / "manifest.json",
        skill_dir / "plugin.json",
    ]
    for manifest_path in manifest_candidates:
        relative_manifest = manifest_path.relative_to(skill_dir).as_posix()
        if result.text(relative_manifest) is not None:
            result.has_manifest = True
            if manifest_path.name == "plugin.json":
                result.has_plugin_manifest = True
            result.manifest_data = result.json_object(relative_manifest)
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
    *,
    policy: ScanPolicy | None = None,
    inventory: ScanInventory | None = None,
    file_contents: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """发现仓库中的多个能力包目录（多 Skill / MCP / Plugin 仓库）。

    命中 manifest / SKILL.md 的目录视为一个能力包边界，不再深入其子目录。
    返回按深度排序的 [{path, name, type}]。
    """
    root = Path(source_dir).resolve()
    effective_policy = (
        policy or (inventory.policy if inventory else None) or ScanPolicy()
    )
    if (
        policy is not None
        and inventory is not None
        and inventory.policy not in {None, policy}
    ):
        raise ValueError("inventory policy does not match discovery policy")
    if inventory is None:
        inventory = build_inventory(root, effective_policy)
    if file_contents is None:
        file_contents = load_text_files(inventory, policy=effective_policy)

    for record in inventory.files:
        try:
            record.absolute_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("inventory is outside the discovery root") from exc

    found: list[dict[str, str]] = []
    seen: set[str] = set()

    relative_files = {record.relative_path for record in inventory.files}
    directories: set[Path] = {Path(".")}
    for relative_file in relative_files:
        path = Path(relative_file)
        directory_parts = path.parts[:-1]
        if any(
            part in _SKIP_CAPABILITY_DIRS or part.startswith(".")
            for part in directory_parts
        ):
            continue
        directory = Path(*directory_parts) if directory_parts else Path(".")
        depth = 0 if directory == Path(".") else len(directory.parts)
        if depth <= min(max_depth, effective_policy.max_depth):
            directories.add(directory)

    boundaries: list[Path] = []
    for rel_dir in sorted(directories, key=lambda item: (len(item.parts), item.as_posix())):
        if any(parent == rel_dir or parent in rel_dir.parents for parent in boundaries):
            continue
        current = root if rel_dir == Path(".") else root / rel_dir
        depth = 0 if rel_dir == Path(".") else len(rel_dir.parts)

        def relative_file(name: str) -> str:
            return name if depth == 0 else (rel_dir / name).as_posix()

        ptype: str | None = None
        name: str | None = None
        skill_md = relative_file("SKILL.md")
        plugin_manifest = relative_file(".claude-plugin/plugin.json")
        plugin_json = relative_file("plugin.json")
        manifest_json = relative_file("manifest.json")

        if skill_md in relative_files:
            ptype = "skill"
            skill_text = file_contents.get(skill_md)
            if skill_text is not None:
                try:
                    name = split_frontmatter(skill_text)[0].data.get("name")
                except Exception:
                    pass
        elif plugin_manifest in relative_files or plugin_json in relative_files:
            ptype = "plugin"
        elif manifest_json in relative_files:
            manifest_text = file_contents.get(manifest_json)
            manifest = (
                _parse_json_object(manifest_text, manifest_json)
                if manifest_text is not None else {}
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
        boundaries.append(rel_dir)

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


def extract_license(result: ScanResult) -> str:
    """从受限快照中的 license 元数据提取 SPDX 标识符。"""
    for fname in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        text = result.text(fname)
        if text is not None:
            spdx = detect_license(text)
            if spdx != "UNLICENSED":
                return spdx

    pkg = result.json_object("package.json")
    if "license" in pkg:
        return str(pkg["license"])

    text = result.text("pyproject.toml")
    if text is not None:
        m = re.search(r'license\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)

    return "UNLICENSED"


# ═══════════════════════════════════════════════════════════════════
# Step 2 & 3: 版本、依赖、入口提取
# ═══════════════════════════════════════════════════════════════════

def extract_version(result: ScanResult) -> str:
    """提取版本号：VERSION > package.json > pyproject.toml > 默认。"""
    # 1) VERSION 文件
    version_text = result.text("VERSION")
    if version_text is not None:
        v = version_text.strip()
        if re.match(r"^\d+\.\d+\.\d+", v):
            return v

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
    pkg = result.json_object("package.json")
    v = pkg.get("version", "")
    if re.match(r"^\d+\.\d+\.\d+", str(v)):
        return str(v)

    # 4) pyproject.toml
    text = result.text("pyproject.toml")
    if text is not None:
        m = re.search(r'version\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)

    return "0.1.0"


def extract_package_json_deps(result: ScanResult) -> list[dict[str, str]]:
    """从 package.json 提取 npm 依赖。"""
    pkg_relative = "package.json"
    if result.text(pkg_relative) is None:
        # 也查子目录
        for f in result.all_files:
            if f.endswith("/package.json") and result.text(f) is not None:
                pkg_relative = f
                break
        else:
            return []
    pkg = result.json_object(pkg_relative)

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
        req_text = result.text(fname)
        if req_text is None:
            continue
        for line in req_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # 格式: package==version 或 package>=version 或 package
            m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+)?", line)
            if m:
                name = m.group(1)
                ver = m.group(2).strip() if m.group(2) else "*"
                deps.append({"name": name, "version": ver})

    # pyproject.toml (仅解析 [project] dependencies 列表)
    text = result.text("pyproject.toml")
    if text is not None:
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

    return deps


def extract_docker_deps(result: ScanResult) -> tuple[list[dict[str, str]], str]:
    """从 Dockerfile 提取 docker 依赖和安装命令。返回 (images, cmd)。"""
    text = result.text("Dockerfile")
    if text is None:
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

    pkg_relative = "package.json"
    if result.text(pkg_relative) is None:
        # 查子目录
        for f in result.all_files:
            if f.endswith("/package.json") and result.text(f) is not None:
                pkg_relative = f
                break
        else:
            return None
    pkg = result.json_object(pkg_relative)

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


def _load_parent_package_json(
    source_path: Path,
    policy: ScanPolicy,
) -> dict[str, Any] | None:
    """Read ancestor package metadata through a bounded snapshot."""
    max_bytes = max(policy.max_file_bytes, 0)
    candidates: list[Path] = []
    git_root = _find_git_root(source_path)
    if git_root is not None:
        candidates.append(git_root / "package.json")

    current = source_path.resolve().parent
    for _ in range(10):
        candidates.append(current / "package.json")
        parent = current.parent
        if parent == current:
            break
        current = parent

    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            with candidate.open("rb") as handle:
                raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes:
                continue
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("author"):
            return value
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

def infer_permissions(result: ScanResult) -> dict[str, Any]:
    """Infer permissions from executable evidence and conditional instructions.

    A keyword in prose is context, not proof that a package can access a
    database, delete files, or read credentials.  The returned permission
    contract remains compatible with the existing schema while the
    permission_evidence field records how each capability was inferred.
    """

    result.permission_evidence = []

    def add_evidence(
        capability: str,
        status: str,
        confidence: float,
        source: str,
        evidence: str,
        file: str | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "capability": capability,
            "status": status,
            "confidence": round(confidence, 2),
            "source": source,
            "evidence": evidence[:240],
        }
        if file:
            item["file"] = file
        result.permission_evidence.append(item)

    def read_bounded_text(relative_path: str, max_bytes: int) -> tuple[str, int] | None:
        content = result.text(relative_path)
        if content is None:
            return None
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > max_bytes:
            log.warning("permission inference skipped oversized file: %s", relative_path)
            return None
        return content, content_bytes

    code_parts: list[tuple[str, str]] = []
    code_candidates = sorted(
        filename
        for filename in result.all_files
        if Path(filename).suffix.lower() in CODE_EXTENSIONS
    )
    total_permission_bytes = 0
    for filename in code_candidates[:PERMISSION_INFERENCE_MAX_CODE_FILES]:
        read_result = read_bounded_text(filename, PERMISSION_INFERENCE_MAX_FILE_BYTES)
        if read_result is None:
            continue
        content, content_bytes = read_result
        if total_permission_bytes + content_bytes > PERMISSION_INFERENCE_MAX_TOTAL_BYTES:
            log.warning(
                "permission inference byte limit reached at file: %s",
                filename,
            )
            break
        code_parts.append((filename, content))
        total_permission_bytes += content_bytes

    def installer_paths() -> set[str]:
        """Find package entry points whose effects happen during install."""

        paths: set[str] = set()
        nonlocal total_permission_bytes
        package_candidates = sorted(
            filename
            for filename in result.all_files
            if Path(filename).name == "package.json"
        )
        for filename in package_candidates[:PERMISSION_INFERENCE_MAX_CODE_FILES]:
            remaining_bytes = PERMISSION_INFERENCE_MAX_TOTAL_BYTES - total_permission_bytes
            if remaining_bytes <= 0:
                log.warning("permission inference byte limit reached in package metadata")
                break
            read_result = read_bounded_text(
                filename, min(PERMISSION_INFERENCE_MAX_FILE_BYTES, remaining_bytes)
            )
            if read_result is None:
                continue
            package_text, package_bytes = read_result
            total_permission_bytes += package_bytes
            try:
                package = json.loads(package_text)
            except json.JSONDecodeError:
                continue
            values: list[str] = []
            bin_field = package.get("bin") if isinstance(package, dict) else None
            if isinstance(bin_field, str):
                values.append(bin_field)
            elif isinstance(bin_field, dict):
                values.extend(value for value in bin_field.values() if isinstance(value, str))
            scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
            if isinstance(scripts, dict):
                for lifecycle in ("preinstall", "install", "postinstall"):
                    command = scripts.get(lifecycle)
                    if isinstance(command, str):
                        values.extend(re.findall(
                            r"(?:node|python3?|bash|sh)\s+([^\s;&|]+)", command
                        ))
            for value in values:
                normalized = value.replace("\\", "/").lstrip("./")
                paths.add(normalized)
        return paths

    docs_text = result.skill_md_body
    if len(docs_text) > PERMISSION_INFERENCE_MAX_FILE_BYTES:
        log.warning("permission inference truncated SKILL.md content")
        docs_text = docs_text[:PERMISSION_INFERENCE_MAX_FILE_BYTES]
    code_text = "\n".join(content for _, content in code_parts)
    code_file = code_parts[0][0] if code_parts else None
    installer_file_paths = installer_paths()
    def code_matches(pattern: str) -> bool:
        return bool(re.search(pattern, code_text, re.IGNORECASE | re.MULTILINE))

    def docs_matches(pattern: str) -> bool:
        return bool(re.search(pattern, docs_text, re.IGNORECASE | re.MULTILINE))

    def domains_from(text: str) -> list[str]:
        domains = {
            match.split(":", 1)[0]
            for match in re.findall(r"https?://([^/\s\"'\`)>]+)", text)
        }
        return sorted(domains)[:10]

    # ── filesystem ────────────────────────────────────────────────
    write_pattern = (
        r"(?:fs\.(?:writeFile|appendFile|mkdir|copyFile|rename)|"
        r"writeFile(?:Sync)?|appendFile(?:Sync)?|"
        r"open\s*\([^\n]{0,120}['\"](?:w|a)|"
        r"os\.(?:makedirs|mkdir)|pathlib\.[A-Za-z]+\.write_text)"
    )
    write_files = [
        filename for filename, content in code_parts
        if re.search(write_pattern, content, re.IGNORECASE | re.MULTILINE)
    ]
    code_writes = bool(write_files)
    docs_writes = docs_matches(
        r"\b(?:write|create|save|export|update|append)\b.{0,90}"
        r"(?:file|directory|folder|\.json|\.md|\.css|\.html)"
    )
    filesystem: dict[str, Any] = {"read": ["./"], "write": [], "delete": False}
    if code_writes:
        installer_only = bool(installer_file_paths) and all(
            filename in installer_file_paths for filename in write_files
        )
        if installer_only:
            add_evidence(
                "installation.filesystem.write", "observed", 0.9, "code",
                "安装入口包含文件写入或目录创建 API", write_files[0],
            )
        else:
            filesystem["write"] = ["./"]
            add_evidence(
                "filesystem.write", "observed", 0.95, "code",
                "运行时代码包含文件写入或目录创建 API", write_files[0],
            )
    elif docs_writes:
        add_evidence(
            "filesystem.write", "conditional", 0.65, "docs",
            "技能流程要求写入项目文件", "SKILL.md",
        )

    delete_pattern = (
        r"(?:fs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)|"
        r"os\.(?:remove|unlink|rmdir)|shutil\.rmtree|\brm\s+-[rf]+)"
    )
    delete_files = [
        filename for filename, content in code_parts
        if re.search(delete_pattern, content, re.IGNORECASE | re.MULTILINE)
    ]
    code_deletes = bool(delete_files)
    docs_deletes = docs_matches(
        r"(?:\brm\s+-[rf]+|\bunlink\b|\brsync\b[^\n]*--delete|"
        r"\bdelete\b.{0,60}\b(?:file|directory|folder)\b)"
    )
    if code_deletes:
        installer_only = bool(installer_file_paths) and all(
            filename in installer_file_paths for filename in delete_files
        )
        if installer_only:
            add_evidence(
                "installation.filesystem.delete", "observed", 0.9, "code",
                "安装入口包含递归删除、文件删除或 rm 命令", delete_files[0],
            )
        else:
            filesystem["delete"] = True
            add_evidence(
                "filesystem.delete", "observed", 0.98, "code",
                "运行时代码包含递归删除、文件删除或 rm 命令", delete_files[0],
            )
    elif docs_deletes:
        add_evidence(
            "filesystem.delete", "conditional", 0.6, "docs",
            "文档流程包含删除文件或 --delete 操作", "SKILL.md",
        )

    # ── shell ─────────────────────────────────────────────────────
    shell_commands: set[str] = set()
    known_shell_commands = {
        "bash", "sh", "zsh", "pwsh", "powershell", "python", "python3",
        "node", "npm", "npx", "pip", "pip3", "docker", "git", "gh",
        "curl", "wget", "ssh", "scp", "rsync", "make", "cat", "grep",
        "sed", "awk", "find", "rm", "chmod", "chown", "tar", "unzip",
        "zip", "readelf", "objdump", "strings", "checksec", "ropper",
        "ropgadget",
    }
    for filename in result.all_files:
        ext = Path(filename).suffix.lower()
        if ext in SYSTEM_DEPENDENCY_HINTS:
            shell_commands.add(SYSTEM_DEPENDENCY_HINTS[ext])
    for block in re.findall(r"\`([^\`]+)\`", docs_text):
        command = block.strip().split(None, 1)[0] if block.strip() else ""
        command = command.rsplit("/", 1)[-1]
        if command.lower() in known_shell_commands:
            shell_commands.add(command.lower())

    shell_process_api = code_matches(
        r"(?:child_process\.(?:exec|execFile|spawn|fork)|"
        r"subprocess\.(?:run|Popen|call|check_call|check_output)|"
        r"os\.system\s*\(|Runtime\.getRuntime\(\)\.exec)"
    )
    script_files = [
        filename for filename in result.all_files
        if Path(filename).suffix.lower() in {".sh", ".bash", ".zsh", ".bat", ".ps1"}
    ]
    shell_observed = shell_process_api or bool(script_files)
    docs_commands = docs_matches(
        r"(?:\b(?:run|execute|start|stop|invoke)\b.{0,50}\`[^\`]+\`|"
        r"\b(?:ssh|scp|gh\s+api|npm|npx|python3?|node|bash|sh)\b)"
    )
    shell_allowed = shell_observed
    shell: dict[str, Any] = {
        "allowed": shell_allowed,
        "commands": sorted(shell_commands) if shell_allowed else [],
    }
    if shell_observed:
        shell["description"] = "技能包含脚本或流程命令，具体执行需按条件确认"
        add_evidence(
            "shell",
            "observed",
            0.95 if shell_process_api else 0.85,
            "code",
            "代码包含进程执行 API" if shell_process_api else "包内包含 Shell/脚本入口",
            code_file,
        )
    elif docs_commands:
        add_evidence(
            "shell", "conditional", 0.6, "docs",
            "技能文件或流程包含可执行命令", "SKILL.md",
        )

    # ── network ───────────────────────────────────────────────────
    code_network = code_matches(
        r"(?:\b(?:fetch|axios|curl|wget|requests?\.(?:get|post|request)|"
        r"urllib\.request|http\.(?:get|request)|https?\.request)\b|"
        r"\b(?:ssh|scp)\s+-)"
    )
    docs_network = docs_matches(
        r"(?:https?://|\b(?:fetch|download|connect|request|deploy|curl|wget|"
        r"ssh|scp|gh\s+api)\b)"
    )
    network_allowed = code_network
    network_domains = domains_from(code_text) if code_network else []
    network: dict[str, Any] = {
        "allowed": network_allowed,
        "domains": network_domains,
    }
    if code_network:
        network["description"] = "代码包含网络调用"
        add_evidence(
            "network",
            "observed", 0.95, "code", "代码包含网络调用", code_file,
        )
    elif docs_network:
        add_evidence(
            "network", "conditional", 0.6, "docs",
            "技能流程包含明确网络访问动作", "SKILL.md",
        )

    # ── environment ──────────────────────────────────────────────
    env_read: set[str] = set()
    for match in re.finditer(
        r"(?:process\.env(?:\.([A-Z][A-Z0-9_]*)|\[['\"]([A-Z][A-Z0-9_]*)['\"]\])|"
        r"os\.environ(?:\.get)?\(['\"]([A-Z][A-Z0-9_]*)['\"]\)|"
        r"os\.getenv\(['\"]([A-Z][A-Z0-9_]*)['\"]\))",
        code_text,
    ):
        env_read.update(item for item in match.groups() if item)
    env_write = set(
        re.findall(r"process\.env\.([A-Z][A-Z0-9_]*)\s*=", code_text)
    )
    env_write.update(
        re.findall(
            r"os\.environ\[['\"]([A-Z][A-Z0-9_]*)['\"]\]\s*=",
            code_text,
        )
    )
    environment: dict[str, Any] = {
        "read": sorted(env_read),
        "write": sorted(env_write),
    }
    if env_read:
        add_evidence(
            "environment.read", "observed", 0.95, "code",
            "代码读取环境变量", code_file,
        )
    if env_write:
        add_evidence(
            "environment.write", "observed", 0.95, "code",
            "代码写入环境变量", code_file,
        )

    permissions: dict[str, Any] = {
        "filesystem": filesystem,
        "shell": shell,
        "network": network,
        "environment": environment,
    }

    # ── credentials ──────────────────────────────────────────────
    code_credentials = code_matches(
        r'''(?:process\.env(?:\.[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|'''
        r'''AUTH(?:ORIZATION)?[_-]?(?:TOKEN|KEY)|TOKEN|SECRET|PASSWORD|'''
        r'''CREDENTIAL|PRIVATE[_-]?KEY|SSH[_-]?KEY))|'''
        r'''process\.env\[['"][^'"]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|'''
        r'''AUTH(?:ORIZATION)?[_-]?(?:TOKEN|KEY)|TOKEN|SECRET|PASSWORD|'''
        r'''CREDENTIAL|PRIVATE[_-]?KEY|SSH[_-]?KEY)[^'"]*['"]\]|'''
        r'''os\.(?:getenv|environ(?:\.get)?)\(['"][^'"]*(?:API[_-]?KEY|'''
        r'''ACCESS[_-]?TOKEN|AUTH(?:ORIZATION)?[_-]?(?:TOKEN|KEY)|TOKEN|'''
        r'''SECRET|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|SSH[_-]?KEY)[^'"]*['"]\)|'''
        r'''ssh\s+-i|private[_ -]?key|keytar|secret[_ -]?manager|getpass|'''
        r'''(?:readFile(?:Sync)?|read_text)\([^\n]{0,100}(?:token|secret|credential|key)'''
        r''')'''
    )
    docs_credentials = docs_matches(
        r"\b(?:set|export|provide|configure|enter|use|confirm|pass)\b.{0,45}"
        r"\b(?:api key|api_key|token|password|ssh key|credential)\b"
    )
    if code_credentials:
        credential_source = code_text + docs_text
        access = (
            ["ssh_key"]
            if re.search(r"ssh\s+key|ssh\s+-i|private[_ -]?key", credential_source, re.I)
            else ["api_key"]
            if re.search(r"api[_ -]?key|access[_ -]?token|auth(?:entication|orization)?[_ -]?(?:token|key)|openai|anthropic", credential_source, re.I)
            else ["session_token"]
        )
        permissions["credentials"] = {
            "access": access,
            "description": "代码或条件流程需要凭据",
        }
        add_evidence(
            "credentials",
            "observed", 0.9, "code", "代码访问凭据或密钥", code_file,
        )
    elif docs_credentials:
        add_evidence(
            "credentials", "conditional", 0.55, "docs",
            "流程要求用户提供凭据", "SKILL.md",
        )

    # ── database ──────────────────────────────────────────────────
    database_matches = code_matches(
        r"(?:sqlite3|psycopg2?|sqlalchemy|prisma|mongodb|pymongo|mysql|"
        r"postgres(?:ql)?|create_engine\s*\(|(?:sqlite|mongo|mysql|postgres).*connect)"
    )
    docs_database = docs_matches(
        r"\b(?:database|sqlite|postgres(?:ql)?|mysql|mongodb|sql)\b"
    )
    if database_matches:
        drivers = [
            driver
            for driver, pattern in (
                ("sqlite", r"sqlite"),
                ("postgresql", r"postgres|psycopg|sqlalchemy"),
                ("mysql", r"mysql"),
                ("mongodb", r"mongo|pymongo|prisma"),
            )
            if re.search(pattern, code_text, re.I)
        ]
        permissions["database"] = {
            "allowed": True,
            "drivers": sorted(set(drivers)) or ["unknown"],
            "description": "代码包含数据库驱动或连接调用",
        }
        add_evidence(
            "database", "observed", 0.95, "code",
            "代码包含数据库驱动或连接调用", code_file,
        )
    elif docs_database:
        add_evidence(
            "database", "conditional", 0.55, "docs",
            "文档提到数据库或 SQL 流程", "SKILL.md",
        )

    # ── browser ───────────────────────────────────────────────────
    code_browser = code_matches(
        r"(?:playwright|puppeteer|selenium|webdriver|chromium|page\.goto|"
        r"browser\.(?:open|launch))"
    )
    docs_browser = docs_matches(
        r"(?:playwright|puppeteer|selenium|browser automation|"
        r"open (?:a )?browser|visual companion)"
    )
    if code_browser:
        permissions["browser"] = {
            "allowed": True,
            "description": "代码包含浏览器控制调用",
        }
        add_evidence(
            "browser",
            "observed", 0.9, "code",
            "代码包含浏览器自动化调用", code_file,
        )
    elif docs_browser:
        add_evidence(
            "browser", "conditional", 0.55, "docs",
            "流程要求打开或控制浏览器", "SKILL.md",
        )

    # ── explicit permissions override inferred values ─────────────
    explicit = result.manifest_data.get("permissions")
    explicit_source = "manifest"
    if not isinstance(explicit, dict):
        explicit = result.frontmatter.get("permissions")
        explicit_source = "frontmatter"
    if isinstance(explicit, dict):
        for capability, value in explicit.items():
            if value:
                permissions[capability] = value
                add_evidence(
                    str(capability), "declared", 1.0, explicit_source,
                    "包元数据明确声明该权限",
                )

    if network_domains:
        permissions["external_services"] = [
            {
                "name": domain.split(":", 1)[0],
                "url": f"https://{domain}",
                "description": "从代码或明确网络流程中提取的外部服务",
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
        if result.has_file(filename):
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
    distribution_name = ""
    if is_tool:
        # 查找 package.json（可能在子目录）
        pkg_relative = "package.json"
        if result.text(pkg_relative) is None:
            for f in result.all_files:
                if f.endswith("/package.json") and result.text(f) is not None:
                    pkg_relative = f
                    break
        pkg = result.json_object(pkg_relative)
        if isinstance(pkg.get("name"), str):
            distribution_name = pkg["name"]
        scripts = pkg.get("scripts", {})
        if isinstance(scripts, dict):
            if "start" in scripts:
                command = scripts["start"]
            elif "build" in scripts:
                command = scripts["build"]
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
    if method == "npm_install" and distribution_name:
        inst["package"] = distribution_name
    return inst


# ═══════════════════════════════════════════════════════════════════
# ── 公共 API ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

def extract_single_skill(
    source_dir: str | Path,
    repo_url: str = "",
    subdirectory: str | None = None,
    *,
    policy: ScanPolicy | None = None,
    inventory: ScanInventory | None = None,
    file_contents: dict[str, str] | None = None,
    parent_package_json: dict[str, Any] | None = None,
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

    result = scan_directory(
        source_path,
        policy=policy,
        inventory=inventory,
        file_contents=file_contents,
    )
    if not result.has_skill_md and not (
        result.has_manifest or result.has_plugin_manifest
    ):
        raise ValueError(
            f"目录内无 SKILL.md/其他 .md 文件，也无 manifest.json/plugin.json: "
            f"{source_path}"
        )

    git_root = _find_git_root(source_path)
    effective_policy = (
        policy or (inventory.policy if inventory else None) or ScanPolicy()
    )
    if parent_package_json is None and not result.frontmatter.get("author"):
        parent_package_json = _load_parent_package_json(source_path, effective_policy)

    data = build_metadata_json(
        result,
        repo_url=repo_url,
        git_root=git_root,
        subdirectory=subdirectory,
        parent_package_json=parent_package_json,
    )
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
    parent_package_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """根据 ScanResult 构建完整的 agent-package JSON 对象。

    Args:
        result: 目录扫描结果
        repo_url: 外部传入的 GitHub 仓库 URL（git clone 场景有值）
        git_root: Git 仓库根目录（用于提取 commit_hash/ref）
    """
    if subdirectory is not None:
        subdirectory = _require_safe_source_subdirectory(subdirectory)

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

    # ── 回退：从受限快照中的当前或父级 package.json 提取 author ──
    if not fm_author:
        pkg = result.json_object("package.json")
        pkg_author = pkg.get("author")
        if not pkg_author and isinstance(parent_package_json, dict):
            pkg_author = parent_package_json.get("author")
        if pkg_author:
            if isinstance(pkg_author, str):
                fm_author = pkg_author
            elif isinstance(pkg_author, dict):
                fm_author = pkg_author.get("name", str(pkg_author))
                if not fm_email and pkg_author.get("email"):
                    fm_email = pkg_author["email"]
                if not fm_url and pkg_author.get("url"):
                    fm_url = pkg_author["url"]

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
    manifest_text = result.text("manifest.json")
    if manifest_text is not None:
        manifest = _parse_json_object(manifest_text, "manifest.json")
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
    if result.permission_evidence:
        data["permission_evidence"] = result.permission_evidence
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
    if subdirectory is not None:
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



