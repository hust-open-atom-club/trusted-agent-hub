"""SR-020: Static checks for package installers and lifecycle entry points."""

from __future__ import annotations

import json
import posixpath
import re
from typing import Any


_DESTRUCTIVE_PATTERNS = (
    r"\bfs\.(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(",
    r"\b(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir))\s*\(",
    r"\brm\s+-[rf]+\b",
    r"\brsync\b[^\n]*--delete\b",
)


def _package_json_paths(scanner: Any) -> list[str]:
    """Return every bounded, loaded package manifest in stable path order."""
    paths = getattr(scanner, "scanned_files", None)
    if paths is None:
        paths = getattr(scanner, "_file_contents", {}).keys()

    normalized_paths = {
        posixpath.normpath(str(path).replace("\\", "/"))
        for path in paths
        if posixpath.basename(str(path).replace("\\", "/")) == "package.json"
    }
    return sorted(normalized_paths)


def _read_package_json(scanner: Any, manifest_path: str) -> dict[str, Any] | None:
    content = scanner._read_file_content(manifest_path)
    if not content:
        return None
    try:
        value = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _relative_target(manifest_path: str, value: str) -> str:
    """Resolve a package bin entry relative to its own package manifest."""
    manifest_dir = posixpath.dirname(manifest_path)
    return posixpath.normpath(
        posixpath.join(manifest_dir, value.replace("\\", "/"))
    )


def run(scanner: Any) -> None:
    """Inspect executable package entry points without executing them."""
    for manifest_path in _package_json_paths(scanner):
        package = _read_package_json(scanner, manifest_path)
        if not package:
            continue

        targets: list[tuple[str, str]] = []
        bin_field = package.get("bin")
        if isinstance(bin_field, str):
            targets.append((
                f"{manifest_path}.bin",
                _relative_target(manifest_path, bin_field),
            ))
        elif isinstance(bin_field, dict):
            for name, value in bin_field.items():
                if isinstance(value, str):
                    targets.append((
                        f"{manifest_path}.bin.{name}",
                        _relative_target(manifest_path, value),
                    ))

        lifecycle = package.get("scripts")
        if isinstance(lifecycle, dict):
            for name in ("preinstall", "install", "postinstall"):
                command = lifecycle.get(name)
                if isinstance(command, str) and command.strip():
                    scanner._add_finding(
                        rule_id="SR-020",
                        severity="medium",
                        category="supply_chain",
                        title=f"安装生命周期脚本: {name} ({manifest_path})",
                        description=(
                            f"{manifest_path} 声明了 {name} 生命周期脚本，"
                            "安装时会自动执行命令。"
                        ),
                        location={"file": manifest_path},
                        evidence=f"清单={manifest_path}；{name}: {command[:160]}",
                        remediation="安装前展示生命周期命令并要求确认；避免从不受信任输入拼接命令。",
                        requires_confirmation=True,
                    )

        for source, target in targets:
            content = scanner._read_file_content(target)
            if not content:
                continue
            lines = content.splitlines()
            for pattern in _DESTRUCTIVE_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if not match:
                    continue
                line = content.count("\n", 0, match.start()) + 1
                line_text = lines[line - 1] if 0 < line <= len(lines) else ""
                arbitrary_target = bool(re.search(
                    r"(?:process\.argv|--path|targetDir|path\.resolve|input)",
                    content,
                    re.IGNORECASE,
                ))
                # A bin entry point is not run merely because the skill is present;
                # the user explicitly invokes it.  Keep the destructive behavior in
                # the audit report, but model it as a confirmation gate rather than
                # as an automatic high-risk runtime capability.  Runtime code and
                # automatic lifecycle scripts are assessed by their own rules.
                severity = "medium"
                scanner._add_finding(
                    rule_id="SR-020",
                    severity=severity,
                    category="supply_chain",
                    title=f"安装器包含破坏性文件操作 ({manifest_path})",
                    description=(
                        f"{manifest_path} 的安装入口 {target} 包含递归删除、"
                        "删除同步或等效破坏性操作。"
                        + ("目标路径可能来自用户输入。" if arbitrary_target else "")
                    ),
                    location={"file": target, "line": line, "snippet": line_text[:240]},
                    evidence=f"清单={manifest_path}；来源={source}；匹配模式={match.group()[:120]}",
                    remediation=(
                        "限制目标路径在允许的 skills 根目录内，使用显式 --force 和用户确认；"
                        "不要无条件递归删除任意目录。"
                    ),
                    requires_confirmation=True,
                )
                break
