"""Trust Scan Router — URL 识别、代码拉取、扫描调度与结果获取。

端点:
    POST /scan              — 提交扫描任务（URL 或文件上传）
    GET  /scan/{scan_id}    — 查询扫描状态
    GET  /scan/{scan_id}/report — 获取完整扫描报告
"""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time as _time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from src.auth import require_role, verify_resource_access
from src.dependencies import CurrentUser
from src.services.artifacts import force_rmtree
from src.services.source_snapshots import SourceSnapshotStore

router = APIRouter(tags=["trust-scan"])

# ---------------------------------------------------------------------------
# 项目路径推导
# ---------------------------------------------------------------------------
_API_SRC_DIR = Path(__file__).resolve().parent.parent  # apps/api/src/
_PROJECT_ROOT = _API_SRC_DIR.parent.parent.parent  # repo root
_SCANNER_PATH = _PROJECT_ROOT / "scanners" / "risk_scanner" / "scanner.py"
_EXTRACTOR_PATH = _PROJECT_ROOT / "packages" / "schema" / "extract_skills.py"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
from scanners.risk_scanner.redaction import build_finding_contexts, redact_report

# ---------------------------------------------------------------------------
# 内存状态存储（scans 字典）
# ---------------------------------------------------------------------------
# key: scan_id, value: {status, package_name, created_at, finished_at, report_path, error, expires_at}
_scans: Dict[str, Dict[str, Any]] = {}
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()

_SCAN_TTL_SECONDS = 3600  # 临时扫描结果保留 1 小时


def _cleanup_expired_scans() -> None:
    """清理超过 TTL 的临时扫描结果，避免字典无限增长。"""
    now = _time.time()
    expired = [sid for sid, info in _scans.items() if info.get("expires_at", 0) < now]
    for sid in expired:
        info = _scans[sid]
        local_dir = (info.get("full_report") or {}).get("local_source_dir")
        if local_dir:
            force_rmtree(local_dir)
        del _scans[sid]


def _scan_not_found_detail(scan_id: str) -> str:
    return f"Scan '{scan_id}' not found or expired (scans are kept for 1 hour). Please re-scan."

# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """扫描提交请求。"""
    repo_url: Optional[str] = Field(default=None, description="GitHub 仓库 HTTPS URL")


class ScanResponse(BaseModel):
    """扫描任务创建响应。"""
    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str


class ScanStatusResponse(BaseModel):
    """扫描状态查询响应。"""
    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str
    finished_at: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    trust_score: Optional[Dict[str, Any]] = None
    llm_review: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# 扫描器加载（通过 importlib 动态加载）
# ---------------------------------------------------------------------------

def _load_scanner():
    """动态加载 RiskScanner 类。"""
    spec = importlib.util.spec_from_file_location(
        "risk_scanner", str(_SCANNER_PATH)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load scanner from {_SCANNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["risk_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod.RiskScanner


# ---------------------------------------------------------------------------
# 评分引擎加载
# ---------------------------------------------------------------------------

def _load_scorer():
    """动态加载 calculate_trust_score 函数。"""
    """加载评分引擎（虚拟包方式处理相对导入）。"""
    import types as _types
    ts_src = _PROJECT_ROOT / "packages" / "trust-score" / "src"
    if "src" not in sys.modules or not getattr(sys.modules["src"], "__path__", None):
        src_pkg = _types.ModuleType("src")
        src_pkg.__path__ = [str(ts_src)]
        src_pkg.__package__ = "src"
        sys.modules["src"] = src_pkg
    for name in ["provenance", "intent", "community", "derived_score", "explainer"]:
        key = f"src.{name}"
        if key not in sys.modules:
            s = importlib.util.spec_from_file_location(key, str(ts_src / f"{name}.py"))
            m = importlib.util.module_from_spec(s)
            m.__package__ = "src"
            sys.modules[key] = m
            s.loader.exec_module(m)
    ek = "src.engine"
    if ek in sys.modules:
        return sys.modules[ek].rate
    es = importlib.util.spec_from_file_location(ek, str(ts_src / "engine.py"))
    em = importlib.util.module_from_spec(es)
    em.__package__ = "src"
    sys.modules[ek] = em
    es.loader.exec_module(em)
    return em.rate


# ---------------------------------------------------------------------------
# 远程仓库获取：Phase A git clone → Phase B ZIP 下载
# ---------------------------------------------------------------------------


def _is_github_reachable(timeout: float = 5) -> bool:
    """Quick TCP connectivity check before attempting git clone."""
    try:
        s = socket.create_connection(("github.com", 443), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _git_clone_with_retries(parsed: dict[str, Any], tmp_dir: str, max_attempts: int = 2) -> bool:
    """Phase A：用 GitHub Token 认证的 git clone，重试 max_attempts 次。"""

    if not _is_github_reachable():
        print("[TAH-trust]     github.com unreachable, skipping git clone")
        return False

    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        clone_url = f"https://{token}@github.com/{parsed['owner']}/{parsed['repo']}.git"
        safe_url = f"https://***@github.com/{parsed['owner']}/{parsed['repo']}.git"
    else:
        clone_url = f"https://github.com/{parsed['owner']}/{parsed['repo']}.git"
        safe_url = clone_url

    for attempt in range(1, max_attempts + 1):
        print(f"[TAH-trust]     git clone {safe_url} (attempt {attempt}/{max_attempts}) --depth 1 ...")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, tmp_dir],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            print(f"[TAH-trust]     clone attempt {attempt} timed out after 60s")
            if attempt < max_attempts:
                _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
            continue
        if result.returncode == 0:
            print(f"[TAH-trust]     git clone OK (attempt {attempt})")
            return True
        last_err = result.stderr[:500].replace("\n", " ")
        print(f"[TAH-trust]     clone attempt {attempt} failed: {last_err}")
        if attempt < max_attempts:
            _time.sleep(3)
            force_rmtree(tmp_dir)
            os.makedirs(tmp_dir, exist_ok=True)
    return False


def _download_zipball(parsed: dict[str, Any], tmp_dir: str, max_attempts: int = 3) -> bool:
    """Phase B：通过 GitHub API 下载 ZIP 包，解压到 tmp_dir。"""
    token = os.environ.get("GITHUB_TOKEN", "")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/zipball/{parsed['ref']}"
    )
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        print(f"[TAH-trust]     ZIP 下载使用 Token 认证")
    else:
        print(f"[TAH-trust]     ZIP 下载无 Token（匿名）")

    for attempt in range(1, max_attempts + 1):
        print(f"[TAH-trust]     ZIP download (attempt {attempt}/{max_attempts}) {api_url}")
        try:
            req = urllib.request.Request(api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                zip_data = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                zf.extractall(tmp_dir)
            print(f"[TAH-trust]     ZIP download OK (attempt {attempt})")
            return True
        except Exception as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            if attempt < max_attempts:
                _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
    return False


def _git_head_hash(repo_dir: str) -> str:
    """读取 git 仓库当前 HEAD 的完整 commit hash（40 位 hex）。"""
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _acquire_repo_source(parsed: dict[str, Any]) -> tuple[str | None, str, str]:
    """级联获取代码：Phase A git clone → Phase B ZIP 下载。

    Returns:
        (repo_root, source_method, commit_hash) — repo_root 是仓库内容根目录路径，
        source_method 为 "git" 或 "zip"，commit_hash 为真实 40 位 git hash
        （git 模式读 HEAD，zip 模式从目录名提取；提取失败为空字符串）。
        失败返回 (None, "", "")。
    """
    tmp_dir = tempfile.mkdtemp(prefix=f"tah_repo_")

    print(f"[TAH-trust] === Phase A: git clone ===")
    if _git_clone_with_retries(parsed, tmp_dir):
        commit_hash = _git_head_hash(tmp_dir)
        print(f"[TAH-trust]     HEAD commit: {commit_hash[:8] if commit_hash else 'N/A'}")
        return tmp_dir, "git", commit_hash

    force_rmtree(tmp_dir)
    tmp_dir = tempfile.mkdtemp(prefix=f"tah_repo_")
    print(f"[TAH-trust] === Phase B: ZIP download ===")
    if _download_zipball(parsed, tmp_dir):
        commit_hash = ""
        # ZIP 解压后内容在一层子目录中 {owner}-{repo}-{hash}/
        entries = os.listdir(tmp_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(tmp_dir, entries[0])):
            inner = os.path.join(tmp_dir, entries[0])
            match = re.search(r"-([0-9a-f]{40})$", entries[0])
            if match:
                commit_hash = match.group(1)
            # 将内层目录内容移到 tmp_dir
            for item in os.listdir(inner):
                shutil.move(os.path.join(inner, item), os.path.join(tmp_dir, item))
            os.rmdir(inner)
        print(f"[TAH-trust]     ZIP commit: {commit_hash[:8] if commit_hash else 'N/A'}")
        return tmp_dir, "zip", commit_hash

    force_rmtree(tmp_dir)
    return None, "", ""


# ---------------------------------------------------------------------------
# 后台扫描任务
# ---------------------------------------------------------------------------


def _run_scan_task(
    scan_id: str,
    source: str,
    *,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None] | None = None,
    signals: Dict[str, Any] | None = None,
) -> None:
    """后台执行扫描流水线：acquire → scan → score → save。

    此函数在 BackgroundTasks 中异步运行。
    signals: 提交时从数据库采集的平台信号（author_history / review_records / feedback）。
    """
    try:
        print(f"\n[TAH-trust] >>> _run_scan_task 开始 scan_id={scan_id}")
        print(f"[TAH-trust]     source = {source}")

        parsed = _parse_github_url(source)
        print(f"[TAH-trust]     owner={parsed['owner']}, repo={parsed['repo']}, "
              f"ref={parsed['ref']}, subdir={parsed['subdir']}")

        _scans[scan_id]["status"] = "cloning"

        repo_root, method, commit_hash = _acquire_repo_source(parsed)
        if repo_root is None:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"] = (
                "无法获取仓库（Git clone + ZIP 下载均失败）。"
                "请检查 GitHub 连接。"
            )
            print(f"[TAH-trust] *** 获取仓库失败（git + zip 均失败）")
            if on_complete:
                on_complete(scan_id, None, _scans[scan_id]["error"])
            return
        tmp_dir = repo_root
        print(f"[TAH-trust]     仓库获取方式: {method}")

        # ── 确定扫描目标目录（子目录优先） ──
        subdir = parsed.get("subdir") if parsed else None
        if not subdir:
            root_manifest = Path(repo_root) / "manifest.json"
            if root_manifest.is_file():
                try:
                    root_data = json.loads(
                        root_manifest.read_text(encoding="utf-8")
                    )
                    declared = (root_data.get("source") or {}).get(
                        "subdirectory"
                    )
                    if declared and (Path(repo_root) / declared).is_dir():
                        subdir = declared
                        print(
                            f"[TAH-trust]     manifest 声明子目录: {subdir}"
                        )
                except (json.JSONDecodeError, OSError):
                    pass
        if subdir:
            scan_dir = os.path.join(repo_root, subdir)
            if not os.path.isdir(scan_dir):
                print(f"[TAH-trust]     子目录不存在: {scan_dir}, 回退到根目录")
                scan_dir = repo_root
            else:
                print(f"[TAH-trust]     扫描子目录: {subdir}")
        else:
            scan_dir = repo_root

        # ── 多能力发现（供提交页选择子目录） ──
        capabilities: list[dict[str, str]] = []
        try:
            if not hasattr(
                sys.modules.get("extract_skills", None),
                "discover_capabilities",
            ):
                spec = importlib.util.spec_from_file_location(
                    "extract_skills", str(_EXTRACTOR_PATH)
                )
                if spec and spec.loader:
                    extract_mod = importlib.util.module_from_spec(spec)
                    sys.modules["extract_skills"] = extract_mod
                    spec.loader.exec_module(extract_mod)
            capabilities = sys.modules["extract_skills"].discover_capabilities(
                repo_root
            )
            if subdir:
                prefix = str(subdir).rstrip("/")
                filtered = [
                    c for c in capabilities
                    if c["path"] == prefix
                    or c["path"].startswith(prefix + "/")
                ]
                if filtered:
                    capabilities = filtered
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[TAH-trust]     能力发现失败（忽略）: {exc}")
            capabilities = []
        _scans[scan_id]["capabilities"] = capabilities
        print(
            f"[TAH-trust]     发现能力包: {len(capabilities)} 个"
        )

        # Step 2: 运行扫描器
        _scans[scan_id]["status"] = "scanning"
        print(f"[TAH-trust]     加载扫描器, scan_dir={scan_dir}")
        RiskScanner = _load_scanner()
        scanner = RiskScanner(scan_dir, source_commit_hash=commit_hash)
        scan_report = scanner.scan()

        pkg_name = scan_report.get("package_name", "unknown")
        pkg_version = scan_report.get("version", "0.0.0")
        _scans[scan_id]["package_name"] = pkg_name
        print(f"[TAH-trust]     扫描完成: {pkg_name} v{pkg_version}, findings={scan_report['summary']['total']}")

        # Step 2.5: LLM 深度审查（当有 findings 时触发）
        findings = scan_report.get("findings", [])
        if findings:
            _scans[scan_id]["status"] = "llm_review"
            print(f"[TAH-trust]     LLM 审查: {len(findings)} findings 待审查...")
            try:
                _LLM_REVIEWER_PATH = _PROJECT_ROOT / "scanners" / "risk_scanner" / "llm_reviewer.py"
                spec_lr = importlib.util.spec_from_file_location(
                    "llm_reviewer", str(_LLM_REVIEWER_PATH)
                )
                if spec_lr and spec_lr.loader:
                    mod_lr = importlib.util.module_from_spec(spec_lr)
                    spec_lr.loader.exec_module(mod_lr)
                    finding_contexts = build_finding_contexts(
                        findings, scanner._file_contents,
                    )
                    llm_result = mod_lr.run_llm_review(
                        findings=findings,
                        finding_contexts=finding_contexts,
                        manifest=scanner._package_metadata,
                    )
                    for f_item in findings:
                        fid = f_item.get("id", "")
                        if fid in llm_result.get("labels", {}):
                            f_item["llm_label"] = llm_result["labels"][fid]
                    scan_report["llm_review"] = llm_result
                    print(
                        f"[TAH-trust]     LLM 审查完成: "
                        f"malicious={llm_result['labels_summary']['suspected_malicious']}, "
                        f"negligent={llm_result['labels_summary']['suspected_negligent']}, "
                        f"benign={llm_result['labels_summary']['likely_benign']}, "
                        f"uncertain={llm_result['labels_summary']['uncertain']}, "
                        f"unavailable={llm_result['labels_summary']['unavailable']}"
                    )
            except Exception as e:
                print(f"[TAH-trust]     LLM 审查跳过（{e}）")
                scan_report["llm_review"] = {
                    "triggered": True,
                    "error": str(e),
                    "fallback": "LLM review unavailable, all findings preserved",
                }
        else:
            scan_report["llm_review"] = {"triggered": False}

        snapshot_metadata = _SOURCE_SNAPSHOT_STORE.save(
            scanner._file_contents,
            source_hash=scanner._content_tree_sha256(),
        )
        scan_report["source_snapshot_id"] = snapshot_metadata["snapshot_id"]
        scan_report["source_snapshot_sha256"] = snapshot_metadata["sha256"]
        scan_report["source_snapshot_created_at"] = snapshot_metadata["created_at"]
        scan_report["source_snapshot_expires_at"] = snapshot_metadata["expires_at"]
        scan_report = redact_report(scan_report)

        # Step 3: 运行评分引擎
        _scans[scan_id]["status"] = "scoring"
        print(f"[TAH-trust]     加载评分引擎...")
        calculate_trust_score = _load_scorer()

        repo_url = parsed["base_url"] if parsed else source
        package_metadata = _build_package_metadata(scan_report, scan_dir, repo_url=repo_url, subdirectory=subdir)
        # Preserve acquisition-time facts for scoring as well as SR-009.  The
        # extractor reads package-authored metadata and must not overwrite them.
        scanned_meta = scanner._package_metadata or {}
        scanned_source = scanned_meta.get("source") or {}
        scanned_integrity = scanned_meta.get("integrity") or {}
        if isinstance(scanned_source, dict):
            package_metadata["source"] = {
                **(package_metadata.get("source") or {}),
                **scanned_source,
            }
        if isinstance(scanned_integrity, dict):
            package_metadata["integrity"] = {
                **(package_metadata.get("integrity") or {}),
                **scanned_integrity,
            }

        platform_signals = signals or {}
        trust_score_result = calculate_trust_score(
            package_metadata=package_metadata,
            scan_report=scan_report,
            author_history=platform_signals.get("author_history"),
            review_records=platform_signals.get("review_records"),
            feedback=platform_signals.get("feedback"),
        )
        if platform_signals:
            print(
                f"[TAH-trust]     平台信号接入: "
                f"author={platform_signals.get('author_history')}, "
                f"review={platform_signals.get('review_records', {}).get('status')}, "
                f"installs={platform_signals.get('feedback', {}).get('total_installs')}"
            )
        print(f"[TAH-trust]     评分完成: score={trust_score_result.get('score')}, level={trust_score_result.get('risk_summary', {}).get('level')}")

        # Step 4: 合并报告并保存到磁盘
        _scans[scan_id]["status"] = "saving"
        full_report: Dict[str, Any] = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "package_name": pkg_name,
            "version": pkg_version,
            "commit_hash": commit_hash,
            "created_at": _scans[scan_id]["created_at"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "scan_report": scan_report,
            "trust_score": trust_score_result,
            "package_metadata": package_metadata,
            "source_snapshot_id": snapshot_metadata["snapshot_id"],
            "source_snapshot_sha256": snapshot_metadata["sha256"],
            # 保留本地代码目录供提交时打包安装产物（不重新拉取）。
            # 由 handle_scan_complete 消费后清理，或随扫描记录过期清理。
            "local_source_dir": tmp_dir,
        }

        # Step 5: 更新内存状态
        _scans[scan_id].update({
            "status": "complete",
            "finished_at": full_report["finished_at"],
            "full_report": full_report,
            "package_metadata": package_metadata,
            "summary": scan_report.get("summary", {}),
            "trust_score": {
                "level": trust_score_result.get("risk_summary", {}).get("level"),
                "grade": trust_score_result.get("risk_summary", {}).get("grade"),
                "recommendation": trust_score_result.get("risk_summary", {}).get("install_recommendation"),
            },
            "llm_review": scan_report.get("llm_review"),
        })

        # 临时目录保留给提交阶段打包产物，由 handle_scan_complete / 过期清理负责删除
        if on_complete:
            on_complete(scan_id, full_report, None)
        print(f"[TAH-trust] *** 扫描流水线完成: {scan_id}, grade={trust_score_result.get('risk_summary', {}).get('grade')}")

    except Exception as exc:
        _scans[scan_id]["status"] = "error"
        err_msg = str(exc)
        token = os.environ.get("GITHUB_TOKEN", "")
        if token and token in err_msg:
            err_msg = err_msg.replace(token, "***")
        _scans[scan_id]["error"] = f"Scan failed: {type(exc).__name__}: {err_msg}"
        print(f"[TAH-trust] *** 扫描异常: {type(exc).__name__}: {err_msg}", flush=True)
        if "tmp_dir" in locals():
            force_rmtree(tmp_dir)
        if on_complete:
            on_complete(scan_id, None, err_msg)

def _build_package_metadata(scan_report: Dict[str, Any], target_dir: str, repo_url: str = "", subdirectory: str | None = None) -> Dict[str, Any]:
    """从扫描报告和目标目录构建 package_metadata 用于评分引擎。

    优先使用 extract_skills 模块进行完整提取（11 个必填字段、依赖解析、
    权限推断、分类推断）；失败时回退到原始简易逻辑。
    """
    target = Path(target_dir)

    # ── 优先：使用 extract_skills 完整提取 ──
    try:
        # 动态加载 extract_skills 模块（仅首次）
        if not hasattr(sys.modules.get("extract_skills", None), "extract_single_skill"):
            spec = importlib.util.spec_from_file_location(
                "extract_skills", str(_EXTRACTOR_PATH))
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["extract_skills"] = mod
                spec.loader.exec_module(mod)

        extract_single_skill = sys.modules["extract_skills"].extract_single_skill
        data = extract_single_skill(target, repo_url=repo_url, subdirectory=subdirectory)
        if data:
            print(f"[TAH-trust]     extract_skills 成功提取: name={data.get('name')}, "
                  f"version={data.get('version')}, category={data.get('category')}")
            return data
    except (ValueError, FileNotFoundError) as e:
        print(f"[TAH-trust]     extract_skills 跳过（{e}），回退到简易提取")
    except Exception as e:
        print(f"[TAH-trust]     extract_skills 失败（{e}），回退到简易提取")

    # ── 回退：原始简易提取逻辑 ──
    # 尝试 manifest.json
    manifest = target / "manifest.json"
    if manifest.is_file():
        try:
            with open(manifest, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning("manifest.json fallback failed for %s: %s", target, e)

    # 尝试 plugin.json
    plugin = target / "plugin.json"
    if plugin.is_file():
        try:
            with open(plugin, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning("plugin.json fallback failed for %s: %s", target, e)

    # 尝试解析 SKILL.md frontmatter
    skill = target / "SKILL.md"
    if skill.is_file():
        try:
            with open(skill, encoding="utf-8") as fh:
                fm_content = fh.read()
            fm = _parse_frontmatter(fm_content)
            if fm:
                return fm
        except (OSError, UnicodeDecodeError) as e:
            logging.warning("SKILL.md fallback failed for %s: %s", target, e)

    # 从 scan_report 构建最简 metadata
    logging.warning("All metadata fallbacks failed for %s, returning stub metadata", target)
    return {
        "name": scan_report.get("package_name", "unknown"),
        "version": scan_report.get("version", "0.0.0"),
        "type": "unknown",
        "description": "Scanned package",
        "author": {"name": "unknown", "email": "unknown@unknown.com"},
        "license": "UNKNOWN",
        "source": {"type": "unknown", "repository_url": "", "ref": "", "commit_hash": ""},
        "integrity": {"sha256": ""},
        "compatibility": [],
        "permissions": {},
        "installation": {"method": "unknown", "targets": []},
    }


def _parse_frontmatter(content: str) -> Dict[str, Any] | None:
    """解析 YAML frontmatter（与 scanner.py 中的实现一致）。"""
    if not content.startswith("---"):
        return None
    end_idx = content.find("---", 3)
    if end_idx == -1:
        return None
    fm_text = content[3:end_idx].strip()
    result: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_list: List[str] = []
    for line in fm_text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_key:
            current_list.append(stripped[2:].strip())
            continue
        if current_key and current_list:
            result[current_key] = current_list
            current_list = []
            current_key = None
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            current_key = key
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            else:
                try:
                    result[key] = int(value)
                except ValueError:
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = value
    if current_key and current_list:
        result[current_key] = current_list
    return result if result else None


# ---------------------------------------------------------------------------
# URL 规范化
# ---------------------------------------------------------------------------


def _parse_github_url(url: str) -> dict[str, Any]:
    """解析 GitHub URL，提取 owner / repo / ref / subdir。

    处理以下格式:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/main
        https://github.com/owner/repo/tree/main/subdir/path

    返回:
        {
            "base_url": "https://github.com/owner/repo",
            "owner": "owner",
            "repo": "repo",
            "ref": "main",
            "subdir": "skills/hallmark" | None,
        }
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    m = re.search(
        r"^https://github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+)(?:/(.+))?)?$", url
    )
    if not m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )

    owner = m.group(1)
    repo = m.group(2)
    ref = m.group(3) or "main"
    subdir = m.group(4) or None

    return {
        "base_url": f"https://github.com/{owner}/{repo}",
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "subdir": subdir,
    }


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
async def submit_scan(
    background_tasks: BackgroundTasks,
    repo_url: Optional[str] = None,
    body: Optional[ScanRequest] = None,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """提交一个新的扫描任务。

    支持两种方式:
    1. JSON body: {"repo_url": "https://github.com/..."}
    2. Query param: ?repo_url=https://github.com/...

    返回 scan_id 用于后续查询。
    """
    # 获取 URL
    url = repo_url
    if body and body.repo_url:
        url = body.repo_url

    print(f"\n[TAH-trust] >>> POST /scan 收到请求")
    print(f"[TAH-trust]     query_param repo_url = {repo_url!r}")
    print(f"[TAH-trust]     body.repo_url       = {body.repo_url if body else 'N/A'!r}")

    if not url:
        print(f"[TAH-trust] *** 缺少 repo_url，返回 400")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'repo_url'. Provide it in JSON body or as query parameter.",
        )

    # 基本 URL 验证
    url = url.strip()
    print(f"[TAH-trust]     raw url = {url!r}")
    if not url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only https://github.com/... URLs are supported at this time.",
        )

    # 解析 URL
    parsed = _parse_github_url(url)
    print(f"[TAH-trust]     parsed: owner={parsed['owner']}, repo={parsed['repo']}, "
          f"ref={parsed['ref']}, subdir={parsed['subdir']}")

    source = url

    # 创建扫描任务
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    print(f"[TAH-trust]     scan_id = {scan_id}, 启动后台任务...")

    _scans[scan_id] = {
        "status": "pending",
        "package_name": None,
        "created_at": now,
        "finished_at": None,
        "full_report": None,
        "summary": None,
        "trust_score": None,
        "error": None,
        "expires_at": _time.time() + _SCAN_TTL_SECONDS,
        "user_id": _user.id,
    }

    # 启动后台扫描
    background_tasks.add_task(_run_scan_task, scan_id, source)

    return {
        "scan_id": scan_id,
        "status": "pending",
        "package_name": None,
        "created_at": now,
    }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """查询扫描任务的状态。

    status 可能的值:
        pending  — 已入队，等待处理
        cloning  — 正在克隆仓库
        scanning — 正在运行风险扫描
        scoring  — 正在计算信任评分
        saving   — 正在保存报告
        complete — 扫描完成
        error    — 扫描失败
    """
    _cleanup_expired_scans()
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )

    verify_resource_access(_user, info.get("user_id", ""))

    return {
        "scan_id": scan_id,
        "status": info["status"],
        "package_name": info.get("package_name"),
        "created_at": info["created_at"],
        "finished_at": info.get("finished_at"),
        "summary": info.get("summary"),
        "trust_score": info.get("trust_score"),
        "llm_review": info.get("llm_review"),
        "error": info.get("error"),
    }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}/report
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """获取完整的扫描报告 JSON。

    仅在扫描完成 (status=complete) 时返回完整报告。
    在扫描进行中时返回 202 Accepted 及当前状态。
    扫描失败时返回 422 Unprocessable Entity 及错误信息。
    """
    _cleanup_expired_scans()
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )

    verify_resource_access(_user, info.get("user_id", ""))

    if info["status"] == "complete":
        full_report = info.get("full_report")
        if full_report:
            # 剔除内部字段（本地代码目录路径），不对外暴露
            report = dict(full_report)
            report.pop("local_source_dir", None)
            report.pop("file_contents", None)
            report.pop("source_snapshot_sha256", None)
            if isinstance(report.get("scan_report"), dict):
                report["scan_report"] = dict(report["scan_report"])
                report["scan_report"].pop("file_contents", None)
            return redact_report(report)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Report data not found in memory.",
            )

    elif info["status"] == "error":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "scan_id": scan_id,
                "status": "error",
                "error": info.get("error", "Unknown error"),
            },
        )

    else:
        # 仍在进行中
        return {
            "scan_id": scan_id,
            "status": info["status"],
            "message": "Scan is still in progress. Poll /scan/{scan_id} for status updates.",
        }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}/metadata
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}/metadata")
def get_scan_metadata(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """获取扫描过程中提取的完整元数据（供提交页自动填充使用）。"""
    _cleanup_expired_scans()
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )
    verify_resource_access(_user, info.get("user_id", ""))
    if info["status"] != "complete":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not complete yet. Current status: {info['status']}",
        )

    metadata = info.get("package_metadata")
    if not metadata:
        full_report = info.get("full_report", {})
        scan_report = full_report.get("scan_report", {})
        metadata = {
            "name": scan_report.get("package_name", "unknown"),
            "version": scan_report.get("version", "0.1.0"),
            "description": "",
            "license": "UNKNOWN",
        }

    return {
        "scan_id": scan_id,
        "metadata": metadata,
        "capabilities": info.get("capabilities", []),
    }


# ---------------------------------------------------------------------------
# GET /scans (管理用，列出所有扫描)
# ---------------------------------------------------------------------------


@router.get("/scans")
def list_scans(
    _user: CurrentUser = Depends(require_role("submitter")),
) -> List[Dict[str, Any]]:
    """列出扫描任务（submitter 及以上角色）。

    admin 可查看全部扫描记录；其他角色仅返回自己发起的扫描。
    """
    from schema.constants import UserRole
    _cleanup_expired_scans()
    is_admin = _user.role == UserRole.ADMIN.value
    return [
        {
            "scan_id": sid,
            "status": info["status"],
            "package_name": info.get("package_name"),
            "created_at": info["created_at"],
        }
        for sid, info in _scans.items()
        if is_admin or info.get("user_id") == _user.id
    ]
