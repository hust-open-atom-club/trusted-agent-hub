"""Trust Scan Router — URL 识别、代码拉取、扫描调度与结果获取。

端点:
    POST /scan              — 提交扫描任务（URL 或文件上传）
    GET  /scan/{scan_id}    — 查询扫描状态
    GET  /scan/{scan_id}/report — 获取完整扫描报告
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

router = APIRouter(tags=["trust-scan"])

# ---------------------------------------------------------------------------
# 项目路径推导
# ---------------------------------------------------------------------------
_API_SRC_DIR = Path(__file__).resolve().parent.parent  # apps/api/src/
_PROJECT_ROOT = _API_SRC_DIR.parent.parent.parent  # repo root
_REPORTS_DIR = _PROJECT_ROOT / "packages" / "schema" / "reports"
_SCANNER_PATH = _PROJECT_ROOT / "scanners" / "risk_scanner" / "scanner.py"
_EXTRACTOR_PATH = _PROJECT_ROOT / "packages" / "schema" / "extract_skills.py"

# 确保 reports 目录存在
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# 内存状态存储（scans 字典）
# ---------------------------------------------------------------------------
# key: scan_id, value: {status, package_name, created_at, finished_at, report_path, error}
_scans: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """扫描提交请求。"""
    repo_url: Optional[str] = Field(default=None, description="GitHub 仓库 HTTPS URL")
    local_path: Optional[str] = Field(default=None, description="本地目录路径（仅开发/测试用）")
    # 文件上传通过 multipart/form-data，不在 JSON body 中


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
# 后台扫描任务
# ---------------------------------------------------------------------------


def _run_scan_task(
    scan_id: str,
    source: str,
    *,
    is_local: bool = False,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None] | None = None,
) -> None:
    """后台执行扫描流水线：clone → scan → score → save。

    此函数在 BackgroundTasks 中异步运行。
    """
    try:
        print(f"\n[TAH-trust] >>> _run_scan_task 开始 scan_id={scan_id}")
        print(f"[TAH-trust]     source = {source}, is_local = {is_local}")

        if is_local:
            # 本地模式：直接使用本地目录
            tmp_dir = source
            if not os.path.isdir(tmp_dir):
                raise FileNotFoundError(f"Local path not found: {tmp_dir}")
            print(f"[TAH-trust]     本地目录: {tmp_dir}")
        else:
            _scans[scan_id]["status"] = "cloning"

            # Step 1: git clone --depth 1（最多重试 3 次应对网络抖动）
            tmp_dir = tempfile.mkdtemp(prefix=f"tah_scan_{scan_id}_")
            clone_ok = False
            last_err = ""
            for attempt in range(1, 4):
                print(f"[TAH-trust]     git clone (attempt {attempt}/3) --depth 1 {source} ...")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", source, tmp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    clone_ok = True
                    print(f"[TAH-trust]     git clone OK (attempt {attempt})")
                    break
                last_err = result.stderr[:500]
                print(f"[TAH-trust]     clone attempt {attempt} failed, {'retrying in 3s...' if attempt < 3 else 'giving up'}")
                if attempt < 3:
                    import time as _time
                    _time.sleep(3)
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    tmp_dir = tempfile.mkdtemp(prefix=f"tah_scan_{scan_id}_")
            if not clone_ok:
                _scans[scan_id]["status"] = "error"
                _scans[scan_id]["error"] = f"Git clone failed after 3 attempts ({source}). If GitHub is unreachable, try using a local path."
                print(f"[TAH-trust] *** git clone FAILED after 3 attempts")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                if on_complete:
                    on_complete(scan_id, None, _scans[scan_id]["error"])
                return

        # Step 2: 运行扫描器
        _scans[scan_id]["status"] = "scanning"
        print(f"[TAH-trust]     加载扫描器...")
        RiskScanner = _load_scanner()
        scanner = RiskScanner(tmp_dir)
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
                    file_cache = {}
                    for f in scanner.scanned_files:
                        file_cache[f] = scanner._read_file_content(f)
                    llm_result = mod_lr.run_llm_review(
                        findings=findings,
                        file_cache=file_cache,
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

        # Step 3: 运行评分引擎
        _scans[scan_id]["status"] = "scoring"
        print(f"[TAH-trust]     加载评分引擎...")
        calculate_trust_score = _load_scorer()

        # 构建 package_metadata（从扫描器的 metadata 或 scan_report 中提取）
        package_metadata = _build_package_metadata(scan_report, tmp_dir, repo_url=source)

        trust_score_result = calculate_trust_score(
            package_metadata=package_metadata,
            scan_report=scan_report,
        )
        print(f"[TAH-trust]     评分完成: score={trust_score_result.get('score')}, level={trust_score_result.get('risk_summary', {}).get('level')}")

        # Step 4: 合并报告并保存到磁盘
        _scans[scan_id]["status"] = "saving"
        full_report: Dict[str, Any] = {
            "scan_id": scan_id,
            "repo_url": source,
            "package_name": pkg_name,
            "version": pkg_version,
            "created_at": _scans[scan_id]["created_at"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "scan_report": scan_report,
            "trust_score": trust_score_result,
        }

        report_path = _REPORTS_DIR / f"{scan_id}.json"
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(full_report, fh, indent=2, ensure_ascii=False)

        # Step 5: 更新状态
        _scans[scan_id].update({
            "status": "complete",
            "finished_at": full_report["finished_at"],
            "report_path": str(report_path),
            "summary": scan_report.get("summary", {}),
            "trust_score": {
                "score": trust_score_result.get("score"),
                "level": trust_score_result.get("risk_summary", {}).get("level"),
                "grade": trust_score_result.get("risk_summary", {}).get("grade"),
                "recommendation": trust_score_result.get("risk_summary", {}).get("install_recommendation"),
            },
        })

        # 清理临时目录（仅 git clone 模式）
        if not is_local:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if on_complete:
            on_complete(scan_id, full_report, None)
        print(f"[TAH-trust] *** 扫描流水线完成: {scan_id}, score={trust_score_result.get('score')}")

    except Exception as exc:
        _scans[scan_id]["status"] = "error"
        _scans[scan_id]["error"] = f"Scan failed: {type(exc).__name__}: {exc}"
        print(f"[TAH-trust] *** 扫描异常: {type(exc).__name__}: {exc}", flush=True)
        import traceback; traceback.print_exc()
        if "tmp_dir" in locals() and not is_local:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if on_complete:
            on_complete(scan_id, None, str(exc))

def _build_package_metadata(scan_report: Dict[str, Any], target_dir: str, repo_url: str = "") -> Dict[str, Any]:
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
                spec.loader.exec_module(mod)
                sys.modules["extract_skills"] = mod

        extract_single_skill = sys.modules["extract_skills"].extract_single_skill
        data = extract_single_skill(target, repo_url=repo_url)
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
        except (json.JSONDecodeError, OSError):
            pass

    # 尝试 plugin.json
    plugin = target / "plugin.json"
    if plugin.is_file():
        try:
            with open(plugin, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass

    # 尝试解析 SKILL.md frontmatter
    skill = target / "SKILL.md"
    if skill.is_file():
        try:
            with open(skill, encoding="utf-8") as fh:
                fm_content = fh.read()
            fm = _parse_frontmatter(fm_content)
            if fm:
                return fm
        except (OSError, UnicodeDecodeError):
            pass

    # 从 scan_report 构建最简 metadata
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
# 缓存中已有报告的加载（供已存在的 scan_id 使用）
# ---------------------------------------------------------------------------

def _load_cached_reports() -> None:
    """从磁盘加载已有的扫描报告到内存索引。"""
    if not _REPORTS_DIR.is_dir():
        return
    for fpath in sorted(_REPORTS_DIR.glob("*.json")):
        scan_id = fpath.stem
        if scan_id in _scans:
            continue
        try:
            with open(fpath, encoding="utf-8") as fh:
                report = json.load(fh)
            _scans[scan_id] = {
                "status": "complete",
                "package_name": report.get("package_name"),
                "created_at": report.get("created_at", ""),
                "finished_at": report.get("finished_at", ""),
                "report_path": str(fpath),
                "summary": report.get("scan_report", {}).get("summary", {}),
                "trust_score": report.get("trust_score", {}),
            }
        except (json.JSONDecodeError, OSError):
            continue


# 启动时加载缓存
_load_cached_reports()


# ---------------------------------------------------------------------------
# URL 规范化
# ---------------------------------------------------------------------------


def _normalize_github_url(url: str) -> str:
    """将 GitHub URL 规范化为纯仓库根地址。

    处理以下格式:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/main/subdir
        https://github.com/owner/repo/tree/v1.0.0

    返回:
        https://github.com/owner/repo
    """
    import re

    url = url.strip().rstrip("/")

    # 去掉 .git 后缀
    if url.endswith(".git"):
        url = url[:-4]

    # 去掉 /tree/... 路径（GitHub 网页目录浏览）
    # 匹配 /tree/<ref>/<optional-subpath>
    tree_match = re.search(r"^(https://github\.com/[^/]+/[^/]+)/tree/", url)
    if tree_match:
        url = tree_match.group(1)

    return url


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
async def submit_scan(
    background_tasks: BackgroundTasks,
    repo_url: Optional[str] = None,
    body: Optional[ScanRequest] = None,
    local_path: Optional[str] = None,
) -> Dict[str, Any]:
    """提交一个新的扫描任务。

    支持两种方式:
    1. JSON body: {"repo_url": "https://github.com/..."}
    2. Query param: ?repo_url=https://github.com/...

    返回 scan_id 用于后续查询。
    """
    # 获取 URL / 本地路径
    url = repo_url
    local = local_path
    if body:
        if not url and body.repo_url:
            url = body.repo_url
        if not local and body.local_path:
            local = body.local_path

    print(f"\n[TAH-trust] >>> POST /scan 收到请求")
    print(f"[TAH-trust]     query_param repo_url = {repo_url!r}")
    print(f"[TAH-trust]     body.repo_url       = {body.repo_url if body else 'N/A'!r}")
    print(f"[TAH-trust]     body.local_path     = {body.local_path if body else 'N/A'!r}")

    # 本地路径模式
    if local:
        local = local.strip()
        print(f"[TAH-trust]     本地扫描路径: {local!r}")
        if not os.path.isabs(local):
            local = os.path.normpath(os.path.join(_PROJECT_ROOT, local))
        if not os.path.isdir(local):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Local path not found: {local}",
            )
        source = local
        is_local = True
    elif not url:
        print(f"[TAH-trust] *** 缺少 repo_url，返回 400")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'repo_url'. Provide it in JSON body or as query parameter.",
        )
    else:
        # 基本 URL 验证
        url = url.strip()
        print(f"[TAH-trust]     raw url = {url!r}")
        if not url.startswith("https://github.com/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only https://github.com/... URLs are supported at this time.",
            )

        # 规范化 URL：去掉 /tree/... 路径、.git 后缀等
        url = _normalize_github_url(url)
        print(f"[TAH-trust]     normalized url = {url!r}")

        source = url
        is_local = False

    # 创建扫描任务
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    print(f"[TAH-trust]     scan_id = {scan_id}, is_local={is_local}, 启动后台任务...")

    _scans[scan_id] = {
        "status": "pending",
        "package_name": None,
        "created_at": now,
        "finished_at": None,
        "report_path": None,
        "summary": None,
        "trust_score": None,
        "error": None,
    }

    # 启动后台扫描
    background_tasks.add_task(_run_scan_task, scan_id, source, is_local=is_local)

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
def get_scan_status(scan_id: str) -> Dict[str, Any]:
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
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    return {
        "scan_id": scan_id,
        "status": info["status"],
        "package_name": info.get("package_name"),
        "created_at": info["created_at"],
        "finished_at": info.get("finished_at"),
        "summary": info.get("summary"),
        "trust_score": info.get("trust_score"),
        "error": info.get("error"),
    }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}/report
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str) -> Dict[str, Any]:
    """获取完整的扫描报告 JSON。

    仅在扫描完成 (status=complete) 时返回完整报告。
    在扫描进行中时返回 202 Accepted 及当前状态。
    扫描失败时返回 422 Unprocessable Entity 及错误信息。
    """
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    if info["status"] == "complete":
        # 从磁盘读取完整报告
        report_path = info.get("report_path")
        if report_path and os.path.isfile(report_path):
            with open(report_path, encoding="utf-8") as fh:
                return json.load(fh)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Report file missing.",
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
# GET /scans (管理用，列出所有扫描)
# ---------------------------------------------------------------------------


@router.get("/scans")
def list_scans() -> List[Dict[str, Any]]:
    """列出所有扫描任务（管理调试用）。"""
    return [
        {
            "scan_id": sid,
            "status": info["status"],
            "package_name": info.get("package_name"),
            "created_at": info["created_at"],
        }
        for sid, info in _scans.items()
    ]
