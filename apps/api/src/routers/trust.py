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
import stat
import struct
import sys
import tempfile
import time as _time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from src.auth import require_role, verify_resource_access
from src.dependencies import CurrentUser
from src.models.common import require_safe_source_subdirectory
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
from scanners.risk_scanner.redaction import (
    build_finding_contexts,
    redact_report,
    redact_value,
)
from scanners.risk_scanner.provenance import build_verification_facts
from scanners.risk_scanner.inventory import ScanInventory
from scanners.risk_scanner.policy import ScanPolicy
from packages.schema.frontmatter import parse_frontmatter
from schema.constants import HASH_SCOPE_SCANNED_SOURCE

# ---------------------------------------------------------------------------
# 内存状态存储（scans 字典）
# ---------------------------------------------------------------------------
# key: scan_id, value: {status, package_name, created_at, finished_at, report_path, error, expires_at}
_scans: Dict[str, Dict[str, Any]] = {}
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()

_SCAN_TTL_SECONDS = 3600  # 临时扫描结果保留 1 小时
_SOURCE_POLICY = ScanPolicy()
_ZIP_READ_CHUNK_BYTES = 64 * 1024


class _DeterministicAcquisitionError(ValueError):
    """A source validation or budget failure that must not be retried."""


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


_LLM_REVIEWED_SEVERITIES = frozenset({"critical", "high"})


def _load_llm_reviewer() -> Any:
    """动态加载 LLM 审查器模块。"""
    llm_reviewer_path = _PROJECT_ROOT / "scanners" / "risk_scanner" / "llm_reviewer.py"
    spec = importlib.util.spec_from_file_location(
        "llm_reviewer", str(llm_reviewer_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load LLM reviewer from {llm_reviewer_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mark_llm_review_unavailable(
    findings: list[dict[str, Any]],
    error: Exception,
) -> dict[str, Any]:
    """Fail closed when the outer LLM-review orchestration cannot complete.

    The reviewer normally labels every critical/high finding. If loading the
    reviewer, building context, or invoking it raises before labels are
    returned, attach the same unavailable label directly so scoring retains
    its per-finding fail-closed signal.
    """
    labels: dict[str, str] = {}
    reviewed_count = 0
    skipped_count = 0

    for finding in findings:
        if not isinstance(finding, dict):
            skipped_count += 1
            continue

        severity = str(finding.get("severity", "")).lower()
        if severity not in _LLM_REVIEWED_SEVERITIES:
            skipped_count += 1
            continue

        finding["llm_label"] = "llm:unavailable"
        finding_id = str(finding.get("id", ""))
        if finding_id:
            labels[finding_id] = "llm:unavailable"
        reviewed_count += 1

    return {
        "triggered": True,
        "findings_reviewed": reviewed_count,
        "findings_skipped": skipped_count,
        "findings_pending": 0,
        "status": "call_failed",
        "attempts": 0,
        "labels": labels,
        "labels_summary": {
            "suspected_malicious": 0,
            "suspected_negligent": 0,
            "likely_benign": 0,
            "uncertain": 0,
            "unavailable": reviewed_count,
        },
        "error": f"{type(error).__name__}: {error}",
        "fallback": "fail_closed_after_outer_exception",
    }


def _run_llm_review_with_fallback(
    findings: list[dict[str, Any]],
    scanner: Any,
) -> dict[str, Any]:
    """Run LLM review and preserve fail-closed labels on outer failures."""
    try:
        reviewer = _load_llm_reviewer()
        finding_contexts = build_finding_contexts(findings, scanner._file_contents)
        result = reviewer.run_llm_review(
            findings=findings,
            finding_contexts=finding_contexts,
            manifest=scanner._package_metadata,
        )
        labels = result.get("labels", {})
        if not isinstance(labels, dict):
            raise ValueError("LLM review labels must be an object")

        for finding in findings:
            finding_id = finding.get("id", "")
            if finding_id in labels:
                finding["llm_label"] = labels[finding_id]

        labels_summary = result.get("labels_summary")
        if not isinstance(labels_summary, dict):
            raise ValueError("LLM review result is missing labels_summary")
        print(
            f"[TAH-trust]     LLM 审查完成: "
            f"malicious={labels_summary['suspected_malicious']}, "
            f"negligent={labels_summary['suspected_negligent']}, "
            f"benign={labels_summary['likely_benign']}, "
            f"uncertain={labels_summary['uncertain']}, "
            f"unavailable={labels_summary['unavailable']}"
        )
        return result
    except Exception as exc:
        print(f"[TAH-trust]     LLM 审查跳过（{exc}）")
        return _mark_llm_review_unavailable(findings, exc)


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
# 远程仓库获取：固定 commit + 受限 ZIP 下载
# ---------------------------------------------------------------------------


def _github_api_headers() -> dict[str, str]:
    """Return the shared, optional-token headers for GitHub API requests."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_repository_default_branch(parsed: dict[str, Any]) -> str:
    """Resolve a repository's GitHub default branch before acquiring source."""
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
    )
    try:
        request = urllib.request.Request(api_url, headers=_github_api_headers())
        with urllib.request.urlopen(request, timeout=20) as response:
            buffer = io.BytesIO()
            _copy_response_bounded(response, buffer, _SOURCE_POLICY.max_file_bytes)
            payload = json.loads(buffer.getvalue().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="GitHub repository was not found or is not accessible.",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to resolve the repository default branch from GitHub.",
        ) from exc
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to resolve the repository default branch from GitHub.",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub did not return a valid repository metadata object.",
        )

    expected_full_name = f"{parsed['owner']}/{parsed['repo']}".casefold()
    actual_full_name = payload.get("full_name")
    if (
        not isinstance(actual_full_name, str)
        or actual_full_name.casefold() != expected_full_name
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub repository identity did not match the requested source.",
        )

    default_branch = payload.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch.strip():
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub did not return a valid repository default branch.",
        )
    return default_branch


def _resolve_default_branch_source(parsed: dict[str, Any]) -> dict[str, Any]:
    """Allow only a repository's default branch and an optional path within it."""
    default_branch = _fetch_repository_default_branch(parsed)
    tree_path = parsed.get("tree_path")
    subdir: str | None = None

    if tree_path:
        if tree_path == default_branch:
            pass
        elif tree_path.startswith(default_branch + "/"):
            subdir = tree_path[len(default_branch) + 1:]
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Only the repository default branch is supported. "
                    f"Use '{default_branch}' instead of another branch or tag."
                ),
            )

    return {
        **parsed,
        # This marker is written only after the server validates the GitHub
        # repository response against the requested owner/repo.
        "repository_verified": True,
        "ref": default_branch,
        "subdir": subdir,
        # This proves only that the canonical repository endpoint resolved.
        # Repository ownership is a separate claim and remains unverified
        # until an independent server-side verifier establishes it.
        "repository_resolved": True,
    }


def _is_full_commit_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", value))


def _fetch_repository_commit_hash(parsed: dict[str, Any]) -> str:
    """Resolve the default branch to an immutable full commit hash."""
    encoded_ref = urllib.parse.quote(parsed["ref"], safe="")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/commits/{encoded_ref}"
    )
    request = urllib.request.Request(api_url, headers=_github_api_headers())
    with urllib.request.urlopen(request, timeout=20) as response:
        buffer = io.BytesIO()
        _copy_response_bounded(response, buffer, _SOURCE_POLICY.max_file_bytes)
    payload = json.loads(buffer.getvalue().decode("utf-8"))
    commit_hash = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(commit_hash, str) or not _is_full_commit_hash(commit_hash):
        raise ValueError("GitHub did not return a valid full commit hash")
    return commit_hash


def _copy_response_bounded(response: Any, destination: Any, max_bytes: int) -> int:
    """Stream an HTTP body into a seekable file without exceeding max_bytes."""
    if max_bytes < 0:
        raise _DeterministicAcquisitionError(
            "HTTP response byte limit must not be negative"
        )
    headers = getattr(response, "headers", None)
    content_length = headers.get("Content-Length") if headers else None
    declared_length: int | None = None
    if content_length:
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError):
            pass
    if declared_length is not None and declared_length > max_bytes:
        raise _DeterministicAcquisitionError(
            f"HTTP response exceeds {max_bytes} byte limit"
        )

    total = 0
    while True:
        chunk = response.read(min(_ZIP_READ_CHUNK_BYTES, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise _DeterministicAcquisitionError(
                f"HTTP response exceeds {max_bytes} byte limit"
            )
        destination.write(chunk)
    destination.seek(0)
    return total


def _preflight_zip_entry_count(archive_file: Any, max_entries: int) -> None:
    """Reject oversized ZIP central directories before ZipFile parses them."""
    eocd_struct = "<4s4H2LH"
    zip64_eocd_struct = "<4sQ2H2L4Q"
    eocd_size = struct.calcsize(eocd_struct)
    max_comment_size = 0xFFFF
    signature = b"PK\x05\x06"
    archive_file.seek(0, 2)
    archive_size = archive_file.tell()
    tail_size = min(archive_size, eocd_size + max_comment_size)
    archive_file.seek(archive_size - tail_size)
    tail = archive_file.read(tail_size)
    archive_file.seek(0)

    eocd_offset = tail.rfind(signature)
    if eocd_offset < 0 or eocd_offset + eocd_size > len(tail):
        return

    fields = struct.unpack_from(eocd_struct, tail, eocd_offset)
    total_entries = fields[4]
    if total_entries == 0xFFFF:
        zip64_signature = b"PK\x06\x06"
        zip64_offset = tail.rfind(zip64_signature, 0, eocd_offset)
        zip64_size = struct.calcsize(zip64_eocd_struct)
        if zip64_offset < 0 or zip64_offset + zip64_size > len(tail):
            raise _DeterministicAcquisitionError(
                "ZIP64 entry count cannot be bounded before archive parsing"
            )
        zip64_fields = struct.unpack_from(zip64_eocd_struct, tail, zip64_offset)
        total_entries = zip64_fields[7]
    if total_entries > max_entries:
        raise _DeterministicAcquisitionError(
            f"ZIP contains more than {max_entries} entries"
        )


def _read_text_file_bounded(path: Path, max_bytes: int) -> str:
    """Read a UTF-8 file with an explicit byte ceiling."""
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} byte limit: {path.name}")
    return data.decode("utf-8")


def _safe_extract_zip(
    archive: zipfile.ZipFile,
    destination: str | Path,
    policy: ScanPolicy = _SOURCE_POLICY,
) -> None:
    """Extract a ZIP under the scanner's file/count/depth/byte budgets."""
    destination_path = Path(destination).resolve()
    infos = archive.infolist()
    if len(infos) > policy.max_files:
        raise _DeterministicAcquisitionError(
            f"ZIP contains more than {policy.max_files} entries"
        )

    declared_total = 0
    normalized_targets: set[str] = set()
    validated: list[tuple[zipfile.ZipInfo, Path, bool]] = []
    for info in infos:
        name = info.filename
        if not name or "\x00" in name or "\\" in name:
            raise _DeterministicAcquisitionError("ZIP contains an invalid entry name")
        path = Path(name)
        if path.is_absolute() or re.match(r"^[A-Za-z]:", name):
            raise _DeterministicAcquisitionError(f"ZIP entry is absolute: {name!r}")
        parts = tuple(part for part in path.parts if part not in {"", "."})
        if not parts or any(part == ".." for part in parts):
            raise _DeterministicAcquisitionError(
                f"ZIP entry escapes extraction root: {name!r}"
            )
        # GitHub zipballs add one wrapper directory which is removed later.
        if len(parts) - 1 > policy.max_depth + 1:
            raise _DeterministicAcquisitionError(
                f"ZIP entry exceeds depth limit: {name!r}"
            )
        if info.flag_bits & 0x1:
            raise _DeterministicAcquisitionError(
                f"encrypted ZIP entry is not supported: {name!r}"
            )

        unix_mode = info.external_attr >> 16
        unix_file_type = stat.S_IFMT(unix_mode)
        is_directory = info.is_dir()
        if unix_file_type and not (
            stat.S_ISDIR(unix_mode) if is_directory else stat.S_ISREG(unix_mode)
        ):
            raise _DeterministicAcquisitionError(
                f"ZIP contains a special file: {name!r}"
            )

        target = destination_path.joinpath(*parts)
        resolved_target = target.resolve()
        if (
            resolved_target != destination_path
            and destination_path not in resolved_target.parents
        ):
            raise _DeterministicAcquisitionError(
                f"ZIP entry escapes extraction root: {name!r}"
            )
        target_key = os.path.normcase(str(resolved_target))
        if target_key in normalized_targets:
            raise _DeterministicAcquisitionError(
                f"ZIP contains a duplicate entry: {name!r}"
            )
        normalized_targets.add(target_key)

        if not is_directory:
            declared_total += info.file_size
            if declared_total > policy.max_total_bytes:
                raise _DeterministicAcquisitionError(
                    f"ZIP expands beyond {policy.max_total_bytes} byte limit"
                )
        validated.append((info, resolved_target, is_directory))

    actual_total = 0
    for info, target, is_directory in validated:
        if is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with (
            archive.open(info, "r") as source_handle,
            target.open("xb") as target_handle,
        ):
            while True:
                remaining = policy.max_total_bytes - actual_total
                chunk = source_handle.read(min(_ZIP_READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                actual_total += len(chunk)
                written += len(chunk)
                if actual_total > policy.max_total_bytes:
                    raise _DeterministicAcquisitionError(
                        f"ZIP expands beyond {policy.max_total_bytes} byte limit"
                    )
                target_handle.write(chunk)
        if written != info.file_size:
            raise _DeterministicAcquisitionError(
                f"ZIP entry size changed while extracting: {info.filename!r}"
            )


def _download_zipball(parsed: dict[str, Any], tmp_dir: str, max_attempts: int = 3) -> bool:
    """下载固定 ref 的 ZIP 包，并在资源预算内解压到 tmp_dir。"""
    token = os.environ.get("GITHUB_TOKEN", "")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/zipball/{parsed['ref']}"
    )
    headers = _github_api_headers()
    if token:
        print(f"[TAH-trust]     ZIP 下载使用 Token 认证")
    else:
        print(f"[TAH-trust]     ZIP 下载无 Token（匿名）")

    for attempt in range(1, max_attempts + 1):
        print(f"[TAH-trust]     ZIP download (attempt {attempt}/{max_attempts}) {api_url}")
        try:
            req = urllib.request.Request(api_url, headers=headers)
            with tempfile.TemporaryFile() as archive_file:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    _copy_response_bounded(
                        resp,
                        archive_file,
                        _SOURCE_POLICY.max_total_bytes,
                    )
                _preflight_zip_entry_count(
                    archive_file,
                    _SOURCE_POLICY.max_files,
                )
                with zipfile.ZipFile(archive_file) as zf:
                    _safe_extract_zip(zf, tmp_dir, _SOURCE_POLICY)
            print(f"[TAH-trust]     ZIP download OK (attempt {attempt})")
            return True
        except _DeterministicAcquisitionError as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            return False
        except urllib.error.HTTPError as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            if exc.code not in {408, 429, 500, 502, 503, 504}:
                return False
            if attempt < max_attempts:
                _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            if attempt < max_attempts:
                _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
        except Exception as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            return False
    return False


def _acquire_repo_source(parsed: dict[str, Any]) -> tuple[str | None, str, str]:
    """Resolve a commit and acquire it through the budgeted ZIP path.

    Returns:
        (repo_root, source_method, commit_hash) — repo_root 是仓库内容根目录路径，
        source_method 为 "zip"，commit_hash 为真实 40 位 git hash。
        ZIP 使用默认分支解析出的不可变 commit，而不是可变分支名。
        失败返回 (None, "", "")。
    """
    tmp_dir = tempfile.mkdtemp(prefix=f"tah_repo_")
    try:
        commit_hash = _fetch_repository_commit_hash(parsed)
    except Exception as exc:
        print(f"[TAH-trust]     commit resolution failed: {exc}")
        force_rmtree(tmp_dir)
        return None, "", ""

    print(f"[TAH-trust] === Budgeted ZIP acquisition: {commit_hash[:8]} ===")
    pinned = {**parsed, "ref": commit_hash}
    if _download_zipball(pinned, tmp_dir):
        # ZIP 解压后内容在一层子目录中 {owner}-{repo}-{hash}/
        entries = os.listdir(tmp_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(tmp_dir, entries[0])):
            inner = os.path.join(tmp_dir, entries[0])
            # 将内层目录内容移到 tmp_dir
            for item in os.listdir(inner):
                shutil.move(os.path.join(inner, item), os.path.join(tmp_dir, item))
            os.rmdir(inner)
            print(f"[TAH-trust]     ZIP commit: {commit_hash[:8]}")
            return tmp_dir, "zip", commit_hash
        print("[TAH-trust]     ZIP download lacks a single repository root")

    force_rmtree(tmp_dir)
    return None, "", ""


# ---------------------------------------------------------------------------
# 后台扫描任务
# ---------------------------------------------------------------------------


def _build_acquisition_facts(
    parsed: dict[str, Any] | None,
    repo_url: str,
    subdir: str | None,
    method: str,
    commit_hash: str,
    scanner: Any,
) -> dict[str, Any]:
    """Build provenance facts from acquisition, never from package metadata.

    Repository identity is verified from the acquired URL/commit.  Signature,
    attestation, and SBOM flags are accepted only from an independent
    server-side verifier; package metadata is never used as a fallback.
    """
    scanner_facts = getattr(scanner, "acquisition_facts", {})
    if not isinstance(scanner_facts, dict):
        scanner_facts = {}
    scanner_source = scanner_facts.get("source", {})
    if not isinstance(scanner_source, dict):
        scanner_source = {}
    scanner_integrity = scanner_facts.get("integrity", {})
    if not isinstance(scanner_integrity, dict):
        scanner_integrity = {}
    scanner_verification = scanner_facts.get("verification", {})
    if not isinstance(scanner_verification, dict):
        scanner_verification = {}

    valid_commit = bool(re.fullmatch(r"^[a-f0-9]{40}$", commit_hash))
    acquired_commit = commit_hash if valid_commit else scanner_source.get("commit_hash", "")
    if not re.fullmatch(r"^[a-f0-9]{40}$", str(acquired_commit)):
        acquired_commit = ""
    acquired_sha256 = scanner_integrity.get("sha256", "")
    if not re.fullmatch(r"^[a-f0-9]{64}$", str(acquired_sha256)):
        acquired_sha256 = ""
    hash_scope = scanner_integrity.get("hash_scope")
    if hash_scope != HASH_SCOPE_SCANNED_SOURCE:
        hash_scope = None
    hash_complete = (
        bool(acquired_sha256)
        and hash_scope == HASH_SCOPE_SCANNED_SOURCE
        and scanner_integrity.get("is_complete") is True
    )
    verification = build_verification_facts(
        parsed=parsed,
        repository_url=repo_url,
        acquisition_method=method,
        commit_hash=str(acquired_commit),
        content_sha256=str(acquired_sha256),
        content_hash_complete=hash_complete,
        server_verification=scanner_verification,
    )

    source: dict[str, Any] = {
        "type": "github" if parsed else "unknown",
        "repository_url": repo_url if repo_url.startswith("https://") else "",
        "owner": (parsed or {}).get("owner", ""),
        "repo": (parsed or {}).get("repo", ""),
        # Treat the resolved commit as the only stable ref we know was
        # acquired.  A manifest cannot upgrade a branch into a tag/release.
        "ref_type": "commit" if acquired_commit else "branch",
        "ref": acquired_commit or (parsed or {}).get("ref", ""),
        "commit_hash": acquired_commit,
        "verified_owner": verification["owner"],
    }
    if subdir:
        source["subdirectory"] = subdir

    integrity = {
        "sha256": acquired_sha256,
        "hash_scope": hash_scope,
        "is_complete": hash_complete,
    }
    return {
        "source": source,
        "integrity": integrity,
        "verification": verification,
        "acquisition_method": method,
    }


def _provenance_claims(scanner: Any) -> dict[str, Any]:
    """Retain redacted source/integrity claims for audit, never for scoring."""
    claims = getattr(scanner, "package_claims", None)
    if not isinstance(claims, dict):
        claims = getattr(scanner, "_package_metadata", None)
    if not isinstance(claims, dict):
        return {"source": {}, "integrity": {}}
    source_claims = claims.get("source")
    integrity_claims = claims.get("integrity")
    claims = {
        "source": deepcopy(source_claims) if isinstance(source_claims, dict) else {},
        "integrity": (
            deepcopy(integrity_claims)
            if isinstance(integrity_claims, dict)
            else {}
        ),
    }
    redacted_claims = redact_value(claims)
    return redacted_claims if isinstance(redacted_claims, dict) else {
        "source": {},
        "integrity": {},
    }


def _apply_acquisition_facts(
    package_metadata: dict[str, Any],
    acquisition_facts: dict[str, Any],
) -> dict[str, Any]:
    """Replace provenance namespaces with server-established facts."""
    safe_metadata = deepcopy(package_metadata)
    safe_metadata["source"] = deepcopy(acquisition_facts.get("source") or {})
    safe_metadata["integrity"] = deepcopy(acquisition_facts.get("integrity") or {})
    return safe_metadata


def _run_scan_task(
    scan_id: str,
    source: str,
    *,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None] | None = None,
    signals: Dict[str, Any] | None = None,
    resolved_source: dict[str, Any] | None = None,
) -> None:
    """后台执行扫描流水线：acquire → scan → score → save。

    此函数在 BackgroundTasks 中异步运行。
    signals: 提交时从数据库采集的平台信号（author_history / review_records / feedback）。
    """
    try:
        print(f"\n[TAH-trust] >>> _run_scan_task 开始 scan_id={scan_id}")
        print(f"[TAH-trust]     source = {source}")

        parsed = (
            dict(resolved_source)
            if resolved_source is not None
            else _resolve_default_branch_source(_parse_github_url(source))
        )
        print(f"[TAH-trust]     owner={parsed['owner']}, repo={parsed['repo']}, "
              f"default_branch={parsed['ref']}, subdir={parsed['subdir']}")

        _scans[scan_id]["status"] = "downloading"

        repo_root, method, commit_hash = _acquire_repo_source(parsed)
        if repo_root is None:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"] = (
                "无法解析或下载受限的仓库快照。"
                "请检查 GitHub 连接。"
            )
            print(f"[TAH-trust] *** 获取仓库失败（commit + budgeted ZIP）")
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
                    root_data = json.loads(_read_text_file_bounded(
                        root_manifest,
                        _SOURCE_POLICY.max_file_bytes,
                    ))
                    if not isinstance(root_data, dict):
                        raise ValueError("manifest root must be an object")
                    source_data = root_data.get("source") or {}
                    if not isinstance(source_data, dict):
                        raise ValueError("manifest source must be an object")
                    declared = source_data.get("subdirectory")
                    if declared is not None:
                        subdir = require_safe_source_subdirectory(declared)
                        print(
                            f"[TAH-trust]     manifest 声明子目录: {subdir}"
                        )
                except (json.JSONDecodeError, OSError, ValueError) as exc:
                    logging.warning("Ignoring invalid root manifest source: %s", exc)
                    pass
        if subdir:
            subdir = require_safe_source_subdirectory(subdir)
            repo_path = Path(repo_root).resolve()
            candidate = (repo_path / subdir).resolve()
            if candidate != repo_path and repo_path not in candidate.parents:
                raise ValueError(f"source subdirectory escapes repository root: {subdir}")
            if not candidate.is_dir():
                raise ValueError(f"source subdirectory does not exist: {subdir}")
            subdir = candidate.relative_to(repo_path).as_posix()
            scan_dir = str(candidate)
            print(f"[TAH-trust]     扫描子目录: {subdir}")
        else:
            scan_dir = repo_root

        parent_package_json: dict[str, Any] | None = None
        if subdir:
            root_package = Path(repo_root) / "package.json"
            if root_package.is_file():
                try:
                    root_package_data = json.loads(_read_text_file_bounded(
                        root_package,
                        _SOURCE_POLICY.max_file_bytes,
                    ))
                    if (
                        isinstance(root_package_data, dict)
                        and root_package_data.get("author")
                    ):
                        parent_package_json = root_package_data
                except (json.JSONDecodeError, OSError, ValueError) as exc:
                    logging.warning(
                        "Ignoring invalid bounded parent package metadata: %s",
                        exc,
                    )

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
                repo_root,
                policy=_SOURCE_POLICY,
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
        scanner = RiskScanner(
            scan_dir,
            source_commit_hash=commit_hash,
            policy=_SOURCE_POLICY,
        )
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
            scan_report["llm_review"] = _run_llm_review_with_fallback(
                findings,
                scanner,
            )
        else:
            scan_report["llm_review"] = {"triggered": False}

        snapshot_metadata = _SOURCE_SNAPSHOT_STORE.save(
            scanner._file_contents,
            owner_id=str(
                _scans.get(scan_id, {}).get("source_owner_id")
                or _scans.get(scan_id, {}).get("user_id")
                or ""
            ) or None,
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
        package_metadata = _build_package_metadata(
            scan_report,
            scan_dir,
            repo_url=repo_url,
            subdirectory=subdir,
            policy=scanner.policy,
            inventory=scanner.inventory,
            file_contents=scanner._file_contents,
            parent_package_json=parent_package_json,
        )
        acquisition_facts = _build_acquisition_facts(
            parsed,
            repo_url,
            subdir,
            method,
            commit_hash,
            scanner,
        )
        package_claims = _provenance_claims(scanner)
        package_metadata = _apply_acquisition_facts(
            package_metadata,
            acquisition_facts,
        )
        # Persist claims as evidence, but keep them outside the metadata
        # namespaces consumed by the score engine.
        scan_report["provenance"] = {
            "acquisition_facts": deepcopy(acquisition_facts),
            "package_claims": deepcopy(package_claims),
        }
        # Keep permission provenance in the persisted audit report.  The
        # score uses the same evidence to avoid treating documentation-only
        # mentions as observed capabilities.
        scan_report["permission_evidence"] = package_metadata.get(
            "permission_evidence", []
        )
        # Provenance claims are untrusted package input.  Redact once more at
        # the report boundary so future additions cannot bypass the scanner's
        # earlier redaction pass.
        scan_report = redact_report(scan_report)

        platform_signals = signals or {}
        trust_score_result = calculate_trust_score(
            package_metadata=package_metadata,
            scan_report=scan_report,
            author_history=platform_signals.get("author_history"),
            review_records=platform_signals.get("review_records"),
            feedback=platform_signals.get("feedback"),
            acquisition_facts=acquisition_facts,
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
            "source_ref": parsed["ref"],
            "source_method": method,
            "commit_hash": commit_hash,
            "created_at": _scans[scan_id]["created_at"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "scan_report": scan_report,
            "trust_score": trust_score_result,
            "package_metadata": package_metadata,
            "acquisition_facts": acquisition_facts,
            "package_claims": package_claims,
            "source_snapshot_id": snapshot_metadata["snapshot_id"],
            "source_snapshot_sha256": snapshot_metadata["sha256"],
            "source_subdirectory": subdir,
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
            "acquisition_facts": acquisition_facts,
            "package_claims": package_claims,
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

def _build_package_metadata(
    scan_report: Dict[str, Any],
    target_dir: str,
    repo_url: str = "",
    subdirectory: str | None = None,
    *,
    policy: ScanPolicy | None = None,
    inventory: ScanInventory | None = None,
    file_contents: dict[str, str] | None = None,
    parent_package_json: dict[str, Any] | None = None,
) -> Dict[str, Any]:
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
        data = extract_single_skill(
            target,
            repo_url=repo_url,
            subdirectory=subdirectory,
            policy=policy,
            inventory=inventory,
            file_contents=file_contents,
            parent_package_json=parent_package_json,
        )
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
    bounded_contents = file_contents or {}
    manifest_text = bounded_contents.get("manifest.json")
    if manifest_text is not None:
        try:
            value = json.loads(manifest_text)
            if isinstance(value, dict):
                return value
            logging.warning("manifest.json root is not an object for %s", target)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning("manifest.json fallback failed for %s: %s", target, e)

    # 尝试 plugin.json
    plugin_text = bounded_contents.get("plugin.json")
    if plugin_text is not None:
        try:
            value = json.loads(plugin_text)
            if isinstance(value, dict):
                return value
            logging.warning("plugin.json root is not an object for %s", target)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning("plugin.json fallback failed for %s: %s", target, e)

    # 尝试解析 SKILL.md frontmatter
    skill_text = bounded_contents.get("SKILL.md")
    if skill_text is not None:
        try:
            result = parse_frontmatter(skill_text)
            if result.data:
                return result.data
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


# ---------------------------------------------------------------------------
# URL 规范化
# ---------------------------------------------------------------------------


def _parse_github_url(url: str) -> dict[str, Any]:
    """解析 GitHub URL，提取 owner / repo / tree 路径。

    处理以下格式:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/main
        https://github.com/owner/repo/tree/main/subdir/path

    ``tree_path`` 会在查询 GitHub ``default_branch`` 后再解析，避免将
    非默认分支误作为扫描来源，也能正确处理名称带斜杠的默认分支。
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    m = re.search(r"^https://github\.com/([^/]+)/([^/]+)(?:/tree/(.+))?$", url)
    if not m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )

    owner = m.group(1)
    repo = m.group(2)

    return {
        "base_url": f"https://github.com/{owner}/{repo}",
        "owner": owner,
        "repo": repo,
        "tree_path": m.group(3) or None,
    }


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
def submit_scan(
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

    # 解析 URL 并同步校验：仅允许 GitHub 声明的默认分支。
    # 同步端点由 FastAPI 放入线程池，避免阻塞事件循环的 GitHub API 请求。
    parsed = _resolve_default_branch_source(_parse_github_url(url))
    print(f"[TAH-trust]     parsed: owner={parsed['owner']}, repo={parsed['repo']}, "
          f"default_branch={parsed['ref']}, subdir={parsed['subdir']}")

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
        "source_owner_id": _user.id,
    }

    # 启动后台扫描
    background_tasks.add_task(
        _run_scan_task,
        scan_id,
        source,
        resolved_source=parsed,
    )

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
        downloading — 正在下载受限仓库快照
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
