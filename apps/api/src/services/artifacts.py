"""Artifact packaging service — clone repo, zip skill dir, compute SHA-256."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timezone


# Persisted artifacts directory (mounted as a Docker volume)
ARTIFACTS_ROOT = Path(os.environ.get("ARTIFACTS_ROOT", "/artifacts"))


class ArtifactError(Exception):
    """Artifact packaging failure."""


def _find_skill_dir(repo_dir: Path) -> Path:
    """Find the top-level skill directory inside a cloned repo.

    Heuristic: look for a directory containing SKILL.md, package.json,
    manifest.json, or pyproject.toml.  If the repo root itself is a skill,
    return the root.
    """
    markers = ["SKILL.md", "package.json", "manifest.json", "pyproject.toml", "setup.py"]

    # Check root first
    for marker in markers:
        if (repo_dir / marker).exists():
            return repo_dir

    # Check immediate subdirectories
    for child in sorted(repo_dir.iterdir()):
        if child.is_dir() and not child.name.startswith("."):
            for marker in markers:
                if (child / marker).exists():
                    return child

    # Fallback: return the whole repo
    return repo_dir


def build_artifact(
    *,
    repo_url: str,
    commit_hash: str,
    package_name: str,
    version: str,
) -> dict[str, object]:
    """Clone repo, zip the skill directory, compute SHA-256.

    Returns a dict with:
      download_url  — relative URL path for the download endpoint
      sha256        — hex digest
      download_size_bytes — byte count
    """
    # Validate commit_hash
    if not commit_hash or len(commit_hash) != 40:
        raise ArtifactError(f"Invalid commit_hash: {commit_hash!r}")

    # Ensure artifacts directory exists
    ARTIFACTS_ROOT.mkdir(parents=True, exist_ok=True)

    zip_name = f"{package_name}-{version}-{commit_hash[:8]}.zip"
    zip_path = ARTIFACTS_ROOT / zip_name

    # If artifact already exists, reuse it
    if zip_path.exists():
        sha256 = _sha256_file(zip_path)
        size = zip_path.stat().st_size
        return {
            "download_url": f"/api/v0/artifacts/{zip_name}",
            "sha256": sha256,
            "download_size_bytes": size,
        }

    with tempfile.TemporaryDirectory(prefix="tah-artifact-") as tmp:
        tmp_dir = Path(tmp)

        # Clone the repo (shallow, no checkout yet)
        _run(
            ["git", "clone", "--depth=1", repo_url, str(tmp_dir / "repo")],
            cwd=tmp,
            description=f"Clone {repo_url}",
        )

        repo_dir = tmp_dir / "repo"

        # Fetch and checkout the exact commit
        _run(
            ["git", "fetch", "--depth=1", "origin", commit_hash],
            cwd=str(repo_dir),
            description="Fetch exact commit",
        )
        _run(
            ["git", "checkout", commit_hash],
            cwd=str(repo_dir),
            description=f"Checkout {commit_hash[:8]}",
        )

        # Find skill directory
        skill_dir = _find_skill_dir(repo_dir)

        # Create ZIP
        _create_zip(skill_dir, zip_path, package_name)

    sha256 = _sha256_file(zip_path)
    size = zip_path.stat().st_size

    return {
        "download_url": f"/api/v0/artifacts/{zip_name}",
        "sha256": sha256,
        "download_size_bytes": size,
    }


def _create_zip(source_dir: Path, dest_path: Path, package_name: str) -> None:
    """Create a ZIP containing skill files directly (no wrapper directory)."""
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if file_path.is_file():
                # Skip .git and other VCS dirs
                parts = file_path.relative_to(source_dir).parts
                if any(p.startswith(".git") for p in parts):
                    continue
                arcname = str(file_path.relative_to(source_dir))
                zf.write(file_path, arcname)


def _sha256_file(path: Path) -> str:
    """Compute hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str], *, cwd: str, description: str) -> None:
    """Run a subprocess, raise ArtifactError on failure."""
    try:
        subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ArtifactError(
            f"{description} failed: {exc.stderr.strip()}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ArtifactError(
            f"{description} timed out"
        ) from exc
