"""Development server launcher.

Usage:
    cd apps/api && python run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

if __name__ == "__main__":
    # 确保项目根目录和 packages 目录在 Python 搜索路径中
    _repo_root = Path(__file__).resolve().parents[2]  # apps/api → repo root
    _packages = _repo_root / "packages"
    sys.path.insert(0, str(_repo_root))
    sys.path.insert(0, str(_packages))

    uvicorn.run(
        "src.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
