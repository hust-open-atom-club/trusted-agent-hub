from pathlib import Path

Path("package_state.json").write_text("{}", encoding="utf-8")
