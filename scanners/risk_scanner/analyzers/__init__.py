"""Structured, bounded analysis helpers used by the risk scanner.

Analyzers are deliberately side-effect free: they consume the scanner's text
cache and return facts.  Rules decide whether a fact is a security finding.
This keeps parsing errors observable without making a malformed source file
abort the complete scan.
"""

from __future__ import annotations

from typing import Any

from .capability_graph import build_capability_graph
from .javascript_ast import analyze_javascript
from .manifest_analysis import analyze_structured_documents
from .models import AnalysisSnapshot
from .python_ast import analyze_python
from .shell_analysis import analyze_shell
from .source_integrity import capture_source_state


def analyze_snapshot(
    contents: dict[str, str],
    files: list[str],
    metadata: dict[str, Any] | None,
    *,
    target_dir: Any = None,
    inventory: Any = None,
) -> AnalysisSnapshot:
    """Build all structural facts from the already bounded text cache."""
    snapshot = AnalysisSnapshot()

    for relative_path in sorted(files):
        content = contents.get(relative_path, "")
        if not content:
            continue
        suffix = relative_path.rsplit(".", 1)[-1].lower() if "." in relative_path else ""
        if suffix == "py":
            result = analyze_python(relative_path, content)
            snapshot.python_ast[relative_path] = result
            if result.error:
                snapshot.parse_errors.append({"file": relative_path, "parser": "python_ast", "error": result.error})
        elif suffix in {"js", "jsx", "ts", "tsx", "mjs", "cjs"}:
            result = analyze_javascript(relative_path, content)
            snapshot.javascript_ast[relative_path] = result
            if result.error:
                snapshot.parse_errors.append({"file": relative_path, "parser": "javascript_structured", "error": result.error})
        elif suffix in {"sh", "bash", "zsh", "bat", "ps1"}:
            result = analyze_shell(relative_path, content)
            snapshot.shell[relative_path] = result
            if result.errors:
                for error in result.errors:
                    snapshot.parse_errors.append({"file": relative_path, "parser": "shell", "error": error})

    snapshot.structured_documents = analyze_structured_documents(contents, files)
    for document in snapshot.structured_documents:
        if document.error:
            snapshot.parse_errors.append({"file": document.path, "parser": document.parser, "error": document.error})

    snapshot.capability_graph = build_capability_graph(
        metadata,
        snapshot.python_ast,
        snapshot.javascript_ast,
        snapshot.shell,
        contents,
    )
    if target_dir is not None and inventory is not None:
        snapshot.source_integrity = capture_source_state(target_dir, inventory)
    return snapshot


__all__ = ["AnalysisSnapshot", "analyze_snapshot"]
