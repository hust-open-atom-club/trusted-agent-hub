"""Data models shared by structured analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PythonCallEvent:
    line: int
    calling: str
    resolved: str | None
    kind: str


@dataclass
class PythonAstAnalysis:
    path: str
    calls: list[PythonCallEvent] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class JavaScriptCallEvent:
    line: int
    calling: str
    kind: str
    dynamic: bool = False
    input_source: str = "unknown"
    shell_capable: bool = False
    column: int = 0


@dataclass
class JavaScriptAstAnalysis:
    path: str
    calls: list[JavaScriptCallEvent] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class ShellCommand:
    line: int
    argv: tuple[str, ...]
    pipeline: bool = False
    redirections: tuple[str, ...] = ()


@dataclass
class ShellAnalysis:
    path: str
    commands: list[ShellCommand] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class StructuredDocument:
    path: str
    format: str
    parser: str
    data: Any = None
    error: str | None = None


@dataclass(frozen=True)
class CapabilityEdge:
    capability: str
    source: str
    line: int | None = None
    declared: bool = False


@dataclass
class CapabilityGraph:
    edges: list[CapabilityEdge] = field(default_factory=list)

    def as_report(self) -> dict[str, Any]:
        declared = sorted({edge.capability for edge in self.edges if edge.declared})
        observed = sorted({edge.capability for edge in self.edges if not edge.declared})
        mismatches = sorted(set(observed) - set(declared))
        return {
            "declared": declared,
            "observed": observed,
            "undeclared_observed": mismatches,
            "edge_count": len(self.edges),
        }


@dataclass
class AnalysisSnapshot:
    python_ast: dict[str, PythonAstAnalysis] = field(default_factory=dict)
    javascript_ast: dict[str, JavaScriptAstAnalysis] = field(default_factory=dict)
    shell: dict[str, ShellAnalysis] = field(default_factory=dict)
    structured_documents: list[StructuredDocument] = field(default_factory=list)
    capability_graph: CapabilityGraph = field(default_factory=CapabilityGraph)
    source_integrity: Any = None
    parse_errors: list[dict[str, str]] = field(default_factory=list)

    def as_report(self) -> dict[str, Any]:
        return {
            "python_files": len(self.python_ast),
            "javascript_files": len(self.javascript_ast),
            "shell_files": len(self.shell),
            "structured_documents": len(self.structured_documents),
            "parse_errors": len(self.parse_errors),
            "capability_graph": self.capability_graph.as_report(),
        }
