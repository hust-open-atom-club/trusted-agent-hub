"""Build a small declared-vs-observed capability graph."""

from __future__ import annotations

from typing import Any

from .models import CapabilityEdge, CapabilityGraph, JavaScriptAstAnalysis, PythonAstAnalysis, ShellAnalysis


def _declared_capabilities(metadata: dict[str, Any] | None) -> set[str]:
    permissions = (metadata or {}).get("permissions", {}) or {}
    if not isinstance(permissions, dict):
        return set()
    result: set[str] = set()
    for name, value in permissions.items():
        allowed = value.get("allowed") if isinstance(value, dict) else bool(value)
        if allowed:
            result.add(str(name).lower())
    return result


def build_capability_graph(
    metadata: dict[str, Any] | None,
    python: dict[str, PythonAstAnalysis],
    javascript: dict[str, JavaScriptAstAnalysis],
    shell: dict[str, ShellAnalysis],
) -> CapabilityGraph:
    graph = CapabilityGraph()
    for capability in sorted(_declared_capabilities(metadata)):
        graph.edges.append(CapabilityEdge(capability, "manifest", declared=True))

    for path, analysis in python.items():
        for event in analysis.calls:
            capability = "dynamic_code" if event.kind in {"dangerous", "reflective"} else "dynamic_import"
            if event.resolved and ("subprocess" in event.resolved or event.resolved.startswith("os.")):
                capability = "process"
            graph.edges.append(CapabilityEdge(capability, path, event.line))
    for path, analysis in javascript.items():
        for event in analysis.calls:
            graph.edges.append(CapabilityEdge(event.kind, path, event.line))
    for path, analysis in shell.items():
        for command in analysis.commands:
            if command.argv:
                graph.edges.append(CapabilityEdge("shell", path, command.line))
    return graph
