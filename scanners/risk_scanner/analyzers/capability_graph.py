"""Build a declared-vs-observed capability graph with concrete scopes."""

from __future__ import annotations

import re
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
    contents: dict[str, str] | None = None,
) -> CapabilityGraph:
    graph = CapabilityGraph()
    for capability in sorted(_declared_capabilities(metadata)):
        graph.edges.append(CapabilityEdge(capability, "manifest", declared=True))

    for path, analysis in python.items():
        for event in analysis.calls:
            capability = "dynamic_code" if event.kind in {"dangerous", "reflective"} else "dynamic_import"
            if event.resolved and "subprocess" in event.resolved:
                capability = "process.spawn"
            elif event.resolved and event.resolved.startswith("os."):
                capability = "shell.execute"
            graph.edges.append(CapabilityEdge(capability, path, event.line))
    for path, analysis in javascript.items():
        for event in analysis.calls:
            capability = event.kind
            if event.kind == "process":
                capability = "shell.execute" if (
                    event.shell_capable or event.calling.endswith(".execFile")
                ) else "process.spawn"
            elif event.kind == "network":
                capability = "network.request"
            elif event.kind == "filesystem":
                capability = "filesystem.access"
            graph.edges.append(CapabilityEdge(capability, path, event.line))
    for path, analysis in shell.items():
        for command in analysis.commands:
            lowered = tuple(value.lower() for value in command.argv)
            if lowered and lowered[0] in {"curl", "wget"}:
                graph.edges.append(CapabilityEdge("network.download", path, command.line))
            if command.pipeline and any(value in {"sh", "bash"} for value in lowered):
                graph.edges.append(CapabilityEdge("shell.execute", path, command.line))

    for path, content in sorted((contents or {}).items()):
        _add_source_capabilities(graph, path, content)
    return graph


_LOOPBACK = r"(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)"


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _add_source_capabilities(graph: CapabilityGraph, path: str, content: str) -> None:
    for match in re.finditer(
        rf"\.listen\s*\([^)]*[\"']{_LOOPBACK}[\"']\s*\)", content, re.I
    ):
        graph.edges.append(CapabilityEdge("network.listen_local", path, _line_number(content, match.start())))
    for match in re.finditer(
        r"\.listen\s*\([^)]*[\"'](?:0\.0\.0\.0|::)[\"']\s*\)", content, re.I
    ):
        graph.edges.append(CapabilityEdge("network.listen_public", path, _line_number(content, match.start())))

    # Python test/server launchers commonly express the bind address as argv.
    if re.search(r"\bhttp\.server\b", content) and re.search(
        rf"(?:--bind[\"',\s]+{_LOOPBACK}|[\"']{_LOOPBACK}[\"'])", content, re.I
    ):
        graph.edges.append(CapabilityEdge("network.local_service", path))

    for match in re.finditer(rf"https?://{_LOOPBACK}\b", content, re.I):
        line = content.splitlines()[_line_number(content, match.start()) - 1]
        if not re.search(r"(?:===|==|!==|!=)", line):
            graph.edges.append(CapabilityEdge("network.local_service", path, _line_number(content, match.start())))

    asset_url = re.search(r"https://[^\s\"'<>`]+", content, re.I)
    if asset_url and re.search(
        r"(?:<img\b|\bsrc\s*=|background-image|\.png\b|\.jpe?g\b|\.svg\b|\.webp\b)",
        content,
        re.I,
    ):
        graph.edges.append(CapabilityEdge("network.external_asset", path, _line_number(content, asset_url.start())))

    metadata = re.search(r"(?:169\.254\.169\.254|metadata\.google\.internal)", content, re.I)
    if metadata:
        graph.edges.append(CapabilityEdge("network.metadata", path, _line_number(content, metadata.start())))

    if re.search(r"\b(?:GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)\b", content):
        graph.edges.append(CapabilityEdge("credential.read", path))
        if re.search(r"https?://", content) and re.search(
            r"(?:urlopen|requests?\.|httpx\.|fetch|axios)", content, re.I
        ):
            graph.edges.append(CapabilityEdge("network.egress", path))
