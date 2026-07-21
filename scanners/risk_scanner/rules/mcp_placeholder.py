"""SR-017: MCP Server security placeholder.

This rule is reserved for future MCP (Model Context Protocol) server security checks:
  - Manifest-vs-code capability cross-referencing (least privilege)
  - Tool poisoning detection (hidden instructions / Unicode deception / parameter injection)
  - HTTP transport security
  - Version drift detection

Currently returns no findings. Revisit when MCP support is added to the platform.
"""

from __future__ import annotations

from typing import Any


def run(scanner: Any) -> None:
    pass
