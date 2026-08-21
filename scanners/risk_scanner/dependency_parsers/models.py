from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyRecord:
    name: str
    version: str | None
    ecosystem: str
    direct: bool
    source_file: str
    registry: str | None = None
    integrity: str | None = None
