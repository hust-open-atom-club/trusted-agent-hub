"""Tests for the daily empty-package maintenance worker."""

from __future__ import annotations

from typing import Any

from src.services.package_cleanup import (
    EMPTY_PACKAGE_CLEANUP_INTERVAL_SECONDS,
    run_artifact_cleanup_loop,
    run_empty_package_cleanup_loop,
)


def test_empty_package_cleanup_loop_runs_daily() -> None:
    waits: list[float] = []
    cleanup_calls: list[int] = []

    class StopEvent:
        def wait(self, timeout: float) -> bool:
            waits.append(timeout)
            return len(waits) > 1

    class Repository:
        def delete_empty_draft_packages(self) -> int:
            cleanup_calls.append(1)
            return 0

    def repository_factory() -> Any:
        return Repository()

    run_empty_package_cleanup_loop(
        StopEvent(),
        repository_factory=repository_factory,
    )

    assert waits == [EMPTY_PACKAGE_CLEANUP_INTERVAL_SECONDS] * 2
    assert cleanup_calls == [1]


def test_artifact_cleanup_loop_runs_daily(monkeypatch) -> None:
    waits: list[float] = []
    cleanup_calls: list[int] = []

    class StopEvent:
        def wait(self, timeout: float) -> bool:
            waits.append(timeout)
            return len(waits) > 1

    class Repository:
        pass

    def cleanup_artifacts(_service) -> int:
        cleanup_calls.append(1)
        return 0

    monkeypatch.setattr(
        "src.services.package_cleanup.ProducerService.cleanup_orphan_artifacts",
        cleanup_artifacts,
    )

    def repository_factory() -> Any:
        return Repository()

    run_artifact_cleanup_loop(
        StopEvent(),
        repository_factory=repository_factory,
    )

    assert waits == [EMPTY_PACKAGE_CLEANUP_INTERVAL_SECONDS] * 2
    assert cleanup_calls == [1]
