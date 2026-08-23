"""Artifact cleanup must preserve files referenced by active versions."""

from pathlib import Path

from src.services import artifacts
from src.services.producer import ProducerService


class _ArtifactRepository:
    def list_artifact_versions(self) -> list[dict[str, object]]:
        return [
            {
                "status": "published",
                "package_name": "demo",
                "version": "1.0.0",
                "source": {
                    "commit_hash": "a" * 40,
                    "download_url": "/api/v0/artifacts/demo-1.0.0-aaaaaaaa.zip",
                },
            },
            {
                "status": "rejected",
                "package_name": "rejected",
                "version": "1.0.0",
                "source": {"commit_hash": "b" * 40},
            },
        ]


def test_cleanup_keeps_legacy_and_v2_artifacts(tmp_path: Path, monkeypatch) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    names = (
        "demo-1.0.0-aaaaaaaa.zip",
        "demo-1.0.0-aaaaaaaa-v2.zip",
        "rejected-1.0.0-bbbbbbbb.zip",
        "orphan.zip",
    )
    for name in names:
        (artifact_root / name).write_bytes(b"artifact")
    monkeypatch.setattr(artifacts, "ARTIFACTS_ROOT", artifact_root)

    deleted = ProducerService(_ArtifactRepository()).cleanup_orphan_artifacts()

    assert deleted == 2
    assert (artifact_root / "demo-1.0.0-aaaaaaaa.zip").exists()
    assert (artifact_root / "demo-1.0.0-aaaaaaaa-v2.zip").exists()
    assert not (artifact_root / "rejected-1.0.0-bbbbbbbb.zip").exists()
    assert not (artifact_root / "orphan.zip").exists()
