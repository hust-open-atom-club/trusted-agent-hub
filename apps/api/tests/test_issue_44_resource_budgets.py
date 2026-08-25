"""Regression coverage for bounded repository acquisition and extraction."""

from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path

import pytest

from packages.schema.extract_skills import extract_single_skill
from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from src.routers import trust


class _ChunkedResponse:
    def __init__(self, payload: bytes, content_length: str | None = None) -> None:
        self._payload = payload
        self.headers = (
            {"Content-Length": content_length}
            if content_length is not None
            else {}
        )
        self.requested_sizes: list[int] = []

    def read(self, size: int) -> bytes:
        self.requested_sizes.append(size)
        chunk, self._payload = self._payload[:size], self._payload[size:]
        return chunk


def _archive(entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> zipfile.ZipFile:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        for name, data in entries:
            handle.writestr(name, data)
    buffer.seek(0)
    archive = zipfile.ZipFile(buffer)
    archive._test_buffer = buffer  # type: ignore[attr-defined]
    return archive


def test_http_body_is_streamed_and_rejected_at_the_byte_limit() -> None:
    response = _ChunkedResponse(b"123456789")

    with pytest.raises(ValueError, match="HTTP response exceeds"):
        trust._copy_response_bounded(response, io.BytesIO(), max_bytes=8)

    assert response.requested_sizes
    assert max(response.requested_sizes) <= trust._ZIP_READ_CHUNK_BYTES


def test_http_content_length_is_rejected_before_body_read() -> None:
    response = _ChunkedResponse(b"unused", content_length="100")

    with pytest.raises(ValueError, match="HTTP response exceeds"):
        trust._copy_response_bounded(response, io.BytesIO(), max_bytes=10)

    assert response.requested_sizes == []


@pytest.mark.parametrize(
    "entry_name",
    ["../escape.txt", "/absolute.txt", "C:/drive.txt"],
)
def test_safe_zip_extraction_rejects_unsafe_paths(
    tmp_path: Path,
    entry_name: str,
) -> None:
    with _archive([(entry_name, b"bad")]) as archive:
        with pytest.raises(ValueError):
            trust._safe_extract_zip(archive, tmp_path)

    assert list(tmp_path.iterdir()) == []
def test_safe_zip_extraction_rejects_symlinks(tmp_path: Path) -> None:
    link = zipfile.ZipInfo("root/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16

    with _archive([(link, b"../outside")]) as archive:
        with pytest.raises(ValueError, match="special file"):
            trust._safe_extract_zip(archive, tmp_path)


def test_safe_zip_extraction_enforces_count_depth_and_expanded_bytes(
    tmp_path: Path,
) -> None:
    count_policy = ScanPolicy(max_files=1)
    with _archive([("root/a", b"a"), ("root/b", b"b")]) as archive:
        with pytest.raises(ValueError, match="entries"):
            trust._safe_extract_zip(archive, tmp_path / "count", count_policy)

    depth_policy = ScanPolicy(max_depth=1)
    with _archive([("root/a/b/c.txt", b"x")]) as archive:
        with pytest.raises(ValueError, match="depth"):
            trust._safe_extract_zip(archive, tmp_path / "depth", depth_policy)

    bytes_policy = ScanPolicy(max_total_bytes=3)
    with _archive([("root/data", b"1234")]) as archive:
        with pytest.raises(ValueError, match="expands beyond"):
            trust._safe_extract_zip(archive, tmp_path / "bytes", bytes_policy)


def test_safe_zip_extraction_accepts_a_bounded_regular_archive(
    tmp_path: Path,
) -> None:
    with _archive([("root/SKILL.md", b"# demo\n")]) as archive:
        trust._safe_extract_zip(archive, tmp_path)

    assert (tmp_path / "root" / "SKILL.md").read_bytes() == b"# demo\n"


def test_acquisition_downloads_only_the_resolved_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_hash = "a" * 40
    acquisition_root = tmp_path / "acquired"
    observed_ref: list[str] = []

    def fake_mkdtemp(*, prefix: str) -> str:
        assert prefix == "tah_repo_"
        acquisition_root.mkdir()
        return str(acquisition_root)

    def fake_download(parsed: dict[str, object], destination: str) -> bool:
        observed_ref.append(str(parsed["ref"]))
        wrapper = Path(destination) / "acme-demo-shortsha"
        wrapper.mkdir()
        (wrapper / "SKILL.md").write_text("# demo\n", encoding="utf-8")
        return True

    monkeypatch.setattr(trust.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        lambda _parsed: commit_hash,
    )
    monkeypatch.setattr(trust, "_download_zipball", fake_download)

    root, method, acquired_commit = trust._acquire_repo_source({
        "owner": "acme",
        "repo": "demo",
        "ref": "main",
    })

    assert (root, method, acquired_commit) == (
        str(acquisition_root),
        "zip",
        commit_hash,
    )
    assert observed_ref == [commit_hash]
    assert (acquisition_root / "SKILL.md").is_file()


def test_extractor_reuses_the_scanner_snapshot_without_disk_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: original\ndescription: Original description\n---\nBody.\n",
        encoding="utf-8",
    )
    policy = ScanPolicy(max_file_bytes=1024, max_total_bytes=1024)
    inventory = build_inventory(tmp_path, policy)
    contents = load_text_files(inventory, policy=policy)

    # A source mutation after the scanner snapshot must not be observed by the
    # metadata pass, and passing the snapshot must not trigger another walk.
    (tmp_path / "SKILL.md").write_text(
        "---\nname: changed\ndescription: Changed description\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "packages.schema.extract_skills.build_inventory",
        lambda *_args, **_kwargs: pytest.fail("unexpected second inventory"),
    )
    monkeypatch.setattr(
        "packages.schema.extract_skills.load_text_files",
        lambda *_args, **_kwargs: pytest.fail("unexpected second read"),
    )

    metadata = extract_single_skill(
        tmp_path,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
    )

    assert metadata["name"] == "original"
    assert metadata["description"] == "Original description"


def test_extractor_refuses_an_oversized_skill_document(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("x" * 128, encoding="utf-8")

    with pytest.raises(ValueError, match="SKILL.md"):
        extract_single_skill(
            tmp_path,
            policy=ScanPolicy(max_file_bytes=32, max_total_bytes=1024),
        )
