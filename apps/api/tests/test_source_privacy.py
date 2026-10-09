import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

from scanners.risk_scanner.redaction import redact_report
from scanners.risk_scanner.source_context import build_finding_context_bundle
from src.services.source_snapshots import SourceSnapshotStore
from src.services import source_snapshots


def test_redaction_removes_secrets_from_report_and_context():
    secret = "Bearer abcdefghijklmnop password=supersecret"
    report = redact_report({"evidence": secret, "nested": {"api_key": "raw-key"}})
    assert "supersecret" not in str(report)
    assert "raw-key" not in str(report)

    contexts, _ = build_finding_context_bundle(
        [{
            "id": "f1",
            "severity": "high",
            "requires_llm_validation": True,
            "location": {"file": "main.py", "line": 2},
        }],
        {"main.py": "safe = 1\npassword=supersecret\nreturn safe\n"},
    )
    assert "supersecret" not in contexts["f1"]
    assert len(contexts["f1"].encode()) <= 4096


def test_semantic_candidate_uses_original_severity_for_context():
    contexts, _ = build_finding_context_bundle(
        [{
            "id": "semantic-1",
            "severity": "info",
            "candidate_severity": "high",
            "requires_llm_validation": True,
            "location": {"file": "SKILL.md", "line": 2},
        }],
        {"SKILL.md": "# Safe example\nDo not run the quoted destructive command\n"},
    )

    assert "semantic-1" in contexts
    assert "Do not run" in contexts["semantic-1"]


def test_context_bundle_audits_all_referenced_locations_and_actual_ranges():
    contexts, audit = build_finding_context_bundle(
        [{
            "id": "f1",
            "severity": "high",
            "requires_llm_validation": True,
            "location": {"file": "main.py", "line": 2},
            "occurrences": {
                "count": 2,
                "items": [
                    {"file": "main.py", "line": 2},
                    {"file": "helper.py", "line": 3},
                ],
            },
        }],
        {
            "main.py": "one\ntwo\nthree\n",
            "helper.py": "alpha\nbeta\ngamma\ndelta\n",
        },
        max_lines=3,
    )

    finding_audit = audit["findings"]["f1"]
    assert "[SOURCE file=main.py" in contexts["f1"]
    assert "[SOURCE file=helper.py" in contexts["f1"]
    assert finding_audit["delivery_status"] == "complete"
    assert finding_audit["requested_locations"] == 2
    assert finding_audit["included_locations"] == 2
    assert finding_audit["files"] == ["helper.py", "main.py"]
    assert finding_audit["transport_truncated"] is False
    assert audit["summary"]["complete"] == 1


def test_context_bundle_marks_byte_truncation_partial_without_overstating_lines():
    contexts, audit = build_finding_context_bundle(
        [{
            "id": "f1",
            "severity": "high",
            "requires_llm_validation": True,
            "location": {"file": "main.py", "line": 3},
        }],
        {"main.py": "one\ntwo\nthree\nfour\nfive\n"},
        max_lines=5,
        max_bytes_per_finding=60,
    )

    finding_audit = audit["findings"]["f1"]
    delivered_numbers = [
        int(line.split(":", 1)[0])
        for line in contexts["f1"].splitlines()
        if line.split(":", 1)[0].isdigit()
    ]
    assert finding_audit["delivery_status"] == "partial"
    assert finding_audit["transport_truncated"] is True
    assert finding_audit["included_line_count"] == len(set(delivered_numbers))
    assert finding_audit["line_ranges"][0]["end_line"] == max(delivered_numbers)


def test_source_snapshot_store_is_independent_and_expiring(tmp_path: Path):
    store = SourceSnapshotStore(tmp_path, ttl_seconds=60)
    files = {"main.py": "print('hello')\npassword=supersecret\n"}
    metadata = store.save(files, source_hash="a" * 64, owner_id="user-1")
    assert metadata["snapshot_id"].startswith("snapshot-")
    expected_hash = hashlib.sha256(
        json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert metadata["sha256"] == expected_hash
    assert metadata["sha256"] != "a" * 64
    assert store.load_for_diff(metadata["snapshot_id"]) == {
        "main.py": "print('hello')\npassword=supersecret\n",
    }
    assert (tmp_path / f"{metadata['snapshot_id']}.json").exists()

    context = store.load_context(
        metadata["snapshot_id"], "main.py", line=2, expected_owner_id="user-1"
    )
    assert context is not None
    assert context["redacted"] is True
    assert "supersecret" not in context["content"]
    assert store.load_context(
        metadata["snapshot_id"], "main.py", expected_owner_id="other-user"
    ) is None
    assert store.load_context(metadata["snapshot_id"], "../secret.txt") is None

    # A second store instance represents another API worker sharing the same
    # configured persistent volume.
    worker_store = SourceSnapshotStore(tmp_path, ttl_seconds=60)
    assert worker_store.load_for_diff(metadata["snapshot_id"])["main.py"].startswith("print")
    expired = worker_store.save({"old.py": "old"}, ttl_seconds=1)
    assert worker_store.cleanup_expired(now=expired["expires_at"] + 1) == 1

    store.delete(metadata["snapshot_id"])
    assert store.load_for_diff(metadata["snapshot_id"]) == {}


def test_preview_redacts_a_large_file_once_across_windows(tmp_path, monkeypatch):
    redact = Mock(wraps=source_snapshots.redact_text)
    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    store = SourceSnapshotStore(tmp_path)
    source = (
        "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n"
        + "let value = 1;\n" * 160_000
    )
    snapshot_id = store.save({"bundle.js": source})["snapshot_id"]

    middle = store.load_context(snapshot_id, "bundle.js", line=2, max_lines=1)
    later = store.load_context(snapshot_id, "bundle.js", line=10, max_lines=2)

    assert middle["content"] == ""
    assert middle["start_line"] == middle["end_line"] == 2
    assert later["content"] == "let value = 1;\nlet value = 1;"
    assert later["total_lines"] == 160_003
    assert redact.call_count == 1
    # Only redacted data is retained in the cache.
    assert all(
        "private-material" not in line
        for entry in store._context_cache.values()
        for line in entry.lines
    )


def test_preview_cache_detects_replacement_by_another_worker(tmp_path, monkeypatch):
    redact = Mock(wraps=source_snapshots.redact_text)
    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    store = SourceSnapshotStore(tmp_path)
    snapshot_id = store.save({"main.py": "old\npassword=firstsecret"})["snapshot_id"]
    assert store.load_context(snapshot_id, "main.py")["content"].startswith("old\n")

    worker = SourceSnapshotStore(tmp_path)
    worker.save({"main.py": "new\npassword=secondsecret"}, snapshot_id=snapshot_id)
    preview = store.load_context(snapshot_id, "main.py")

    assert preview["content"].startswith("new\n")
    assert "secondsecret" not in preview["content"]
    assert redact.call_count == 2
    store.load_context(snapshot_id, "main.py")
    assert redact.call_count == 2

    store.save({"main.py": "latest"}, snapshot_id=snapshot_id)
    assert not store._context_cache
    assert store.load_context(snapshot_id, "main.py")["content"] == "latest"
    assert redact.call_count == 3


def test_preview_cache_preserves_owner_and_expiry_checks(tmp_path, monkeypatch):
    redact = Mock(wraps=source_snapshots.redact_text)
    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    store = SourceSnapshotStore(tmp_path)
    metadata = store.save({"main.py": "safe"}, owner_id="owner", ttl_seconds=60)
    snapshot_id = metadata["snapshot_id"]
    assert store.load_context(
        snapshot_id, "main.py", expected_owner_id="owner",
    ) is not None
    assert store.load_context(
        snapshot_id, "main.py", expected_owner_id="other",
    ) is None
    monkeypatch.setattr(source_snapshots.time, "time", lambda: metadata["expires_at"] + 1)

    assert store.load_context(
        snapshot_id, "main.py", expected_owner_id="owner",
    ) is None
    assert redact.call_count == 1
    assert not store._context_cache
    assert store._context_cache_bytes == 0
    assert not (tmp_path / f"{snapshot_id}.json").exists()


@pytest.mark.parametrize("operation", ["delete", "cleanup_expired"])
def test_removing_a_snapshot_evicts_its_preview_cache(tmp_path, operation):
    store = SourceSnapshotStore(tmp_path)
    metadata = store.save({"main.py": "safe"}, ttl_seconds=60)
    snapshot_id = metadata["snapshot_id"]
    store.load_context(snapshot_id, "main.py")

    if operation == "delete":
        store.delete(snapshot_id)
    else:
        assert store.cleanup_expired(now=metadata["expires_at"] + 1) == 1

    assert store.load_context(snapshot_id, "main.py") is None
    assert not store._context_cache
    assert store._context_cache_bytes == 0


@pytest.mark.parametrize("bound", ["entries", "bytes"])
def test_preview_cache_evicts_least_recently_used_files_within_bounds(
    tmp_path, monkeypatch, bound,
):
    redact = Mock(wraps=source_snapshots.redact_text)
    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    monkeypatch.setattr(source_snapshots, "_CONTEXT_CACHE_MAX_ENTRIES", 2)
    store = SourceSnapshotStore(tmp_path)
    snapshot_id = store.save({"a.py": "a" * 100, "b.py": "b" * 100, "c.py": "c" * 100})[
        "snapshot_id"
    ]
    store.load_context(snapshot_id, "a.py")
    if bound == "bytes":
        monkeypatch.setattr(source_snapshots, "_CONTEXT_CACHE_MAX_ENTRIES", 128)
        monkeypatch.setattr(
            source_snapshots, "_CONTEXT_CACHE_MAX_BYTES", store._context_cache_bytes * 2,
        )
    store.load_context(snapshot_id, "b.py")
    store.load_context(snapshot_id, "a.py")
    store.load_context(snapshot_id, "c.py")
    store.load_context(snapshot_id, "a.py")
    assert redact.call_count == 3

    store.load_context(snapshot_id, "b.py")
    assert redact.call_count == 4
    assert len(store._context_cache) == 2
    assert store._context_cache_bytes <= source_snapshots._CONTEXT_CACHE_MAX_BYTES


def test_preview_does_not_cache_a_file_larger_than_the_cache_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(source_snapshots, "_CONTEXT_CACHE_MAX_BYTES", 100)
    store = SourceSnapshotStore(tmp_path)
    snapshot_id = store.save({"main.py": "x" * 200})["snapshot_id"]

    assert store.load_context(snapshot_id, "main.py")["content"] == "x" * 200
    assert not store._context_cache
    assert store._context_cache_bytes == 0


@pytest.mark.parametrize("text", ["var x=1;" * 2000, "变" * 6000], ids=["ascii", "unicode"])
def test_preview_keeps_a_marked_utf8_prefix_of_an_oversized_line(tmp_path, text):
    store = SourceSnapshotStore(tmp_path)
    snapshot = store.save({"bundle.min.js": text})["snapshot_id"]
    preview = store.load_context(snapshot, "bundle.min.js", max_bytes=8192)
    assert preview is not None
    assert preview["content"] and text.startswith(preview["content"])
    assert len(preview["content"].encode()) <= 8192
    assert preview["start_line"] == preview["end_line"] == preview["total_lines"] == 1
    assert preview["truncated"] and preview["partial_line"]


def test_private_key_redaction_handles_unclosed_blocks_in_bounded_time(monkeypatch):
    # A subprocess timeout makes a regression fail instead of wedging pytest.
    # pytest's pythonpath setting is not inherited by the child interpreter.
    monkeypatch.delenv("PYTHONPATH", raising=False)
    subprocess.run([
        sys.executable, "-c", "\n".join([
            "from scanners.risk_scanner.redaction import redact_text",
            "value = '-----BEGIN PRIVATE KEY-----\\nsecret-material\\n' * 50000",
            "result = redact_text(value)",
            "assert 'secret-material' not in result",
            "assert result.count('\\n') == value.count('\\n')",
            "assert redact_text('x' * 2097152) == 'x' * 2097152",
            "assert redact_text('postgresql://user:secret@host') == 'postgresql://user:[REDACTED]@host'",
        ]),
    ],
        check=True,
        timeout=10,
        capture_output=True,
        cwd=Path(__file__).resolve().parents[3],
    )


def test_preview_cache_miss_does_not_block_other_files(tmp_path, monkeypatch):
    store = SourceSnapshotStore(tmp_path)
    snapshot = store.save({"slow.py": "slow", "fast.py": "fast"})["snapshot_id"]
    started, release = Event(), Event()
    original = source_snapshots.redact_text
    calls = []

    def redact(value):
        calls.append(value)
        if value == "slow":
            started.set()
            assert release.wait(5)
        return original(value)

    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    with ThreadPoolExecutor(max_workers=3) as pool:
        slow = pool.submit(store.load_context, snapshot, "slow.py")
        try:
            assert started.wait(2)
            duplicate = pool.submit(store.load_context, snapshot, "slow.py")
            fast = pool.submit(store.load_context, snapshot, "fast.py")
            assert fast.result(timeout=2)["content"] == "fast"
        finally:
            release.set()
        assert slow.result(timeout=2) == duplicate.result(timeout=2)
    assert calls.count("slow") == 1


def test_deleting_snapshot_during_redaction_does_not_repopulate_cache(tmp_path, monkeypatch):
    store = SourceSnapshotStore(tmp_path)
    snapshot = store.save({"slow.py": "slow"})["snapshot_id"]
    started, release = Event(), Event()

    def redact(value):
        started.set()
        assert release.wait(5)
        return value

    monkeypatch.setattr(source_snapshots, "redact_text", redact)
    with ThreadPoolExecutor(max_workers=2) as pool:
        preview = pool.submit(store.load_context, snapshot, "slow.py")
        try:
            assert started.wait(2)
            pool.submit(store.delete, snapshot).result(timeout=2)
        finally:
            release.set()
        preview.result(timeout=2)
    assert not store._context_cache
    assert not store._context_pending
    assert store.load_context(snapshot, "slow.py") is None


@pytest.mark.parametrize("source", [
    "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nsecret-material",
    "Bearer\nsecret-material",
], ids=["closed-key", "unclosed-key", "bearer"])
def test_redaction_preserves_the_last_source_line_without_a_trailing_newline(tmp_path, source):
    last = len(source.splitlines())
    store = SourceSnapshotStore(tmp_path)
    snapshot = store.save({"source.txt": source})["snapshot_id"]
    preview = store.load_context(snapshot, "source.txt", line=last, max_lines=1)
    assert preview is not None
    assert preview["start_line"] == preview["end_line"] == preview["total_lines"] == last
    assert "secret-material" not in preview["content"]
    finding = {
        "id": "last-line", "requires_llm_validation": True,
        "location": {"file": "source.txt", "line": last},
    }
    contexts, audit = build_finding_context_bundle([finding], {"source.txt": source})
    assert audit["summary"]["complete"] == 1
    assert f"{last}: " in contexts["last-line"]
