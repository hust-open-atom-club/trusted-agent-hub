from pathlib import Path

from scanners.risk_scanner.redaction import build_finding_contexts, redact_report
from src.services.source_snapshots import SourceSnapshotStore


def test_redaction_removes_secrets_from_report_and_context():
    secret = "Bearer abcdefghijklmnop password=supersecret"
    report = redact_report({"evidence": secret, "nested": {"api_key": "raw-key"}})
    assert "supersecret" not in str(report)
    assert "raw-key" not in str(report)

    contexts = build_finding_contexts(
        [{"id": "f1", "severity": "high", "location": {"file": "main.py", "line": 2}}],
        {"main.py": "safe = 1\npassword=supersecret\nreturn safe\n"},
    )
    assert "supersecret" not in contexts["f1"]
    assert len(contexts["f1"].encode()) <= 4096


def test_source_snapshot_store_is_independent_and_expiring(tmp_path: Path):
    store = SourceSnapshotStore(tmp_path, ttl_seconds=60)
    metadata = store.save({"main.py": "print('hello')\npassword=supersecret\n"}, owner_id="user-1")
    assert metadata["snapshot_id"].startswith("snapshot-")
    assert store.load_for_diff(metadata["snapshot_id"]) == {
        "main.py": "print('hello')\npassword=supersecret\n"
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
