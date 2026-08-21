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
    metadata = store.save({"main.py": "print('hello')"})
    assert metadata["snapshot_id"].startswith("snapshot-")
    assert store.load_for_diff(metadata["snapshot_id"]) == {"main.py": "print('hello')"}
    assert (tmp_path / f"{metadata['snapshot_id']}.json").exists()
    store.delete(metadata["snapshot_id"])
    assert store.load_for_diff(metadata["snapshot_id"]) == {}
