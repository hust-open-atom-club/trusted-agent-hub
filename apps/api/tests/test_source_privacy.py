import hashlib
import json
from pathlib import Path

from scanners.risk_scanner.redaction import (
    build_finding_context_bundle,
    build_finding_contexts,
    redact_report,
)
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


def test_semantic_candidate_uses_original_severity_for_context():
    contexts = build_finding_contexts(
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
