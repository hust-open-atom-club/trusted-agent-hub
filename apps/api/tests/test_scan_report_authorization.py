"""Authorization boundaries for persisted scanner reports and source context."""

from __future__ import annotations

from fastapi.testclient import TestClient

from src.dependencies import CurrentUser, get_current_user
from src.main import create_app
from src.routers import producer as producer_router


class _VersionRepository:
    def get_version(self, version_id: str) -> dict[str, object]:
        return {
            "id": version_id,
            "package_id": "pkg-1",
            "version": "1.0.0",
            "status": "pending_review",
            "submitter_id": "submitter-1",
            "trust_score": {
                "score": 82,
                "risk_summary": {
                    "level": "low_risk",
                    "grade": "B",
                    "install_recommendation": "review_recommended",
                    "top_risks": ["api_key=SUPERSECRET"],
                    "requires_confirmation": True,
                },
                "explanations": [{
                    "dimension": "scan_results",
                    "message": "内部评分说明",
                    "evidence": "api_key=SUPERSECRET",
                }],
                "dimensions": {
                    "scan_results": {"details": {"evidence": "source"}},
                },
                "score_breakdown": {"evidence": "source"},
                "evidence_assessment": {"score": 10},
                "acquisition_facts": {"integrity": {"sha256": "secret"}},
            },
            "acquisition_facts": {"integrity": {"sha256": "secret"}},
        }

    def get_package(self, package_id: str) -> dict[str, object]:
        return {"id": package_id, "submitter_id": "submitter-1"}

    def get_scan_report(self, _version_id: str) -> dict[str, object]:
        return {
            "scan_json": {
                "scanner_version": "0.13.0",
                "summary": {"total": 1, "high": 1},
                "findings": [{
                    "id": "finding-1",
                    "rule_id": "SR-004",
                    "severity": "high",
                    "title": "硬编码密钥",
                    "description": "发现疑似凭据",
                    "location": {
                        "file": "SKILL.md",
                        "line": 3,
                        "snippet": "api_key: raw-secret",
                    },
                    "evidence": "api_key: raw-secret",
                    "remediation": "移除硬编码凭据",
                    "static_severity": "high",
                    "effective_severity": "high",
                    "category": "hardcoded_secret",
                    "cwe_id": "CWE-798",
                    "requires_confirmation": True,
                    "kind": "vulnerability",
                    "disposition": "confirmed_vulnerability",
                    "detector_hits": [{"evidence": "internal source context"}],
                    "llm_supporting_evidence": [{"quote": "internal source"}],
                }],
                "source_snapshot_id": "snapshot-1",
                "scan_limits": {
                    "configured": {"allow_parent_license_files": False}
                },
            }
        }


def _client_for_user(user: CurrentUser) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_version_detail_exposes_redacted_findings_to_owner_only(monkeypatch) -> None:
    repository = _VersionRepository()
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )

    with _client_for_user(CurrentUser(id="submitter-1", role="submitter")) as client:
        response = client.get("/api/v0/producer/versions/ver-1")
    assert response.status_code == 200
    submitter_payload = response.json()
    assert "scan_report" not in submitter_payload
    assert submitter_payload["findings"] == [{
        "id": "finding-1",
        "rule_id": "SR-004",
        "severity": "high",
        "file": "SKILL.md",
        "line": 3,
        "location": {"file": "SKILL.md", "line": 3},
        "remediation": "移除硬编码凭据",
        "cwe_id": "CWE-798",
    }]
    assert "evidence" not in submitter_payload["findings"][0]
    assert "description" not in submitter_payload["findings"][0]
    assert "static_severity" not in submitter_payload["findings"][0]
    assert "effective_severity" not in submitter_payload["findings"][0]
    assert "category" not in submitter_payload["findings"][0]
    assert "requires_confirmation" not in submitter_payload["findings"][0]
    assert "kind" not in submitter_payload["findings"][0]
    assert "disposition" not in submitter_payload["findings"][0]
    assert "detector_hits" not in submitter_payload["findings"][0]
    assert "llm_supporting_evidence" not in submitter_payload["findings"][0]
    assert submitter_payload["trust_score"] == {
        "score": 82,
        "risk_summary": {
            "level": "low_risk",
            "grade": "B",
            "install_recommendation": "review_recommended",
        },
    }
    for field in (
        "explanations",
        "dimensions",
        "score_breakdown",
        "evidence_assessment",
        "acquisition_facts",
    ):
        assert field not in submitter_payload["trust_score"]
    assert "acquisition_facts" not in submitter_payload
    assert submitter_payload["scan_summary"]["total"] == 1
    assert "findings" not in submitter_payload["scan_summary"]

    with _client_for_user(CurrentUser(id="submitter-2", role="submitter")) as client:
        response = client.get("/api/v0/producer/versions/ver-1")
    assert response.status_code == 403

    with _client_for_user(CurrentUser(id="reviewer-1", role="reviewer")) as client:
        response = client.get("/api/v0/producer/versions/ver-1")
    assert response.status_code == 200
    reviewer_payload = response.json()
    assert reviewer_payload["scan_report"]["scanner_version"] == "0.13.0"
    assert reviewer_payload["findings"][0]["rule_id"] == "SR-004"
    assert reviewer_payload["trust_score"]["explanations"][0]["evidence"] == (
        "api_key=SUPERSECRET"
    )


def test_source_context_is_reviewer_only(monkeypatch) -> None:
    repository = _VersionRepository()
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )

    query = "?path=SKILL.md&line=1"
    with _client_for_user(CurrentUser(id="submitter-1", role="submitter")) as client:
        response = client.get(f"/api/v0/producer/versions/ver-1/file-context{query}")
    assert response.status_code == 403
