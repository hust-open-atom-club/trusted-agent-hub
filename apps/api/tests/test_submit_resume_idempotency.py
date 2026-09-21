"""中断续接（幂等提交）契约测试。"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from src.database import Base, create_engine_from_url, create_session_factory
from src.models.producer import CreatePackageRequest, CreateVersionRequest
from src.repositories.orm_producer import UserRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import ProducerService, ProducerServiceError

REPO_URL = "https://github.com/repro-owner/repro-demo"
USER = "resume-user"


@pytest.fixture
def service() -> ProducerService:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        session.add_all(
            [
                UserRow(
                    id=USER,
                    email="resume@example.com",
                    password_hash="hash",
                    role="submitter",
                    display_name="Resume User",
                ),
                UserRow(
                    id="other-user",
                    email="other@example.com",
                    password_hash="hash",
                    role="submitter",
                    display_name="Other User",
                ),
            ]
        )
        session.commit()
    try:
        yield ProducerService(ProducerRepository(session_factory))
    finally:
        engine.dispose()


def _package_request(
    name: str = "resume-demo", **overrides: object
) -> CreatePackageRequest:
    payload: dict[str, object] = {
        "name": name,
        "type": "skill",
        "description": "resume test package",
        "source": {
            "type": "github",
            "repository_url": REPO_URL,
            "ref": "main",
            "commit_hash": "a" * 40,
        },
    }
    payload.update(overrides)
    return CreatePackageRequest.model_validate(payload)


def _version_request(
    version: str = "0.1.0",
    repository_url: str = REPO_URL,
    **overrides: object,
) -> CreateVersionRequest:
    payload: dict[str, object] = {
        "version": version,
        "repo_url": repository_url,
        "source": {
            "type": "github",
            "repository_url": repository_url,
            "ref": "main",
            "commit_hash": "a" * 40,
        },
    }
    payload.update(overrides)
    return CreateVersionRequest.model_validate(payload)


def test_create_package_resumes_own_empty_draft_package(service: ProducerService) -> None:
    """刷新打断在建包之后、建版本之前 → 二次 create_package 续接原包。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    second = service.create_package(_package_request(), submitter_id=USER)

    assert second.id == first.id
    assert second.name == first.name


def test_create_package_updates_editable_fields_when_resuming(
    service: ProducerService,
) -> None:
    first = service.create_package(
        _package_request(description="before", license="MIT"),
        submitter_id=USER,
    )

    resumed = service.create_package(
        _package_request(
            description="after",
            license="Apache-2.0",
            keywords=["edited"],
        ),
        submitter_id=USER,
    )
    stored = service.repository.get_package(first.id)

    assert resumed.id == first.id
    assert resumed.description == "after"
    assert resumed.license == "Apache-2.0"
    assert resumed.keywords == ["edited"]
    assert stored is not None
    assert stored["description"] == "after"
    assert stored["license"] == "Apache-2.0"
    assert stored["keywords"] == ["edited"]


def test_create_package_resume_refreshes_updated_at(
    service: ProducerService,
) -> None:
    first = service.create_package(_package_request(), submitter_id=USER)
    old_updated_at = "2000-01-01T00:00:00Z"
    service.repository.update_package_data(
        first.id,
        {"updated_at": old_updated_at},
    )

    resumed = service.create_package(_package_request(), submitter_id=USER)
    stored = service.repository.get_package(first.id)

    assert resumed.updated_at != old_updated_at
    assert resumed.updated_at is not None
    assert resumed.updated_at.endswith("Z")
    assert stored is not None
    assert stored["updated_at"] == resumed.updated_at


def test_create_package_partial_resume_preserves_omitted_metadata(
    service: ProducerService,
) -> None:
    first = service.create_package(
        _package_request(
            description="before",
            license="MIT",
            keywords=["keep"],
            category="security",
            author={"url": "https://github.com/repro-owner"},
        ),
        submitter_id=USER,
    )

    resumed = service.create_package(
        _package_request(description="after", license=None),
        submitter_id=USER,
    )
    stored = service.repository.get_package(first.id)

    assert resumed.description == "after"
    assert resumed.license == "MIT"
    assert resumed.keywords == ["keep"]
    assert resumed.category == "security"
    assert stored is not None
    assert stored["author"] == {"url": "https://github.com/repro-owner"}


def test_create_package_resume_rejects_status_change_during_update(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = service.create_package(
        _package_request(description="before"),
        submitter_id=USER,
    )
    original_update = service.repository.update_package_data_if_status

    def racing_update(
        package_id: str,
        updates: dict[str, object],
        expected_statuses: tuple[str, ...],
        *,
        expected_version_statuses: tuple[str, ...] | None = None,
    ) -> dict[str, object] | None:
        service.repository.update_package_status(package_id, "pending_review")
        return original_update(
            package_id,
            updates,
            expected_statuses,
            expected_version_statuses=expected_version_statuses,
        )

    monkeypatch.setattr(
        service.repository,
        "update_package_data_if_status",
        racing_update,
    )

    with pytest.raises(ProducerServiceError, match="状态已变化"):
        service.create_package(
            _package_request(description="after"),
            submitter_id=USER,
        )

    stored = service.repository.get_package(first.id)
    assert stored is not None
    assert stored["status"] == "pending_review"
    assert stored["description"] == "before"


def test_create_package_recovers_from_concurrent_duplicate_insert(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create = service.repository.create_package
    winner: dict[str, object] = {}

    def racing_create(**kwargs: object) -> dict[str, object]:
        winner.update(original_create(**kwargs))  # type: ignore[arg-type]
        raise IntegrityError("INSERT packages", kwargs, Exception("unique"))

    monkeypatch.setattr(service.repository, "create_package", racing_create)

    resumed = service.create_package(_package_request(), submitter_id=USER)

    assert resumed.id == winner["id"]


def test_create_package_concurrent_conflict_is_a_business_error(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create = service.repository.create_package

    def racing_create(**kwargs: object) -> dict[str, object]:
        original_create(**{**kwargs, "submitter_id": "other-user"})  # type: ignore[arg-type]
        raise IntegrityError("INSERT packages", kwargs, Exception("unique"))

    monkeypatch.setattr(service.repository, "create_package", racing_create)

    with pytest.raises(ProducerServiceError, match="当前账号续接"):
        service.create_package(_package_request(), submitter_id=USER)


def test_create_package_resumes_draft_package_with_matching_draft_version(
    service: ProducerService,
) -> None:
    """刷新打断在建版本之后、submit 之前 → 二次 create_package 续接原包。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(first.id, _version_request(), submitter_id=USER)

    second = service.create_package(_package_request(), submitter_id=USER)
    assert second.id == first.id


def test_create_package_does_not_resume_from_another_users_draft_version(
    service: ProducerService,
) -> None:
    package = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(
        package.id,
        _version_request(),
        submitter_id="other-user",
    )

    with pytest.raises(ProducerServiceError, match="当前账号续接"):
        service.create_package(_package_request(), submitter_id=USER)


def test_create_package_resume_rejects_version_transition_during_update(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = service.create_package(
        _package_request(description="before"),
        submitter_id=USER,
    )
    version = service.create_version(
        first.id,
        _version_request(),
        submitter_id=USER,
    )
    original_update = service.repository.update_package_data_if_status

    def racing_update(
        package_id: str,
        updates: dict[str, object],
        expected_statuses: tuple[str, ...],
        *,
        expected_version_statuses: tuple[str, ...] | None = None,
    ) -> dict[str, object] | None:
        service.repository.update_version_status(str(version["id"]), "scanning")
        return original_update(
            package_id,
            updates,
            expected_statuses,
            expected_version_statuses=expected_version_statuses,
        )

    monkeypatch.setattr(
        service.repository,
        "update_package_data_if_status",
        racing_update,
    )

    with pytest.raises(ProducerServiceError, match="状态已变化"):
        service.create_package(
            _package_request(description="after"),
            submitter_id=USER,
        )

    stored = service.repository.get_package(first.id)
    assert stored is not None
    assert stored["description"] == "before"


def test_create_package_rejects_other_users_draft_name(service: ProducerService) -> None:
    """他人的同名 draft 包不可续接，且不泄露具体归属。"""
    service.create_package(_package_request(), submitter_id=USER)

    with pytest.raises(ProducerServiceError, match="当前账号续接"):
        service.create_package(_package_request(), submitter_id="other-user")


def test_create_package_rejects_non_draft_name(service: ProducerService) -> None:
    """已进入流程（非 draft）的同名包不可续接。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    service.repository.update_package_status(first.id, "pending_review")

    with pytest.raises(ProducerServiceError, match="审核或发布流程"):
        service.create_package(_package_request(), submitter_id=USER)


def test_create_package_rejects_draft_package_with_non_draft_version(
    service: ProducerService,
) -> None:
    package = service.create_package(_package_request(), submitter_id=USER)
    version = service.create_version(
        package.id,
        _version_request(),
        submitter_id=USER,
    )
    service.repository.update_version_status(str(version["id"]), "scanning")

    candidates = service.repository.list_package_version_sources(package.id)
    assert candidates == [
        {
            "status": "scanning",
            "submitter_id": USER,
            "source": version["source"],
            "repo_url": None,
        }
    ]
    with pytest.raises(ProducerServiceError, match="相关版本已进入审核流程"):
        service.create_package(_package_request(), submitter_id=USER)


def test_create_package_rejects_mismatched_source_on_draft_with_versions(
    service: ProducerService,
) -> None:
    """draft 包已有 draft 版本但源码地址不同 → 不续接（防误挂别的提交流程）。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(first.id, _version_request(), submitter_id=USER)

    other_source = CreatePackageRequest.model_validate(
        {
            "name": "resume-demo",
            "type": "skill",
            "description": "different source",
            "source": {
                "type": "github",
                "repository_url": "https://github.com/repro-owner/other-repo",
                "ref": "main",
                "commit_hash": "b" * 40,
            },
        }
    )
    with pytest.raises(ProducerServiceError, match="源码地址"):
        service.create_package(other_source, submitter_id=USER)


def test_create_package_rejects_mismatched_source_on_empty_draft(
    service: ProducerService,
) -> None:
    service.create_package(_package_request(), submitter_id=USER)
    other_source = CreatePackageRequest.model_validate(
        {
            "name": "resume-demo",
            "type": "skill",
            "description": "different source",
            "source": {
                "type": "github",
                "repository_url": "https://github.com/repro-owner/other-repo",
                "ref": "main",
                "commit_hash": "b" * 40,
            },
        }
    )

    with pytest.raises(ProducerServiceError, match="源码地址"):
        service.create_package(other_source, submitter_id=USER)


def test_create_package_without_source_keeps_legacy_conflict(
    service: ProducerService,
) -> None:
    """请求不带 source（非提交流程的裸建包）时维持原重名报错。"""
    service.create_package(_package_request(), submitter_id=USER)
    bare = CreatePackageRequest.model_validate(
        {"name": "resume-demo", "type": "skill", "description": "bare"}
    )
    with pytest.raises(ProducerServiceError, match="源码地址"):
        service.create_package(bare, submitter_id=USER)


def test_create_package_resumes_legacy_repo_url_draft(
    service: ProducerService,
) -> None:
    first = service.create_package(_package_request(), submitter_id=USER)
    service.repository.update_package_data(
        first.id,
        {"source": None, "repo_url": REPO_URL},
    )

    second = service.create_package(_package_request(), submitter_id=USER)

    assert second.id == first.id


def test_create_version_resumes_own_draft_version(service: ProducerService) -> None:
    """本人 + 同包 + 同版本号 + draft → 返回已有版本（含原 id）。"""
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(pkg.id, _version_request(), submitter_id=USER)
    second = service.create_version(pkg.id, _version_request(), submitter_id=USER)

    assert second["id"] == first["id"]
    assert second["status"] == "draft"
    assert first["updated_at"] == first["created_at"]


def test_create_version_repo_url_only_create_uses_repository_fallback(
    service: ProducerService,
) -> None:
    package = service.create_package(_package_request(), submitter_id=USER)
    request = CreateVersionRequest.model_validate(
        {"version": "0.2.0", "repo_url": REPO_URL}
    )

    created = service.create_version(package.id, request, submitter_id=USER)

    assert created["source"] == {
        "type": "git",
        "repository_url": REPO_URL,
        "ref": "",
        "commit_hash": "",
    }
    assert created["updated_at"] == created["created_at"]


def test_create_version_updates_editable_fields_when_resuming(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(
        pkg.id,
        _version_request(description="before", license="MIT"),
        submitter_id=USER,
    )

    resumed = service.create_version(
        pkg.id,
        _version_request(
            description="after",
            license="Apache-2.0",
            author={"url": "https://github.com/repro-owner"},
        ),
        submitter_id=USER,
    )
    stored = service.repository.get_version(str(first["id"]))

    assert resumed["id"] == first["id"]
    assert resumed["description"] == "after"
    assert resumed["license"] == "Apache-2.0"
    assert resumed["author"] == {"url": "https://github.com/repro-owner"}
    assert stored is not None
    assert stored["description"] == "after"
    assert stored["license"] == "Apache-2.0"


def test_create_version_resume_refreshes_updated_at_when_updates_are_empty(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(
        pkg.id,
        _version_request(),
        submitter_id=USER,
    )
    old_updated_at = "2000-01-01T00:00:00Z"
    service.repository.update_version_data(
        str(first["id"]),
        {"updated_at": old_updated_at},
    )
    partial = CreateVersionRequest.model_validate(
        {"version": "0.1.0", "repo_url": REPO_URL}
    )

    resumed = service.create_version(pkg.id, partial, submitter_id=USER)
    stored = service.repository.get_version(str(first["id"]))

    assert resumed["updated_at"] != old_updated_at
    assert str(resumed["updated_at"]).endswith("Z")
    assert resumed["source"] == first["source"]
    assert stored is not None
    assert stored["updated_at"] == resumed["updated_at"]


def test_create_version_resume_rejects_status_change_during_update(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(
        pkg.id,
        _version_request(description="before"),
        submitter_id=USER,
    )
    original_update = service.repository.update_version_data_if_status

    def racing_update(
        version_id: str,
        updates: dict[str, object],
        expected_statuses: tuple[str, ...],
    ) -> dict[str, object] | None:
        service.repository.update_version_status(version_id, "scanning")
        return original_update(version_id, updates, expected_statuses)

    monkeypatch.setattr(
        service.repository,
        "update_version_data_if_status",
        racing_update,
    )

    with pytest.raises(ProducerServiceError, match="状态页"):
        service.create_version(
            pkg.id,
            _version_request(description="after"),
            submitter_id=USER,
        )

    stored = service.repository.get_version(str(first["id"]))
    assert stored is not None
    assert stored["status"] == "scanning"
    assert stored["description"] == "before"


def test_create_version_partial_resume_preserves_omitted_metadata(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(
        pkg.id,
        _version_request(
            description="before",
            license="MIT",
            author={"url": "https://github.com/repro-owner"},
            type_config={"skill_config": {"tools": ["Read"]}},
            use_cases=[{"title": "keep", "description": "keep this"}],
        ),
        submitter_id=USER,
    )

    resumed = service.create_version(
        pkg.id,
        _version_request(description="after", license=None),
        submitter_id=USER,
    )
    stored = service.repository.get_version(str(first["id"]))

    assert resumed["description"] == "after"
    assert resumed["license"] == "MIT"
    assert resumed["author"] == {"url": "https://github.com/repro-owner"}
    assert resumed["type_config"] == {"skill_config": {"tools": ["Read"]}}
    assert resumed["use_cases"] == [
        {"title": "keep", "description": "keep this"}
    ]
    assert stored is not None
    assert stored["license"] == "MIT"


def test_create_version_repo_url_only_resume_preserves_source_details(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(
        pkg.id,
        _version_request(),
        submitter_id=USER,
    )
    partial = CreateVersionRequest.model_validate(
        {
            "version": "0.1.0",
            "repo_url": REPO_URL,
            "description": "updated",
        }
    )

    resumed = service.create_version(pkg.id, partial, submitter_id=USER)

    assert resumed["id"] == first["id"]
    assert resumed["description"] == "updated"
    assert resumed["source"] == first["source"]


def test_create_version_recovers_from_concurrent_duplicate_insert(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    original_create = service.repository.create_version
    winner: dict[str, object] = {}

    def racing_create(**kwargs: object) -> dict[str, object]:
        winner.update(original_create(**kwargs))  # type: ignore[arg-type]
        raise IntegrityError("INSERT package_versions", kwargs, Exception("unique"))

    monkeypatch.setattr(service.repository, "create_version", racing_create)

    resumed = service.create_version(
        pkg.id,
        _version_request(),
        submitter_id=USER,
    )

    assert resumed["id"] == winner["id"]


def test_create_version_concurrent_conflict_is_a_business_error(
    service: ProducerService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    original_create = service.repository.create_version

    def racing_create(**kwargs: object) -> dict[str, object]:
        original_create(**{**kwargs, "submitter_id": "other-user"})  # type: ignore[arg-type]
        raise IntegrityError(
            "INSERT package_versions", kwargs, Exception("unique")
        )

    monkeypatch.setattr(service.repository, "create_version", racing_create)

    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_version(
            pkg.id,
            _version_request(),
            submitter_id=USER,
        )


def test_create_version_resumes_legacy_repo_url_draft(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(pkg.id, _version_request(), submitter_id=USER)
    service.repository.update_version_data(
        str(first["id"]),
        {"source": None, "repo_url": REPO_URL},
    )

    resumed = service.create_version(
        pkg.id,
        _version_request(description="legacy resumed"),
        submitter_id=USER,
    )

    assert resumed["id"] == first["id"]
    assert resumed["description"] == "legacy resumed"


def test_create_version_rejects_other_users_draft_version(
    service: ProducerService,
) -> None:
    with pytest.raises(ProducerServiceError):
        service.create_version("missing-package", _version_request(), submitter_id=USER)

    pkg = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(pkg.id, _version_request(), submitter_id=USER)
    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_version(pkg.id, _version_request(), submitter_id="other-user")


def test_create_version_rejects_non_draft_duplicate(service: ProducerService) -> None:
    """已提交（非 draft）的同版本号不允许静默续接。"""
    pkg = service.create_package(_package_request(), submitter_id=USER)
    created = service.create_version(pkg.id, _version_request(), submitter_id=USER)
    service.repository.update_version_status(str(created["id"]), "scanning")

    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_version(pkg.id, _version_request(), submitter_id=USER)


def test_create_version_rejects_mismatched_source_on_draft(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(pkg.id, _version_request(), submitter_id=USER)

    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_version(
            pkg.id,
            _version_request(
                repository_url="https://github.com/repro-owner/other-repo"
            ),
            submitter_id=USER,
        )


def test_create_version_resumes_canonical_equivalent_source(
    service: ProducerService,
) -> None:
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(pkg.id, _version_request(), submitter_id=USER)
    second = service.create_version(
        pkg.id,
        _version_request(repository_url=f"{REPO_URL.upper()}.git/"),
        submitter_id=USER,
    )

    assert second["id"] == first["id"]


def test_resumed_package_end_to_end_second_submission(
    service: ProducerService,
) -> None:
    """完整重演路径 A：建包+建版本后"刷新"（submit 未发出），再走一遍
    create_package → create_version → submit_version，全程不报错且落在
    同一包/版本上。"""
    first_pkg = service.create_package(_package_request(), submitter_id=USER)
    first_ver = service.create_version(first_pkg.id, _version_request(), submitter_id=USER)

    # —— 模拟刷新后的二次提交 ——
    second_pkg = service.create_package(_package_request(), submitter_id=USER)
    second_ver = service.create_version(second_pkg.id, _version_request(), submitter_id=USER)
    assert second_pkg.id == first_pkg.id
    assert second_ver["id"] == first_ver["id"]

    repo_url, scan_id, next_status = service.submit_version(
        str(first_ver["id"]),
        user_id=USER,
        scan_task={
            "owner_user_id": USER,
            "source_ref": "main",
            "commit_hash": "a" * 40,
            "source_subdirectory": None,
        },
    )
    assert next_status == "scanning"
    assert scan_id
    assert repo_url == REPO_URL
