"""中断续接（幂等提交）契约测试。

覆盖刷新一致性修复：点「提交审核」后刷新页面导致前端丢失 packageId /
versionId，用户重新走完整提交流程时——
  - create_package：本人 + 同名 + draft 包 + 同源码地址 → 续接返回原包；
  - create_version：本人 + 同包 + 同版本号 + draft → 续接返回原版本；
其余场景（他人包名、非 draft、源码不匹配）必须维持报错，防止同名劫持。
"""

from __future__ import annotations

import pytest

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


def _package_request(name: str = "resume-demo") -> CreatePackageRequest:
    return CreatePackageRequest.model_validate(
        {
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
    )


def _version_request(version: str = "0.1.0") -> CreateVersionRequest:
    return CreateVersionRequest.model_validate(
        {
            "version": version,
            "repo_url": REPO_URL,
            "source": {
                "type": "github",
                "repository_url": REPO_URL,
                "ref": "main",
                "commit_hash": "a" * 40,
            },
        }
    )


def test_create_package_resumes_own_empty_draft_package(service: ProducerService) -> None:
    """刷新打断在建包之后、建版本之前 → 二次 create_package 续接原包。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    second = service.create_package(_package_request(), submitter_id=USER)

    assert second.id == first.id
    assert second.name == first.name


def test_create_package_resumes_draft_package_with_matching_draft_version(
    service: ProducerService,
) -> None:
    """刷新打断在建版本之后、submit 之前 → 二次 create_package 续接原包。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    service.create_version(first.id, _version_request(), submitter_id=USER)

    second = service.create_package(_package_request(), submitter_id=USER)
    assert second.id == first.id


def test_create_package_rejects_other_users_draft_name(service: ProducerService) -> None:
    """他人的同名 draft 包不可续接，维持原报错且不泄露归属。"""
    service.create_package(_package_request(), submitter_id=USER)

    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_package(_package_request(), submitter_id="other-user")


def test_create_package_rejects_non_draft_name(service: ProducerService) -> None:
    """已进入流程（非 draft）的同名包不可续接。"""
    first = service.create_package(_package_request(), submitter_id=USER)
    service.repository.update_package_status(first.id, "pending_review")

    with pytest.raises(ProducerServiceError, match="已存在"):
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
    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_package(other_source, submitter_id=USER)


def test_create_package_without_source_keeps_legacy_conflict(
    service: ProducerService,
) -> None:
    """请求不带 source（非提交流程的裸建包）时维持原重名报错。"""
    service.create_package(_package_request(), submitter_id=USER)
    bare = CreatePackageRequest.model_validate(
        {"name": "resume-demo", "type": "skill", "description": "bare"}
    )
    with pytest.raises(ProducerServiceError, match="已存在"):
        service.create_package(bare, submitter_id=USER)


def test_create_version_resumes_own_draft_version(service: ProducerService) -> None:
    """本人 + 同包 + 同版本号 + draft → 返回已有版本（含原 id）。"""
    pkg = service.create_package(_package_request(), submitter_id=USER)
    first = service.create_version(pkg.id, _version_request(), submitter_id=USER)
    second = service.create_version(pkg.id, _version_request(), submitter_id=USER)

    assert second["id"] == first["id"]
    assert second["status"] == "draft"


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
