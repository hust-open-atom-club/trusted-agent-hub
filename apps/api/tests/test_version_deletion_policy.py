"""Scope V matrix, authorization, confirmation and transactional regressions."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from src.auth import get_current_user
from src.dependencies import CurrentUser
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.orm_producer import AuditLogRow
from src.routers import review, trust
from src.services.producer import ProducerService
from src.version_deletion import VersionDeletionError, WITHDRAWABLE_STATUSES
from tests.test_scan_task_persistence import scan_repository

STATES = ['draft', 'pending_review', 'changes_requested', 'rejected', 'error', 'yanked',
          'submitted', 'scanning', 'resubmitted', 'approved', 'published']


def seed(repository, status='draft', number='1.0.0', package_id=None):
    if not package_id:
        package_id = repository.create_package(name='deletion-demo', type='skill', description='delete', submitter_id='scan-user-1')['id']
    version = repository.create_version(package_id=package_id, version=number, repo_url='https://github.com/acme/demo', submitter_id='scan-user-1')
    repository.update_version_status(version['id'], status)
    return package_id, version['id']


@pytest.mark.parametrize('status', STATES)
@pytest.mark.parametrize('role,owner', [('submitter', True), ('reviewer', True), ('admin', False), ('submitter', False), ('reviewer', False), ('user', True)])
def test_version_deletion_matrix_over_http(scan_repository, monkeypatch, status, role, owner):
    repository, _ = scan_repository
    package_id, version_id = seed(repository, status)
    monkeypatch.setattr(review, '_get_producer_repository', lambda: repository)
    monkeypatch.setattr(trust, '_scans', {})
    app = FastAPI()
    app.include_router(review.router)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(id='scan-user-1' if owner else 'scan-user-2', role=role)
    authorized = role == 'admin' or (owner and role in {'submitter', 'reviewer'})
    allowed = authorized and (status in WITHDRAWABLE_STATUSES or (role == 'admin' and status == 'yanked'))
    with TestClient(app) as client:
        preview = client.get(f'/api/v0/producer/versions/{version_id}/deletion-preview')
        assert preview.status_code == (200 if authorized else 403)
        if authorized:
            assert preview.json()['allowed'] == allowed
            assert preview.json()['scope'] == ('V' if allowed else 'N')
            if allowed:
                assert preview.json()['action'] == ('删除版本' if status == 'yanked' else '撤回并删除提交')
        response = client.request('DELETE', f'/api/v0/producer/versions/{version_id}', json={'confirmed': True, 'expected_status': status})
        assert response.status_code == (200 if allowed else 409 if authorized else 403)
    assert (repository.get_version(version_id) is None) == allowed
    assert repository.get_package(package_id) is not None
    assert len(repository.list_audit_logs(target_id=version_id, action='delete_version')) == int(allowed)


@pytest.mark.parametrize('body', [None, {}, {'confirmed': False, 'expected_status': 'draft'}, {'confirmed': True}])
def test_version_deletion_requires_explicit_confirmation(scan_repository, monkeypatch, body):
    repository, _ = scan_repository
    _, version_id = seed(repository)
    monkeypatch.setattr(review, '_get_producer_repository', lambda: repository)
    app = FastAPI()
    app.include_router(review.router)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(id='scan-user-1', role='submitter')
    with TestClient(app) as client:
        assert client.request('DELETE', f'/api/v0/producer/versions/{version_id}', json=body).status_code == 422
    assert repository.get_version(version_id) is not None


def test_delete_rechecks_relational_status_and_writes_nothing_after_race(scan_repository):
    repository, _ = scan_repository
    _, version_id = seed(repository, 'pending_review')
    preview = repository.preview_version_deletion(version_id, operator_id='scan-user-1', operator_role='submitter')
    # Even stale JSON must not override the authoritative state changed by review.
    with repository.session_factory() as session:
        session.get(PackageVersionRow, version_id).status = 'approved'
        session.commit()
    with pytest.raises(VersionDeletionError):
        repository.delete_version(version_id, operator_id='scan-user-1', operator_role='submitter', expected_status=preview['status'])
    assert repository.get_version(version_id) is not None
    assert repository.list_audit_logs(target_id=version_id, action='delete_version') == []


@pytest.mark.parametrize('scan_status,callback,lease', [('scanning', 'pending', False), ('complete', 'pending', False), ('complete', 'delivered', True)])
def test_version_cannot_delete_active_scans_callbacks_or_leases(scan_repository, scan_status, callback, lease):
    repository, _ = scan_repository
    _, version_id = seed(repository, 'error')
    repository.create_scan_task(scan_id='busy', owner_user_id='scan-user-1', client_request_id='busy', repo_url='https://github.com/acme/busy', status=scan_status, callback_status=callback, version_id=version_id)
    if lease:
        repository.update_scan_task('busy', {'lease_until': datetime.now(timezone.utc) + timedelta(minutes=2)})
    preview = repository.preview_version_deletion(version_id, operator_id='admin', operator_role='admin')
    assert preview['allowed'] is False
    with pytest.raises(VersionDeletionError):
        repository.delete_version(version_id, operator_id='admin', operator_role='admin', expected_status='error')
    assert repository.get_scan_task('busy') is not None


def test_scope_v_preserves_package_other_versions_and_independent_audits(scan_repository, monkeypatch):
    repository, _ = scan_repository
    package_id, old_id = seed(repository, 'published')
    _, version_id = seed(repository, 'changes_requested', '2.0.0', package_id)
    repository.update_package_status(package_id, 'published', latest_version='1.0.0')
    repository.create_scan_task(scan_id='attached', owner_user_id='scan-user-1', client_request_id='attached', repo_url='https://github.com/acme/attached', status='complete', callback_status='delivered', version_id=version_id)
    repository.save_scan_report(version_id=version_id, scan_json={'findings': []})
    repository.create_review_record(version_id=version_id, reviewer_id='scan-user-2', conclusion='changes_requested')
    repository.create_audit_log(action='review', target_type='version', target_id=version_id, operator_id='scan-user-2')
    package_before = repository.get_package(package_id)
    old_before = repository.get_version(old_id)
    monkeypatch.setattr(trust, '_scans', {'attached': {'version_id': version_id}, 'other': {'version_id': old_id}})
    preview = repository.preview_version_deletion(version_id, operator_id='scan-user-1', operator_role='submitter')
    assert [preview[k] for k in ('scan_count', 'report_count', 'review_count')] == [1, 1, 1]
    ProducerService(repository).delete_version(version_id=version_id, operator_id='scan-user-1', operator_role='submitter', expected_status='changes_requested')
    assert repository.get_version(version_id) is None
    assert repository.get_version(old_id) == old_before
    assert repository.get_package(package_id)['latest_version'] == package_before['latest_version']
    assert repository.get_scan_task('attached') is None
    assert repository.get_scan_report(version_id) is None
    assert repository.list_review_records(version_id) == []
    assert set(trust._scans) == {'other'}
    assert {a['action'] for a in repository.list_audit_logs(target_id=version_id)} == {'review', 'delete_version'}


def test_audit_failure_rolls_back_deletion(scan_repository):
    repository, engine = scan_repository
    _, version_id = seed(repository)
    repository.save_scan_report(version_id=version_id, scan_json={})
    def fail_audit(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith('INSERT INTO AUDIT_LOGS'):
            raise RuntimeError('audit unavailable')
    event.listen(engine, 'before_cursor_execute', fail_audit)
    try:
        with pytest.raises(RuntimeError, match='audit unavailable'):
            repository.delete_version(version_id, operator_id='scan-user-1', operator_role='submitter', expected_status='draft')
    finally:
        event.remove(engine, 'before_cursor_execute', fail_audit)
    assert repository.get_version(version_id) is not None
    assert repository.get_scan_report(version_id) is not None


@pytest.mark.parametrize('scan_status', ['pending', 'downloading', 'scanning', 'llm_review', 'scoring', 'saving', 'complete', 'error', 'llm_timeout', 'total_timeout'])
@pytest.mark.parametrize('attached', [False, True])
@pytest.mark.parametrize('role', ['submitter', 'admin'])
def test_scope_s_matrix_matches_projection_and_storage(scan_repository, scan_status, attached, role):
    repository, _ = scan_repository
    _, version_id = seed(repository)
    repository.create_scan_task(scan_id='matrix', owner_user_id='scan-user-1', client_request_id='matrix', repo_url='https://github.com/acme/matrix', status=scan_status, callback_status='delivered' if attached else 'not_required', version_id=version_id if attached else None)
    info = trust._scan_info_from_task(repository.get_scan_task('matrix'))
    allowed = not attached and scan_status in {'complete', 'error', 'llm_timeout', 'total_timeout'}
    assert trust._scan_delete_allowed_for_user(info, CurrentUser(id='scan-user-1' if role == 'submitter' else 'admin', role=role)) == allowed
    if allowed:
        assert repository.delete_scan_task('matrix', owner_user_id='scan-user-1' if role == 'submitter' else None) is not None
    else:
        with pytest.raises(ValueError):
            repository.delete_scan_task('matrix', owner_user_id='scan-user-1' if role == 'submitter' else None)
        assert repository.get_scan_task('matrix') is not None


@pytest.mark.parametrize('scan_status', ['complete', 'error', 'llm_timeout', 'total_timeout'])
def test_scope_s_blocks_live_lease_even_for_admin(scan_repository, scan_status):
    repository, _ = scan_repository
    repository.create_scan_task(scan_id='leased', owner_user_id='scan-user-1', client_request_id='leased', repo_url='https://github.com/acme/lease', status=scan_status)
    repository.update_scan_task('leased', {'lease_until': datetime.now(timezone.utc) + timedelta(minutes=3)})
    info = trust._scan_info_from_task(repository.get_scan_task('leased'))
    assert trust._scan_delete_allowed_for_user(info, CurrentUser(id='admin', role='admin')) is False
    with pytest.raises(ValueError):
        repository.delete_scan_task('leased')
