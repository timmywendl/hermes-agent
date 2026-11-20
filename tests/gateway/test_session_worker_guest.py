"""Offline Guest-channel integration against the original Owner SQLite store.

These tests do not qualify VZ or pretend that a Worker/VM/model executed.
"""
from contextlib import closing
from dataclasses import replace
from types import SimpleNamespace

import pytest

from agent.runtime_session_guest import GuestWorkerRPC, guest_session_store
from agent.runtime_session_store import WorkerPersistenceError
from gateway.session_worker_guest import GuestBinding, GuestOwnerEndpoint, reserve_guest_admission
from hermes_state import SessionDB
from hermes_state_runtime import (
    RuntimeStoreError, admit_session_input, begin_runtime_epoch,
    claim_session_input, recover_session_inputs, resolve_unknown_session_input, settle_session_input,
)


@pytest.fixture
def owner(tmp_path):
    with closing(SessionDB(tmp_path / 'owner.db')) as db:
        db.create_session('owned', 'cli')
        db.create_session('other', 'cli')
        epoch = begin_runtime_epoch(db, instance_id='original-owner')
        authority = SimpleNamespace(db=db, epoch=epoch, _require_admission_open=lambda: None)
        admit_session_input(db, epoch=epoch, principal_id='human', session_id='owned',
                            request_id='task', payload={'text': 'work original task'})
        row = claim_session_input(db, epoch=epoch, session_id='owned')
        binding = GuestBinding('task-1', 7, 'vm-1', 1, 'a' * 64, 'b' * 64)
        scope = reserve_guest_admission(authority, admission_id=row['admission_id'],
                                       principal_id='human', binding=binding)
        yield authority, row, scope, GuestOwnerEndpoint(authority, scope, principal_id='human')


def test_guest_persistence_uses_original_store_and_retains_physical_exclusion(owner, tmp_path):
    authority, row, scope, endpoint = owner
    assert not ({'pid', 'birth', 'secret', 'profile_id', 'db', 'claim_lock'} & set(scope))
    store = guest_session_store(endpoint, scope, tmp_path / 'guest-outbox')
    try:
        messages = [{'role': 'assistant', 'content': 'Engineering worklog'}]
        assert store.append_messages_batch('owned', messages) == 1
        assert messages[0]['_row_id'] is not None
        assert authority.db.get_messages('owned')[0]['content'] == 'Engineering worklog'
        assert authority.db.get_messages('other') == []
        assert store.finish() == {'status': 'pending_retirement'}
        worker = authority.db._read_one('SELECT * FROM worker_executions')
        assert worker['status'] == 'running'
        assert worker['execution_id'] == 'admission-worker:' + row['admission_id']
        assert worker['kind'] == 'kanban'
        retry = {'method': 'worker.persist', 'scope': scope, 'params': {
            'sequence': worker['last_sequence'], 'operation': 'execution.finish', 'payload': {}}}
        assert endpoint(retry) == {'status': 'pending_retirement'}
        with pytest.raises(RuntimeStoreError, match='guest_result_pending_retirement'):
            endpoint({'method': 'worker.persist', 'scope': scope, 'params': {
                'sequence': worker['last_sequence'] + 1, 'operation': 'transcript.append',
                'payload': {'messages': [{'role': 'assistant', 'content': 'late mutation'}]}}})
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            reserve_guest_admission(authority, admission_id=row['admission_id'], principal_id='human',
                binding=GuestBinding('task-1', 8, 'successor-vm', 1, 'a' * 64, 'b' * 64))
    finally:
        store.close()


def test_lost_ack_replays_existing_receipt_without_duplicate_message(owner, tmp_path):
    authority, _row, scope, endpoint = owner
    dropped = False

    def exchange(frame):
        nonlocal dropped
        result = endpoint(frame)
        if frame['method'] == 'worker.persist' and not dropped:
            dropped = True
            raise TimeoutError('lost transport ACK after commit')
        return result

    store = guest_session_store(exchange, scope, tmp_path / 'outbox')
    try:
        with pytest.raises(TimeoutError, match='lost transport ACK'):
            store.append_messages_batch('owned', [{'role': 'assistant', 'content': 'one result'}])
        assert len(authority.db.get_messages('owned')) == 1
        assert store.retry_pending()[0]['count'] == 1
        assert len(authority.db.get_messages('owned')) == 1
        assert store.journal['pending'] == []
    finally:
        store.close()


@pytest.mark.parametrize(('field', 'value'), [
    ('task_id', 'foreign-task'), ('run_id', 8), ('vm_id', 'foreign-vm'),
    ('connection_generation', 2), ('epoch', 2), ('session_id', 'other'),
    ('generation', True), ('image_digest', 'c' * 64), ('policy_digest', 'd' * 64),
])
def test_foreign_guest_assignment_cannot_adopt_or_write(owner, field, value):
    authority, _row, scope, endpoint = owner
    changed = scope | {field: value}
    with pytest.raises(RuntimeStoreError, match='permission_denied'):
        endpoint({'method': 'worker.adopt', 'scope': changed, 'params': {}})
    rpc = GuestWorkerRPC(endpoint, scope)
    with pytest.raises(WorkerPersistenceError, match='guest_scope_mismatch'):
        rpc('worker.adopt', **changed)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'registered'
    assert authority.db._read_one('SELECT count(*) FROM worker_receipts')[0] == 0


def test_guest_channel_revocation_is_unknown_and_owner_restart_cannot_readopt(owner):
    authority, row, scope, endpoint = owner
    endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    endpoint.revoke()
    revision = authority.db._read_one("SELECT runtime_revision FROM sessions WHERE id='owned'")[0]
    endpoint.revoke()
    assert authority.db._read_one("SELECT runtime_revision FROM sessions WHERE id='owned'")[0] == revision
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
    with pytest.raises(RuntimeStoreError, match='guest_channel_revoked'):
        endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    authority.epoch = begin_runtime_epoch(authority.db, instance_id='restarted-owner')
    recover_session_inputs(authority.db, epoch=authority.epoch)
    restarted = GuestOwnerEndpoint(authority, scope, principal_id='human')
    with pytest.raises(RuntimeStoreError, match='stale_epoch'):
        restarted({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    assert authority.db._read_one('SELECT status FROM session_admissions WHERE admission_id=?',
                                 (row['admission_id'],))[0] == 'unknown'


def test_unknown_committed_by_independent_owner_connection_cannot_be_readopted(owner, tmp_path, monkeypatch):
    authority, _row, scope, endpoint = owner
    original = authority.db._execute_write
    with closing(SessionDB(tmp_path / 'owner.db')) as competing:
        def competing_unknown_then_adopt(write, *args, **kwargs):
            def lose(conn):
                conn.execute("UPDATE worker_executions SET status='unknown'")
                conn.execute("UPDATE session_admissions SET status='unknown' WHERE status='started'")
            competing._execute_write(lose)
            return original(write, *args, **kwargs)
        monkeypatch.setattr(authority.db, '_execute_write', competing_unknown_then_adopt)
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'


def test_settlement_and_discard_cannot_retire_guest_without_physical_proof(owner):
    authority, row, scope, endpoint = owner
    endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    with pytest.raises(RuntimeStoreError, match='guest_physical_retirement_required'):
        settle_session_input(authority.db, epoch=authority.epoch, admission_id=row['admission_id'],
                             generation=scope['generation'], outcome='completed')
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'started'
    endpoint.revoke()
    with pytest.raises(RuntimeStoreError, match='guest_physical_retirement_required'):
        resolve_unknown_session_input(authority.db, epoch=authority.epoch,
            admission_id=row['admission_id'], generation=scope['generation'])
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
    with pytest.raises(RuntimeStoreError, match='unknown_execution'):
        claim_session_input(authority.db, epoch=authority.epoch, session_id='owned')


def test_forged_endpoint_scope_fails_the_durable_adoption_digest(owner):
    authority, _row, scope, _endpoint = owner
    forged = scope | {'vm_id': 'foreign-vm'}
    endpoint = GuestOwnerEndpoint(authority, forged, principal_id='human')
    with pytest.raises(RuntimeStoreError, match='permission_denied'):
        endpoint({'method': 'worker.adopt', 'scope': forged, 'params': {}})


def test_guest_denies_host_operations_and_foreign_transcript_with_real_rollback(owner):
    authority, _row, scope, endpoint = owner
    endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    for operation, payload in [
        ('delegation.dispatch', {}), ('session.context', {}), ('compression.publish', {}),
        ('host.shell', {'command': 'never execute'}),
        ('transcript.append', {'messages': [{'role': 'assistant', 'content': 'bad', 'api_key': 'forbidden'}]}),
    ]:
        with pytest.raises(RuntimeStoreError, match='invalid_params'):
            endpoint({'method': 'worker.persist', 'scope': scope, 'params': {
                'sequence': 1, 'operation': operation, 'payload': payload}})
    assert authority.db.get_messages('owned') == []
    assert authority.db._read_one('SELECT count(*) FROM worker_receipts')[0] == 0
    assert authority.db._read_one('SELECT last_sequence FROM worker_executions')[0] == 0


@pytest.mark.parametrize('binding', [
    {'run_id': True}, {'connection_generation': 0}, {'vm_id': ''}, {'image_digest': 'G' * 64},
])
def test_binding_rejects_missing_or_malformed_identity(binding):
    with pytest.raises(RuntimeStoreError, match='invalid_guest_binding'):
        replace(GuestBinding('task', 1, 'vm', 1, 'a' * 64, 'b' * 64), **binding)


def test_actual_byte_channel_persists_into_original_owner_without_host_discovery(owner, tmp_path):
    import socket
    from concurrent.futures import ThreadPoolExecutor
    from agent.runtime_session_guest import GuestByteChannel
    from gateway.session_worker_guest import serve_guest_request
    authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    with host, guest:
        host.settimeout(5)
        guest.settimeout(5)
        with host.makefile('rwb') as owner_stream, guest.makefile('rwb') as guest_stream:
            def serve():
                for _ in range(3):  # adopt, append, result-ready; no listener or Gateway
                    serve_guest_request(owner_stream, endpoint)
            with ThreadPoolExecutor(max_workers=1) as pool:
                served = pool.submit(serve)
                store = guest_session_store(GuestByteChannel(guest_stream), scope, tmp_path / 'wire-outbox')
                try:
                    assert store.append_messages_batch('owned', [
                        {'role': 'assistant', 'content': 'actual bounded byte stream'}]) == 1
                    assert store.finish() == {'status': 'pending_retirement'}
                finally:
                    store.close()
                served.result(timeout=10)
    assert authority.db.get_messages('owned')[0]['content'] == 'actual bounded byte stream'
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'

