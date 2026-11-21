"""Offline original-Owner Q1 custody contracts; no VZ or Worker execution.

Real Board/SessionDB transactions exercise durable intent, refusal and restart.
These tests do not supply the missing Host boundary or retirement observer.
"""
import asyncio
from contextlib import closing
from dataclasses import replace
import json
import sqlite3
from types import SimpleNamespace

import pytest

from gateway.session_authorities import SessionAuthorities
from gateway.session_authority import SessionAuthority
from gateway.session_contract import SessionRef
from gateway.session_vz_adapter import (
    NAMESPACE, PREFIX, Q1Diagnostic, recover_q1_reservations, reserve_q1_diagnostic,
)
from gateway.session_worker_guest import GuestBinding
from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_connect import connect
from hermes_state import SessionDB
from hermes_state_runtime import (
    RuntimeStoreError, admit_session_input, begin_runtime_epoch,
    claim_session_input, recover_session_inputs, resolve_unknown_session_input,
)


@pytest.fixture(params=['WAL', 'DELETE'])
def original_owner(tmp_path, monkeypatch, request):
    monkeypatch.setattr('hermes_state_wal.resolve_journal_mode', lambda: request.param.lower())
    home = tmp_path / 'disposable'
    home.mkdir()
    board_path = home / 'kanban' / 'boards' / 'q1-qualification' / 'kanban.db'
    board_path.parent.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(home))
    with closing(SessionDB(home / 'state.db')) as db, closing(connect(board_path)) as board:
        db.create_session('diagnostic', source='q1_diagnostic')
        epoch = begin_runtime_epoch(db, instance_id='original-owner')
        registry = SessionAuthorities(home)
        runner = SimpleNamespace(session_authorities=registry, _draining=False, _running_agents={})
        authority = SessionAuthority(runner, profile_id=str(home), instance_id='original-owner', db=db, epoch=epoch)
        registry.add(home, authority)
        ref = SessionRef(str(home), 'diagnostic')
        admit_session_input(db, epoch=epoch, principal_id='human', session_id=ref.session_id,
                            request_id='q1-inert', payload={'text': 'Q1 inert diagnostic'})
        row = claim_session_input(db, epoch=epoch, session_id=ref.session_id)
        task_id = kb.create_task(board, title='Disposable Q1 inert diagnostic',
                                 session_id=ref.session_id, workspace_kind='scratch')
        task = kb.claim_task(board, task_id)
        diagnostic = Q1Diagnostic(board_path,
            GuestBinding(task.id, task.current_run_id, 'disposable-vm', 1, 'a' * 64, 'b' * 64),
            'c' * 64, 'd' * 64)
        assert db._read_one('PRAGMA journal_mode')[0] == request.param.lower()
        assert board.execute('PRAGMA journal_mode').fetchone()[0] == request.param.lower()
        yield authority, ref, row, diagnostic, board


def test_original_owner_entry_denies_before_any_subprocess_and_keeps_custody(original_owner, monkeypatch):
    from gateway.run_runtime import managed_turn_count, qualify_q1_guest, stop_authority_turns
    authority, ref, row, diagnostic, board = original_owner
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('Native preconditions must precede every spawn')

    monkeypatch.setattr('gateway.session_managed_worker.subprocess.Popen', forbidden)
    with pytest.raises(RuntimeStoreError, match='q1_native_preconditions_unavailable'):
        asyncio.run(qualify_q1_guest(authority.runner, authority.profile_id, ref, row, diagnostic))
    assert calls == []
    handle, = authority._q1_native_workers.values()
    assert handle.stop.is_set() and not handle.closed.is_set()
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
    assert managed_turn_count(authority.runner) == 1
    async def stopped():
        count = stop_authority_turns(authority)
        await asyncio.gather(*authority._mutation_tasks)
        return count
    assert asyncio.run(stopped()) == 1
    assert not handle.closed.is_set()
    metadata = json.loads(board.execute('SELECT metadata FROM task_runs').fetchone()[0])
    record = metadata[NAMESPACE]
    assert record['state'] == 'STOP_UNCERTAIN' and record['native'] == 'NOT_RUN'
    assert record['claim_digest'] != kb.get_task(board, diagnostic.binding.task_id).claim_lock
    assert 'claim_lock' not in record
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
    assert handle.retirement_receipt()['stop_verified'] is False


def test_committed_binding_is_visible_on_independent_connections(original_owner):
    from gateway.run_runtime import managed_turn_count
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    with closing(sqlite3.connect(diagnostic.board_path)) as other:
        metadata = json.loads(other.execute('SELECT metadata FROM task_runs').fetchone()[0])
    with closing(sqlite3.connect(authority.db.db_path)) as other:
        key, encoded = other.execute('SELECT key,value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',)).fetchone()
    assert key == handle.key
    assert json.loads(encoded) == metadata[NAMESPACE] == handle.record
    assert handle.endpoint.scope['task_id'] == diagnostic.binding.task_id
    assert handle.endpoint.scope['run_id'] == diagnostic.binding.run_id
    assert handle.endpoint.scope['vm_id'] == diagnostic.binding.vm_id
    assert handle.endpoint.scope['epoch'] == authority.epoch
    assert recover_q1_reservations(authority) == (handle.key,)
    assert managed_turn_count(authority.runner) == 1
    with pytest.raises(RuntimeStoreError, match='q1_unretired_execution'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)


def test_restart_preserves_binding_and_blocks_discard_or_readoption(original_owner):
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    encoded = authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (handle.key,))[0]
    epoch = begin_runtime_epoch(authority.db, instance_id='restarted-owner')
    recover_session_inputs(authority.db, epoch=epoch)
    replacement = SessionAuthority(authority.runner, profile_id=authority.profile_id,
                                  instance_id='restarted-owner', db=authority.db, epoch=epoch)
    registry = SessionAuthorities(authority.profile_id)
    registry.add(authority.profile_id, replacement)
    authority.runner.session_authorities = registry
    assert recover_q1_reservations(replacement) == (handle.key,)
    with pytest.raises(RuntimeStoreError, match='q1_unretired_execution'):
        reserve_q1_diagnostic(replacement, ref, row, diagnostic)
    with pytest.raises(RuntimeStoreError, match='stale_epoch'):
        handle.endpoint({'method': 'worker.adopt', 'scope': handle.endpoint.scope, 'params': {}})
    with pytest.raises(RuntimeStoreError, match='guest_physical_retirement_required'):
        resolve_unknown_session_input(authority.db, epoch=epoch,
                                      admission_id=row['admission_id'], generation=row['generation'])
    assert authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (handle.key,))[0] == encoded


def test_damaged_recovery_bytes_remain_accounted(original_owner):
    from gateway.run_runtime import managed_turn_count
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    authority.db._execute_write(lambda conn: conn.execute(
        'UPDATE state_meta SET value=? WHERE key=?', ('{broken', handle.key)))
    authority._q1_native_workers.clear()
    assert recover_q1_reservations(authority) == (handle.key,)
    assert managed_turn_count(authority.runner) == 1
    with pytest.raises(RuntimeStoreError, match='q1_unretired_execution'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)


@pytest.mark.parametrize('metadata', ['{broken', '[]', '{"x":1,"x":2}',
                                      '{"vz_custody_v1":{"state":"STOP_UNCERTAIN"}}',
                                      '{"local_launch_v1":{"state":"RETIRED"}}'])
def test_history_or_damaged_metadata_refuses_without_mutation(original_owner, metadata):
    authority, ref, row, diagnostic, board = original_owner
    board.execute('UPDATE task_runs SET metadata=?', (metadata,))
    board.commit()
    with pytest.raises(RuntimeStoreError, match='q1_(metadata_unavailable|unretired_execution)'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == metadata
    assert not authority.db._read_all('SELECT key FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))


def test_legacy_pid_evidence_is_not_signalled_or_erased(original_owner):
    authority, ref, row, diagnostic, board = original_owner
    board.execute('UPDATE task_runs SET worker_pid=1234567')
    board.commit()
    with pytest.raises(RuntimeStoreError, match='q1_unretired_execution'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert board.execute('SELECT worker_pid FROM task_runs').fetchone()[0] == 1234567


def test_board_rollback_after_recovery_index_commit_keeps_owner_fence(original_owner, monkeypatch):
    from gateway.session_vz_adapter import Q1OwnerHandle
    authority, ref, row, diagnostic, board = original_owner
    original = Q1OwnerHandle._persist

    def interrupted(handle):
        original(handle)
        raise OSError('crash after recovery-index commit')

    monkeypatch.setattr(Q1OwnerHandle, '_persist', interrupted)
    before = board.execute('SELECT metadata FROM task_runs').fetchone()[0]
    with pytest.raises(OSError, match='recovery-index'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == before
    key, = recover_q1_reservations(authority)
    assert key.startswith(PREFIX)
    assert authority._q1_native_workers


def test_worker_reservation_failure_never_removes_committed_board_intent(original_owner, monkeypatch):
    import gateway.session_vz_adapter as adapter
    authority, ref, row, diagnostic, board = original_owner

    def fail(*args, **kwargs):
        raise OSError('worker reservation commit failed')

    monkeypatch.setattr(adapter, 'reserve_guest_admission', fail)
    with pytest.raises(OSError, match='commit failed'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    metadata = json.loads(board.execute('SELECT metadata FROM task_runs').fetchone()[0])
    assert metadata[NAMESPACE]['state'] == 'STOP_UNCERTAIN'
    assert recover_q1_reservations(authority)


def test_non_disposable_or_mismatched_session_is_refused(original_owner):
    authority, ref, row, diagnostic, board = original_owner
    bad_ref = replace(ref, session_id='different')
    with pytest.raises(RuntimeStoreError, match='invalid_q1_assignment'):
        reserve_q1_diagnostic(authority, bad_ref, row, diagnostic)
    authority.db._execute_write(lambda conn: conn.execute("UPDATE sessions SET source='kanban'"))
    before = board.execute('SELECT metadata FROM task_runs').fetchone()[0]
    with pytest.raises(RuntimeStoreError, match='q1_disposable_admission_required'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == before
    assert not authority._q1_native_workers


def test_foreign_board_path_is_refused_before_either_store_changes(original_owner, tmp_path):
    authority, ref, row, diagnostic, board = original_owner
    foreign = tmp_path / 'unrelated-board.db'
    with closing(sqlite3.connect(foreign)) as copy:
        board.backup(copy)
    before = foreign.read_bytes()
    with pytest.raises(RuntimeStoreError, match='q1_disposable_board_required'):
        reserve_q1_diagnostic(authority, ref, row, replace(diagnostic, board_path=foreign))
    assert foreign.read_bytes() == before
    assert not authority._q1_native_workers
    assert not recover_q1_reservations(authority)


def test_admission_invalidated_before_actual_writer_leaves_no_phantom(original_owner, monkeypatch):
    from gateway.session_vz_adapter import Q1OwnerHandle
    authority, ref, row, diagnostic, board = original_owner
    original = Q1OwnerHandle._persist

    def invalidated(handle):
        authority.db._execute_write(lambda conn: conn.execute("UPDATE sessions SET source='kanban'"))
        original(handle)

    monkeypatch.setattr(Q1OwnerHandle, '_persist', invalidated)
    before = board.execute('SELECT metadata FROM task_runs').fetchone()[0]
    with pytest.raises(RuntimeStoreError, match='q1_disposable_admission_required'):
        reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == before
    assert not authority._q1_native_workers
    assert not recover_q1_reservations(authority)


def test_retirement_join_refuses_to_release_unknown_reservations(original_owner):
    from gateway.session_runtime_workers import join_authority_work
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    with pytest.raises(TimeoutError, match='ownership retained'):
        asyncio.run(join_authority_work(authority, timeout=0))
    assert not handle.closed.is_set()


def test_cancelled_acquisition_revokes_late_committed_reservation(original_owner, monkeypatch):
    import threading
    from gateway.run_runtime import qualify_q1_guest
    from gateway.session_vz_adapter import Q1OwnerHandle
    from tests.waiting import async_wait_until
    authority, ref, row, diagnostic, _board = original_owner
    entered, release = threading.Event(), threading.Event()
    original = Q1OwnerHandle._persist

    def held(handle):
        original(handle)
        entered.set()
        assert release.wait(10)

    monkeypatch.setattr(Q1OwnerHandle, '_persist', held)

    async def scenario():
        task = asyncio.create_task(qualify_q1_guest(
            authority.runner, authority.profile_id, ref, row, diagnostic))
        try:
            assert await asyncio.to_thread(entered.wait, 10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        await async_wait_until(lambda: not authority._mutation_tasks,
                               timeout=10, what='late reservation and revocation')
    asyncio.run(scenario())
    handle, = authority._q1_native_workers.values()
    assert handle.stop.is_set() and not handle.closed.is_set()
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'


def test_stop_before_endpoint_adoption_is_consumed(original_owner, monkeypatch):
    import gateway.session_vz_adapter as adapter
    authority, ref, row, diagnostic, _board = original_owner
    original = adapter.reserve_guest_admission

    def stopped_before_adoption(*args, **kwargs):
        handle, = authority._q1_native_workers.values()
        handle.control({'type': 'stop'})
        assert handle.endpoint is None
        return original(*args, **kwargs)

    monkeypatch.setattr(adapter, 'reserve_guest_admission', stopped_before_adoption)
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    assert handle.stop.is_set()
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'


def test_old_epoch_stop_failure_does_not_hide_other_worker_stop(original_owner):
    import threading
    from gateway.run_runtime import stop_authority_turns
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    begin_runtime_epoch(authority.db, instance_id='replacement')
    signalled = []
    authority._managed_workers = {
        'ordinary': SimpleNamespace(closed=threading.Event(), stop=threading.Event(),
                                    control=signalled.append),
    }
    async def stopped():
        count = stop_authority_turns(authority)
        await asyncio.gather(*authority._mutation_tasks)
        return count
    assert asyncio.run(stopped()) == 2
    assert signalled == [{'type': 'stop'}]
    assert handle.stop.is_set() and not handle.closed.is_set()


def test_final_writer_rechecks_competing_custody_after_busy(original_owner, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from gateway.session_worker_spawn import check_q1_acquisition
    from hermes_cli import kanban_db_connect as kbc
    authority, ref, row, diagnostic, _board = original_owner
    handle = reserve_q1_diagnostic(authority, ref, row, diagnostic)
    entered = threading.Event()
    original = kbc._execute_boundary_with_retry

    def traced(conn, statement):
        if statement == 'BEGIN IMMEDIATE':
            entered.set()
        return original(conn, statement)

    monkeypatch.setattr(kbc, '_execute_boundary_with_retry', traced)
    with closing(sqlite3.connect(diagnostic.board_path)) as competitor, ThreadPoolExecutor(max_workers=1) as pool:
        competitor.execute('BEGIN IMMEDIATE')
        future = pool.submit(check_q1_acquisition, handle, diagnostic)
        try:
            assert entered.wait(10)
            metadata = json.loads(competitor.execute('SELECT metadata FROM task_runs').fetchone()[0])
            metadata['vz_custody_v1'] = {'state': 'STOP_UNCERTAIN'}
            encoded = json.dumps(metadata)
            competitor.execute('UPDATE task_runs SET metadata=?', (encoded,))
            competitor.commit()
        finally:
            competitor.rollback()
        with pytest.raises(RuntimeStoreError, match='q1_unretired_execution'):
            future.result(timeout=10)
        assert competitor.execute('SELECT metadata FROM task_runs').fetchone()[0] == encoded
    assert not handle.closed.is_set()
