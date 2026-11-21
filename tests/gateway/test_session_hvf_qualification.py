"""Offline Owner ledger/pipe contracts. These tests never execute QEMU or a VM."""
from contextlib import closing
import asyncio
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
from types import SimpleNamespace

import psutil
import pytest

from gateway import session_hvf_adapter as adapter
from gateway import session_hvf_process as physical
from hermes_state_runtime import RuntimeStoreError


@pytest.fixture
def owner(tmp_path, monkeypatch):
    home = tmp_path / 'hvf-qualification'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    from gateway.session_authority import SessionAuthority
    from gateway.session_authorities import SessionAuthorities
    from hermes_state import SessionDB
    from hermes_state_runtime import begin_runtime_epoch
    db = SessionDB(db_path=home / 'state.db')
    epoch = begin_runtime_epoch(db, instance_id='offline-test-owner')
    runner = SimpleNamespace(_draining=False, config=SimpleNamespace(multiplex_profiles=False),
                             session_authorities=SessionAuthorities(home))
    authority = SessionAuthority(runner, profile_id=str(home), instance_id='offline-test-owner', db=db, epoch=epoch)
    runner.session_authorities.add(home, authority)
    from hermes_cli.kanban_db_connect import connect_closing
    board = home / 'kanban/boards/hvf-qualification/kanban.db'
    board.parent.mkdir(parents=True)
    with connect_closing(board):
        pass
    authority._hvf_campaign_active = True
    import threading
    authority._hvf_campaign_stop = threading.Event()
    candidate = SimpleNamespace(profile=home, board=home / 'kanban/boards/hvf-qualification/kanban.db',
        output=tmp_path / 'output', helper=tmp_path / 'helper',
        files={str(tmp_path / 'helper'): 'a' * 64}, source_head='b' * 40)
    try:
        yield authority, candidate
    finally:
        authority.db.close()
        from gateway.runtime_ownership import process_ownership
        process_ownership.release(home)


@pytest.mark.parametrize('journal', ['WAL', 'DELETE'])
def test_durable_intent_rollback_restart_prevents_successor(owner, journal, monkeypatch):
    authority, candidate = owner
    import hermes_state_wal
    monkeypatch.setattr(hermes_state_wal, 'resolve_journal_mode', lambda: journal.lower())
    with closing(sqlite3.connect(candidate.board)) as connection:
        connection.execute(f'PRAGMA journal_mode={journal}')
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(candidate.board) as board, write_txn(board):
        adapter._guard(board, handle)
    # A second connection must see the durable STARTING record, with no PID.
    with closing(sqlite3.connect(candidate.board)) as independent:
        old = independent.execute('SELECT metadata FROM task_runs').fetchone()[0]
        record = json.loads(old)[adapter.NAMESPACE]
        assert record['state'] == 'STOP_UNCERTAIN'
        assert record['native_spawned'] is False
        independent.execute('BEGIN IMMEDIATE')
        independent.execute("UPDATE task_runs SET metadata='{}'")
        independent.rollback()
        assert independent.execute('SELECT metadata FROM task_runs').fetchone()[0] == old
    authority._hvf_workers.clear()
    authority._hvf_campaign_active = False
    assert handle.key in adapter.recover_hvf_reservations(authority)
    authority._hvf_campaign_active = True
    with pytest.raises(RuntimeStoreError, match='hvf_no_successor'):
        adapter._reserve(authority, candidate, 2)
    with pytest.raises(RuntimeStoreError):
        adapter._grant(authority, candidate)


def test_claim_corruption_and_epoch_change_refuse_release(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(candidate.board) as board, write_txn(board):
        board.execute("UPDATE task_runs SET metadata='{' WHERE id=?", (handle.record['run_id'],))
    with connect_closing(candidate.board) as board, write_txn(board):
        with pytest.raises(RuntimeStoreError):
            adapter._guard(board, handle)
    assert adapter.recover_hvf_reservations(authority)
    authority.epoch += 1
    with pytest.raises(RuntimeStoreError):
        authority.db._execute_write(lambda conn: adapter._require_owner(authority, conn))


def test_retired_label_without_physical_proof_never_releases(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    counterfeit = {**handle.record, 'state': 'RETIRED', 'native_spawned': True, 'proof': {}}
    assert not adapter._valid_retirement(counterfeit)
    authority.db._execute_write(lambda conn: conn.execute(
        'UPDATE state_meta SET value=? WHERE key=?', (adapter.canonical(counterfeit), handle.key)))
    baseline = psutil.Process().num_fds()
    for _ in range(20):
        assert adapter.recover_hvf_reservations(authority)
        assert not adapter._matching_board_retirement(authority, counterfeit)
    assert psutil.Process().num_fds() <= baseline


@pytest.mark.parametrize('raw', ['{', '[]', '{"x":1,"x":2}', '{"x":NaN}'])
def test_malformed_metadata_preserves_unknown(raw):
    with pytest.raises(RuntimeStoreError):
        adapter.metadata(raw)


@pytest.mark.platforms('macos')
def test_real_inert_child_identity_wait_group_and_pipe_cleanup(tmp_path):
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    try:
        identity = physical.child_identity(child, '/bin/cat')
        physical.verify_child(child, identity)
        assert physical.group_members(child.pid) == (child.pid,)
        pipes = physical.ChildPipes(child)
        assert pipes.drain_and_wait(time.monotonic() + 5) == 0
        assert not physical.group_members(child.pid)
        assert all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('frame,expected', [(physical.RELEASE, 0), (b'wrong\n', 2), (b'', 2)])
def test_compiled_gate_requires_exact_release_and_disables_core(tmp_path, frame, expected):
    binary = tmp_path / 'gate'
    source = Path(adapter.__file__).resolve().parents[1] / 'native/qemu_hvf/admission_gate.c'
    subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror',
                    '-DHERMES_HVF_GATE_TEST_MAIN', str(source), '-o', str(binary)],
                   check=True, capture_output=True, timeout=30)
    result = subprocess.run([str(binary)], input=frame, capture_output=True, timeout=5, check=False)
    assert result.returncode == expected
    assert b'current=0 maximum=0' in result.stderr
    assert (b'RELEASED_NO_VM' in result.stdout) == (expected == 0)


def test_backend_marker_requires_actual_destroy_success():
    markers = (b'HERMES_HVF_CORE_LIMIT_V1 pid=123 current=0 maximum=0\n'
               b'HERMES_HVF_VM_CREATE_V1 pid=123 result=0\n'
               b'HERMES_HVF_SANDBOX_V1 {"pass":true}\n'
               b'HERMES_HVF_VM_DESTROY_V1 pid=123 result=0 joined=2\n')
    assert physical._markers(markers, 123, 'normal')['destroy_success']
    for wrong in (markers.replace(b'result=0 joined=2', b'result=1 joined=2'),
                  markers.replace(b'joined=2', b'joined=1'),
                  markers.replace(b'pid=123 result=0 joined=2', b'pid=124 result=0 joined=2')):
        with pytest.raises(RuntimeStoreError):
            physical._markers(wrong, 123, 'normal')
    with pytest.raises(RuntimeStoreError):
        physical._markers(markers, 123, 'sigkill')


def test_invalid_paths_rejected_before_artifact_access(tmp_path):
    values = {key: tmp_path / key for key in ('profile', 'board', 'helper', 'plan', 'kernel', 'initramfs', 'disk', 'output')}
    values['disk'] = tmp_path / 'injected,format=qcow2'
    with pytest.raises(RuntimeStoreError, match='hvf_invalid_candidate_paths'):
        adapter.HVFCandidate(**values, source_head='a' * 40, files={})


def test_unknown_retained_at_actual_owner_join_boundary(owner):
    from gateway.session_runtime_workers import join_authority_work
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    authority._hvf_workers.clear()
    adapter.recover_hvf_reservations(authority)
    with pytest.raises(TimeoutError, match='ownership retained'):
        asyncio.run(join_authority_work(authority, 0))
    assert handle.key in authority._hvf_retained


def test_failed_campaign_live_handle_blocks_owner_retirement(owner):
    from gateway.session_runtime_workers import join_authority_work
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    adapter._finish_grant(authority, failure=RuntimeStoreError('offline_failure'))
    authority._hvf_retained = ()
    with pytest.raises(TimeoutError, match='ownership retained'):
        asyncio.run(join_authority_work(authority, 0))
    assert handle.stop.is_set() or authority._hvf_campaign_stop.is_set()
    assert not handle.closed.is_set()


def _normal_proof():
    return {key: True for key in ('exact_child_waited', 'process_group_empty', 'all_pipes_closed',
            'guest_ready', 'core_limit_zero', 'owner_work_completed', 'owner_accounting_complete',
            'destroy_success', 'explicit_vm_destroy', 'guest_orderly_shutdown')} | {
            'vm_create_successes': 1, 'exit_code': 0}


def test_retirement_completes_diagnostic_only_and_matches_both_stores(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(candidate.board) as board, write_txn(board):
        adapter._persist(board, handle, {**handle.record, 'native_spawned': True})
    adapter._retire(candidate, handle, _normal_proof())
    handle.closed.set()
    assert not adapter.recover_hvf_reservations(authority)
    with connect_closing(candidate.board) as board, write_txn(board):
        adapter._history(board, authority)
    # Missing Owner evidence cannot be reconstructed from the RETIRED label.
    authority.db._execute_write(lambda db: db.execute('DELETE FROM state_meta WHERE key=?', (handle.key,)))
    with connect_closing(candidate.board) as board, write_txn(board):
        with pytest.raises(RuntimeStoreError, match='hvf_retirement_index_missing'):
            adapter._history(board, authority)
    assert authority.db._read_one('SELECT 1 FROM worker_executions') is None


@pytest.mark.parametrize('missing', ['exact_child_waited', 'process_group_empty', 'all_pipes_closed',
    'guest_ready', 'core_limit_zero', 'owner_work_completed', 'owner_accounting_complete',
    'destroy_success', 'explicit_vm_destroy', 'guest_orderly_shutdown'])
def test_each_required_normal_retirement_proof_is_mandatory(missing):
    proof = _normal_proof()
    proof.pop(missing)
    record = {'version': 'HERMES_Q1_HVF_V1', 'state': 'RETIRED', 'mode': 'normal',
              'native_spawned': True, 'proof': proof}
    assert not adapter._valid_retirement(record)


def test_final_transaction_rechecks_stop_before_any_spawn(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    candidate.verify = lambda authority: None
    spawned = []
    monkeypatch.setattr(adapter.subprocess, 'Popen', lambda *args, **kwargs: spawned.append(args))
    handle.stop.set()
    with pytest.raises(RuntimeStoreError, match='hvf_claim_or_reservation_changed'):
        adapter._execute(authority, candidate, handle, time.monotonic() + 300)
    assert spawned == []


def test_grant_cannot_finish_without_all_five_retired_records(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    with pytest.raises(RuntimeStoreError, match='hvf_campaign_completion_incomplete'):
        adapter._finish_grant(authority)


@pytest.mark.platforms('macos')
def test_actual_admission_child_released_only_after_durable_booking(owner, tmp_path):
    authority, candidate = owner
    binary = tmp_path / 'inert-gate'
    source = Path(adapter.__file__).resolve().parents[1] / 'native/qemu_hvf/admission_gate.c'
    subprocess.run(['xcrun', 'clang', '-DHERMES_HVF_GATE_TEST_MAIN', str(source), '-o', str(binary)],
                   check=True, capture_output=True, timeout=30)
    candidate.helper = binary
    candidate.files[str(binary)] = 'a' * 64
    candidate.plan = tmp_path / 'plan.json'
    candidate.verify = lambda authority: None
    candidate.argv = lambda: [str(binary)]
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    # This gate deliberately has no QMP or Hypervisor. Releasing it must fail
    # qualification while preserving the real child identity and sticky intent.
    with pytest.raises((RuntimeStoreError, json.JSONDecodeError)):
        adapter._execute(authority, candidate, handle, time.monotonic() + 300)
    child = handle.process
    assert child is not None and child.returncode == 0
    assert handle.record['native_spawned'] is True
    assert handle.record['phase'] == 'VM_RELEASE_STARTING'
    assert handle.record['state'] == 'STOP_UNCERTAIN'
    with closing(sqlite3.connect(candidate.board)) as independent:
        record = json.loads(independent.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
        assert record == handle.record
        assert record['identity']['pid'] == child.pid
    assert adapter.recover_hvf_reservations(authority)


def test_durable_grant_revoke_blocks_final_spawn(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    adapter._finish_grant(authority, failure=RuntimeStoreError('offline_revoke'))
    candidate.verify = lambda authority: None
    spawned = []
    monkeypatch.setattr(adapter.subprocess, 'Popen', lambda *args, **kwargs: spawned.append(args))
    with pytest.raises(RuntimeStoreError, match='hvf_native_grant_changed'):
        adapter._execute(authority, candidate, handle, time.monotonic() + 300)
    assert not spawned
