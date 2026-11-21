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
        files={str(tmp_path / 'helper'): 'a' * 64}, source_head='b' * 40,
        prior_profile=tmp_path / 'prior', prior_snapshot_sha256='c' * 64)
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
        proof = _normal_proof()
        observation = {'pid': 123, 'identity': _fixture_identity(), 'identity_status': 'VERIFIED', 'returncode': 0,
            'wait_result': 'REAPED_BY_ORIGINAL_OWNER', 'process_group_status': 'EMPTY', 'process_group_members': [],
            'all_pipes_closed': True, 'pipes': {key: {'closed': True} for key in
                ('stdin', 'stdout', 'stderr', 'serial', 'child_serial_in_parent')},
            'drain_observation': {'selector_drained': True, 'eof': {'stdin': True}}}
        observation['drain_observation']['eof'] = {'stdout': True, 'stderr': True, 'serial': True}
        proof['exit_observation'] = observation
        adapter._persist(board, handle, {**handle.record, 'native_spawned': True,
            'identity': _fixture_identity(), 'exit_observation': observation})
    adapter._retire(candidate, handle, proof)
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
    observed = _fixture_exit_observation()
    proof['exit_observation'] = observed
    record = {'version': 'HERMES_Q1_HVF_V1', 'state': 'RETIRED', 'mode': 'normal',
              'native_spawned': True, 'proof': proof, 'identity': _fixture_identity(), 'exit_observation': observed}
    assert adapter._valid_retirement(record)
    proof.pop(missing)
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
    candidate.argv = lambda fd: [str(binary)]
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    # This gate deliberately has no QMP or Hypervisor. Releasing it must fail
    # qualification while preserving the real child identity and sticky intent.
    with pytest.raises((RuntimeStoreError, json.JSONDecodeError)):
        adapter._execute(authority, candidate, handle, time.monotonic() + 300)
    child = handle.process
    assert child is not None and child.returncode == 0
    assert handle.record['native_spawned'] is True
    assert handle.record['phase'] == 'FAILED'
    assert handle.record['exit_observation']['returncode'] == 0
    assert handle.record['exit_observation']['wait_result'] == 'REAPED_BY_ORIGINAL_OWNER'
    assert handle.record['exit_observation']['all_pipes_closed'] is True
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


@pytest.mark.platforms('macos')
def test_real_sandbox_allows_only_explicit_inherited_serial_socket(tmp_path):
    import plistlib
    import socket
    app = tmp_path / 'SerialCanary.app'
    macos = app / 'Contents/MacOS'
    macos.mkdir(parents=True)
    source, binary = tmp_path / 'serial-canary.c', macos / 'serial-canary'
    source.write_text('''#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = atoi(argv[1]);
    struct sockaddr_storage peer; socklen_t size = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &size) || peer.ss_family != AF_UNIX) return 3;
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, 5000) != 1) return 4;
    char data[32]; ssize_t count = read(fd, data, sizeof(data));
    if (count != 19 || memcmp(data, "HERMES_HVF_STOP_V1\\n", 19)) return 5;
    return write(fd, data, count) == count ? 0 : 6;
}
''', encoding='utf-8')
    subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)],
                   check=True, capture_output=True, timeout=30)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'org.hermes.pr15.serial-test',
        'CFBundleExecutable':'serial-canary', 'CFBundlePackageType':'APPL', 'CFBundleVersion':'1'}))
    entitlement = Path(adapter.__file__).resolve().parents[1] / 'native/qemu_hvf/helper.entitlements'
    subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', str(entitlement), str(app)],
                   check=True, capture_output=True, timeout=30)
    parent, guest = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child = None
    try:
        child = subprocess.Popen([str(binary), str(guest.fileno())], pass_fds=(guest.fileno(),),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        guest.close()
        parent.settimeout(5)
        parent.sendall(physical.STOP.encode())
        assert parent.recv(32) == physical.STOP.encode()
        assert child.wait(timeout=5) == 0
        assert parent.recv(1) == b''
    finally:
        parent.close()
        guest.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()


@pytest.mark.platforms('macos')
def test_open_serial_endpoint_blocks_retirement_after_child_exit():
    import socket
    parent, guest = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    pipes = physical.ChildPipes(child, parent)
    try:
        with pytest.raises(RuntimeStoreError, match='hvf_control_timeout'):
            pipes.drain_and_wait(time.monotonic() + 2)
        assert child.wait(timeout=5) == 0
        assert parent.fileno() >= 0
    finally:
        pipes.close()
        guest.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
    assert parent.fileno() == -1
    assert all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))


def _fixture_identity():
    return {'pid': 123, 'ppid': 100, 'pgid': 123, 'created': 1000.0, 'boot_time': 500.0,
            'fingerprint': 'fixture', 'executable': '/fixture/inert'}


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('signal_number', [None, signal.SIGTERM])
def test_failed_exit_facts_persist_to_both_ledgers_without_retiring(owner, signal_number):
    import socket
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
    handle.process = child
    handle.identity = physical.child_identity(child, '/bin/cat')
    handle.serial, remote = socket.socketpair()
    handle.guest_serial_closed = True
    try:
        if signal_number is None:
            child.stdin.close()
        else:
            os.kill(child.pid, signal_number)
        # Owner Popen wait is observed directly; pid absence alone is insufficient.
        physical._wait_for_child(handle, 5)
        observation = adapter._contain_failed_child(handle, time.monotonic() + 5)
        adapter._persist_exit(candidate, handle, observation, failure=RuntimeStoreError('inert_fault'))
        assert observation['pid'] == child.pid
        assert observation['identity'] == handle.identity
        assert observation['returncode'] == (0 if signal_number is None else -signal_number)
        assert observation['terminating_signal'] == signal_number
        assert observation['wait_result'] == 'REAPED_BY_ORIGINAL_OWNER'
        assert observation['process_group_status'] == 'EMPTY'
        assert observation['all_pipes_closed'] is True
        with closing(sqlite3.connect(candidate.board)) as independent:
            stored = json.loads(independent.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
        indexed = adapter.metadata(authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (handle.key,))[0])
        assert stored == indexed == handle.record
        assert stored['exit_observation'] == observation
        assert stored['state'] == 'STOP_UNCERTAIN'
        assert not adapter._valid_retirement(stored)
        assert adapter.recover_hvf_reservations(authority)
        with pytest.raises(RuntimeStoreError, match='hvf_no_successor'):
            adapter._reserve(authority, candidate, 2)
    finally:
        remote.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@pytest.mark.platforms('macos')
def test_failed_group_observation_is_unknown_and_receipt_survives_db_failure(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    handle.process = child
    handle.identity = physical.child_identity(child, '/bin/cat')
    try:
        observation = adapter._contain_failed_child(handle, time.monotonic() + 5)
        def unavailable(pgid):
            raise RuntimeStoreError('group_census_denied')
        monkeypatch.setattr(physical, 'group_members', unavailable)
        observation = physical.exit_observation(handle)
        assert observation['process_group_status'] == 'UNKNOWN'
        assert observation['process_group_members'] is None
        assert observation['errors']
        def broken(*args):
            raise sqlite3.OperationalError('inert_ledger_failure')
        monkeypatch.setattr(adapter, '_write_board_exit', broken)
        with pytest.raises(sqlite3.OperationalError):
            adapter._persist_exit(candidate, handle, observation, failure=RuntimeStoreError('inert_fault'))
        receipt = json.loads((candidate.output / 'slot-1/failure-observation.json').read_text())
        assert receipt['observation'] == observation
        assert receipt['ledger_persistence'].startswith('UNKNOWN')
        assert handle.record['state'] == 'STOP_UNCERTAIN'
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@pytest.mark.platforms('macos')
def test_reconciliation_never_accepts_live_pid_or_nonempty_group(tmp_path, monkeypatch):
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    identity = physical.child_identity(child, '/bin/cat')
    try:
        with pytest.raises(RuntimeStoreError, match='hvf_prior_pid_still_present'):
            physical.verify_prior_absent(identity)
        child.stdin.close()
        child.wait(timeout=5)
        assert physical.verify_prior_absent(identity) == []
        monkeypatch.setattr(physical, 'group_members', lambda pgid: (999999,))
        with pytest.raises(RuntimeStoreError, match='hvf_prior_group_not_empty'):
            physical.verify_prior_absent(identity)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


@pytest.mark.platforms('macos')
def test_failed_abort_wait_status_is_persisted_with_core_zero(owner, tmp_path):
    authority, candidate = owner
    binary = tmp_path / 'core-zero-gate'
    source = Path(adapter.__file__).resolve().parents[1] / 'native/qemu_hvf/admission_gate.c'
    subprocess.run(['xcrun', 'clang', '-DHERMES_HVF_GATE_TEST_MAIN', str(source), '-o', str(binary)],
                   check=True, capture_output=True, timeout=30)
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    handle.process = child
    handle.identity = physical.child_identity(child, binary)
    try:
        import selectors
        with selectors.DefaultSelector() as poller:
            poller.register(child.stderr, selectors.EVENT_READ)
            assert poller.select(5)
        assert b'current=0 maximum=0' in child.stderr.readline()
        os.kill(child.pid, signal.SIGABRT)
        physical._wait_for_child(handle, 5)
        observation = adapter._contain_failed_child(handle, time.monotonic() + 5)
        adapter._persist_exit(candidate, handle, observation, failure=RuntimeStoreError('inert_abort'))
        assert handle.record['state'] == 'STOP_UNCERTAIN'
        assert observation['returncode'] == -signal.SIGABRT
        assert observation['terminating_signal'] == signal.SIGABRT
        assert observation['wait_result'] == 'REAPED_BY_ORIGINAL_OWNER'
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@pytest.mark.platforms('macos')
def test_wait_failure_keeps_unknown_even_if_signal_was_sent(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    handle.process = child
    handle.identity = physical.child_identity(child, '/bin/cat')
    try:
        with monkeypatch.context() as patch:
            def unavailable(*args, **kwargs):
                raise subprocess.TimeoutExpired('/bin/cat', 1)
            patch.setattr(child, 'wait', unavailable)
            observation = adapter._contain_failed_child(handle, time.monotonic() + 2)
        adapter._persist_exit(candidate, handle, observation, failure=RuntimeStoreError('inert_wait_failure'))
        assert observation['wait_result'] == 'UNKNOWN'
        assert observation['returncode'] is None
        assert observation['errors']
        assert handle.record['state'] == 'STOP_UNCERTAIN'
        assert not adapter._valid_retirement(handle.record)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_receipt_failure_does_not_prevent_exit_facts_in_available_ledgers(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    observation = {'pid': 123, 'wait_result': 'UNKNOWN', 'errors': [{'operation': 'inert_fault'}]}
    def denied(*args):
        raise PermissionError('inert_receipt_directory_denied')
    monkeypatch.setattr(adapter, '_write_exit_receipt', denied)
    with pytest.raises(PermissionError):
        adapter._persist_exit(candidate, handle, observation, failure=RuntimeStoreError('inert_failure'))
    with closing(sqlite3.connect(candidate.board)) as independent:
        recorded = json.loads(independent.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
    indexed = adapter.metadata(authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (handle.key,))[0])
    assert recorded == indexed
    assert recorded['state'] == 'STOP_UNCERTAIN'
    assert recorded['exit_observation'] == observation


@pytest.mark.parametrize('broken', [None, [], {'stdin': None}])
def test_malformed_nested_exit_evidence_cannot_establish_retirement(broken):
    identity = _fixture_identity()
    record = {'identity': identity, 'exit_observation': {'identity': identity, 'pipes': broken, 'drain_observation': broken}}
    assert not adapter._valid_exit_observation(record, {'exit_code': 0})


@pytest.mark.platforms('macos')
def test_terminal_monitor_input_remains_live_until_child_exit():
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
    pipes = physical.ChildPipes(child)
    try:
        with pytest.raises(RuntimeStoreError, match='hvf_control_timeout'):
            pipes.drain_and_wait(time.monotonic() + 2, close_input=False)
        assert not child.stdin.closed
    finally:
        pipes.close()
        child.wait(timeout=5)


def _fixture_exit_observation():
    return {'pid': 123, 'identity': _fixture_identity(), 'identity_status': 'VERIFIED', 'returncode': 0,
            'terminating_signal': None, 'wait_result': 'REAPED_BY_ORIGINAL_OWNER',
            'process_group_status': 'EMPTY', 'process_group_members': [], 'all_pipes_closed': True,
            'pipes': {key: {'closed': True} for key in ('stdin', 'stdout', 'stderr', 'serial', 'child_serial_in_parent')},
            'drain_observation': {'selector_drained': True, 'eof': {'stdout': True, 'stderr': True, 'serial': True}}}


@pytest.mark.parametrize('missing', ['created', 'boot_time', 'fingerprint', 'executable'])
def test_birth_identity_is_mandatory_in_retirement_evidence(missing):
    proof = _normal_proof()
    observed = _fixture_exit_observation()
    proof['exit_observation'] = observed
    identity = observed['identity']
    record = {'version': 'HERMES_Q1_HVF_V1', 'state': 'RETIRED', 'mode': 'normal',
              'native_spawned': True, 'proof': proof, 'identity': identity, 'exit_observation': observed}
    assert adapter._valid_retirement(record)
    del identity[missing]
    assert not adapter._valid_retirement(record)


def test_new_grant_never_resumes_a_profile_with_old_grant(owner):
    authority, candidate = owner
    authority.db._execute_write(lambda db: db.execute('INSERT INTO state_meta(key,value) VALUES(?,?)',
        ('q1.hvf.grant:7058818518', '{"status":"STOP_UNCERTAIN"}')))
    with pytest.raises(RuntimeStoreError, match='hvf_grant_already_reserved'):
        adapter._unused_profile(candidate.profile)


@pytest.mark.parametrize('field', ['profile', 'helper', 'files', 'prior_snapshot_sha256'])
def test_grant_manifest_cannot_be_rebound_to_other_artifacts_or_profile(field):
    from dataclasses import replace
    lock_path = Path(adapter.__file__).resolve().parents[1] / 'native/qemu_hvf/rerun-authorization.json'
    values = json.loads(lock_path.read_text())['candidate']
    paths = ('profile', 'board', 'helper', 'plan', 'kernel', 'initramfs', 'disk', 'output', 'prior_profile')
    candidate = adapter.HVFCandidate(**{name: Path(values[name]) for name in paths},
        files=values['files'], prior_snapshot_sha256=values['prior_snapshot_sha256'], source_head='a' * 40)
    adapter._verify_authorization(candidate)
    replacement = ({**values['files'], str(candidate.helper): '0' * 64} if field == 'files'
                   else '0' * 64 if field == 'prior_snapshot_sha256' else getattr(candidate, field).with_name('unapproved'))
    changed = replace(candidate, **({'files': dict(candidate.files)} | {field: replacement}))
    with pytest.raises(RuntimeStoreError, match='hvf_exact_grant_candidate_binding_changed'):
        adapter._verify_authorization(changed)


def test_owner_sink_failure_does_not_prevent_board_exit_evidence(owner, monkeypatch):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    observed = {'pid': 123, 'wait_result': 'UNKNOWN'}
    def denied(*args):
        raise sqlite3.OperationalError('inert_owner_sink_unavailable')
    monkeypatch.setattr(adapter, '_write_owner_exit', denied)
    with pytest.raises(sqlite3.OperationalError):
        adapter._persist_exit(candidate, handle, observed, failure=RuntimeStoreError('inert_fault'))
    with closing(sqlite3.connect(candidate.board)) as db:
        recorded = json.loads(db.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
    assert recorded['state'] == 'STOP_UNCERTAIN'
    assert recorded['exit_observation'] == observed
    assert adapter.recover_hvf_reservations(authority)


@pytest.mark.platforms('macos')
def test_finalizer_persists_late_exact_reap_without_retiring_failed_attempt(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    handle.process = child
    handle.identity = physical.child_identity(child, '/bin/cat')
    try:
        unknown = physical.exit_observation(handle)
        adapter._persist_exit(candidate, handle, unknown, failure=RuntimeStoreError('inert_initial_timeout'))
        assert handle.record['exit_observation']['wait_result'] == 'UNKNOWN'
        adapter._final_wait_and_record(candidate, handle)
        observed = handle.record['exit_observation']
        assert observed['wait_result'] == 'REAPED_BY_ORIGINAL_OWNER'
        assert observed['returncode'] == 0
        assert observed['process_group_status'] == 'EMPTY'
        assert handle.record['state'] == 'STOP_UNCERTAIN'
        assert handle.record['failure'] == 'inert_initial_timeout'
        with closing(sqlite3.connect(candidate.board)) as db:
            persisted = json.loads(db.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
        indexed = adapter.metadata(authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (handle.key,))[0])
        assert persisted == indexed == handle.record
        assert not adapter._valid_retirement(persisted)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@pytest.mark.platforms('macos')
@pytest.mark.asyncio
async def test_failed_pending_campaign_join_does_not_skip_late_reap(owner):
    authority, candidate = owner
    adapter._grant(authority, candidate)
    handle = adapter._reserve(authority, candidate, 1)
    child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    handle.process = child
    handle.identity = physical.child_identity(child, '/bin/cat')
    path = Path(authority.db.db_path)
    try:
        observed = physical.exit_observation(handle)
        adapter._persist_exit(candidate, handle, observed, failure=RuntimeStoreError('inert_original_timeout'))
        async def pending_failure():
            raise RuntimeStoreError('inert_pending_campaign_failure')
        authority._hvf_campaign_task = asyncio.create_task(pending_failure())
        with pytest.raises(RuntimeStoreError, match='inert_pending_campaign_failure'):
            await adapter._finish_qualification_owner(candidate, authority, candidate.profile)
        with closing(sqlite3.connect(path)) as db:
            persisted = json.loads(db.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()[0])
        assert persisted['state'] == 'STOP_UNCERTAIN'
        assert persisted['failure'] == 'inert_original_timeout'
        assert persisted['exit_observation']['returncode'] == 0
        assert persisted['exit_observation']['wait_result'] == 'REAPED_BY_ORIGINAL_OWNER'
        with closing(sqlite3.connect(candidate.board)) as db:
            board_record = json.loads(db.execute('SELECT metadata FROM task_runs').fetchone()[0])[adapter.NAMESPACE]
        assert board_record == persisted
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
