"""Q2 original-Owner SQLite/physical contracts. No QEMU, Guest, Worker or model."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

import httpx
import psutil
import pytest

from gateway import session_guest_hvf as q2
from gateway.session_authority import SessionAuthority
from gateway.session_authorities import SessionAuthorities
from hermes_state import SessionDB
from hermes_state_runtime import RuntimeStoreError, begin_runtime_epoch


@pytest.fixture
def owner(tmp_path, monkeypatch):
    home = tmp_path / 'campaign/q2-qualification'
    home.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(home))
    fixture = home.parent / 'fixtures/source'
    fixture.mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', str(fixture)], check=True, capture_output=True)
    (fixture / 'base.txt').write_text('public disposable fixture\n')
    subprocess.run(['git', '-C', str(fixture), 'add', '.'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(fixture), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base'],
                   check=True, capture_output=True)
    head = subprocess.check_output(['git', '-C', str(fixture), 'rev-parse', 'HEAD'], text=True).strip()
    with closing(SessionDB(home / 'state.db')) as db:
        epoch = begin_runtime_epoch(db, instance_id='q2-offline-owner')
        runner = SimpleNamespace(_draining=False, session_authorities=SessionAuthorities(home))
        authority = SessionAuthority(runner, profile_id=str(home), instance_id='q2-offline-owner', db=db, epoch=epoch)
        runner.session_authorities.add(home, authority)
        batch = q2.Q2Batch(home.parent / 'batch.json', {'profile': str(home), 'output': str(home.parent / 'output'),
            'fixture_source': str(fixture), 'original_artifacts': {name: {'sha256': hashlib.sha256(name.encode()).hexdigest()}
                for name in ('kernel.Image', 'initramfs.cpio.gz', 'root.raw')}, 'helper_package': {'helper': '/bin/cat',
            'resources': str(home.parent / 'resources'), 'static_policy_sha256': 'b' * 64}})
        batch.output.mkdir()
        from hermes_cli.kanban_db_connect import connect_closing
        batch.board.parent.mkdir(parents=True)
        with connect_closing(batch.board):
            pass
        yield authority, batch, fixture, head


def approve_fixture(authority, batch):
    authority.db.set_meta(q2.APPROVALS + batch.sha256, q2.canonical({
        'payload_sha256': batch.sha256, 'profile': authority.profile_id,
        'subject': 'offline-human', 'decision_uri': 'https://github.com/spareribes/ai-colleague/issues/139#issuecomment-1',
        'budget': q2.BUDGET}))
    authority.db.set_meta(q2.GRANTS + batch.sha256, q2.canonical({
        'payload_sha256': batch.sha256, 'status': 'IN_PROGRESS', 'spent': 0,
        'epoch': authority.epoch, 'instance': authority.instance_id,
        'started_monotonic': time.monotonic(), 'boot_time': psutil.boot_time()}))
    authority._q2_active_grant = q2.GRANTS + batch.sha256


def reserve(owner):
    authority, batch, source, head = owner
    approve_fixture(authority, batch)
    return q2.reserve_attempt(authority, batch, 1, source=source, head=head)


def test_no_native_grant_refuses_before_any_spawn(owner, monkeypatch):
    authority, batch, _source, _head = owner
    calls = []
    monkeypatch.setattr(q2.subprocess, 'Popen', lambda *_a, **_kw: calls.append(True))
    with pytest.raises(RuntimeStoreError, match='q2_native_not_authorized'):
        q2.begin_batch(authority, batch)
    assert calls == []
    assert authority.db._read_one('SELECT count(*) FROM worker_executions')[0] == 0


@pytest.mark.parametrize('raw', ['{', '[]', '{"x":1,"x":2}', '{"x":NaN}', '{"x": 1}'])
def test_damaged_metadata_is_never_normalized(raw):
    with pytest.raises(RuntimeStoreError):
        q2.metadata(raw)


def test_reservation_is_original_owner_exact_and_persistent(owner):
    authority, batch, _source, _head = owner
    handle, work = reserve(owner)
    assert work['assignment'] == handle.scope
    assert handle.record['state'] == 'STARTING'
    assert handle.record['instance'] == authority.instance_id
    assert authority.db.get_meta(handle.key) == q2.canonical(handle.record)
    from hermes_cli.kanban_db_connect import connect_closing
    with connect_closing(batch.board) as independent:
        run = independent.execute('SELECT metadata FROM task_runs WHERE id=?', (handle.scope['run_id'],)).fetchone()
        assert q2.metadata(run[0])[q2.NAMESPACE] == handle.record
    assert 'claim_lock' not in work['assignment']
    assert q2.recover_q2_reservations(authority) == (handle.key,)


@pytest.mark.parametrize('damage', ['metadata', 'claim', 'owner', 'grant'])
def test_final_writer_guard_rejects_unknown_or_changed_evidence(owner, damage):
    authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as conn:
        if damage == 'metadata':
            conn.execute("UPDATE task_runs SET metadata='{'")
        elif damage == 'claim':
            conn.execute("UPDATE tasks SET claim_lock='foreign'")
        elif damage == 'owner':
            authority.epoch += 1
        else:
            grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
            grant['status'] = 'STOP_UNCERTAIN'
            authority.db.set_meta(q2.GRANTS + batch.sha256, q2.canonical(grant))
        with write_txn(conn), pytest.raises(RuntimeStoreError):
            q2._board_guard(conn, handle)
    assert not handle.closed.is_set()


def test_spent_slot_cannot_retry_or_skip(owner):
    authority, batch, source, head = owner
    reserve(owner)
    for slot in (1, 2, 3):
        with pytest.raises(RuntimeStoreError):
            q2.reserve_attempt(authority, batch, slot, source=source, head=head)
    grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
    assert grant['spent'] == 1


def test_corrupt_board_raw_survives_failure_accounting(owner):
    authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    from hermes_cli.kanban_db_connect import connect_closing
    with connect_closing(batch.board) as board:
        board.execute("UPDATE task_runs SET metadata='{'")
    q2.mark_uncertain(handle, RuntimeError('inert failure'))
    with connect_closing(batch.board) as board:
        assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == '{'
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))['status'] == 'STOP_UNCERTAIN'
    assert q2.recover_q2_reservations(authority)


@pytest.mark.parametrize('proof', [{}, {'all_pipes_closed': True}, {'exit_code': 0},
                                  {'exact_child_waited': True, 'process_group_empty': True}])
def test_partial_physical_facts_never_retire(owner, proof):
    authority, _batch, _source, _head = owner
    handle, _work = reserve(owner)
    handle.proof = proof
    with pytest.raises(RuntimeStoreError, match='q2_physical_retirement_incomplete'):
        q2.require_physical_handle(handle.endpoint, handle)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'registered'


def test_restart_keeps_original_assignment_and_blocks_adoption(owner):
    authority, _batch, _source, _head = owner
    handle, _work = reserve(owner)
    saved = authority.db.get_meta('guest.assignment.v1:' + handle.scope['execution_id'])
    begin_runtime_epoch(authority.db, instance_id='after-crash')
    assert q2.recover_q2_reservations(authority)
    with pytest.raises(RuntimeStoreError, match='stale_epoch'):
        handle.endpoint({'method': 'worker.adopt', 'scope': handle.scope, 'params': {}})
    assert authority.db.get_meta('guest.assignment.v1:' + handle.scope['execution_id']) == saved


def test_fixed_fixture_cannot_finish_without_real_tool_output():
    fake = q2.FixtureResponses('developer')
    request = httpx.Request('POST', 'http://127.0.0.1/v1/responses', json={'input': []})
    assert fake(request).status_code == 200
    with pytest.raises(RuntimeStoreError, match='q2_actual_tool_result_required'):
        fake(request)


def test_held_fake_cancellation_is_deterministic_without_network():
    fake = q2.FixtureResponses('cancellation')
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(fake, httpx.Request('POST', 'http://127.0.0.1/v1/responses', json={'input': []}))
        assert fake.entered.wait(2)
        assert not pending.done()
        fake.release.set()
        assert pending.result(timeout=2).status_code == 200
    assert fake.late_returned and fake.calls == 1


def small_image(batch, tmp_path):
    from native.qemu_guest.image_contract import GuestImage
    paths = []
    for name in ('kernel', 'initramfs', 'root', 'task', 'assignment'):
        path = tmp_path / name
        path.write_bytes((name + '-inert-data-only').encode())
        paths.append(path)
    hashes = {str(path): __import__('hashlib').sha256(path.read_bytes()).hexdigest() for path in paths}
    devices = {}
    for name, path in zip(('root', 'task', 'assignment'), paths[2:]):
        st = path.stat()
        devices[name] = {'path': str(path), 'sha256': hashes[str(path)],
                         'st_dev': st.st_dev, 'st_ino': st.st_ino, 'readonly': name != 'task'}
    manifest = {'role': 'developer', 'workspace': {'kind': 'directory_snapshot', 'mount': '/task',
                'head': 'a' * 40, 'role': 'developer', 'readonly': False, 'host_share': False}, 'devices': devices}
    return GuestImage(*paths, hashes, 'developer', q2.canonical(manifest))


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('mode', ['WAL', 'DELETE'])
def test_unknown_intent_before_actual_acquisition_has_zero_spawn(owner, tmp_path, monkeypatch, mode):
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as competitor:
        competitor.execute('PRAGMA journal_mode=' + mode)
        with write_txn(competitor):
            body = q2.metadata(competitor.execute('SELECT metadata FROM task_runs').fetchone()[0])
            body[q2.NAMESPACE]['state'] = 'STOP_UNCERTAIN'
            competitor.execute('UPDATE task_runs SET metadata=?', (q2.canonical(body),))
    calls = []
    monkeypatch.setattr(q2.Q2Batch, 'verify', lambda *_a, **_kw: None)  # No Native qualification: inert transaction seam.
    def forbidden_spawn(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError('spawn callback forbidden by existing UNKNOWN')
    monkeypatch.setattr(q2.subprocess, 'Popen', forbidden_spawn)
    image = small_image(batch, tmp_path)
    try:
        with pytest.raises(RuntimeStoreError):
            q2.acquire_child(handle, image, None, batch.output / 'inert-bootstrap.json')
        assert calls == []
        assert not handle.record['native_spawned']
    finally:
        close_inert_handle(handle)


def close_inert_handle(handle):
    """Own and reap only the exact /bin/cat created by these transaction tests."""
    if handle.process is not None:
        handle.process.stdin.close()
        assert handle.process.wait(timeout=5) == 0
        handle.process.stdout.close()
        handle.process.stderr.close()
    if handle.channel is not None:
        handle.channel.close_transport(deadline=time.monotonic() + 5)
    if handle.executor is not None:
        handle.executor.shutdown(wait=True)
    if handle.serial is not None:
        handle.serial.close()
    q2._close_task_checkpoint(handle)


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('mode', ['WAL', 'DELETE'])
def test_actual_spawn_writer_serializes_competing_unknown(owner, tmp_path, monkeypatch, mode):
    """Independent real SQLite writers surround an actual inert child acquisition."""
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    with closing(sqlite3.connect(batch.board, isolation_level=None)) as conn:
        assert conn.execute('PRAGMA journal_mode=' + mode).fetchone()[0].upper() == mode
    spawned, blocked, may_write = threading.Event(), threading.Event(), threading.Event()
    observed = {}
    original_popen, original_readback = subprocess.Popen, q2._booked_readback

    def compete():
        with closing(sqlite3.connect(batch.board, isolation_level=None, timeout=0)) as competitor:
            assert spawned.wait(5)
            try:
                competitor.execute('BEGIN IMMEDIATE')
            except sqlite3.OperationalError as error:
                assert 'locked' in str(error)
                blocked.set()
            else:
                competitor.rollback()
                raise AssertionError('Competing writer acquired before PID booking commit')
            assert may_write.wait(5)
            competitor.execute('BEGIN IMMEDIATE')
            body = q2.metadata(competitor.execute('SELECT metadata FROM task_runs').fetchone()[0])
            observed.update(body[q2.NAMESPACE])
            body[q2.NAMESPACE]['state'] = 'STOP_UNCERTAIN'
            competitor.execute('UPDATE task_runs SET metadata=?', (q2.canonical(body),))
            competitor.commit()

    def popen_inert(_argv, **kwargs):
        child = original_popen(['/bin/cat'], **kwargs)
        spawned.set()
        assert blocked.wait(5)
        return child

    with ThreadPoolExecutor(1) as pool:
        competing = pool.submit(compete)

        def readback_then_intent(current):
            original_readback(current)
            may_write.set()
            competing.result(timeout=5)

        monkeypatch.setattr(q2.Q2Batch, 'verify', lambda *_a, **_kw: None)
        monkeypatch.setattr(q2.subprocess, 'Popen', popen_inert)
        monkeypatch.setattr(q2, '_booked_readback', readback_then_intent)
        try:
            with pytest.raises(RuntimeStoreError):
                q2.acquire_child(handle, small_image(batch, tmp_path), None, batch.output / 'bootstrap.json')
            competing.result(timeout=5)
            assert observed['phase'] == 'CHILD_BOOKED'
            assert observed['native_spawned'] is True
            assert observed['identity']['pid'] == handle.process.pid
            assert handle.process.poll() is None
            assert not handle.closed.is_set()
        finally:
            may_write.set()
            close_inert_handle(handle)


@pytest.mark.platforms('macos')
def test_child_booking_failure_preserves_precommitted_exclusion(owner, tmp_path, monkeypatch):
    authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    original_popen, original_persist = subprocess.Popen, q2._persist

    def popen_inert(_argv, **kwargs):
        return original_popen(['/bin/cat'], **kwargs)

    def fail_booking(board, current, record):
        if record['phase'] == 'CHILD_BOOKED':
            raise sqlite3.OperationalError('offline injected booking commit failure')
        return original_persist(board, current, record)

    monkeypatch.setattr(q2.Q2Batch, 'verify', lambda *_a, **_kw: None)
    monkeypatch.setattr(q2.subprocess, 'Popen', popen_inert)
    monkeypatch.setattr(q2, '_persist', fail_booking)
    try:
        with pytest.raises(sqlite3.OperationalError, match='booking commit failure'):
            q2.acquire_child(handle, small_image(batch, tmp_path), None, batch.output / 'bootstrap.json')
        assert handle.process.poll() is None
        assert handle.identity['pid'] == handle.process.pid
        assert not handle.closed.is_set()
        with closing(sqlite3.connect(batch.board)) as conn:
            raw = conn.execute('SELECT metadata FROM task_runs').fetchone()[0]
            assert q2.metadata(raw)[q2.NAMESPACE]['state'] == 'STARTING'
        q2.mark_uncertain(handle, RuntimeError('child exists despite rollback'))
        assert q2.metadata(authority.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
        assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))['spent'] == 1
    finally:
        close_inert_handle(handle)


def synthetic_retirement_record():
    """Data-only predicate fixture; never evidence of an actual VM lifecycle."""
    identity = {'pid': 999999, 'ppid': os.getpid(), 'created': psutil.boot_time() + 1,
                'boot_time': psutil.boot_time(), 'pgid': 999999, 'executable': '/inert-proof-fixture',
                'fingerprint': 'public-boot|public-start'}
    scope = {'session_id': 'proof-session', 'generation': 1, 'epoch': 1, 'execution_id': 'admission-worker:proof',
             'task_id': 'proof-task', 'run_id': 1, 'vm_id': 'proof-vm', 'connection_generation': 1,
             'image_digest': 'a' * 64, 'policy_digest': 'b' * 64}
    serial = {key: True for key in ('peer_eof', 'descriptor_closed', 'receive_pump_joined',
        'writer_joined', 'service_joined', 'http_joined', 'transport_joined', 'complete')}
    serial.update(serial_observer='ORIGINAL_OWNER_SERIALWIRE', cleanup_errors=[], scope=scope)
    proof = {key: True for key in ('exact_child_waited', 'process_group_empty', 'all_pipes_closed',
        'guest_orderly_shutdown', 'explicit_vm_destroy', 'destroy_success', 'owner_work_completed',
        'owner_accounting_complete', 'guest_ready', 'bootstrap_fd_closed', 'child_serial_in_parent_closed',
        'core_limit_zero', 'task_checkpoint_closed', 'device_exit_verified')}
    proof.update(exit_code=0, vm_create_successes=1, parent_device_capabilities={'closed': True},
        serial_observation=serial, serial_read_by_process_observer=False,
        wait_result='REAPED_BY_ORIGINAL_OWNER', identity=identity, pid=identity['pid'],
        process_group_members=[], terminating_signal=None, stdio_eof={'stdout': True, 'stderr': True},
        pipes={name: {'closed': True} for name in ('stdin', 'stdout', 'stderr')},
        owner_fds_before=10, owner_fds_after=10)
    return {**scope, 'identity': identity, 'owner_pid': os.getpid(), 'native_spawned': True, 'proof': proof}


def test_complete_physical_predicate_requires_separate_accounting():
    record = synthetic_retirement_record()
    assert q2._valid_proof(record)
    record['proof']['owner_accounting_complete'] = False
    assert not q2._valid_proof(record)
    assert q2._valid_proof(record, accounted=False)


@pytest.mark.parametrize(('path', 'value'), [
    (('native_spawned',), False),
    (('proof', 'exit_code'), False),
    (('proof', 'exit_code'), -9),
    (('proof', 'vm_create_successes'), True),
    (('proof', 'vm_create_successes'), 2),
    (('proof', 'exact_child_waited'), False),
    (('proof', 'guest_orderly_shutdown'), False),
    (('proof', 'explicit_vm_destroy'), False),
    (('proof', 'destroy_success'), False),
    (('proof', 'process_group_members'), [999998]),
    (('proof', 'terminating_signal'), 9),
    (('proof', 'pid'), 999998),
    (('proof', 'owner_fds_after'), 11),
    (('proof', 'owner_fds_before'), True),
    (('proof', 'core_limit_zero'), False),
    (('proof', 'task_checkpoint_closed'), False),
    (('proof', 'device_exit_verified'), False),
    (('proof', 'bootstrap_fd_closed'), False),
    (('proof', 'parent_device_capabilities', 'closed'), False),
    (('proof', 'stdio_eof', 'stderr'), False),
    (('proof', 'pipes', 'stdin', 'closed'), False),
    (('proof', 'pipes', 'stdout', 'closed'), False),
    (('proof', 'serial_observation', 'descriptor_closed'), False),
    (('proof', 'serial_observation', 'service_joined'), False),
    (('proof', 'serial_observation', 'http_joined'), False),
    (('proof', 'serial_observation', 'writer_joined'), False),
    (('proof', 'serial_observation', 'receive_pump_joined'), False),
    (('proof', 'serial_observation', 'cleanup_errors'), ['close failed']),
    (('proof', 'serial_observation', 'serial_observer'), 'Q1_CHILD_PIPES'),
    (('proof', 'serial_read_by_process_observer'), True),
])
def test_each_missing_physical_fact_blocks_retirement(path, value):
    record = synthetic_retirement_record()
    target = record
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    assert not q2._valid_proof(record)


def test_revoke_failure_does_not_skip_uncertainty_sinks(owner, monkeypatch):
    authority, batch, _source, _head = owner
    handle, _work = reserve(owner)

    def failed_revoke():
        raise sqlite3.OperationalError('offline injected revoke persistence failure')

    monkeypatch.setattr(handle.endpoint, 'revoke', failed_revoke)
    result = q2.mark_uncertain(handle, RuntimeError('offline cancellation'))
    assert result['state'] == 'STOP_UNCERTAIN'
    assert q2.metadata(authority.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
    assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))['status'] == 'STOP_UNCERTAIN'
    receipt = q2.read_json(batch.output / (handle.record['attempt'] + '-failure.json'))
    assert any('revoke persistence failure' in entry for entry in receipt['sink_failures'])
    assert not handle.closed.is_set()


def test_cancellation_unknown_survives_complete_physical_facts(owner):
    authority, batch, source, head = owner
    handle, _work = reserve(owner)
    q2.mark_uncertain(handle, RuntimeError('offline cancellation'))
    cancelled = q2.metadata(authority.db.get_meta(handle.key))
    cancelled['proof'] = synthetic_retirement_record()['proof']
    authority.db.set_meta(handle.key, q2.canonical(cancelled))
    retained = q2.recover_q2_reservations(authority)
    assert handle.key in retained
    assert q2.metadata(authority.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
    with pytest.raises(RuntimeStoreError):
        q2.reserve_attempt(authority, batch, 2, source=source, head=head)


def test_pre_attempt_crash_retains_spent_grant_without_child_row(owner):
    authority, batch, _source, _head = owner
    approve_fixture(authority, batch)
    grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
    grant.update(spent=1, phase='RESERVING')
    authority.db.set_meta(q2.GRANTS + batch.sha256, q2.canonical(grant))
    assert q2.recover_q2_reservations(authority) == ()
    authority.__dict__.pop('_q2_active_grant')
    assert q2.recover_q2_reservations(authority) == (q2.GRANTS + batch.sha256,)
    assert authority.db._read_one('SELECT count(*) FROM worker_executions')[0] == 0
    assert q2.physical_pending(authority) == 1
    assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256)) == grant


@pytest.mark.parametrize('raw', ['{', '[]', '{"status":"IN_PROGRESS","status":"COMPLETE"}'])
def test_malformed_grant_retained_without_normalizing_bytes(owner, raw):
    authority, batch, _source, _head = owner
    authority.db.set_meta(q2.GRANTS + batch.sha256, raw)
    assert q2.recover_q2_reservations(authority) == (q2.GRANTS + batch.sha256,)
    assert authority.db.get_meta(q2.GRANTS + batch.sha256) == raw


def test_reservation_failure_spends_batch_without_worker_handle(owner):
    authority, batch, source, head = owner
    approve_fixture(authority, batch)
    q2.stop_batch(authority, batch, RuntimeError('offline pre-handle reservation failure'))
    grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
    assert grant['status'] == 'STOP_UNCERTAIN'
    assert authority.db._read_one('SELECT count(*) FROM worker_executions')[0] == 0
    with pytest.raises(RuntimeStoreError):
        q2.reserve_attempt(authority, batch, 1, source=source, head=head)
    assert list(batch.output.glob('batch-failure-*.json'))


def prepared_accounting(owner, slot=1):
    """Real Owner persistence with synthetic physical facts, never a Native PASS."""
    authority, batch, source, head = owner
    if slot == 1:
        handle, _work = reserve(owner)
    else:
        handle, _work = q2.reserve_attempt(authority, batch, slot, source=source, head=head)
    handle.endpoint({'method': 'worker.adopt', 'scope': handle.scope, 'params': {}})
    pending = handle.endpoint({'method': 'worker.persist', 'scope': handle.scope,
        'params': {'sequence': 1, 'operation': 'execution.finish', 'payload': {}}})
    assert pending == {'status': 'pending_retirement'}
    complete = synthetic_retirement_record()
    complete['proof']['serial_observation']['scope'] = dict(handle.scope)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as board, write_txn(board):
        q2._persist(board, handle, {**handle.record, 'native_spawned': True, 'identity': complete['identity']})
    handle.process = SimpleNamespace(returncode=0)
    handle.executor = ThreadPoolExecutor(1)
    handle.service = handle.executor.submit(lambda: None)
    handle.service.result(timeout=5)
    handle.executor.shutdown(wait=True)
    handle.service_done.set()
    authority._q2_guest_channels = {handle.scope['session_id']: None}
    complete['proof']['owner_accounting_complete'] = False
    return handle, complete['proof']


def test_healthy_original_owner_accounting_commits_retirement_last(owner):
    authority, batch, _source, _head = owner
    handle, proof = prepared_accounting(owner)
    record = q2.finish_attempt(handle, proof)
    assert record['state'] == 'RETIRED'
    assert record['proof']['owner_accounting_complete'] is True
    assert handle.closed.is_set()
    assert q2.matching_board(authority, record)
    assert q2.metadata(authority.db.get_meta(handle.key)) == record
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'terminal'
    grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
    assert grant['spent'] == 1 and grant['phase'] == 'SLOT_COMPLETE' and grant['handoff'] == 2
    assert q2.recover_q2_reservations(authority) == ()


def test_accounting_failure_after_worker_terminal_keeps_successor_exclusion(owner, monkeypatch):
    authority, batch, source, head = owner
    handle, proof = prepared_accounting(owner)
    import hermes_state_runtime

    def fail_settlement(*_args, **_kwargs):
        during = q2.metadata(authority.db.get_meta(handle.key))
        assert during['state'] == 'STARTING' and during['phase'] == 'ACCOUNTING'
        raise sqlite3.OperationalError('offline injected accounting failure')

    monkeypatch.setattr(hermes_state_runtime, 'settle_session_input', fail_settlement)
    with pytest.raises(sqlite3.OperationalError, match='accounting failure'):
        q2.finish_attempt(handle, proof)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'terminal'
    assert q2.metadata(authority.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
    assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))['status'] == 'STOP_UNCERTAIN'
    assert not handle.closed.is_set()
    assert handle.key in q2.recover_q2_reservations(authority)
    with pytest.raises(RuntimeStoreError):
        q2.reserve_attempt(authority, batch, 2, source=source, head=head)


def inputs_batch(owner, tmp_path):
    _authority, batch, source, head = owner
    tools = [tmp_path / 'artifact-python', tmp_path / 'mke2fs']
    for tool in tools:
        tool.write_bytes(b'public inert input only; never executed\n')
    inventory = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in source.rglob('*') if path.is_file()}
    tree = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    body = {**batch.body, 'mke2fs': str(tools[1]), 'artifact_python': {'path': str(tools[0])},
        'tool_inventory': {str(tool): hashlib.sha256(tool.read_bytes()).hexdigest() for tool in tools},
        'fixture_identity': {'head': head, 'tree': tree, 'common_dir': str(source / '.git'), 'inventory': inventory}}
    return q2.Q2Batch(batch.path, body), tools


def test_exact_public_fixture_and_tool_inputs_accept(owner, tmp_path):
    batch, _tools = inputs_batch(owner, tmp_path)
    batch.verify_inputs()
    assert q2._fixture_source(batch) == (owner[2], owner[3])


@pytest.mark.parametrize('damage', ['missing', 'changed', 'unlisted'])
def test_changed_or_missing_build_tool_cannot_pass_preflight(owner, tmp_path, damage):
    batch, tools = inputs_batch(owner, tmp_path)
    if damage == 'missing':
        tools[0].unlink()
    elif damage == 'changed':
        tools[0].write_bytes(b'changed input')
    else:
        del batch.body['tool_inventory'][str(tools[0])]
    with pytest.raises((RuntimeStoreError, OSError)):
        batch.verify_inputs()


@pytest.mark.parametrize('damage', ['file', 'new', 'symlink', 'hardlink'])
def test_fixture_content_or_inode_alias_cannot_pass_preflight(owner, tmp_path, damage):
    batch, _tools = inputs_batch(owner, tmp_path)
    source = owner[2]
    if damage == 'file':
        (source / 'base.txt').write_bytes(b'changed fixture')
    elif damage == 'new':
        (source / 'extra.txt').write_bytes(b'undeclared fixture')
    elif damage == 'symlink':
        (source / 'alias').symlink_to(source / 'base.txt')
    else:
        os.link(source / 'base.txt', source / 'alias')
    with pytest.raises(RuntimeStoreError, match='q2_fixture_identity_changed'):
        batch.verify_inputs()


@pytest.mark.parametrize('field', ['head', 'tree', 'common_dir'])
def test_frozen_fixture_git_identity_is_not_selected_by_branch(owner, tmp_path, field):
    batch, _tools = inputs_batch(owner, tmp_path)
    batch.body['fixture_identity'][field] = 'a' * 40 if field != 'common_dir' else str(tmp_path / 'foreign.git')
    with pytest.raises(RuntimeStoreError, match='q2_fixture_git_changed'):
        q2._fixture_source(batch)


@pytest.mark.parametrize('identity', [None, [], 'malformed'])
def test_malformed_process_identity_is_incomplete_proof(identity):
    record = synthetic_retirement_record()
    record['identity'] = identity
    record['proof']['identity'] = identity
    assert not q2._valid_proof(record)


@pytest.mark.parametrize('path', [
    ('serial_observation',), ('parent_device_capabilities',), ('pipes',), ('pipes', 'stdin'),
])
def test_malformed_nested_physical_observation_is_incomplete_proof(path):
    record = synthetic_retirement_record()
    target = record['proof']
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = None
    assert not q2._valid_proof(record)


@pytest.mark.parametrize(('slot', 'changes'), [
    (0, {'spent': -1}),
    (4, {'spent': 3, 'phase': 'SLOT_COMPLETE', 'handoff': 4}),
    (1, {'started_monotonic': 0}),
    (1, {'boot_time': 0}),
    (1, {'instance': 'foreign-owner'}),
    (1, {'epoch': -1}),
    (2, {'spent': 1, 'phase': 'SLOT_COMPLETE', 'handoff': None}),
])
def test_grant_budget_history_and_owner_binding_reject_before_reservation(owner, slot, changes):
    authority, batch, _source, _head = owner
    approve_fixture(authority, batch)
    grant = q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))
    grant.update(changes)
    authority.db.set_meta(q2.GRANTS + batch.sha256, q2.canonical(grant))
    with authority.db._read_ctx() as conn, pytest.raises(RuntimeStoreError):
        q2._grant(conn, authority, batch, slot)
    assert authority.db._read_one('SELECT count(*) FROM worker_executions')[0] == 0


def test_existing_board_json_writer_spacing_preserves_exact_reservation(owner):
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as board, write_txn(board):
        board.execute('UPDATE task_runs SET metadata=?', (json.dumps({q2.NAMESPACE: handle.record}, indent=2),))
        assert q2._board_guard(board, handle)['id'] == handle.scope['run_id']


def test_board_duplicate_namespace_cannot_be_reserialized_as_valid(owner):
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    raw = '{"q2_hvf_v1":' + q2.canonical(handle.record) + ',"q2_hvf_v1":' + q2.canonical(handle.record) + '}'
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as board:
        board.execute('UPDATE task_runs SET metadata=?', (raw,))
        with write_txn(board), pytest.raises(RuntimeStoreError):
            q2._board_guard(board, handle)
        assert board.execute('SELECT metadata FROM task_runs').fetchone()[0] == raw


def exit_devices(owner, tmp_path, *, reviewer=False):
    from dataclasses import replace
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    image = small_image(batch, tmp_path)
    if reviewer:
        manifest = json.loads(image.manifest_json)
        manifest['role'] = 'reviewer'
        manifest['workspace'].update(role='reviewer', readonly=True)
        manifest['devices']['task']['readonly'] = True
        image = replace(image, role='reviewer', manifest_json=q2.canonical(manifest))
    with image.open_devices() as devices:
        handle.parent_device_observation = {'descriptors': devices.descriptors(), 'closed': False}
        handle.task_checkpoint_fd = os.dup(devices.fds['task'])
    handle.parent_device_observation['closed'] = devices.closed
    return handle, image


def test_developer_task_checkpoint_fsyncs_exact_capability_and_accepts_actual_changes(owner, tmp_path):
    handle, image = exit_devices(owner, tmp_path)
    fd = handle.task_checkpoint_fd
    original = image.task.read_bytes()
    image.task.write_bytes(original[:-1] + b'!')
    facts = q2._device_exit_facts(handle, image)
    assert handle.task_checkpoint_fd is None
    with pytest.raises(OSError):
        os.fstat(fd)
    assert facts['task']['sha256'] != handle.parent_device_observation['descriptors']['task']['sha256']
    assert facts['root']['sha256'] == image.sha256[str(image.root)]


@pytest.mark.parametrize(('name', 'reviewer'), [('root', False), ('assignment', False), ('task', True)])
def test_readonly_device_change_after_exact_wait_cannot_retire(owner, tmp_path, name, reviewer):
    handle, image = exit_devices(owner, tmp_path, reviewer=reviewer)
    path = getattr(image, name)
    original = path.read_bytes()
    path.write_bytes(original[:-1] + b'!')
    try:
        with pytest.raises(RuntimeStoreError, match='q2_stopped_device_changed'):
            q2._device_exit_facts(handle, image)
        assert handle.task_checkpoint_fd is None
    finally:
        q2._close_task_checkpoint(handle)


@pytest.mark.parametrize('name', ['root', 'task', 'assignment'])
def test_replaced_stopped_device_identity_cannot_be_same_bytes(owner, tmp_path, name):
    handle, image = exit_devices(owner, tmp_path)
    path = getattr(image, name)
    original = path.read_bytes()
    replaced = path.with_suffix('.replaced')
    path.rename(replaced)
    path.write_bytes(original)
    try:
        with pytest.raises(RuntimeStoreError, match='q2_stopped_device_changed'):
            q2._device_exit_facts(handle, image)
    finally:
        q2._close_task_checkpoint(handle)


@pytest.mark.asyncio
async def test_original_canonical_epoch_handoffs_keep_cancel_unknown_after_complete_accounting(owner):
    from gateway.config import GatewayConfig
    from gateway.session import SessionStore
    from gateway.session_cron import unbind_owner
    authority, batch, source, head = owner
    authority.runner.session_store = SessionStore(batch.profile / 'sessions', GatewayConfig())
    previous = []
    current = authority
    try:
        for slot in (1, 2, 3):
            handle, proof = prepared_accounting((current, batch, source, head), slot)
            if slot == 3:
                handle.endpoint.revoke()
            q2.finish_attempt(handle, proof)
            previous.append(current)
            current = await q2._reinitialize_epoch(current, batch, slot, cancelled=slot == 3)
            assert current is current.runner.session_authorities.for_home(batch.profile)
            assert current.epoch > previous[-1].epoch
            assert previous[-1].retired
            with pytest.raises(RuntimeStoreError):
                handle.endpoint({'method': 'worker.adopt', 'scope': handle.scope, 'params': {}})
        assert handle.key in q2.recover_q2_reservations(current)
        assert q2.metadata(current.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
        worker = current.db._read_one('SELECT status FROM worker_executions WHERE execution_id=?',
                                     (handle.scope['execution_id'],))
        assert worker[0] == 'unknown'
        assert q2.metadata(current.db.get_meta(q2.GRANTS + batch.sha256))['status'] == 'COMPLETE_CANCELLED_UNKNOWN_RETAINED'
    finally:
        unbind_owner(current)


def test_owner_bootstrap_matches_native_exact_canonical_bytes_without_newline(owner, tmp_path):
    _authority, batch, _source, _head = owner
    handle, _work = reserve(owner)
    image = small_image(batch, tmp_path)
    path = batch.output / 'canonical-bootstrap.json'
    host, child = socket.socketpair()
    with image.open_devices() as devices, host, child:
        plan, checksum = q2._bootstrap(handle, devices, child.fileno(), path)
    raw = path.read_bytes()
    assert raw == q2.canonical(plan).encode()
    assert checksum == hashlib.sha256(raw).hexdigest()
    assert not raw.endswith(b'\n')
    assert plan['owner']['attempt'] == handle.record['attempt']
    assert plan['devices']['task']['st_ino'] == image.task.stat().st_ino


@pytest.mark.parametrize('field', ['pid', 'ppid', 'pgid', 'fingerprint', 'executable', 'created', 'boot_time'])
def test_every_original_child_identity_field_is_required_for_historical_retirement(field):
    record = synthetic_retirement_record()
    del record['identity'][field]
    assert not q2._valid_proof(record)


def test_matching_empty_identity_objects_do_not_prove_process_ownership():
    record = synthetic_retirement_record()
    record['identity'] = {}
    record['proof']['identity'] = {}
    record['proof']['pid'] = None
    assert not q2._valid_proof(record)


@pytest.mark.parametrize('field', ['session_id', 'generation', 'epoch', 'execution_id', 'task_id', 'run_id',
                                  'vm_id', 'connection_generation', 'image_digest', 'policy_digest'])
def test_serial_physical_evidence_must_match_exact_original_assignment(field):
    record = synthetic_retirement_record()
    record['proof']['serial_observation']['scope'][field] = 'foreign-value'
    assert not q2._valid_proof(record)


def test_physical_child_parent_must_match_original_owner_pid():
    record = synthetic_retirement_record()
    record['identity']['ppid'] += 1
    assert not q2._valid_proof(record)


def retired_parent_candidate(owner, *, disk_evidence=True):
    authority, batch, source, head = owner
    handle, proof = prepared_accounting(owner)
    actual = {'manifest_path': str(batch.output / 'actual-candidate.json'), 'manifest_sha256': 'c' * 64,
              'candidate_head': head, 'snapshot_path': str(source)}
    if disk_evidence:
        from native.qemu_guest.artifact_inventory import file_record
        public_disk = batch.output / 'public-inert-source-disk.raw'
        public_disk.write_bytes(b'data-only candidate predicate fixture; never Guest output\n')
        actual['source_disk'] = file_record(public_disk)
        proof['stopped_devices'] = {'task': dict(actual['source_disk'])}
    authority.db.set_meta('q2.hvf.candidate:' + handle.record['attempt'], q2.canonical(actual))
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(batch.board) as board, write_txn(board):
        q2._persist(board, handle, {**handle.record, 'candidate_manifest_sha256': actual['manifest_sha256'],
                                   'candidate_head': actual['candidate_head']})
    q2.finish_attempt(handle, proof)
    return handle, actual


def test_reviewer_uses_unique_retired_actual_candidate_with_matching_owner_board_anchor(owner, monkeypatch):
    authority, batch, _source, _head = owner
    _handle, actual = retired_parent_candidate(owner)
    from native.qemu_guest import qualification_artifacts
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: actual)
    assert q2._reviewer_candidate(authority, batch, actual['manifest_path']) == actual


def test_self_consistent_other_candidate_cannot_replace_actual_slot1(owner, monkeypatch):
    authority, batch, _source, _head = owner
    _handle, actual = retired_parent_candidate(owner)
    substitute = {**actual, 'candidate_head': 'd' * 40, 'manifest_sha256': 'e' * 64}
    from native.qemu_guest import qualification_artifacts
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: substitute)
    with pytest.raises(RuntimeStoreError, match='q2_candidate_parent_changed'):
        q2._reviewer_candidate(authority, batch, substitute['manifest_path'])


@pytest.mark.parametrize('damage', ['candidate_index', 'parent_state', 'board_anchor', 'duplicate_parent'])
def test_missing_or_changed_actual_candidate_anchor_rejects_reviewer(owner, monkeypatch, damage):
    authority, batch, _source, _head = owner
    handle, actual = retired_parent_candidate(owner)
    from native.qemu_guest import qualification_artifacts
    from hermes_cli.kanban_db_connect import connect_closing
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: actual)
    if damage == 'candidate_index':
        authority.db.set_meta('q2.hvf.candidate:' + handle.record['attempt'], '{}')
    elif damage == 'parent_state':
        parent = {**handle.record, 'state': 'STOP_UNCERTAIN'}
        authority.db.set_meta(handle.key, q2.canonical(parent))
    elif damage == 'board_anchor':
        with connect_closing(batch.board) as board:
            board.execute("UPDATE task_runs SET metadata='{}'")
    else:
        authority.db.set_meta(q2.PREFIX + 'duplicate-slot1', q2.canonical(handle.record))
    with pytest.raises(RuntimeStoreError, match='q2_candidate_parent_(missing|changed)'):
        q2._reviewer_candidate(authority, batch, actual['manifest_path'])


def test_candidate_parent_unknown_in_both_stores_never_qualifies_reviewer(owner, monkeypatch):
    authority, batch, _source, _head = owner
    handle, actual = retired_parent_candidate(owner)
    from native.qemu_guest import qualification_artifacts
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: actual)
    with connect_closing(batch.board) as board, write_txn(board):
        q2._persist(board, handle, {**handle.record, 'state': 'STOP_UNCERTAIN'})
    with pytest.raises(RuntimeStoreError, match='q2_candidate_parent_changed'):
        q2._reviewer_candidate(authority, batch, actual['manifest_path'])


def test_missing_candidate_and_physical_disk_records_do_not_equal_retirement(owner, monkeypatch):
    authority, batch, _source, _head = owner
    _handle, actual = retired_parent_candidate(owner, disk_evidence=False)
    from native.qemu_guest import qualification_artifacts
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: actual)
    with pytest.raises(RuntimeStoreError, match='q2_candidate_parent_changed'):
        q2._reviewer_candidate(authority, batch, actual['manifest_path'])


def test_candidate_source_disk_must_match_exact_stopped_developer_capability(owner, monkeypatch):
    authority, batch, _source, _head = owner
    _handle, actual = retired_parent_candidate(owner)
    actual['source_disk'] = {**actual['source_disk'], 'sha256': 'a' * 64}
    # A self-consistent candidate index still cannot contradict the observed Developer device.
    authority.db.set_meta('q2.hvf.candidate:' + _handle.record['attempt'], q2.canonical(actual))
    from native.qemu_guest import qualification_artifacts
    monkeypatch.setattr(qualification_artifacts, 'load_candidate', lambda _path: actual)
    with pytest.raises(RuntimeStoreError, match='q2_candidate_parent_changed'):
        q2._reviewer_candidate(authority, batch, actual['manifest_path'])


@pytest.fixture
def sandbox_sockets(owner, tmp_path):
    _authority, batch, _source, _head = owner
    sockets = []
    with tempfile.TemporaryDirectory(prefix='q2-fixture-', dir='/private/tmp') as short:
        paths = [Path(short) / name for name in ('ssh-agent', 'docker')]
        try:
            for path in paths:
                stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sockets.append(stream)
                stream.bind(str(path))
                stream.listen(1)
            policy = tmp_path / 'public-socket-policy.json'
            q2.write_receipt(policy, {'unix': {'ssh_agent': str(paths[0]), 'docker': str(paths[1])}})
            identities = {str(path): {key: getattr(path.lstat(), key) for key in ('st_dev', 'st_ino', 'st_mode')}
                          for path in paths}
            body = {**batch.body, 'helper_package': {**batch.body['helper_package'], 'static_policy': str(policy)},
                    'sandbox_fixture_identity': identities}
            yield q2.Q2Batch(batch.path, body), sockets, paths
        finally:
            for stream in sockets:
                stream.close()


@pytest.mark.platforms('macos')
def test_bound_and_stale_original_sandbox_socket_identities_are_accepted(sandbox_sockets):
    batch, sockets, _paths = sandbox_sockets
    batch.verify_sandbox_fixtures()
    for stream in sockets:
        stream.close()
    batch.verify_sandbox_fixtures()


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('damage', ['missing_path', 'missing_mapping', 'file_replacement', 'socket_replacement'])
def test_missing_or_replaced_sandbox_socket_fixture_refuses_preflight(sandbox_sockets, damage):
    batch, sockets, paths = sandbox_sockets
    sockets[0].close()
    if damage == 'missing_mapping':
        del batch.body['sandbox_fixture_identity'][str(paths[0])]
    else:
        paths[0].rename(paths[0].with_suffix('.original'))
        if damage == 'file_replacement':
            paths[0].write_bytes(b'public replacement fixture')
        elif damage == 'socket_replacement':
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sockets.append(replacement)
            replacement.bind(str(paths[0]))
    with pytest.raises((RuntimeStoreError, OSError)):
        batch.verify_sandbox_fixtures()


def test_device_cleanup_crossing_stop_deadline_keeps_original_owner_unknown(owner, monkeypatch):
    """Synthetic completed-observer facts exercise the final deadline; no child or VM."""
    authority, batch, source, head = owner
    handle, _work = reserve(owner)
    handle.endpoint({'method': 'worker.adopt', 'scope': handle.scope, 'params': {}})
    handle.endpoint({'method': 'worker.persist', 'scope': handle.scope,
        'params': {'sequence': 1, 'operation': 'execution.finish', 'payload': {}}})
    clock = [time.monotonic()]
    handle.spawned_at = clock[0]
    handle.slot_deadline = handle.batch_deadline = clock[0] + 300
    handle.executor = ThreadPoolExecutor(1)
    handle.service = handle.executor.submit(lambda: None)
    handle.service.result(timeout=5)
    handle.executor.shutdown(wait=True)
    handle.service_done.set()
    handle.parent_device_observation = {'closed': True}
    handle.bootstrap_closed = handle.guest_serial_closed = True
    ready = threading.Event()
    ready.set()
    observations = []

    def forbidden_spawn(*_args, **_kwargs):
        raise AssertionError('Synthetic deadline regression must never create a child')

    def attach_synthetic_channel(current, _image, inference, _bootstrap):
        current.channel = SimpleNamespace(ready=ready, result_ready=ready,
            ready_at=clock[0], result_at=clock[0],
            finish_transport=lambda **_kwargs: inference.close(),
            close_transport=lambda **_kwargs: inference.close(),
            cancel=handle.endpoint.revoke, physical_observation=lambda: {'synthetic': True})

    class CompletedObserver:
        def __init__(self, *_args, **_kwargs):
            self.closed = False

        def start(self, _deadline):
            observations.append('started')

        def finish(self, deadline, serial_observation):
            assert clock[0] < deadline
            serial_observation()
            observations.append('observer_finished_within_deadline')
            return synthetic_retirement_record()['proof']

        def close(self):
            self.closed = True
            observations.append('observer_closed')

    def late_device_completion(_handle, _image):
        assert observations[-1] == 'observer_closed'
        clock[0] += 31
        observations.append('device_cleanup_completed_after_deadline')
        return {'synthetic': 'completed_after_deadline'}

    from gateway import session_hvf_process
    monkeypatch.setattr(q2.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(q2.subprocess, 'Popen', forbidden_spawn)
    monkeypatch.setattr(q2, 'acquire_child', attach_synthetic_channel)
    monkeypatch.setattr(q2, '_device_exit_facts', late_device_completion)
    monkeypatch.setattr(session_hvf_process, 'Q2ProcessObserver', CompletedObserver)
    with pytest.raises(RuntimeStoreError, match='q2_owner_resources_unretired'):
        q2.execute_attempt(handle, SimpleNamespace(role='developer'), q2.FixtureResponses('developer'), None)
    assert observations == ['started', 'observer_finished_within_deadline', 'observer_closed',
                            'device_cleanup_completed_after_deadline']
    assert handle.process is None and handle.proof is None and not handle.closed.is_set()
    assert q2.metadata(authority.db.get_meta(handle.key))['state'] == 'STOP_UNCERTAIN'
    assert q2.metadata(authority.db.get_meta(q2.GRANTS + batch.sha256))['status'] == 'STOP_UNCERTAIN'
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    with pytest.raises(RuntimeStoreError):
        q2.reserve_attempt(authority, batch, 2, source=source, head=head)
