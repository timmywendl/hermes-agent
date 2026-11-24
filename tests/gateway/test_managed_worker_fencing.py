"""Loss is not success; delayed parent results cannot revive an admission."""
from contextlib import closing
import os
import subprocess
import sys
from types import SimpleNamespace

import psutil
import pytest

from hermes_state import SessionDB
from hermes_state_runtime import admit_session_input, begin_runtime_epoch, claim_session_input


def hello(process):
    """A direct child's self-introduction (no launcher: chain length 0)."""
    return {'type': 'hello', 'pid': process.pid, 'birth': psutil.Process(process.pid).create_time(), 'ancestors': [os.getpid()]}


def test_worker_loss_fences_same_generation_parent_result(tmp_path):
    from gateway.session_worker_reservation import reserve_admission_worker, lose_admission_worker
    from gateway.session_results import retain_result
    with closing(SessionDB(tmp_path / 'state.db')) as db:
        db.create_session('owned', 'cli')
        epoch = begin_runtime_epoch(db, instance_id='owner')
        authority = SimpleNamespace(db=db, epoch=epoch, profile_id=str(tmp_path), _require_admission_open=lambda: None)
        admit_session_input(db, epoch=epoch, principal_id='human', session_id='owned', request_id='input', payload={})
        row = claim_session_input(db, epoch=epoch, session_id='owned')
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            scope = reserve_admission_worker(authority, admission_id=row['admission_id'], process=child, principal_id='human', hello=hello(child))
            child.kill()
            child.wait(timeout=5)
            lose_admission_worker(authority, row, scope)
            with pytest.raises(Exception, match='stale_generation'):
                retain_result(db, epoch=epoch, row=row, result={'result': {'final_response': 'STALE'}, 'usage': {}})
            assert db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
            assert db._read_one('SELECT status FROM worker_executions')[0] == 'terminal'
        finally:
            child.stdin.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


@pytest.mark.asyncio
async def test_late_bootstrap_handshake_cannot_rearm_a_recovered_admission(tmp_path):
    """The owner reserved and bootstrapped a managed child, then died before the child's first
    ``worker.adopt``; that handshake reaches the restarted owner. Adopting it would flip the
    recovered ``unknown`` admission back to ``started`` under an owner with no pipe to the child
    (which refuses the foreign epoch and exits), stranding the FIFO where Discard cannot reach it."""
    import hermes_state_runtime as rt
    from gateway.session_worker import worker_request
    from gateway.session_worker_reservation import reserve_admission_worker
    with closing(SessionDB(tmp_path / 'state.db')) as db:
        db.create_session('owned', 'cli')
        epoch = begin_runtime_epoch(db, instance_id='owner')
        authority = SimpleNamespace(db=db, epoch=epoch, profile_id=str(tmp_path), _require_admission_open=lambda: None)
        lost = admit_session_input(db, epoch=epoch, principal_id='human', session_id='owned', request_id='lost', payload={})
        row = claim_session_input(db, epoch=epoch, session_id='owned')
        follower = admit_session_input(db, epoch=epoch, principal_id='human', session_id='owned', request_id='next', payload={})
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],  # noqa: ASYNC220 -- Popen returns immediately; the test drives the child through its handle
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            scope = reserve_admission_worker(authority, admission_id=row['admission_id'], process=child,
                                             principal_id='human', hello=hello(child))
            restarted = begin_runtime_epoch(db, instance_id='restarted')
            rt.recover_session_inputs(db, epoch=restarted)
            owner = SimpleNamespace(db=db, epoch=restarted, profile_id=str(tmp_path), _require_admission_open=lambda: None)
            actor = SimpleNamespace(subject='human', profile_id=str(tmp_path), capabilities={'worker:adopt'})
            identity = {k: v for k, v in scope.items() if k != 'epoch'}
            with pytest.raises(rt.RuntimeStoreError, match='stale_epoch'):
                await worker_request(SimpleNamespace(authority=owner, actor=actor), None, identity, operation='adopt')
            assert db._read_one('SELECT status,owner_epoch FROM session_admissions WHERE admission_id=?',
                                (lost['admission_id'],))[:] == ('unknown', epoch)
            assert db._read_one('SELECT status,owner_epoch FROM worker_executions')[:] == ('unknown', epoch)
            rt.resolve_unknown_session_input(db, epoch=restarted, admission_id=lost['admission_id'],
                                             generation=row['generation'])
            assert claim_session_input(db, epoch=restarted, session_id='owned')['admission_id'] == follower['admission_id']
        finally:
            child.stdin.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


@pytest.mark.asyncio
async def test_board_pause_direct_managed_policy_and_acquisition_refuse(owner, paused_session, monkeypatch):
    from dataclasses import replace
    from gateway import session_managed_worker as managed
    from hermes_state_runtime import RuntimeStoreError
    _actor, ref, policy = paused_session()
    calls = []
    def spawn(*args, **kwargs):
        calls.append(args)
        raise AssertionError('product Worker reached')
    monkeypatch.setattr(managed.subprocess, 'Popen', spawn)
    monkeypatch.setattr(managed, '_worker_env', spawn)
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        managed.managed_policy(owner, ref)
    # A caller cannot replace the passed source and context to erase the original receipt.
    forged = replace(policy, source='cli', kanban_json=None, request_json='{}')
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        await managed.execute_managed(owner, ref, {'payload': {'text': 'held'}}, forged)
    assert calls == []


@pytest.mark.asyncio
async def test_board_pause_final_acquisition_rechecks_after_environment_preparation(owner, paused_session, monkeypatch):
    import json
    from gateway import session_managed_worker as managed
    from hermes_state_local import POLICY_PREFIX
    from hermes_state_runtime import RuntimeStoreError
    _actor, ref, policy = paused_session(board=False)
    calls = []
    def prepare(authority):
        def bind(conn):
            key = POLICY_PREFIX + ref.session_id
            saved = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()[0])
            saved['policy']['kanban_json'] = '{}'
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (json.dumps(saved), key))
        authority.db._execute_write(bind)
        return {}
    def spawn(*args, **kwargs):
        calls.append(args)
        raise AssertionError('product Worker reached')
    monkeypatch.setattr(managed, '_worker_env', prepare)
    monkeypatch.setattr(managed.subprocess, 'Popen', spawn)
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        await managed.execute_managed(owner, ref, {'payload': {'text': 'held'}}, policy)
    assert calls == []


@pytest.mark.asyncio
async def test_board_pause_non_board_managed_reaches_original_acquisition(owner, paused_session, monkeypatch):
    from dataclasses import replace
    from gateway import session_managed_worker as managed
    _actor, ref, policy = paused_session(board=False)
    opted = replace(policy, ignore_user_config=True)
    monkeypatch.setattr('gateway.session_policy.policy_for_source', lambda runner, source: opted)
    assert managed.managed_policy(owner, ref) is opted
    calls = []
    class AcquisitionReached(Exception):
        pass
    def spawn(*args, **kwargs):
        calls.append((args, kwargs))
        raise AcquisitionReached
    monkeypatch.setattr(managed, '_worker_env', lambda authority: {})
    monkeypatch.setattr(managed.subprocess, 'Popen', spawn)
    with pytest.raises(AcquisitionReached):
        await managed.execute_managed(owner, ref, {'payload': {'text': 'ordinary'}}, opted)
    assert len(calls) == 1
    assert calls[0][1]['start_new_session'] is True
