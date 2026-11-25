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


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['model', 'reasoning', 'workspace', 'editor_mcp', 'reset', 'compress_in_place',
                                       'compress_rotate', 'branch', 'recovery'])
async def test_board_pause_policy_provenance_survives_supported_mutations(
        owner, paused_session, monkeypatch, tmp_path, operation):
    """Committed native mutation paths retain all Board policy markers and cannot spawn."""
    from dataclasses import replace
    from gateway import session_managed_worker as managed
    from gateway.session_contract import SessionRef
    from gateway.session_kanban import check_board_execution
    from gateway.session_local_recovery import recover_local_sessions
    from gateway.session_mutations import mutate_session
    from gateway.session_policy import restore_policy
    from hermes_state_local import local_receipt
    from hermes_state_runtime import RuntimeStoreError

    actor, ref, original = paused_session(board=True)
    keys = ('source', 'kanban_json', 'request_json')
    expected = {key: getattr(original, key) for key in keys}
    calls = []
    def no_spawn(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('Popen must not run')
    monkeypatch.setattr(managed.subprocess, 'Popen', no_spawn)
    owner.runner._evict_cached_agent = lambda route: None
    owner.runner._cached_agent_for = lambda route: None
    owner.runner._set_session_reasoning_override = lambda route, value: None
    owner.runner._resolve_session_agent_runtime = lambda **kwargs: ('fixture', {})
    if operation == 'editor_mcp':
        # The offline test environment does not install the optional ACP schema.
        monkeypatch.setattr('gateway.session_local_mcp.validate_servers', lambda servers: None)
    if operation == 'model':
        from hermes_cli import model_switch
        monkeypatch.setattr(model_switch, 'switch_model', lambda **kwargs: model_switch.ModelSwitchResult(
            success=True, new_model='changed', target_provider='custom', base_url=''))
        async def no_guard(*args, **kwargs):
            return None
        monkeypatch.setattr('gateway.session_mutation_model._selection_guard_refusal', no_guard)
    if operation == 'workspace':
        from tui_gateway import git_probe
        (tmp_path / 'project').mkdir()
        monkeypatch.setattr(git_probe, 'branch', lambda cwd: None)
        monkeypatch.setattr(git_probe, 'common_repo_root', lambda cwd: None)
    if operation.startswith('compress_'):
        # No model: replace only summary generation, not the real fenced mutation or SQLite commit.
        async def offline_summary(authority, live, payload, prepared):
            return dict(prepared, messages=[{'role': 'assistant', 'content': 'fixture summary',
                                             '_compressed_summary': True}],
                        summary='fixture', in_place=operation == 'compress_in_place')
        monkeypatch.setattr('gateway.session_mutation_compress.prepare_compress', offline_summary)

    refs = [ref]
    physical = None
    if operation == 'recovery':
        from gateway.session_authority import SessionAuthority
        from hermes_state_runtime import begin_runtime_epoch
        owner.runner.adapters.clear()
        runner = owner.runner
        epoch = begin_runtime_epoch(owner.db, instance_id='recovered')
        owner = SessionAuthority(runner, profile_id=owner.profile_id, instance_id='recovered', db=owner.db, epoch=epoch)
        runner.session_authority = owner
        recover_local_sessions(owner, schedule=False)
        assert ref.session_id in owner.sessions
    else:
        payloads = {'model': {'model': 'changed'}, 'reasoning': {'effort': 'high'},
                    'workspace': {'cwd': str(tmp_path / 'project')}, 'editor_mcp': {'mcp_servers': []},
                    'reset': {}, 'compress_in_place': {}, 'compress_rotate': {}, 'branch': {}}
        name = 'compress' if operation.startswith('compress_') else operation
        row = owner.db.get_session(ref.session_id)
        params = {'session_id': ref.session_id, 'request_id': 'policy-' + operation,
                  'operation': name, 'payload': payloads[operation], 'expected_revision': row['runtime_revision'],
                  'expected_generation': row['runtime_generation']}
        if operation == 'editor_mcp':
            # Editor MCP is restricted to ACP; a kanban policy is deliberately refused.
            with pytest.raises(RuntimeStoreError, match='invalid_params'):
                await mutate_session(owner, actor, ref, params)
        else:
            result = await mutate_session(owner, actor, ref, params)
            if operation == 'branch':
                refs.append(SessionRef(owner.profile_id, result['branched_session_id']))
            if operation == 'model':
                assert result['model'] == 'changed'
            if operation == 'reasoning':
                assert result['effort'] == 'high'
            if operation == 'workspace':
                assert result['cwd'] == str(tmp_path / 'project')
            if operation in {'reset', 'compress_rotate'}:
                assert result['target_session_id'] != ref.session_id
                physical = SessionRef(owner.profile_id, result['target_session_id'])
            if operation == 'compress_in_place':
                assert result['target_session_id'] == ref.session_id
    for target in refs:
        receipt = local_receipt(owner.db, target.session_id)
        assert {key: receipt['policy'][key] for key in keys} == expected
        restored = restore_policy(receipt['policy'])
        forged = replace(restored, source='cli', kanban_json=None, request_json='{}')
        with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
            check_board_execution(owner, target)
        for policy in (restored, forged):
            with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
                await managed.execute_managed(owner, target, {'payload': {'text': 'held'}}, policy)
    if physical is not None:
        forged = replace(original, source='cli', kanban_json=None, request_json='{}')
        with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
            check_board_execution(owner, physical)
        with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
            await managed.execute_managed(owner, physical, {'payload': {'text': 'held'}}, forged)
    assert calls == []
