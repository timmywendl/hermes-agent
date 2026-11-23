"""Task claims, not caller-supplied launch policy, authorize Kanban execution."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_claim_freezes_task_policy_and_rejects_forgery(tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'pyproject.toml').write_text('[project]\nname = "task"\n')  # a code worktree
    from contextlib import closing
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned acceptance', body='Goal criteria', assignee='default',
            workspace_kind='dir', workspace_path=str(workspace), skills=['owned-skill'], goal_mode=True,
            goal_max_turns=3, model_override='loop-model', provider_override='custom')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=SimpleNamespace(profile_id=str(tmp_path)), actor=actor, native_owner=True)
    params = dict(board='owned', task_id=task.id, run_id=task.current_run_id, claim_lock=task.claim_lock)
    from gateway.session_kanban import build_kanban_policy
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal', 'file']},
              'agent': {'coding_context': 'focus'}}  # the worktree must not collapse a worker into the coding posture
    policy, _secrets = build_kanban_policy(connection, params, config)
    context = json.loads(policy.kanban_json)
    assert policy.source == 'kanban' and policy.cwd == str(workspace)
    assert policy.model == task.model_override and policy.provider == task.provider_override
    assert {'kanban', 'terminal', 'file'} <= set(policy.toolsets)
    assert context['task_id'] == task.id and context['run_id'] == task.current_run_id
    assert context['board'] == 'owned' and context['claim_lock'] == task.claim_lock
    assert context['skills'] == ['owned-skill'] and context['goal_mode'] and context['goal_max_turns'] == 3
    assert context['accept_hooks'] is True and 'Goal criteria' in context['goal_text']
    for changed in ({'run_id': task.current_run_id + 1}, {'board': 'foreign'}, {'claim_lock': 'forged'}, {'cwd': '/tmp'}):
        with pytest.raises(RuntimeStoreError):
            build_kanban_policy(connection, params | changed, config)
    connection.native_owner = False
    with pytest.raises(RuntimeStoreError, match='permission_denied'):
        build_kanban_policy(connection, params, config)
    from gateway.session_policy import build_policy
    with pytest.raises(RuntimeStoreError, match='invalid_params'):
        build_policy({'source': 'kanban', 'cwd': str(workspace)}, config)


@pytest.mark.parametrize('mode', ['complete', 'timeout', 'rate_limit', 'billing', 'crash'])
def test_real_dispatcher_lifecycle(tmp_path, mode):
    import os
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[2]
    from tests.gateway.fixtures.local_recovery_probe import child_env
    env = child_env()
    env.update(HOME=str(tmp_path / 'home'), USERPROFILE=str(tmp_path / 'home'), HERMES_HOME=str(tmp_path / 'state'), PYTHONPATH=str(repo), KANBAN_PROBE_MODE=mode)
    result = subprocess.run([sys.executable, str(Path(__file__).parent / 'fixtures' / 'kanban_owner_probe.py')],
        env=env, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads((tmp_path / 'state' / 'receipt.json').read_text())
    print(json.dumps(receipt))
    if mode != 'complete':
        assert receipt['task_status'] == 'ready'
        return
    assert receipt['task_status'] == 'done' and receipt['source'] == 'kanban'
    assert receipt['tools'] and receipt['task_context'] and receipt['skill_context'] and receipt['hook_effect']
    assert receipt['admissions'] == 1 and receipt['retry_same_session']
    assert receipt['goal_continuation'] and receipt['stable_prefix']
    print(json.dumps(receipt))


def test_late_launcher_cannot_stamp_replacement_claim(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb, kanban_db_dispatch as dispatch
    from hermes_cli.kanban_db_connect import connect
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        tid = kb.create_task(conn, title='Owned race', assignee='default')
        old = kb.claim_task(conn, tid)
        kb.block_task(conn, tid, reason='replace claim', expected_run_id=old.current_run_id)
        kb.unblock_task(conn, tid)
        new = kb.claim_task(conn, tid)
        dispatch._set_worker_pid(conn, tid, 424242, run_id=old.current_run_id, claim_lock=old.claim_lock)
        assert kb.get_task(conn, tid).worker_pid is None
        assert conn.execute('SELECT worker_pid FROM task_runs WHERE id=?', (new.current_run_id,)).fetchone()[0] is None


def test_claim_reclaimed_before_admission_marker_is_refused(tmp_path, monkeypatch):
    """A claim that stops being current between policy/session creation and the marker
    transaction is refused: no owner_admitted row, no resume, no submit."""
    import asyncio
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned race', assignee='default', workspace_kind='dir', workspace_path=str(workspace))
        kb.recompute_ready(conn)
        old = kb.claim_task(conn, task_id)
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal']}}
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda: config)
    calls = []
    def create_local_session(authority, actor, params, *, trusted_policy=None, trusted_secrets=None):
        # Another process reclaims the task while the owner session is being created.
        with closing(connect(board='owned')) as conn:
            kb.block_task(conn, task_id, reason='replace claim', expected_run_id=old.current_run_id)
            kb.unblock_task(conn, task_id)
            kb.claim_task(conn, task_id)
        return SimpleNamespace(session_id='owner-session', profile_id=str(tmp_path))
    monkeypatch.setattr('gateway.session_local.create_local_session', create_local_session)
    async def submit(actor, submission):
        calls.append(('submit', submission))
    async def resume(ref, params):
        calls.append(('resume', ref))
    db = SimpleNamespace(get_session=lambda sid: None, db_path=str(tmp_path / 'state.db'))
    authority = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', epoch=1, db=db, submit=submit)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=authority, actor=actor, native_owner=True, resume=resume)
    params = dict(board='owned', task_id=task_id, run_id=old.current_run_id, claim_lock=old.claim_lock)
    from gateway.session_kanban import run_task
    with pytest.raises(RuntimeStoreError, match='stale_kanban_claim'):
        asyncio.run(run_task(connection, params))
    assert calls == []
    with closing(connect(board='owned')) as conn:
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0] == 0


def test_admission_binding_fences_stale_claim_and_preserves_no_secret(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_kanban import _bind_owner_admission
    from hermes_state_runtime import RuntimeStoreError

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        params = dict(task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
        _bind_owner_admission(conn, params, 's', request, 'admission')
        _bind_owner_admission(conn, params, 's', request, 'admission')
        rows = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchall()
        assert len(rows) == 1 and json.loads(rows[0][0]) == {'session_id': 's', 'request_id': request, 'admission_id': 'admission'}
        assert task.claim_lock not in rows[0][0]
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            _bind_owner_admission(conn, params | {'claim_lock': 'stale'}, 's', request, 'other')
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1
        with kb.write_txn(conn):
            kb._end_run(conn, task_id, outcome='crashed', status='ready')
            conn.execute("UPDATE tasks SET status='ready', claim_lock=NULL, claim_expires=NULL WHERE id=?", (task_id,))
        successor = kb.claim_task(conn, task_id)
        assert successor.current_run_id != task.current_run_id
        before = tuple(conn.execute('SELECT status,current_run_id,claim_lock FROM tasks WHERE id=?', (task_id,)).fetchone())
        # A fully matching old receipt can be read again, but cannot overwrite the new run.
        _bind_owner_admission(conn, params, 's', request, 'admission')
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            _bind_owner_admission(conn, params, 's', request, 'different-admission')
        assert tuple(conn.execute('SELECT status,current_run_id,claim_lock FROM tasks WHERE id=?', (task_id,)).fetchone()) == before
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1


@pytest.mark.asyncio
async def test_finish_readback_never_starts_missing_gateway(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='absent', endpoint=None))
    def forbidden(*args, **kwargs):
        raise AssertionError('missing owner must not be started or contacted')
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', forbidden)
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
            kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
        result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
        assert result == dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')


@pytest.mark.asyncio
async def test_finish_readback_uses_bound_owner_receipt_without_gateway(tmp_path, monkeypatch):
    import os
    import psutil
    from contextlib import asynccontextmanager, closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    from gateway.session_kanban import _bind_owner_admission
    from gateway.session_authority import LiveSession, SessionAuthority
    from gateway.session_controls import AuthorityConnection
    from hermes_state import SessionDB
    from hermes_state_runtime import (admit_session_input, begin_runtime_epoch, claim_session_input,
                                      mutate_worker_execution, register_worker_execution)

    reviewer_home = tmp_path / 'profiles' / 'reviewer'
    reviewer_home.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda profile: str(reviewer_home if profile == 'reviewer' else tmp_path))
    endpoint = SimpleNamespace(profile_id=str(reviewer_home), instance_id='owner', api_origin='http://127.0.0.1:12345')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='ready', endpoint=endpoint))
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn, SessionDB(reviewer_home / 'state.db') as db:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        conn.execute("UPDATE task_runs SET profile='reviewer' WHERE id=?", (task.current_run_id,))
        params = dict(task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        db.create_session('s', source='test')
        epoch = begin_runtime_epoch(db, instance_id='owner')
        authority = SessionAuthority(SimpleNamespace(_draining=False), profile_id=str(reviewer_home), instance_id='owner', db=db, epoch=epoch)
        authority.sessions['s'] = LiveSession(None, 'route')
        connection = AuthorityConnection(authority, object(), {'user_id': 'owner'})
        monkeypatch.setattr('hermes_state_local.local_receipt', lambda *_: {'policy': {}})
        monkeypatch.setattr('gateway.session_policy.restore_policy', lambda _: SimpleNamespace(source='kanban', kanban_json=json.dumps(dict(board='owned', task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock))))
        admitted = admit_session_input(db, epoch=epoch, principal_id=connection.actor.subject, session_id='s', request_id=request, payload={})
        claim = claim_session_input(db, epoch=epoch, session_id='s')
        scope = dict(epoch=epoch, execution_id='admission-worker:' + admitted['admission_id'], session_id='s', generation=claim['generation'])
        register_worker_execution(db, **scope, kind='compute', adoption_secret='private-proof')
        mutate_worker_execution(db, **scope, sequence=1, operation='execution.finish', payload={})
        marker = {'session_id': 's', 'request_id': request, 'db': str(reviewer_home / 'state.db'),
                  'pid': os.getpid(), 'birth': psutil.Process().create_time(),
                  'instance_id': 'owner', 'authority_epoch': epoch}
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', marker, run_id=task.current_run_id)
        _bind_owner_admission(conn, params, 's', request, admitted['admission_id'])
        foreign_connection = AuthorityConnection(authority, object(), {'user_id': 'foreign', 'capabilities': ['session:submit']})
        client_connection = connection
        class Client:
            async def rpc(self, method, **kwargs):
                response = await client_connection.dispatch({'id': 1, 'method': method, 'params': kwargs})
                return response['result']
        @asynccontextmanager
        async def fake_connect(*, endpoint):
            from hermes_constants import get_hermes_home
            assert get_hermes_home().resolve() == reviewer_home
            assert endpoint.api_origin == 'http://127.0.0.1:12345'
            yield Client()
        monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', fake_connect)
        try:
            result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
            assert result == dict(board_terminal='UNKNOWN', receipt='RECORDED', ack='UNKNOWN', physical_retirement='UNKNOWN')
            assert 'private-proof' not in str(result)
            # The original Owner identity must still be provable on the exact bound DB.
            for changes in ({'pid': 0}, {'birth': marker['birth'] + 1}, {'db': str(tmp_path / 'foreign.db')},
                            {'instance_id': ''}, {'authority_epoch': epoch + 1}, {'authority_epoch': True}):
                with kb.write_txn(conn):
                    conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'",
                                 (json.dumps(marker | changes), task_id))
                assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            with kb.write_txn(conn):
                conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'",
                             (json.dumps({k: v for k, v in marker.items() if k != 'instance_id'}), task_id))
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            with kb.write_txn(conn):
                conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'", (json.dumps(marker), task_id))
            endpoint.instance_id = 'replacement-owner'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.instance_id = 'owner'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'RECORDED'
            from hermes_constants import get_hermes_home
            assert get_hermes_home().resolve() == tmp_path
            endpoint.profile_id = str(tmp_path)
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.profile_id = str(reviewer_home)
            client_connection = foreign_connection
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            client_connection = connection
            endpoint.api_origin = 'https://example.com:443'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.api_origin = 'http://127.0.0.1:12345'
            from websockets.exceptions import WebSocketException
            @asynccontextmanager
            async def closed_connect(*, endpoint):
                raise WebSocketException('closed')
                yield  # pragma: no cover
            monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', closed_connect)
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
        finally:
            await foreign_connection.close()
            await connection.close()


@pytest.mark.parametrize('case', ['ordinary', 'bad_contract', 'bad_marker', 'valid_wave2'])
def test_non_wave2_fast_completion_does_not_bind_but_bad_stage3_fails_closed(tmp_path, monkeypatch, case):
    import asyncio
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    from gateway.session_kanban import run_task

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        kwargs = {} if case == 'ordinary' else {'created_by': 'ai-colleague-stage3'}
        if case in {'bad_marker', 'valid_wave2'}:
            kwargs['completion_contract'] = 'owner/repo'
        if case == 'valid_wave2':
            kwargs['body'] = json.dumps({'publication_protocol': 'wave2_v1'})
        task_id = kb.create_task(conn, title='Fast task', assignee='default', workspace_kind='dir',
                                 workspace_path=str(workspace), **kwargs)
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal']}}
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda: config)
    monkeypatch.setattr('gateway.session_local.create_local_session', lambda *a, **k: SimpleNamespace(
        session_id='owner-session', profile_id=str(tmp_path)))
    monkeypatch.setattr('gateway.session_kanban.asdict', lambda _: {'admission_id': 'admission'})
    def forbidden_bind(*args, **kwargs):
        raise AssertionError('ordinary task must not use Wave 2 binding')
    if case == 'ordinary':
        monkeypatch.setattr('gateway.session_kanban._bind_owner_admission', forbidden_bind)
    calls = []
    async def submit(actor, submission):
        calls.append('submit')
        # The Worker can finish before submit returns; this is a real Board transition.
        if case == 'ordinary':
            with closing(connect(board='owned')) as conn:
                assert kb.block_task(conn, task_id, reason='fast completion', expected_run_id=task.current_run_id)
        return SimpleNamespace(admission_id='admission')
    async def resume(ref, params):
        calls.append('resume')
    db = SimpleNamespace(get_session=lambda _: None, db_path=str(tmp_path / 'state.db'))
    authority = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', epoch=1, db=db, submit=submit)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=authority, actor=actor, native_owner=True, resume=resume)
    params = dict(board='owned', task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
    if case in {'bad_contract', 'bad_marker'}:
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            asyncio.run(run_task(connection, params))
        assert calls == []
        with closing(connect(board='owned')) as conn:
            assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0] == 0
    else:
        result = asyncio.run(run_task(connection, params))
        assert result['receipt']['admission_id'] == 'admission'
        assert calls == ['resume', 'submit']
        if case == 'valid_wave2':
            with closing(connect(board='owned')) as conn:
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1
                marker = json.loads(conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0])
                assert marker['instance_id'] == 'owner' and marker['authority_epoch'] == 1


@pytest.mark.asyncio
async def test_finish_readback_rejects_same_task_and_run_ids_on_foreign_board(tmp_path, monkeypatch):
    import os
    import psutil
    from contextlib import asynccontextmanager, closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    monkeypatch.setattr(kb, '_new_task_id', lambda: 't_deadbeef')
    (tmp_path / 'state.db').touch()
    endpoint = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', api_origin='http://127.0.0.1:12345')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='ready', endpoint=endpoint))
    calls = []
    class Client:
        async def rpc(self, method, **kwargs):
            calls.append((method, kwargs))
            return {'authority_epoch': 1, 'worker_finish': {'receipt': 'RECORDED', 'ack': 'UNKNOWN', 'physical_retirement': 'UNKNOWN'}}
    @asynccontextmanager
    async def fake_connect(*, endpoint):
        yield Client()
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', fake_connect)
    for board in ('owned', 'foreign'):
        kb.create_board(board)
        with closing(connect(board=board)) as conn:
            task_id = kb.create_task(conn, title='test', assignee='default')
            kb.recompute_ready(conn)
            task = kb.claim_task(conn, task_id)
            assert task_id == 't_deadbeef' and task.current_run_id == 1
            # A copied foreign marker refers to the other Board despite identical IDs.
            request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
            with kb.write_txn(conn):
                kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request, 'db': str(tmp_path / 'state.db'), 'pid': os.getpid(), 'birth': psutil.Process().create_time(), 'instance_id': 'owner', 'authority_epoch': 1}, run_id=task.current_run_id)
                kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
            result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
            assert result['receipt'] == ('RECORDED' if board == 'owned' else 'UNKNOWN')
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['early_return', 'exception'])
async def test_finish_readback_discards_stale_terminal_on_early_exit(tmp_path, monkeypatch, failure):
    import asyncio
    import threading
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    entered, proceed = threading.Event(), threading.Event()
    def delayed(*_):
        entered.set()
        assert proceed.wait(5)
        if failure == 'exception':
            raise ValueError('unavailable profile')
    monkeypatch.setattr('hermes_cli.kanban_owner_recovery._matching_profile_home', delayed)
    kb.create_board('owned')
    with closing(connect(board='owned')) as reader, closing(connect(board='owned')) as writer:
        task_id = kb.create_task(reader, title='test', assignee='default')
        kb.recompute_ready(reader)
        task = kb.claim_task(reader, task_id)
        with kb.write_txn(reader):
            reader.execute("UPDATE tasks SET status='done' WHERE id=?", (task_id,))
            reader.execute("UPDATE task_runs SET outcome='completed' WHERE id=?", (task.current_run_id,))
        pending = asyncio.create_task(read_owner_finish(reader, task_id, task.current_run_id, profile_home=tmp_path))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            with kb.write_txn(writer):
                writer.execute("UPDATE tasks SET status='doing' WHERE id=?", (task_id,))
        finally:
            proceed.set()
        assert await pending == dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')


@pytest.mark.asyncio
async def test_finish_readback_rejects_same_named_profile_from_foreign_root(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    authorized = tmp_path / 'authorized'
    foreign = tmp_path / 'foreign'
    for root in (authorized, foreign):
        reviewer = root / 'profiles' / 'reviewer'
        reviewer.mkdir(parents=True)
        (reviewer / '.env').touch()  # profile identity only; no credentials
    monkeypatch.setenv('HERMES_HOME', str(foreign))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(authorized))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    def forbidden(*_args, **_kwargs):
        raise AssertionError('must not discover a foreign Owner')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', forbidden)
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', forbidden)
    token = set_hermes_home_override(authorized)
    try:
        kb.create_board('owned')
        with closing(connect(board='owned')) as conn:
            task_id = kb.create_task(conn, title='test', assignee='default')
            kb.recompute_ready(conn)
            task = kb.claim_task(conn, task_id)
            conn.execute("UPDATE task_runs SET profile='reviewer' WHERE id=?", (task.current_run_id,))
            request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
            with kb.write_txn(conn):
                kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
                kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
            assert await read_owner_finish(conn, task_id, task.current_run_id, profile_home=authorized) == dict(
                board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
    finally:
        reset_hermes_home_override(token)
