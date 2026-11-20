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
def owner(tmp_path, request, monkeypatch):
    if hasattr(request, 'param'):
        monkeypatch.setattr('hermes_state_wal.resolve_journal_mode', lambda: request.param.lower())
    with closing(SessionDB(tmp_path / 'owner.db')) as db:
        db.create_session('owned', 'cli')
        db.create_session('other', 'cli')
        epoch = begin_runtime_epoch(db, instance_id='original-owner')
        mode = db._conn.execute('PRAGMA journal_mode').fetchone()[0]
        if hasattr(request, 'param'):
            assert mode == request.param.lower()
        authority = SimpleNamespace(db=db, epoch=epoch, _require_admission_open=lambda: None, journal_mode=mode)
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


def test_guest_turn_lease_uses_real_store_cleanup_without_host_pid_inference(owner, tmp_path, monkeypatch):
    _authority, _row, scope, endpoint = owner
    import hermes_state

    def forbidden_host_pid_probe(_holder):
        raise AssertionError('Guest lease must not be interpreted as a Host process')

    monkeypatch.setattr(hermes_state, '_compression_lock_holder_process_is_dead', forbidden_host_pid_probe)
    store = guest_session_store(endpoint, scope, tmp_path / 'lease-outbox')
    try:
        assert store.try_acquire_session_turn_lease('owned', 'opaque-guest-holder')
        assert not store.try_acquire_session_turn_lease('owned', 'other-guest-holder')
        store.release_session_turn_lease('owned', 'opaque-guest-holder')
        assert store.try_acquire_session_turn_lease('owned', 'other-guest-holder')
        store.release_session_turn_lease('owned', 'other-guest-holder')
    finally:
        store.close()


def test_original_worker_context_prompt_history_and_constructor_stay_owner_scoped(owner, tmp_path):
    import json
    authority, _row, scope, endpoint = owner
    private = {'api_key': 'HOST_CONTEXT_CANARY', 'base_url': 'https://private.invalid',
               'max_tokens': 2048, 'codex_thread_id': 'guest-thread-before'}

    def seed(conn):
        conn.execute("UPDATE sessions SET cwd='/host/private/task',git_repo_root='/host/private/repo',"
                     "model_config=? WHERE id='owned'", (json.dumps(private),))

    authority.db._execute_write(seed)
    store = guest_session_store(endpoint, scope, tmp_path / 'context-outbox')
    try:
        context = store.get_session('owned')
        assert context['cwd'] == '/task' and context['git_repo_root'] == '/task'
        assert 'HOST_CONTEXT_CANARY' not in json.dumps(context)
        assert 'https://private.invalid' not in json.dumps(context)
        assert json.loads(context['model_config'])['max_tokens'] == 2048
        store.create_session('owned', 'cli', cwd='/task', git_repo_root='/task')
        store.update_system_prompt('owned', 'Original task prompt')
        store.update_session_tool_names('owned', [])
        store.patch_session_model_config('owned', {'codex_thread_id': 'guest-thread-after'})
        store.set_session_title('owned', 'Scoped engineering task')
        assert store.append_messages_batch('owned', [{'role': 'assistant', 'content': 'Original worklog'}]) == 1
        assert store.get_messages_as_conversation('owned')[0]['content'] == 'Original worklog'
        assert store.get_session('owned')['title'] == 'Scoped engineering task'
        assert store.get_session_model_config_value('owned', 'codex_thread_id') == 'guest-thread-after'
        with pytest.raises(WorkerPersistenceError, match='permission_denied'):
            store.get_session('other')
    finally:
        store.close()
    canonical = authority.db._read_one("SELECT cwd,git_repo_root,model_config FROM sessions WHERE id='owned'")
    assert canonical['cwd'] == '/host/private/task' and canonical['git_repo_root'] == '/host/private/repo'
    assert json.loads(canonical['model_config'])['api_key'] == 'HOST_CONTEXT_CANARY'
    assert authority.db.get_messages('other') == []


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


@pytest.fixture
def board_work(tmp_path, monkeypatch):
    import subprocess
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing
    home = tmp_path / 'board-home'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_KANBAN_BOARD', raising=False)
    repo = tmp_path / 'source'
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-q', '--allow-empty', '-m', 'base'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin', 'https://github.com/fixture/project.git'],
                   check=True, capture_output=True)
    base = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    root = tmp_path / 'central'
    contract = {'version': 1, 'repo': 'fixture/project', 'source_root': str(repo),
                'common_dir': str(repo / '.git'), 'remote_url': 'https://github.com/fixture/project.git',
                'base_commit': base, 'branch_name': 'task/fixture', 'workspace_root': str(root),
                'workspace_path': str(root / 'worktrees' / 'task-fixture')}
    kb.init_db()
    with connect_closing() as conn:
        task_id = kb.create_task(conn, title='Reject boolean cleanup identities', body='Run offline checks.',
            project_id='', assignee='fixture', workspace_kind='worktree',
            workspace_path=contract['workspace_path'], branch_name=contract['branch_name'],
            workspace_admission=contract, completion_contract='fixture/project')
        task = kb.claim_task(conn, task_id, ttl_seconds=600)
    context = {'db': str(kb.kanban_db_path()), 'task_id': task_id,
               'run_id': task.current_run_id, 'claim_lock': task.claim_lock}
    return context, contract


def test_work_input_reads_canonical_task_and_never_serializes_host_policy(owner, board_work):
    import json
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing
    authority, _row, _scope, _endpoint = owner
    context, contract = board_work
    authority.db._execute_write(lambda conn: conn.execute("UPDATE sessions SET source='kanban' WHERE id='other'"))
    admit_session_input(authority.db, epoch=authority.epoch, principal_id='human', session_id='other',
                        request_id='board-work', payload={'text': 'work task'})
    row = claim_session_input(authority.db, epoch=authority.epoch, session_id='other')
    binding = GuestBinding(context['task_id'], context['run_id'], 'board-vm', 1, 'a' * 64, 'b' * 64)
    scope = reserve_guest_admission(authority, admission_id=row['admission_id'], principal_id='human', binding=binding)
    endpoint = GuestOwnerEndpoint(authority, scope, principal_id='human')
    policy = SimpleNamespace(source='kanban', kanban_json=json.dumps(context), model='approved-guest-model',
                             api_key='HOST_CANARY_DO_NOT_SEND', config_secret_ref='HOST_SECRET_REF')
    with pytest.raises(RuntimeStoreError, match='guest_session_not_admitted'):
        endpoint.prepare_work(policy)
    with connect_closing() as conn:
        kb._append_event(conn, context['task_id'], 'owner_admitted', {'session_id': 'other'},
                         run_id=context['run_id'])
        before = [tuple(r) for r in conn.execute('SELECT * FROM task_events')]
    work = endpoint.prepare_work(policy)
    encoded = json.dumps(work)
    assert work['title'] == 'Reject boolean cleanup identities'
    assert work['repo'] == 'fixture/project' and work['base_commit'] == contract['base_commit']
    assert work['workspace'] == '/task' and work['role'] == 'developer'
    assert work['assignment'] == scope
    assert all(value not in encoded for value in (context['db'], context['claim_lock'],
               contract['source_root'], contract['common_dir'], 'HOST_CANARY_DO_NOT_SEND', 'HOST_SECRET_REF'))
    with connect_closing() as conn:
        assert [tuple(r) for r in conn.execute('SELECT * FROM task_events')] == before
        conn.execute('UPDATE tasks SET claim_expires=1 WHERE id=?', (context['task_id'],))
        conn.commit()
    with pytest.raises(RuntimeStoreError, match='stale_kanban_claim'):
        endpoint.prepare_work(policy)


def test_guest_runtime_policy_preserves_owner_identity_without_host_config(owner):
    import json
    from agent.runtime_session_guest import guest_worker_frame
    from gateway.session_policy import restore_policy
    _authority, _row, scope, _endpoint = owner
    work = {'version': 'HERMES_GUEST_WORK_V1', 'assignment': scope, 'title': 'Small code fix',
            'body': 'Test and report honestly.', 'repo': 'fixture/project', 'base_commit': 'a' * 40,
            'branch': 'task/small-fix', 'workspace': '/task', 'role': 'developer',
            'model': 'approved-codex', 'completion_contract': 'test and independent review'}
    frame = guest_worker_frame(work, inference_base_url='http://127.0.0.1:9876/v1')
    policy = restore_policy(frame['policy'])
    assert frame['scope'] == scope and 'home' not in frame
    assert policy.source == 'kanban' and policy.cwd == '/task'
    assert policy.kanban_json is None and policy.config_secret_ref is None and policy.credential_ref is None
    assert policy.safe_mode and policy.ignore_user_config and not policy.follows_profile
    assert policy.toolsets == ('terminal', 'file')
    assert json.loads(policy.terminal_json) == {'TERMINAL_CWD': '/task', 'TERMINAL_ENV': 'local'}
    assert policy.config()['model']['openai_runtime'] == 'codex_app_server'
    assert frame['api_key'] == 'guest-transport'  # public placeholder, never a Host credential
    assert not ({'pid', 'secret', 'profile_id'} & frame['scope'].keys())
    for route in ('https://host.invalid/v1', 'http://localhost:9876/v1', 'http://127.0.0.1/v1',
                  'http://secret@127.0.0.1:9876/v1', 'http://127.0.0.1:9876/v1?x=1',
                  'http://127.0.0.1:bad/v1'):
        with pytest.raises(WorkerPersistenceError, match='invalid_guest_inference_route'):
            guest_worker_frame(work, inference_base_url=route)


def test_guest_store_with_worker_posture_never_binds_guest_pid_as_host(owner, tmp_path, monkeypatch):
    from agent import runtime_session_store
    from tools import async_delegation_worker
    _authority, _row, scope, endpoint = owner
    monkeypatch.setattr(runtime_session_store, '_worker_process', True)
    monkeypatch.setattr(async_delegation_worker, '_store', None)
    store = guest_session_store(endpoint, scope, tmp_path / 'guest-posture')
    try:
        assert store.append_messages_batch('owned', [{'role': 'assistant', 'content': 'no Host PID'}]) == 1
        with pytest.raises(WorkerPersistenceError, match='worker_delegation_ledger_unbound'):
            async_delegation_worker.worker_ledger()
        with pytest.raises(WorkerPersistenceError, match='worker_delegation_owner_only'):
            async_delegation_worker.require_ledger_owner()
    finally:
        store.close()


def test_managed_controls_use_dedicated_stream_without_consuming_persistence(monkeypatch):
    import io
    from agent.managed_worker import WorkerControls, encode_frame
    class Channel:
        def send(self, *args, **kwargs):
            raise AssertionError('no prompts on stop/finish')
    controls = WorkerControls(Channel(), 'guest:execution',
                              io.BytesIO(encode_frame({'type': 'stop'}) + encode_frame({'type': 'finish'})))
    controls.reader.join(timeout=5)
    assert not controls.reader.is_alive() and controls.stopped.is_set() and controls.finish.is_set()


def test_guest_consumes_original_managed_runtime_with_real_owner_store(owner, tmp_path, monkeypatch):
    """Offline wiring contract; the Agent double is never an execution receipt."""
    import io
    from contextlib import contextmanager
    from agent import managed_worker, runtime_session_store
    from agent.runtime_session_guest import execute_guest
    authority, _row, scope, endpoint = owner
    authority.db._execute_write(lambda conn: conn.execute("UPDATE sessions SET source='kanban' WHERE id='owned'"))
    work = {'version': 'HERMES_GUEST_WORK_V1', 'assignment': scope, 'title': 'Small code fix',
            'body': 'Test and report honestly.', 'repo': 'fixture/project', 'base_commit': 'a' * 40,
            'branch': 'task/small-fix', 'workspace': '/task', 'role': 'developer',
            'model': 'approved-codex', 'completion_contract': 'test and independent review'}
    events, constructed = [], {}

    def forbidden(*args, **kwargs):
        raise AssertionError('Guest must not discover Host authority or restore Host processes')

    @contextmanager
    def guest_scope(policy):
        assert policy.cwd == '/task' and policy.kanban_json is None
        yield

    class Agent:
        def __init__(self, **kwargs):
            constructed.update(kwargs)
            assert runtime_session_store.is_worker_process()
            self.store, self.sid = kwargs['session_db'], kwargs['session_id']
            self.session_prompt_tokens = self.session_completion_tokens = 0
            self.store.create_session(self.sid, kwargs['platform'], cwd='/task',
                                      user_id=kwargs['user_id'], chat_id=kwargs['chat_id'],
                                      session_key=kwargs['gateway_session_key'], profile_name='default')
        def run_conversation(self, text, *, conversation_history, **kwargs):
            assert 'Small code fix' in text and conversation_history == []
            self.store.append_messages_batch(self.sid, [{'role': 'assistant', 'content': 'offline wiring check'}])
            return {'final_response': 'offline wiring only', 'completed': True}
        def shutdown_memory_provider(self, messages):
            events.append('memory.closed')
        def release_clients(self):
            events.append('clients.closed')

    monkeypatch.setattr(runtime_session_store, '_worker_process', False)
    monkeypatch.setattr(managed_worker, 'bind_worker_policy', lambda frame: None)
    monkeypatch.setattr(managed_worker, 'discover_profile_mcp', lambda policy: None)
    monkeypatch.setattr(managed_worker, '_agent_runtime_route', lambda frame, policy: {
        'provider': 'custom', 'requested_provider': 'custom', 'api_mode': 'codex_app_server'})
    monkeypatch.setattr('gateway.session_policy.policy_scope', guest_scope)
    monkeypatch.setattr('agent.runtime_session_store.WorkerRPC', forbidden)
    monkeypatch.setattr('gateway.session_kanban.bind_worker_context', forbidden)
    monkeypatch.setattr('tools.process_registry.process_registry.recover_from_checkpoint', forbidden)
    monkeypatch.setattr('run_agent.AIAgent', Agent)
    monkeypatch.setattr('agent.title_generator.wait_for_title_upgrades', lambda: None)
    channel = SimpleNamespace(send=lambda kind, **payload: events.append({'type': kind, **payload}))
    execute_guest(work, channel, persistence_exchange=endpoint,
                  control_stream=io.BytesIO(managed_worker.encode_frame({'type': 'finish'})),
                  inference_base_url='http://127.0.0.1:9876/v1', outbox_dir=tmp_path / 'managed-outbox')
    assert constructed['session_id'] == 'owned' and constructed['platform'] == 'kanban'
    assert constructed['api_mode'] == 'codex_app_server' and constructed['disabled_toolsets'] == ['delegation']
    assert constructed['base_url'] == 'http://127.0.0.1:9876/v1'
    ready = next(event for event in events if isinstance(event, dict) and event['type'] == 'ready')
    assert ready == {'type': 'ready', 'assignment': scope} and 'pid' not in ready
    assert events.index('clients.closed') < next(i for i, event in enumerate(events)
        if isinstance(event, dict) and event['type'] == 'result')
    assert events[-1] == {'type': 'finished'}
    assert authority.db.get_messages('owned')[0]['content'] == 'offline wiring check'
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'started'


def test_guest_runtime_route_uses_real_frozen_resolver_without_network(owner, tmp_path):
    import json
    import os
    import subprocess
    import sys
    _authority, _row, scope, _endpoint = owner
    work = {'version': 'HERMES_GUEST_WORK_V1', 'assignment': scope, 'title': 'Small code fix',
            'body': '', 'repo': 'fixture/project', 'base_commit': 'a' * 40,
            'branch': 'task/small-fix', 'workspace': '/task', 'role': 'developer',
            'model': 'approved-codex', 'completion_contract': ''}
    script = """
import json, socket, sys
from agent.runtime_session_guest import guest_worker_frame
from agent.managed_worker import bind_worker_policy, _agent_runtime_route
work = json.load(sys.stdin)
frame = guest_worker_frame(work, inference_base_url='http://127.0.0.1:9876/v1')
bind_worker_policy(frame)
def no_network(*args, **kwargs):
    raise AssertionError('offline resolver must never contact a model')
socket.socket.connect = no_network
from gateway.session_policy import restore_policy
route = _agent_runtime_route(frame, restore_policy(frame['policy']))
print(json.dumps(route))
"""
    result = subprocess.run([sys.executable, '-c', script], input=json.dumps(work), text=True,
                            capture_output=True, timeout=30, env=dict(os.environ), check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {
        'provider': 'custom', 'requested_provider': 'custom:guest-inference', 'api_mode': 'codex_app_server'}


def test_guest_in_place_compression_uses_original_transactions_and_opaque_holders(owner, tmp_path, monkeypatch):
    import time
    _authority, _row, scope, endpoint = owner
    def forbidden(_holder):
        raise AssertionError('Guest compression must never inspect a Host PID')
    monkeypatch.setattr('hermes_state._compression_lock_holder_process_is_dead', forbidden)
    store = guest_session_store(endpoint, scope, tmp_path / 'compression-outbox')
    try:
        assert store.try_acquire_compression_lock('owned', 'guest-holder:first')
        assert not store.try_acquire_compression_lock('owned', 'guest-holder:second')
        assert store.refresh_compression_lock('owned', 'guest-holder:first')
        assert store.get_compression_lock_holder('owned') == 'guest-holder:first'
        rows = [{'role': 'user', 'content': 'before compaction'}, {'role': 'assistant', 'content': 'worklog'}]
        assert store.append_messages_batch('owned', rows, compression_lock_holder='guest-holder:first') == 2
        watermark = store.get_active_message_watermark('owned')
        assert watermark > 0
        compacted = [{'role': 'user', 'content': 'bounded summary'}]
        store.archive_and_compact('owned', compacted, watermark=watermark, lock_holder='guest-holder:first')
        assert store.get_messages_as_conversation('owned')[-1]['content'] == 'bounded summary'
        store.record_compression_failure_cooldown('owned', time.time() + 60, 'offline compression unavailable')
        assert store.get_compression_failure_cooldown('owned') is not None
        store.clear_compression_failure_cooldown('owned')
        store.set_compression_fallback_streak('owned', 1)
        store.set_compression_ineffective_count('owned', 2)
        assert store.get_compression_fallback_streak('owned') == 1
        assert store.get_compression_ineffective_count('owned') == 2
        store.release_compression_lock('owned', 'guest-holder:first')
        assert store.try_acquire_compression_lock('owned', 'guest-holder:second')
        store.release_compression_lock('owned', 'guest-holder:second')
    finally:
        store.close()


def test_real_agent_session_constructor_maps_only_pinned_guest_identity(owner, tmp_path, monkeypatch):
    import json
    from run_agent import AIAgent
    authority, _row, scope, endpoint = owner
    canonical = {'source': 'kanban', 'cwd': '/host/task', 'user_id': 'host-user', 'chat_id': 'host-chat',
                 'session_key': 'host-route', 'profile_name': 'host-profile',
                 'origin_json': json.dumps({'platform': 'kanban', 'profile': 'host-profile'})}
    def seed(conn):
        for key, value in canonical.items():
            conn.execute(f'UPDATE sessions SET {key}=? WHERE id=?', (value, 'owned'))
    authority.db._execute_write(seed)
    store = guest_session_store(endpoint, scope, tmp_path / 'real-constructor')
    monkeypatch.setattr('hermes_cli.profiles.get_active_profile_name', lambda: 'default')
    agent = SimpleNamespace(_persist_disabled=False, _session_db_created=False, _session_db=store,
        session_id='owned', platform='kanban', model='approved-codex',
        _session_row_model_config=lambda: {'max_iterations': 32}, _cached_system_prompt='Guest prompt',
        _user_id='', _chat_id='', _gateway_session_key='guest:' + scope['execution_id'],
        _parent_session_id=None)
    try:
        AIAgent._ensure_db_session(agent)
        assert agent._session_db_created, 'real constructor must not silently defer a rejected Guest identity'
        after = authority.db.get_session('owned')
        assert {key: after[key] for key in canonical} == canonical
        for attack in ({'user_id': 'foreign'}, {'profile_name': 'foreign'},
                       {'session_key': 'guest:foreign'}, {'origin_json': '{broken'},
                       {'origin_json': json.dumps({'platform': 'kanban', 'user_id': 'foreign'})}):
            sequence = authority.db._read_one('SELECT last_sequence FROM worker_executions')[0] + 1
            with pytest.raises(RuntimeStoreError, match='permission_denied'):
                endpoint({'method': 'worker.persist', 'scope': scope, 'params': {
                    'sequence': sequence, 'operation': 'session.create',
                    'payload': {'source': 'kanban', **attack}}})
            # Rejected receipts have not committed or changed the canonical row.
            assert authority.db._read_one('SELECT last_sequence FROM worker_executions')[0] == sequence - 1
            assert {key: authority.db.get_session('owned')[key] for key in canonical} == canonical
    finally:
        store.close()


@pytest.mark.parametrize('owner', ['WAL', 'DELETE'], indirect=True)
def test_guest_reservation_commits_recoverable_identity_atomically(owner):
    import json
    import sqlite3
    authority, row, scope, _endpoint = owner
    key = 'guest.assignment.v1:' + scope['execution_id']
    # A separate connection observes committed identity, not an in-memory Endpoint.
    with closing(sqlite3.connect(authority.db.db_path)) as observer:
        assert observer.execute('PRAGMA journal_mode').fetchone()[0] == authority.journal_mode
        stored = observer.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()
        assert stored is not None, 'Owner restart must retain exact Task/Run/VM assignment before launch'
        record = json.loads(stored[0])
        assert record == {'version': 'HERMES_GUEST_ASSIGNMENT_V1', 'scope': scope,
                          'principal_id': 'human', 'owner_instance': 'original-owner'}
        assert observer.execute('SELECT status FROM worker_executions WHERE execution_id=?',
                                (scope['execution_id'],)).fetchone()[0] == 'registered'
    assert scope['execution_id'] == 'admission-worker:' + row['admission_id']
    assert not ({'secret', 'api_key', 'pid', 'birth', 'profile_id'} & set(record))


def test_guest_reservation_rolls_back_if_identity_cannot_be_saved(owner):
    import sqlite3
    authority, _row, _scope, _endpoint = owner
    admit_session_input(authority.db, epoch=authority.epoch, principal_id='human', session_id='other',
                        request_id='other-reservation', payload={'text': 'same Owner, other task'})
    row = claim_session_input(authority.db, epoch=authority.epoch, session_id='other')
    authority.db._execute_write(lambda conn: conn.execute(
        "CREATE TRIGGER reject_guest_identity BEFORE INSERT ON state_meta "
        "WHEN NEW.key LIKE 'guest.assignment.v1:%' BEGIN SELECT RAISE(ABORT,'identity disk failure'); END"))
    with pytest.raises(sqlite3.IntegrityError, match='identity disk failure'):
        reserve_guest_admission(authority, admission_id=row['admission_id'], principal_id='human',
            binding=GuestBinding('other-task', 8, 'other-vm', 1, 'a' * 64, 'b' * 64))
    execution = 'admission-worker:' + row['admission_id']
    assert authority.db._read_one('SELECT * FROM worker_executions WHERE execution_id=?', (execution,)) is None
    assert authority.db.get_meta('guest.assignment.v1:' + execution) is None
    assert authority.db._read_one('SELECT status FROM session_admissions WHERE admission_id=?',
                                  (row['admission_id'],))[0] == 'started'


@pytest.mark.parametrize('damage', ['missing', 'malformed', 'foreign-instance', 'foreign-vm'])
def test_damaged_guest_identity_refuses_adoption_without_erasing_unknown(owner, damage):
    import json
    authority, _row, scope, endpoint = owner
    key = 'guest.assignment.v1:' + scope['execution_id']
    original = authority.db.get_meta(key)
    assert original is not None, 'durable identity must be present before testing corruption'
    if damage == 'missing':
        authority.db._execute_write(lambda conn: conn.execute('DELETE FROM state_meta WHERE key=?', (key,)))
    elif damage == 'malformed':
        authority.db.set_meta(key, '{broken')
    else:
        record = json.loads(original)
        if damage == 'foreign-instance':
            record['owner_instance'] = 'foreign-owner'
        else:
            record['scope']['vm_id'] = 'foreign-vm'
        authority.db.set_meta(key, json.dumps(record))
    damaged = authority.db.get_meta(key)
    with pytest.raises(RuntimeStoreError, match='guest_assignment_unavailable'):
        endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    assert authority.db.get_meta(key) == damaged
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'registered'
    assert authority.db._read_one('SELECT count(*) FROM worker_receipts')[0] == 0
    endpoint.revoke()
    endpoint.revoke()
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db.get_meta(key) == damaged
    epoch = begin_runtime_epoch(authority.db, instance_id='restart-owner')
    recover_session_inputs(authority.db, epoch=epoch)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db.get_meta(key) == damaged
    with pytest.raises(RuntimeStoreError, match='guest_physical_retirement_required'):
        resolve_unknown_session_input(authority.db, epoch=epoch, admission_id=_row['admission_id'],
                                      generation=scope['generation'])


def test_new_owner_connection_retains_old_vm_identity_without_resume_or_retirement(owner):
    import json
    authority, row, scope, endpoint = owner
    key = 'guest.assignment.v1:' + scope['execution_id']
    before = authority.db.get_meta(key)
    endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    with closing(SessionDB(authority.db.db_path)) as restarted:
        epoch = begin_runtime_epoch(restarted, instance_id='replacement-owner')
        assert recover_session_inputs(restarted, epoch=epoch) == 1
        after = restarted.get_meta(key)
        assert after == before
        record = json.loads(after)
        assert record['scope'] == scope and record['owner_instance'] == 'original-owner'
        assert restarted._read_one('SELECT instance_id FROM runtime_epoch')[0] == 'replacement-owner'
        new_authority = SimpleNamespace(db=restarted, epoch=epoch, _require_admission_open=lambda: None)
        for owner_authority in (authority, new_authority):
            old_endpoint = GuestOwnerEndpoint(owner_authority, record['scope'], principal_id=record['principal_id'])
            with pytest.raises(RuntimeStoreError, match='stale_epoch'):
                old_endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
        with pytest.raises(RuntimeStoreError, match='guest_physical_retirement_required'):
            resolve_unknown_session_input(restarted, epoch=epoch, admission_id=row['admission_id'],
                                          generation=scope['generation'])
        assert restarted._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        assert restarted.get_meta(key) == before


@pytest.mark.parametrize('phase', ['before_request', 'after_receipt_commit'])
def test_real_guest_channel_loss_records_unknown_without_losing_assignment(owner, phase):
    import socket
    from agent.managed_worker import encode_frame
    from gateway.session_worker_guest import serve_guest_request
    authority, _row, scope, endpoint = owner
    key = 'guest.assignment.v1:' + scope['execution_id']
    before = authority.db.get_meta(key)
    host, guest = socket.socketpair()
    with host:
        host.settimeout(5)
        if phase == 'after_receipt_commit':
            endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
            guest.sendall(encode_frame({'version': 1, 'id': 1, 'request': {
                'method': 'worker.persist', 'scope': scope, 'params': {'sequence': 1,
                    'operation': 'transcript.append',
                    'payload': {'messages': [{'role': 'assistant', 'content': 'committed before channel loss'}]}}}}))
        guest.close()  # only this owned socket; no listener, Gateway or Worker
        with host.makefile('rwb', buffering=0) as stream:
            with pytest.raises((EOFError, OSError)):
                serve_guest_request(stream, endpoint)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
    assert authority.db.get_meta(key) == before
    assert len(authority.db.get_messages('owned')) == (1 if phase == 'after_receipt_commit' else 0)
    with pytest.raises(RuntimeStoreError, match='guest_channel_revoked'):
        endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})


def test_constrained_raw_sockets_deliver_complete_large_request_and_response(owner, tmp_path):
    import socket
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import ExitStack
    from agent.runtime_session_guest import GuestByteChannel
    from gateway.session_worker_guest import serve_guest_request
    authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    writes = {'host': [], 'guest': []}
    with ExitStack() as stack:
        stack.enter_context(host)
        stack.enter_context(guest)
        def duplex(sock, label):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            sock.settimeout(3)
            reader = stack.enter_context(sock.makefile('rb'))
            writer = stack.enter_context(sock.makefile('wb', buffering=0))
            def write(data):
                count = writer.write(data)
                writes[label].append((len(data), count))
                return count
            return SimpleNamespace(readline=reader.readline, write=write, flush=writer.flush)
        owner_stream, guest_stream = duplex(host, 'host'), duplex(guest, 'guest')
        def serve():
            for _ in range(3):
                serve_guest_request(owner_stream, endpoint)
        with ThreadPoolExecutor(max_workers=1) as pool:
            served = pool.submit(serve)
            store = guest_session_store(GuestByteChannel(guest_stream), scope, tmp_path / 'large-wire')
            try:
                text = ('large engineering worklog ' * 20000).strip()
                assert store.append_messages_batch('owned', [{'role': 'assistant', 'content': text}]) == 1
                assert store.get_messages_as_conversation('owned')[0]['content'] == text
                served.result(timeout=10)
            finally:
                store.close()
    assert all(any(count < size for size, count in writes[side]) for side in writes)
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'


def test_partial_owner_reply_timeout_preserves_committed_receipt_and_marks_unknown(owner):
    import socket
    from agent.managed_worker import encode_frame
    from gateway.session_worker_guest import serve_guest_request
    authority, _row, scope, endpoint = owner
    endpoint({'method': 'worker.adopt', 'scope': scope, 'params': {}})
    seed = 'large engineering worklog ' * 20000
    endpoint({'method': 'worker.persist', 'scope': scope, 'params': {'sequence': 1,
        'operation': 'transcript.append', 'payload': {'messages': [{'role': 'assistant', 'content': seed}]}}})
    request = {'version': 1, 'id': 1, 'request': {'method': 'worker.persist', 'scope': scope, 'params': {
        'sequence': 2, 'operation': 'compression.history', 'payload': {'target': 'owned',
            'include_ancestors': False, 'include_inactive': False, 'repair_alternation': True,
            'include_row_ids': True, 'include_compacted': False}}}}
    host, guest = socket.socketpair()
    with host, guest:
        host.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        host.settimeout(.2)
        guest.sendall(encode_frame(request))
        with host.makefile('rwb', buffering=0) as stream:
            with pytest.raises(OSError):
                serve_guest_request(stream, endpoint)  # peer deliberately does not read
    assert authority.db._read_one('SELECT last_sequence FROM worker_executions')[0] == 2
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority.db.get_messages('owned')[0]['content'] == seed
    assert endpoint.revoked


def test_partial_guest_request_timeout_is_sticky_before_reading_response():
    import socket
    from agent.runtime_session_guest import GuestByteChannel
    host, guest = socket.socketpair()
    reads = []
    with host, guest:
        guest.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        guest.settimeout(.2)
        with guest.makefile('rwb', buffering=0) as raw:
            def read(size):
                reads.append(size)
                return raw.readline(size)
            channel = GuestByteChannel(SimpleNamespace(write=raw.write, flush=raw.flush, readline=read))
            with pytest.raises(OSError):
                channel({'worklog': 'x' * 500000})  # Owner deliberately does not read
            assert reads == [], 'a truncated request must never enter the reply wait'
            with pytest.raises(WorkerPersistenceError, match='guest_transport_lost'):
                channel({'retry': 'must not reconnect'})
