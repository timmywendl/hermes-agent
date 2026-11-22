"""Offline Q2 serial/Owner contracts; never starts a VM, Worker or model."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import json
import socket
import struct
import threading

import httpx
import pytest

from agent.guest_serial import GuestSerialClient, MAX_FRAME, SerialError, SerialWire
from agent.runtime_session_guest import guest_session_store
from agent.runtime_session_store import WorkerPersistenceError
from gateway.session_guest_serial import OwnerSerialSession, interrupt_guest

from tests.gateway import test_session_worker_guest as guest_fixtures


@pytest.fixture(name='owner')
def guest_owner_fixture(tmp_path, monkeypatch):
    from contextlib import closing
    from pathlib import Path
    from types import SimpleNamespace
    from gateway.session_authority import SessionAuthority
    from gateway.session_authorities import SessionAuthorities
    from gateway.session_worker_guest import GuestBinding, GuestOwnerEndpoint, reserve_guest_admission
    from hermes_state import SessionDB
    from hermes_state_runtime import admit_session_input, begin_runtime_epoch, claim_session_input
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing
    context, _contract = guest_fixtures.board_work.__wrapped__(tmp_path, monkeypatch)
    home = tmp_path / 'board-home'
    with closing(SessionDB(home / 'state.db')) as db:
        epoch = begin_runtime_epoch(db, instance_id='q2-offline-original-owner')
        runner = SimpleNamespace(_draining=False, session_authorities=SessionAuthorities(home))
        authority = SessionAuthority(runner, profile_id=str(home), instance_id='q2-offline-original-owner', db=db, epoch=epoch)
        runner.session_authorities.add(home, authority)
        db.create_session('owned', 'kanban')
        admit_session_input(db, epoch=epoch, principal_id='human', session_id='owned', request_id='work', payload={'text': 'offline'})
        row = claim_session_input(db, epoch=epoch, session_id='owned')
        scope = reserve_guest_admission(authority, admission_id=row['admission_id'], principal_id='human',
            binding=GuestBinding(context['task_id'], context['run_id'], 'offline-vm', 1, 'a' * 64, 'b' * 64))
        endpoint = GuestOwnerEndpoint(authority, scope, principal_id='human')
        with connect_closing(Path(context['db'])) as board:
            kb._append_event(board, context['task_id'], 'owner_admitted', {'session_id': 'owned'}, run_id=context['run_id'])
        policy = SimpleNamespace(source='kanban', kanban_json=json.dumps(context), model='owner-fixed')
        endpoint.test_work = endpoint.prepare_work(policy)
        yield authority, row, scope, endpoint


@contextmanager
def serial(owner, *, client_options=None, **kwargs):
    _authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    host.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    guest.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work, **kwargs)
    client = GuestSerialClient(SerialWire(guest.fileno(), scope, **(client_options or {})))
    try:
        yield server, client
    finally:
        client.close()
        server.wire.close()
        server.wire.release_fd()
        host.close()
        guest.close()


def test_serial_real_sqlite_original_owner_and_large_short_writes(owner, tmp_path):
    authority, _row, scope, _endpoint = owner
    with ThreadPoolExecutor(1) as pool, serial(owner) as (server, client):
        def serve():
            for _ in range(5):
                server.serve_one()
        future = pool.submit(serve)
        assert client.call('context', {'operation': 'assignment'})['assignment'] == scope
        store = guest_session_store(client, scope, tmp_path / 'outbox')
        try:
            text = ('engineering worklog ' * 20000).strip()
            assert store.append_messages_batch('owned', [{'role': 'assistant', 'content': text}]) == 1
            assert store.get_messages_as_conversation('owned')[0]['content'] == text
            assert store.finish() == {'status': 'pending_retirement'}
        finally:
            store.close()
        future.result(timeout=10)
    assert authority.db.get_messages('owned')[0]['content'] == text
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'
    assert authority._q2_guest_channels['owned'] is server


@pytest.mark.parametrize('damage', ['identity', 'sequence', 'oversize', 'duplicate'])
def test_invalid_wire_revokes_original_owner_without_losing_assignment(owner, damage):
    authority, _row, scope, endpoint = owner
    original = authority.db.get_meta('guest.assignment.v1:' + scope['execution_id'])
    host, guest = socket.socketpair()
    wire = SerialWire(guest.fileno(), scope)
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    try:
        if damage == 'identity':
            wire.scope['vm_id'] = 'foreign'
            wire.send('context', 'request', {'operation': 'assignment'})
        elif damage == 'sequence':
            wire.sent = 1
            wire.send('context', 'request', {'operation': 'assignment'})
        elif damage == 'oversize':
            guest.sendall(struct.pack('!I', MAX_FRAME + 1))
        else:
            frame = {'version': 2, 'scope': scope, 'seq': 1, 'channel': 'context',
                     'kind': 'request', 'reply_to': 0, 'payload': {'operation': 'assignment'}}
            raw = json.dumps(frame, separators=(',', ':')).encode().replace(b'"seq":1', b'"seq":2,"seq":1')
            guest.sendall(struct.pack('!I', len(raw)) + raw)
        guest.shutdown(socket.SHUT_WR)
        with pytest.raises(SerialError):
            server.serve_one()
        assert endpoint.revoked
        assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        assert authority.db.get_meta('guest.assignment.v1:' + scope['execution_id']) == original
    finally:
        wire.release_fd()
        server.wire.release_fd()
        host.close()
        guest.close()


def test_serial_cockpit_default_denied_and_no_route_fields(owner):
    with ThreadPoolExecutor(1) as pool, serial(owner) as (server, client):
        serving = pool.submit(server.serve_one)
        with pytest.raises(WorkerPersistenceError, match='d2_not_accepted'):
            client.call('inference', {'input': 'offline input'})
        serving.result(timeout=5)


@pytest.mark.parametrize('extra', [{'url': 'https://foreign.invalid'}, {'model': 'foreign'},
                                  {'headers': {'Authorization': 'secret'}},
                                  {'tools': [{'type': 'web_search'}]}])
def test_serial_inference_cannot_select_routes_or_remote_tools(owner, extra):
    invoked = []
    with ThreadPoolExecutor(1) as pool, serial(owner, inference=lambda payload: invoked.append(payload)) as (server, client):
        serving = pool.submit(server.serve_one)
        with pytest.raises((SerialError, EOFError)):
            client.call('inference', {'input': 'offline input', **extra})
        with pytest.raises(SerialError):
            serving.result(timeout=5)
        assert invoked == []


def test_cancellation_reaches_controls_while_inference_waits(owner):
    entered, release = threading.Event(), threading.Event()
    def inference(_payload):
        entered.set()
        assert release.wait(5)
        return {'events': []}
    with ThreadPoolExecutor(2) as pool, serial(owner, inference=inference) as (server, client):
        serving = pool.submit(server.serve_one)
        reply = pool.submit(client.call, 'inference', {'input': 'offline input'})
        try:
            assert entered.wait(5)
            assert interrupt_guest(server.endpoint.authority, 'owned', server.endpoint.scope['generation'])
            assert json.loads(client.controls.readline()) == {'type': 'stop'}
        finally:
            release.set()
        with pytest.raises(WorkerPersistenceError, match='guest_channel_revoked'):
            reply.result(timeout=5)
        serving.result(timeout=5)
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'


def test_real_sdk_responses_uses_serial_and_cannot_connect_network(owner, monkeypatch):
    from openai import OpenAI
    from agent.guest_inference import SerialHTTPTransport
    inputs = []
    def inference(payload):
        inputs.append(payload)
        return {'events': [{'type': 'response.completed', 'response': {
            'id': 'offline-response', 'object': 'response', 'created_at': 0,
            'status': 'completed', 'model': 'owner-fixed', 'output': []}}]}
    def forbidden(*args, **kwargs):
        raise AssertionError('no HTTP socket or real model allowed')
    with ThreadPoolExecutor(1) as pool, serial(owner, inference=inference) as (server, channel):
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        serving = pool.submit(server.serve_one)
        with httpx.Client(transport=SerialHTTPTransport(channel)) as http:
            sdk = OpenAI(api_key='public-placeholder', base_url='http://guest.invalid/v1',
                         http_client=http, max_retries=0)
            events = list(sdk.responses.create(model='guest-claim', input='offline SDK contract', stream=True))
            assert events[0].type == 'response.completed'
        serving.result(timeout=5)
    assert inputs == [{'input': 'offline SDK contract'}]


def test_eof_keeps_unknown_and_pending_owner_work(owner):
    from gateway.session_runtime_workers import uncounted_runtime_work
    authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    guest.close()
    try:
        with pytest.raises(EOFError):
            server.serve_one()
        assert uncounted_runtime_work(authority.runner) >= 1
        with pytest.raises(ValueError, match='unknown_execution'):
            OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    finally:
        server.wire.release_fd()
        host.close()


def test_serial_timeout_is_sticky_and_bounded():
    host, guest = socket.socketpair()
    wire = SerialWire(host.fileno(), {'vm': 'offline'}, timeout=.1)
    try:
        with pytest.raises(TimeoutError):
            wire.receive()
        with pytest.raises(SerialError, match='serial_failed'):
            wire.receive()
    finally:
        wire.release_fd()
        host.close()
        guest.close()


def test_task_private_git_and_reviewer_exact_readonly_device_contract(tmp_path):
    import subprocess
    from gateway.session_guest_workspace import prepare_workspace
    source = tmp_path / 'source'
    source.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    git('init', '-q')
    (source / 'code.txt').write_text('original\n')
    git('add', '.')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base')
    head = git('rev-parse', 'HEAD')
    git('config', 'credential.helper', 'HOST_SECRET_CANARY')
    developer = prepare_workspace(source, tmp_path / 'developer', head=head, role='developer')
    reviewer = prepare_workspace(source, tmp_path / 'reviewer', head=head, role='reviewer')
    (developer.root / 'code.txt').write_text('changed\n')
    assert (reviewer.root / 'code.txt').read_text() == 'original\n'
    assert (source / 'code.txt').read_text() == 'original\n'
    assert 'HOST_SECRET_CANARY' not in (developer.root / '.git/config').read_text()
    assert not (developer.root / '.git/objects/info/alternates').exists()
    assert reviewer.device_contract() == {'kind': 'directory_snapshot', 'mount': '/task', 'head': head, 'role': 'reviewer',
                                          'readonly': True, 'host_share': False}
    with pytest.raises(ValueError, match='exact_head'):
        prepare_workspace(source, tmp_path / 'moving-review', head='HEAD', role='reviewer')
    with pytest.raises(ValueError, match='not_private'):
        prepare_workspace(source, developer.root, head=head, role='developer')


def test_guest_mount_requires_kernel_readonly_and_private_block():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / 'native/qemu_guest/guest_entry.py'
    spec = importlib.util.spec_from_file_location('q2_entry', path)
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    work = {'role': 'reviewer'}
    entry.validate_mount(work, '1 0 254:1 / /task ro,nosuid,nodev - ext4 /dev/vdb ro')
    with pytest.raises(ValueError, match='readonly'):
        entry.validate_mount(work, '1 0 254:1 / /task rw - ext4 /dev/vdb rw')
    with pytest.raises(ValueError, match='block_device'):
        entry.validate_mount(work, '1 0 0:1 / /task ro - 9p host ro')
    with pytest.raises(ValueError, match='mount_required'):
        entry.validate_mount(work, '')


@pytest.mark.platforms('posix')
def test_serial_framing_on_real_raw_tty():
    import os
    import pty
    import tty
    master, slave = pty.openpty()
    tty.setraw(slave)
    guest = SerialWire(slave, {'assignment': 'offline-pty'})
    host = SerialWire(master, {'assignment': 'offline-pty'})
    try:
        host.send('lifecycle', 'control', {'type': 'stop'})
        assert guest.receive()['payload'] == {'type': 'stop'}
        guest.send('context', 'request', {'operation': 'assignment'})
        assert host.receive()['seq'] == 1
    finally:
        host.release_fd()
        guest.release_fd()
        os.close(master)
        os.close(slave)


def test_original_managed_loop_over_serial_uses_canonical_owner(owner, tmp_path, monkeypatch):
    """Agent double proves wiring only; it is never a Worker execution receipt."""
    from contextlib import closing, contextmanager
    from agent import managed_worker, runtime_session_store
    from agent.runtime_session_guest import execute_guest
    authority, _row, _scope, _endpoint = owner
    events = []
    @contextmanager
    def frozen_scope(_policy):
        yield
    class OfflineAgent:
        def __init__(self, **kwargs):
            from agent.auxiliary_client import resolve_provider_client
            from agent.guest_inference import SerialHTTPTransport
            auxiliary, _model = resolve_provider_client('custom', 'ignored', api_mode='codex_responses')
            assert isinstance(auxiliary._real_client._client._transport, SerialHTTPTransport)
            self.store, self.sid = kwargs['session_db'], kwargs['session_id']
        def run_conversation(self, _text, **kwargs):
            self.store.append_messages_batch(self.sid, [{'role': 'assistant', 'content': 'offline seam only'}])
            return {'final_response': 'offline seam only'}
        def shutdown_memory_provider(self, _messages):
            pass
        def release_clients(self):
            pass
    monkeypatch.setattr(runtime_session_store, '_worker_process', False)
    monkeypatch.setattr(managed_worker, 'bind_worker_policy', lambda _frame: None)
    monkeypatch.setattr(managed_worker, 'discover_profile_mcp', lambda _policy: None)
    monkeypatch.setattr('gateway.session_policy.policy_scope', frozen_scope)
    monkeypatch.setattr('run_agent.AIAgent', OfflineAgent)
    monkeypatch.setattr('agent.title_generator.wait_for_title_upgrades', lambda: None)
    with ThreadPoolExecutor(1) as pool, serial(owner, activity=events.append) as (server, client):
        def serve():
            while not events or events[-1]['type'] != 'finished':
                server.serve_one()
        future = pool.submit(serve)
        execute_guest(server.work, client, persistence_exchange=client,
                      control_stream=client.controls, outbox_dir=tmp_path / 'guest-only-outbox')
        future.result(timeout=5)
    assert [event['type'] for event in events] == ['ready', 'result', 'finished']
    assert authority.db.get_messages('owned')[0]['content'] == 'offline seam only'
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'
    assert authority._q2_guest_channels['owned'] is server
    assert not any(t.name == 'managed-controls' and t.is_alive() for t in threading.enumerate())


def test_image_plan_pins_distinct_artifacts_and_readonly_review_device(tmp_path):
    import hashlib
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / 'native/qemu_guest/image_contract.py'
    spec = importlib.util.spec_from_file_location('q2_image', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = []
    for name in ('kernel', 'initramfs', 'root', 'task', 'assignment'):
        artifact = tmp_path / name
        artifact.write_bytes(('offline-' + name).encode())
        files.append(artifact)
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    image = module.GuestImage(*files, hashes, 'reviewer', image_manifest(files, hashes, 'reviewer'))
    argv = image.device_args(7)
    assert argv[argv.index('-nic') + 1] == 'none'
    assert argv[argv.index('-chardev') + 1] == 'socket,id=worker,fd=7'
    assert 'console=tty0' in argv[argv.index('-append') + 1]
    assert next(arg for arg in argv if 'id=task,' in arg).endswith('readonly=on')
    files[3].write_bytes(b'changed task disk')
    with pytest.raises(ValueError, match='artifact_changed'):
        image.device_args(7)


@pytest.mark.asyncio
async def test_original_owner_interrupt_routes_bound_guest_and_keeps_pending(owner):
    from gateway.session_authority import LiveSession
    from gateway.session_contract import Principal, SessionRef
    authority, _row, scope, _endpoint = owner
    authority.sessions['owned'] = LiveSession(None, 'guest:owned')
    ref = SessionRef(authority.profile_id, 'owned')
    actor = Principal('human', authority.profile_id, frozenset({'session:control'}), 'offline')
    with serial(owner) as (server, client):
        await authority.interrupt(actor, ref, scope['generation'])
        assert json.loads(client.controls.readline()) == {'type': 'stop'}
        assert server.stop.is_set()
        assert authority.db._read_one('SELECT status FROM session_admissions')[0] == 'unknown'
        assert authority._handle(ref).execution_state == 'unknown'


def test_arbitrary_work_projection_cannot_attach_serial(owner):
    authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()
    try:
        changed = {**endpoint.test_work, 'title': 'unverified task input'}
        with pytest.raises(ValueError, match='guest_work_not_prepared'):
            OwnerSerialSession(endpoint, host.fileno(), changed)
        assert not authority._q2_guest_channels
    finally:
        host.close()
        guest.close()


@pytest.mark.parametrize('payload', [
    {'input': 'offline', 'tool_choice': {'type': 'web_search'}},
    {'input': [{'type': 'item_reference', 'id': 'foreign-response'}]},
    {'input': [{'role': 'user', 'content': [{'type': 'input_image', 'image_url': 'https://foreign.invalid'}]}]},
])
def test_inference_request_cannot_fetch_remote_items_or_select_native_tools(payload):
    from agent.guest_inference import validate_request
    with pytest.raises(SerialError):
        validate_request(payload)


@pytest.mark.parametrize('servicing', [True, False])
def test_transport_close_joins_service_and_preserves_unknown(owner, servicing):
    authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(server.serve_one) if servicing else None
        server.close_transport()
        if future is not None:
            with pytest.raises((SerialError, EOFError, OSError)):
                future.result(timeout=5)
    assert server.wire.fd == -1
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    assert authority._q2_guest_channels['owned'] is server
    host.close()
    guest.close()


@pytest.mark.parametrize('damage', ['identity', 'sequence', 'duplicate'])
def test_invalid_wire_rejected_before_peer_eof(damage):
    # An eventual EOF must not mask acceptance of an invalid application frame.
    host, guest = socket.socketpair()
    wire = SerialWire(host.fileno(), {'vm_id': 'offline'})
    frame = {'version': 2, 'scope': {'vm_id': 'offline'}, 'seq': 1,
             'channel': 'context', 'kind': 'request', 'reply_to': 0, 'payload': {}}
    if damage == 'identity':
        frame['scope']['vm_id'] = 'foreign'
    elif damage == 'sequence':
        frame['seq'] = 2
    raw = json.dumps(frame, separators=(',', ':')).encode()
    if damage == 'duplicate':
        raw = raw.replace(b'"seq":1', b'"seq":2,"seq":1')
    try:
        guest.sendall(struct.pack('!I', len(raw)) + raw)
        with pytest.raises(SerialError):
            wire.receive()
    finally:
        wire.release_fd()
        host.close()
        guest.close()


def test_logical_finish_and_request_budget_close_host_inference(owner, tmp_path):
    authority, _row, scope, endpoint = owner
    calls = []
    with serial(owner, inference=lambda payload: calls.append(payload) or {'events': []}) as (server, _client):
        store = guest_session_store(endpoint, scope, tmp_path / 'offline-outbox')
        try:
            assert store.finish() == {'status': 'pending_retirement'}
            with pytest.raises(ValueError, match='guest_result_pending_retirement'):
                server._dispatch('inference', {'input': 'late input'})
            assert calls == []
        finally:
            store.close()
    assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'


def test_owner_inference_budget_is_finite(owner):
    calls = []
    with serial(owner, inference=lambda payload: calls.append(payload) or {'events': []}) as (server, _client):
        server.inference_count = 32
        with pytest.raises(ValueError, match='guest_inference_budget_spent'):
            server._dispatch('inference', {'input': 'over budget'})
        assert calls == []


def test_transport_closes_owned_fd_even_when_revocation_storage_fails(owner, monkeypatch):
    authority, _row, _scope, _endpoint = owner
    with serial(owner) as (server, _client):
        def unavailable(_write, *args, **kwargs):
            raise OSError('offline evidence storage failure')
        monkeypatch.setattr(authority.db, '_execute_write', unavailable)
        with pytest.raises(OSError, match='evidence storage failure'):
            server.close_transport()
        assert server.wire.fd == -1
        assert authority._q2_guest_channels['owned'] is server


def test_unhashable_owner_frame_cannot_kill_receive_pump_silently():
    host, guest = socket.socketpair()
    scope = {'vm': 'offline-malformed-owner'}
    client = GuestSerialClient(SerialWire(guest.fileno(), scope))
    frame = {'version': 2, 'scope': scope, 'seq': 1, 'channel': [],
             'kind': 'reply', 'reply_to': 1, 'payload': {'result': {}}}
    raw = json.dumps(frame).encode()
    try:
        host.sendall(struct.pack('!I', len(raw)) + raw)
        client.reader.join(timeout=5)
        assert client.failure is not None
        with pytest.raises(SerialError):
            client.controls.readline()
    finally:
        client.close()
        host.close()
        guest.close()


def test_deep_json_is_sticky_unknown_on_actual_owner(owner):
    authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    raw = b'[' * 2000 + b'0' + b']' * 2000
    try:
        guest.sendall(struct.pack('!I', len(raw)) + raw)
        with pytest.raises(SerialError):
            server.serve_one()
        assert server.wire.failed
        assert endpoint.revoked
        assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        with pytest.raises(SerialError):
            server.wire.receive()
    finally:
        server.wire.release_fd()
        host.close()
        guest.close()


def test_invalid_reply_body_sets_sticky_failure():
    host, guest = socket.socketpair()
    scope = {'vm': 'offline-bad-reply'}
    client = GuestSerialClient(SerialWire(guest.fileno(), scope))
    wire = SerialWire(host.fileno(), scope)
    try:
        with ThreadPoolExecutor(1) as pool:
            def reply():
                frame = wire.receive()
                wire.send('context', 'reply', [], reply_to=frame['seq'])
            future = pool.submit(reply)
            with pytest.raises(SerialError):
                client.call('context', {'operation': 'assignment'})
            future.result(timeout=5)
        assert client.failure is not None
        with pytest.raises(SerialError):
            client.call('context', {'operation': 'assignment'})
    finally:
        client.close()
        wire.release_fd()
        host.close()
        guest.close()


def test_compression_auxiliary_reuses_serial_owner_and_closes_scoped_clients(owner, monkeypatch):
    from agent import auxiliary_client as aux
    from agent.guest_inference import bind_serial_inference
    seen = []
    message = {'type': 'message', 'id': 'offline-msg', 'role': 'assistant', 'status': 'completed',
               'content': [{'type': 'output_text', 'text': 'offline compression summary', 'annotations': []}]}
    def inference(payload):
        seen.append(payload)
        return {'events': [
            {'type': 'response.output_item.done', 'output_index': 0, 'item': message},
            {'type': 'response.completed', 'response': {'id': 'offline-summary', 'object': 'response',
                'created_at': 0, 'model': 'owner-fixed', 'status': 'completed', 'output': [message],
                'usage': {'input_tokens': 1, 'output_tokens': 2, 'total_tokens': 3}}},
        ]}
    def forbidden(*args, **kwargs):
        raise AssertionError('auxiliary must use serial; no model socket, provider discovery or global cache')
    with ThreadPoolExecutor(1) as pool, serial(owner, inference=inference) as (server, channel):
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        monkeypatch.setattr(aux, '_client_cache_key', forbidden)
        with bind_serial_inference(channel, 'owner-fixed'):
            client, model = aux.resolve_provider_client('custom', 'guest-claim', api_mode='codex_responses')
            assert model == 'owner-fixed'
            leaf = client._real_client
            serving = pool.submit(server.serve_one)
            result = aux.call_llm(task='compression', messages=[{'role': 'user', 'content': 'Summarize offline.'}],
                main_runtime={'provider': 'custom', 'model': 'owner-fixed', 'base_url': 'http://guest.invalid/v1',
                              'api_key': 'guest-transport', 'api_mode': 'codex_responses'})
            serving.result(timeout=5)
            assert result.choices[0].message.content == 'offline compression summary'
        assert leaf._client.is_closed
    assert len(seen) == 1 and 'model' not in seen[0] and 'headers' not in seen[0]


@pytest.mark.asyncio
async def test_async_auxiliary_keeps_existing_responses_adapter_on_serial(owner, monkeypatch):
    from agent import auxiliary_client as aux
    from agent.guest_inference import bind_serial_inference, SerialHTTPTransport
    with serial(owner) as (_server, channel):
        with bind_serial_inference(channel, 'owner-fixed'):
            client, model = aux.resolve_provider_client('custom', 'foreign', async_mode=True, api_mode='codex_responses')
            assert isinstance(client, aux.AsyncCodexAuxiliaryClient)
            assert isinstance(client._real_client._client._transport, SerialHTTPTransport)
            assert model == 'owner-fixed'
            with pytest.raises(SerialError, match='async_raw'):
                aux.resolve_provider_client('custom', 'foreign', async_mode=True, raw_codex=True)
        # Outside the Guest scope the mature router is restored, without storing
        # any of this scope's serial clients in its cross-turn cache.
        def forbidden(*args, **kwargs):
            raise AssertionError('outside-scope construction must not contact a model')
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        ordinary, _model = aux.resolve_provider_client('custom', 'owner-fixed',
            explicit_base_url='http://guest.invalid/v1', explicit_api_key='guest-transport', api_mode='codex_responses')
        try:
            assert not isinstance(ordinary._real_client._client._transport, SerialHTTPTransport)
        finally:
            ordinary.close()


def test_two_attachment_threads_cannot_overwrite_original_owner_slot(owner, monkeypatch):
    from gateway import session_guest_serial as transport
    authority, _row, _scope, endpoint = owner
    entered, second_stage, release = threading.Event(), threading.Event(), threading.Event()
    original_wire = transport.SerialWire
    original_read, original_write = authority.db._read_ctx, authority.db._execute_write
    counter_lock = threading.Lock()
    state = {'wires': 0, 'second_id': None}
    def wire(*args, **kwargs):
        with counter_lock:
            state['wires'] += 1
            first = state['wires'] == 1
        if first:
            entered.set()
            assert release.wait(5)
        return original_wire(*args, **kwargs)
    @contextmanager
    def read():
        if threading.get_ident() == state['second_id']:
            second_stage.set()  # old constructor has already passed its slot check
        with original_read() as conn:
            yield conn
    def write(callback, *args, **kwargs):
        if threading.get_ident() == state['second_id']:
            second_stage.set()  # new constructor is about to wait on the real writer
        return original_write(callback, *args, **kwargs)
    monkeypatch.setattr(transport, 'SerialWire', wire)
    monkeypatch.setattr(authority.db, '_read_ctx', read)
    monkeypatch.setattr(authority.db, '_execute_write', write)
    pairs = [socket.socketpair(), socket.socketpair()]
    results, constructed = [], []
    def attach(index):
        if index == 1:
            state['second_id'] = threading.get_ident()
        try:
            result = OwnerSerialSession(endpoint, pairs[index][0].fileno(), endpoint.test_work)
            constructed.append(result)
            return result
        except ValueError as error:
            return error
    try:
        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(attach, 0)
            assert entered.wait(5)
            try:
                import sqlite3
                with closing(sqlite3.connect(authority.db.db_path, timeout=0)) as observer:
                    with pytest.raises(sqlite3.OperationalError, match='locked'):
                        observer.execute('BEGIN IMMEDIATE')
                second = pool.submit(attach, 1)
                assert second_stage.wait(5)
            finally:
                release.set()
            results = [first.result(timeout=5), second.result(timeout=5)]
        accepted = [value for value in results if isinstance(value, OwnerSerialSession)]
        assert len(accepted) == 1
        assert authority._q2_guest_channels['owned'] is accepted[0]
        assert sum(isinstance(value, ValueError) for value in results) == 1
    finally:
        release.set()
        for value in constructed:
            value.close_transport()
        for host, guest in pairs:
            host.close()
            guest.close()


def test_attachment_commit_ack_loss_keeps_unknown_and_closes_owned_fd(owner, monkeypatch):
    authority, _row, _scope, endpoint = owner
    original = authority.db._execute_write
    fail = True
    def write(callback, *args, **kwargs):
        nonlocal fail
        result = original(callback, *args, **kwargs)
        if fail:
            fail = False
            raise OSError('attachment commit ACK lost')
        return result
    monkeypatch.setattr(authority.db, '_execute_write', write)
    host, guest = socket.socketpair()
    try:
        with pytest.raises(OSError, match='commit ACK lost'):
            OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
        retained = authority._q2_guest_channels['owned']
        assert retained.wire.fd == -1
        assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        with pytest.raises(ValueError, match='unknown_execution'):
            OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    finally:
        host.close()
        guest.close()


def image_manifest(files, hashes, role):
    devices = {}
    for name, path in zip(('root', 'task', 'assignment'), files[2:]):
        info = path.stat()
        devices[name] = {'path': str(path), 'sha256': hashes[str(path)], 'st_dev': info.st_dev, 'st_ino': info.st_ino,
                         'readonly': name != 'task' or role == 'reviewer'}
    return json.dumps({'role': role, 'workspace': {'kind': 'directory_snapshot', 'mount': '/task', 'head': 'a' * 40,
        'role': role, 'readonly': role == 'reviewer', 'host_share': False}, 'devices': devices},
        sort_keys=True, separators=(',', ':'))


def test_bidirectional_heartbeat_keeps_silent_local_work_alive_over_30_seconds(owner):
    import subprocess
    import sys
    from agent.managed_worker import WorkerControls
    with ThreadPoolExecutor(1) as pool, serial(owner) as (server, client):
        controls = WorkerControls(client, 'offline:silent', client.controls)
        serving = pool.submit(server.serve_one)  # no business traffic during the local work
        try:
            child = subprocess.run([sys.executable, '-c', 'import threading; threading.Event().wait(32)'],
                                   capture_output=True, timeout=45, check=True)
            assert child.returncode == 0
            assert not server.stop.is_set() and not controls.stopped.is_set()
            assert server.wire.heartbeat_acks >= 2 and client.wire.heartbeat_acks >= 2
            assert client.call('context', {'operation': 'assignment'}) == server.work
            serving.result(timeout=5)
            server.wire.send('lifecycle', 'control', {'type': 'finish'})
            controls.reader.join(timeout=5)
            assert controls.finish.is_set() and not controls.reader.is_alive()
        finally:
            client.controls.close_reader()
            controls.reader.join(timeout=5)


def test_missing_heartbeat_ack_revokes_actual_owner(owner):
    authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()  # peer deliberately stays open without acknowledging
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work,
                                heartbeat_interval=.05, heartbeat_lease=.3)
    try:
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(server.serve_one)
            try:
                with pytest.raises(TimeoutError, match='heartbeat_expired'):
                    pending.result(timeout=5)
            finally:
                server.wire.close()
        assert server.wire.fd == -1 and server.stop.is_set()
        assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
    finally:
        server.wire.close()
        server.wire.release_fd()
        host.close()
        guest.close()


def test_heartbeat_does_not_extend_rpc_deadline(owner):
    entered, release = threading.Event(), threading.Event()
    def inference(_payload):
        entered.set()
        assert release.wait(5)
        return {'events': []}
    with ThreadPoolExecutor(1) as pool, serial(owner, client_options={'request_timeout': .3}, inference=inference) as (server, client):
        serving = pool.submit(server.serve_one)
        try:
            with pytest.raises(SerialError, match='reply_timeout'):
                client.call('inference', {'input': 'offline bounded request'})
            assert entered.is_set() and client.controls.failure is not None
        finally:
            release.set()
        serving.result(timeout=5)  # a late result is not delivered to the timed-out Guest caller
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] != 'terminal'


def test_stop_is_delivered_before_unknown_storage_completes(owner, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    with ThreadPoolExecutor(2) as pool, serial(owner) as (server, client):
        original = server.endpoint.revoke
        def unavailable():
            entered.set()
            assert release.wait(5)
            raise OSError('offline UNKNOWN storage failure')
        monkeypatch.setattr(server.endpoint, 'revoke', unavailable)
        pending = pool.submit(server.cancel)
        try:
            assert entered.wait(5)
            receiving = pool.submit(client.controls.readline)
            assert json.loads(receiving.result(timeout=5)) == {'type': 'stop'}
            assert server.stop_sent.is_set() and not server.unknown_persisted.is_set()
        finally:
            release.set()
            client.controls.close_reader()
        with pytest.raises(OSError, match='UNKNOWN storage'):
            pending.result(timeout=5)
        monkeypatch.setattr(server.endpoint, 'revoke', original)
        server.cancel()  # retries persistence without sending a duplicate STOP
        assert server.unknown_persisted.is_set()
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'


@pytest.mark.asyncio
async def test_shutdown_retries_unsent_stop_after_first_send_failure(owner, monkeypatch):
    from gateway.session_guest_serial import stop_guest_channels
    with serial(owner) as (server, client):
        original = server.wire.send
        fail = True
        def send(channel, kind, payload, **kwargs):
            nonlocal fail
            if payload == {'type': 'stop'} and fail:
                fail = False
                raise OSError('offline STOP send failure')
            return original(channel, kind, payload, **kwargs)
        monkeypatch.setattr(server.wire, 'send', send)
        stop_guest_channels(owner[0])
        with pytest.raises(OSError, match='STOP send'):
            await server.cancel_task
        assert server.stop.is_set() and not server.stop_sent.is_set()
        stop_guest_channels(owner[0])
        await server.cancel_task
        assert server.stop_sent.is_set() and server.unknown_persisted.is_set()
        assert json.loads(client.controls.readline()) == {'type': 'stop'}


@pytest.mark.parametrize('failure', ['malformed', 'eof'])
def test_fault_cleanup_closes_fd_despite_revoke_write_failure(owner, monkeypatch, failure):
    authority, _row, scope, endpoint = owner
    before = authority.db.get_meta('guest.assignment.v1:' + scope['execution_id'])
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    def unavailable(_write, *args, **kwargs):
        raise OSError('offline revoke database failure')
    monkeypatch.setattr(authority.db, '_execute_write', unavailable)
    try:
        if failure == 'malformed':
            guest.sendall(struct.pack('!I', 2) + b'{}')
        else:
            guest.close()
        with pytest.raises((SerialError, EOFError)) as error:
            server.serve_one()
        assert any('UNKNOWN persistence failed' in note for note in error.value.__notes__)
        assert server.wire.fd == -1 and not server.wire.pump.is_alive()
        assert authority._q2_guest_channels['owned'] is server
        assert authority.db.get_meta('guest.assignment.v1:' + scope['execution_id']) == before
    finally:
        server.wire.close()
        server.wire.release_fd()
        host.close()
        guest.close()


@pytest.fixture
def image_candidate(tmp_path):
    import hashlib
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / 'native/qemu_guest/image_contract.py'
    spec = importlib.util.spec_from_file_location('q2_remediation_image', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = [tmp_path / name for name in ('kernel', 'initramfs', 'root', 'task', 'assignment')]
    for path in files:
        path.write_bytes(('inert-' + path.name).encode())
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    return module, files, hashes


def test_developer_image_rejects_underlying_hardlink_alias(image_candidate):
    import hashlib
    import os
    module, files, hashes = image_candidate
    files[3].unlink()
    os.link(files[2], files[3])
    hashes[str(files[3])] = hashlib.sha256(files[3].read_bytes()).hexdigest()
    image = module.GuestImage(*files, hashes, 'developer', image_manifest(files, hashes, 'developer'))
    with pytest.raises(ValueError, match='inode_alias'):
        image.device_args(7)


@pytest.mark.parametrize(('keys', 'value'), [
    (('role',), 'developer'), (('workspace', 'head'), 'moving-branch'),
    (('devices', 'task', 'readonly'), False), (('devices', 'root', 'readonly'), False),
    (('devices', 'task', 'st_ino'), -1),
])
def test_image_manifest_binds_role_workspace_and_device_modes(image_candidate, keys, value):
    module, files, hashes = image_candidate
    body = json.loads(image_manifest(files, hashes, 'reviewer'))
    target = body
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':'))
    with pytest.raises(ValueError, match='manifest_'):
        module.GuestImage(*files, hashes, 'reviewer', encoded).device_args(7)


@pytest.mark.parametrize('destination', ['same', 'child', 'symlink-child'])
def test_workspace_refuses_nested_host_source_without_writes(tmp_path, destination):
    import subprocess
    from gateway.session_guest_workspace import prepare_workspace
    source = tmp_path / 'host-project'
    source.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    git('init', '-q')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base', '--allow-empty')
    head = git('rev-parse', 'HEAD')
    before = sorted(str(path.relative_to(source)) for path in source.rglob('*'))
    target = source if destination == 'same' else source / 'exports/guest'
    if destination == 'symlink-child':
        link = tmp_path / 'alias'
        link.symlink_to(source, target_is_directory=True)
        target = link / 'exports/guest'
    with pytest.raises(ValueError, match='nested_source'):
        prepare_workspace(source, target, head=head, role='developer')
    assert sorted(str(path.relative_to(source)) for path in source.rglob('*')) == before
    assert git('status', '--porcelain') == ''


def test_workspace_detects_real_linked_git_common_dir(tmp_path):
    import subprocess
    from gateway.session_guest_workspace import verify_common_dir
    source, linked = tmp_path / 'host-project', tmp_path / 'linked'
    subprocess.run(['git', 'init', '-q', str(source)], check=True)
    subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-qm', 'base', '--allow-empty'], check=True)
    subprocess.run(['git', '-C', str(source), 'worktree', 'add', '-q', '--detach', str(linked)], check=True)
    with pytest.raises(ValueError, match='shared_common_dir'):
        verify_common_dir(linked, source / '.git')


@pytest.mark.parametrize('bound_service', [True, False])
def test_healthy_serial_eof_drains_finished_and_preserves_owner_exclusion(owner, tmp_path, bound_service):
    """A real committed finish plus EOF closes transport, never the worker row."""
    import time
    authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    client = GuestSerialClient(SerialWire(guest.fileno(), scope))
    host.close()  # the original Owner retains only SerialWire's owned descriptor
    with ThreadPoolExecutor(1) as pool:
        def serve():
            while server.serve_one():
                pass
        service = pool.submit(serve)
        if bound_service:
            server.bind_service(service)
        store = guest_session_store(client, scope, tmp_path / 'actual-receipt-outbox')
        try:
            client.send('ready')
            client.send('result', result={'final_response': 'qualification fixture'})
            assert json.loads(client.controls.readline()) == {'type': 'finish'}
            assert store.finish() == {'status': 'pending_retirement'}
            client.send('finished')
            client.close()
            guest.close()
            service.result(timeout=5)
            facts = server.finish_transport(deadline=time.monotonic() + 5)
            assert facts['complete'] is bound_service and facts['logical_finished']
            assert facts['service_joined'] is bound_service
            assert facts['serial_observer'] == 'ORIGINAL_OWNER_SERIALWIRE'
            assert not endpoint.revoked and not server.unknown_persisted.is_set()
            assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'running'
            assert authority._q2_guest_channels['owned'] is server
        finally:
            store.close()
            client.close()
            guest.close()
            server.wire.release_fd()


def test_guest_finished_without_canonical_finish_is_unknown(owner):
    authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    client = SerialWire(guest.fileno(), scope)
    try:
        client.send('activity', 'event', {'type': 'result'})
        server.serve_one()
        client.receive()  # actual finish control
        client.send('activity', 'event', {'type': 'finished'})
        with pytest.raises(SerialError, match='canonical_receipt'):
            server.serve_one()
        assert endpoint.revoked
        assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        with pytest.raises(ValueError, match='healthy_finish_revoked'):
            server.finish_transport()
    finally:
        client.release_fd()
        server.wire.release_fd()
        host.close()
        guest.close()


def test_serial_close_facts_do_not_imply_peer_eof(owner):
    _authority, _row, _scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work)
    try:
        server.close_transport()
        facts = server.physical_observation()
        assert facts['descriptor_closed'] and facts['transport_joined']
        assert facts['peer_eof'] is False and facts['complete'] is False
    finally:
        host.close()
        guest.close()


_Q2_PROCESS_FIXTURE = r'''
import json, os, sys
pid = os.getpid()
def emit(value):
    print(json.dumps(value), flush=True)
print("HERMES_HVF_CORE_LIMIT_V1 pid=%d current=0 maximum=0" % pid, file=sys.stderr, flush=True)
print("HERMES_HVF_VM_CREATE_V1 pid=%d result=0" % pid, file=sys.stderr, flush=True)
print("HERMES_Q2_SANDBOX_RESULT_V1 " + json.dumps({"pid":pid,"pass":True,"vm_created":False}), file=sys.stderr, flush=True)
emit({"QMP":{"version":{}}})
readonly = sys.argv[1] == "reviewer"
blocks = [{"device":name,"inserted":{"ro":ro,"image":{"virtual-size":size}}}
          for name,ro,size in [("root",True,1073741824),("task",readonly,67108864),("assignment",True,16777216)]]
table = {"qmp_capabilities":{},"query-cpus-fast":[{},{}],
         "query-memory-size-summary":{"base-memory":2147483648},"query-rx-filter":[],
         "query-pci":[],"human-monitor-command":"","query-block":blocks,"query-status":{"running":True}}
for line in sys.stdin:
    request = json.loads(line)
    if request["execute"] == "system_powerdown":
        emit({"return":{},"id":request["id"]})
        emit({"event":"SHUTDOWN","data":{"guest":True,"reason":"guest-shutdown"}})
        print("HERMES_HVF_VM_DESTROY_V1 pid=%d result=0 joined=2" % pid, file=sys.stderr, flush=True)
        break
    emit({"return":table[request["execute"]],"id":request["id"]})
'''


@contextmanager
def q2_process_fixture():
    """An inert stdio fixture, never QEMU/HVF or evidence of a Native VM."""
    import subprocess
    import sys
    process = subprocess.Popen([sys.executable, '-c', _Q2_PROCESS_FIXTURE, 'developer'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, bufsize=0)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('serial_complete', [True, False])
def test_q2_process_observer_cannot_substitute_unobserved_serial_eof(tmp_path, serial_complete):
    import time
    import sys
    from gateway.session_hvf_process import Q2ProcessObserver, child_identity
    host, guest = socket.socketpair()
    guest.sendall(b'UART must remain exclusively owned by SerialWire')
    with q2_process_fixture() as process:
        identity = child_identity(process, sys.executable)
        observer = Q2ProcessObserver(process, identity, output=tmp_path / 'actual-stdio',
                                    expected_devices={'root': True, 'task': False, 'assignment': True})
        deadline = time.monotonic() + 5
        try:
            observer.start(deadline)
            observer.pipes.request('system_powerdown', deadline=deadline)
            fields = ('peer_eof', 'descriptor_closed', 'receive_pump_joined', 'writer_joined',
                      'service_joined', 'http_joined', 'transport_joined', 'complete')
            serial_facts = {field: serial_complete for field in fields}
            serial_facts.update(serial_observer='ORIGINAL_OWNER_SERIALWIRE', cleanup_errors=[])
            if serial_complete:
                proof = observer.finish(deadline, lambda: serial_facts)
                assert proof['exact_child_waited'] and proof['explicit_vm_destroy']
                assert proof['serial_read_by_process_observer'] is False
                assert set(proof['stdio_eof']) == {'stdout', 'stderr'}
            else:
                with pytest.raises(ValueError, match='owner_serial_unretired'):
                    observer.finish(deadline, lambda: serial_facts)
            assert host.recv(1024, socket.MSG_PEEK) == b'UART must remain exclusively owned by SerialWire'
        finally:
            observer.close()
            host.close()
            guest.close()


def test_q2_runtime_inventory_refuses_writable_review_and_extra_devices():
    from types import SimpleNamespace
    from gateway.session_hvf_process import q2_inventory
    blocks = [{'device': name, 'inserted': {'ro': readonly, 'image': {'virtual-size': 64}}}
              for name, readonly in [('root', True), ('task', False), ('assignment', True)]]
    values = {'query-cpus-fast': [{}, {}], 'query-memory-size-summary': {'base-memory': 2 * 1024**3},
              'query-rx-filter': [], 'query-pci': [], 'human-monitor-command': '',
              'query-block': blocks, 'query-status': {'running': True}}
    pipes = SimpleNamespace(request=lambda name, args=None, deadline=None: values[name])
    with pytest.raises(ValueError, match='block_inventory'):
        q2_inventory(pipes, 0, {'root': True, 'task': True, 'assignment': True})
    blocks.append({'device': 'unapproved', 'inserted': {'ro': True, 'image': {'virtual-size': 64}}})
    with pytest.raises(ValueError, match='runtime_inventory'):
        q2_inventory(pipes, 0, {'root': True, 'task': False, 'assignment': True})


def test_serial_service_future_failure_does_not_skip_http_cleanup(owner):
    from concurrent.futures import Future
    from gateway.session_guest_inference import OwnerResponses, ResponsesPolicy
    _authority, _row, _scope, endpoint = owner
    adapter = OwnerResponses(endpoint, ResponsesPolicy('http://127.0.0.1:51837/v1/responses', 'fixed', 'fixture'),
                             transport=httpx.MockTransport(lambda _request: httpx.Response(200)), headers={})
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work, inference=adapter)
    service = Future()
    service.set_exception(RuntimeError('actual service failure fixture'))
    server.bind_service(service)
    try:
        facts = server.close_transport()
        assert facts['service_joined'] and facts['service_failure'] == 'actual service failure fixture'
        assert server.wire.fd == -1 and adapter.closed and endpoint.revoked
        assert facts['peer_eof'] is False and facts['complete'] is False
    finally:
        adapter.close()
        server.wire.release_fd()
        host.close()
        guest.close()


@pytest.mark.parametrize('damage', ['missing-destroy', 'wrong-pid', 'duplicate-create',
                                    'failed-destroy', 'core-limit', 'sandbox-failed'])
def test_q2_backend_evidence_requires_real_matching_complete_telemetry(damage):
    """Telemetry grammar tests; these synthetic bytes do not qualify a real VM."""
    from gateway.session_hvf_process import q2_markers
    pid = 12345
    rows = [f'HERMES_HVF_CORE_LIMIT_V1 pid={pid} current=0 maximum=0',
            f'HERMES_HVF_VM_CREATE_V1 pid={pid} result=0',
            'HERMES_Q2_SANDBOX_RESULT_V1 ' + json.dumps({'pid': pid, 'pass': True, 'vm_created': False}),
            f'HERMES_HVF_VM_DESTROY_V1 pid={pid} result=0 joined=2']
    assert q2_markers(('\n'.join(rows) + '\n').encode(), pid)['destroy_success']
    mutations = {
        'missing-destroy': lambda items: items.pop(),
        'wrong-pid': lambda items: items.__setitem__(-1, items[-1].replace(str(pid), '98765')),
        'duplicate-create': lambda items: items.append(items[1]),
        'failed-destroy': lambda items: items.__setitem__(-1, items[-1].replace('result=0', 'result=1')),
        'core-limit': lambda items: items.__setitem__(0, items[0].replace('maximum=0', 'maximum=1')),
        'sandbox-failed': lambda items: items.__setitem__(2, items[2].replace('true', 'false')),
    }
    mutations[damage](rows)
    with pytest.raises(ValueError, match='backend_or_sandbox_unverified'):
        q2_markers(('\n'.join(rows) + '\n').encode(), pid)


def test_q2_runtime_inventory_counts_all_attached_disk_bytes():
    from types import SimpleNamespace
    from gateway.session_hvf_process import q2_inventory
    blocks = [{'device': name, 'inserted': {'ro': readonly, 'image': {'virtual-size': 4 * 1024**3}}}
              for name, readonly in [('root', True), ('task', False), ('assignment', True)]]
    values = {'query-cpus-fast': [{}, {}], 'query-memory-size-summary': {'base-memory': 2 * 1024**3},
              'query-rx-filter': [], 'query-pci': [], 'human-monitor-command': '',
              'query-block': blocks, 'query-status': {'running': True}}
    pipes = SimpleNamespace(request=lambda name, args=None, deadline=None: values[name])
    with pytest.raises(ValueError, match='disk_budget_exhausted'):
        q2_inventory(pipes, 0, {'root': True, 'task': False, 'assignment': True})


def test_cancelled_sole_reader_discards_late_frames_until_actual_peer_eof(owner):
    import time
    import select
    authority, _row, scope, endpoint = owner
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work,
                                heartbeat_interval=90, heartbeat_lease=120)
    host.close()
    wire = SerialWire(guest.fileno(), scope)
    drained, allow_shutdown = threading.Event(), threading.Event()
    before = authority.db._read_one('SELECT count(*) FROM worker_receipts')[0]
    with ThreadPoolExecutor(2) as pool:
        def serve():
            count = 0
            while server.serve_one():
                count += 1
                if count == 2:
                    drained.set()
        service = pool.submit(serve)
        server.bind_service(service)
        def peer_waits_for_test_release():
            assert allow_shutdown.wait(10)
            guest.shutdown(socket.SHUT_WR)
        peer = pool.submit(peer_waits_for_test_release)
        try:
            server.cancel()
            assert wire.receive()['payload'] == {'type': 'stop'}
            request = wire.send('persistence', 'request', {'method': 'worker.persist', 'params': {'operation': 'execution.finish'}})
            wire.send('activity', 'event', {'type': 'result', 'result': 'must be discarded'})
            assert drained.wait(5)
            assert not service.done() and not server.peer_eof.is_set()
            assert not server.result_ready.is_set() and not server.persisted_finish.is_set()
            assert authority.db._read_one('SELECT count(*) FROM worker_receipts')[0] == before
            assert select.select([wire.fd], [], [], 2)[0]
            denial = wire.receive()
            assert denial['kind'] == 'reply' and denial['reply_to'] == request
            assert denial['payload'] == {'error': 'guest_channel_revoked'}
            assert select.select([wire.fd], [], [], 2)[0] == []
            assert server.physical_observation()['peer_eof'] is False
            allow_shutdown.set()
            peer.result(timeout=5)
            service.result(timeout=5)
            facts = server.close_transport(deadline=time.monotonic() + 5)
            assert facts['peer_eof'] and facts['complete'] and facts['service_joined']
            assert authority.db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
            assert not server.result_ready.is_set()
        finally:
            allow_shutdown.set()
            wire.close()
            wire.release_fd()
            guest.close()
            server.close_transport(deadline=time.monotonic() + 5)


@pytest.mark.platforms('posix')
def test_deferred_heartbeat_preserves_first_frame_across_guest_uart_flush(owner):
    import os
    import pty
    import select
    import termios
    import tty
    _authority, _row, scope, endpoint = owner
    master, slave = pty.openpty()
    server = OwnerSerialSession(endpoint, master, endpoint.test_work,
                                heartbeat_interval=5, heartbeat_lease=90, defer_heartbeat=True)
    os.close(master)
    wire = None
    with ThreadPoolExecutor(1) as pool:
        service = pool.submit(server.serve_one)
        try:
            assert server.wire.pump is None and server.wire.timeout == 60
            assert select.select([slave], [], [], 2)[0] == []
            assert server.wire.sent == 0 and server.wire.received == 0
            tty.setraw(slave, when=termios.TCSAFLUSH)
            wire = SerialWire(slave, scope)
            request = wire.send('context', 'request', {'operation': 'assignment'})
            frame = wire.receive()
            assert frame['kind'] == 'reply' and frame['reply_to'] == request
            assert frame['seq'] == 1 and frame['payload']['result']['assignment'] == scope
            service.result(timeout=5)
            assert server.wire.pump is not None and server.wire.timeout == 30
            assert server.heartbeat_deferred is False
        finally:
            if wire is not None:
                wire.close()
                wire.release_fd()
            os.close(slave)
            server.wire.close()
            server.wire.release_fd()


@pytest.mark.parametrize('cancel_gap', ['during_inference', 'after_dispatch'])
def test_cancelled_held_inference_emits_only_denial_after_stop(owner, monkeypatch, cancel_gap):
    import select
    _authority, _row, scope, endpoint = owner
    entered, release = threading.Event(), threading.Event()
    def held(_payload):
        if cancel_gap == 'during_inference':
            entered.set()
            assert release.wait(5)
        return {'events': []}
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work, inference=held,
                                heartbeat_interval=90, heartbeat_lease=120)
    host.close()
    wire = SerialWire(guest.fileno(), scope)
    if cancel_gap == 'after_dispatch':
        dispatch = server._dispatch
        def paused_after_dispatch(channel, payload):
            result = dispatch(channel, payload)
            entered.set()
            assert release.wait(5)
            return result
        monkeypatch.setattr(server, '_dispatch', paused_after_dispatch)
    with ThreadPoolExecutor(1) as pool:
        service = pool.submit(server.serve_one)
        server.bind_service(service)
        try:
            request = wire.send('inference', 'request', {'input': 'public held inference fixture'})
            assert entered.wait(5)
            server.cancel()
            assert wire.receive()['payload'] == {'type': 'stop'}
            release.set()
            service.result(timeout=5)
            assert select.select([wire.fd], [], [], 2)[0]
            denial = wire.receive()
            assert denial['kind'] == 'reply' and denial['reply_to'] == request
            assert denial['payload'] == {'error': 'guest_channel_revoked'}
            assert select.select([wire.fd], [], [], 2)[0] == []
            assert server.stop_sent.is_set() and server.unknown_persisted.is_set()
            assert not server.result_ready.is_set()
        finally:
            release.set()
            wire.close()
            wire.release_fd()
            guest.close()
            server.close_transport()


def test_real_owner_responses_cancel_unwinds_before_held_http_returns(owner):
    from gateway.session_guest_inference import OwnerResponses, ResponsesPolicy
    from hermes_state_runtime import RuntimeStoreError
    from tests.gateway.test_guest_cockpit import response
    _authority, _row, _scope, endpoint = owner
    entered, release = threading.Event(), threading.Event()
    def held(_request):
        entered.set()
        assert release.wait(5)
        return response()
    adapter = OwnerResponses(endpoint,
        ResponsesPolicy('http://127.0.0.1:51837/v1/responses', 'fixed', 'public-cancellation-fixture'),
        transport=httpx.MockTransport(held), headers={})
    host, guest = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work, inference=adapter)
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(server._dispatch, 'inference', {'input': 'public cancellation fixture'})
        try:
            assert entered.wait(2)
            server.cancel()
            with pytest.raises(RuntimeStoreError, match='unsettled'):
                pending.result(timeout=2)
            assert not release.is_set() and not adapter.pending.done()
        finally:
            release.set()
            if adapter.pending is not None:
                adapter.pending.result(timeout=3)
            server.close_transport()
            host.close()
            guest.close()


@pytest.mark.platforms('posix')
def test_deferred_pre_ready_peer_eof_is_fact_without_fabricated_pump_or_retirement(owner):
    import time
    _authority, _row, _scope, endpoint = owner
    host, peer = socket.socketpair()
    server = OwnerSerialSession(endpoint, host.fileno(), endpoint.test_work,
                                defer_heartbeat=True)
    host.close()
    peer.close()
    try:
        with pytest.raises(EOFError, match='serial_eof'):
            server.serve_one()
        facts = server.physical_observation()
        assert facts['peer_eof'] is True
        assert facts['peer_eof_at'] is not None
        assert facts['receive_pump_started'] is False
        assert facts['receive_pump_joined'] is False
        assert facts['frames_received'] == 0 and facts['frames_sent'] == 0
        assert facts['complete'] is False and not server.ready.is_set()
    finally:
        server.close_transport(deadline=time.monotonic() + 5)
