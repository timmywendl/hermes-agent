"""D2 original Owner + deterministic Fake Cockpit; no network, Worker or model."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading

import httpx
import pytest

from gateway.session_guest_inference import EventCollector, OwnerResponses, ResponsesPolicy, request_body
from agent.runtime_session_store import WorkerPersistenceError
from hermes_constants import get_hermes_home
from hermes_state_runtime import RuntimeStoreError
from tests.gateway import test_guest_serial as serial_tests


@pytest.fixture
def owner(tmp_path, monkeypatch):
    yield from serial_tests.guest_owner_fixture.__wrapped__(tmp_path, monkeypatch)


def completed(*, usage=True):
    response = {'id': 'offline-response', 'status': 'completed', 'output': []}
    if usage:
        response['usage'] = {'input_tokens': 7, 'output_tokens': 3, 'total_tokens': 10}
    return {'type': 'response.completed', 'response': response}


def sse(events):
    return b''.join(b'data: ' + json.dumps(event).encode() + b'\n\n' for event in events)


def response(events=None, *, status=200, headers=None):
    return httpx.Response(status, headers=headers or {'content-type': 'text/event-stream'},
                          stream=httpx.ByteStream(sse(events or [completed()])))


@contextmanager
def channel(owner, handler, **policy_options):
    adapter = OwnerResponses(owner[3], ResponsesPolicy('http://127.0.0.1:51837/v1/responses',
        'owner-fixed', 'offline-pinned-route-policy', **policy_options),
        transport=httpx.MockTransport(handler), headers={'Authorization': 'Bearer offline-not-a-credential'})
    try:
        with serial_tests.serial(owner, inference=adapter) as (server, client):
            yield server, client, adapter
    finally:
        adapter.close()


def receipt(owner):
    rows = owner[0].db._read_all("SELECT value FROM state_meta WHERE key LIKE 'guest.inference.v1:%' AND key NOT LIKE '%:cursor'")
    assert len(rows) == 1
    return json.loads(rows[0][0])


def test_original_owner_fixed_request_and_durable_usage(owner):
    requests = []
    def handler(request):
        requests.append((request, get_hermes_home()))
        return response()
    with channel(owner, handler) as (server, client, _adapter), ThreadPoolExecutor(1) as pool:
        serving = pool.submit(server.serve_one)
        assert client.call('inference', {'input': 'offline assignment'}) == {'events': [completed()]}
        serving.result(timeout=3)
        request, home = requests[0]
        assert str(request.url) == 'http://127.0.0.1:51837/v1/responses'
        assert request.method == 'POST' and home.as_posix() == owner[0].profile_id
        assert json.loads(request.content) == {'input': 'offline assignment', 'model': 'owner-fixed',
            'stream': True, 'store': False, 'max_output_tokens': 8192}
        assert request.headers['authorization'] == 'Bearer offline-not-a-credential'
        audit = receipt(owner)
        assert audit['status'] == 'RECEIVED' and audit['network_complete'] is True
        assert audit['scope'] == owner[2]
        assert audit['usage'] == {'input_tokens': 7, 'output_tokens': 3, 'total_tokens': 10,
            'tokens_status': 'REPORTED_BY_COCKPIT', 'actual_cost_usd': None, 'cost_status': 'UNKNOWN'}
        assert 'offline assignment' not in json.dumps(audit)
        assert 'offline-not-a-credential' not in json.dumps(audit)
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] != 'terminal'


@pytest.mark.parametrize('extra', [{'model': 'foreign'}, {'headers': {}}, {'url': 'http://foreign'},
    {'previous_response_id': 'foreign'}, {'tools': [{'type': 'web_search'}]},
    {'tools': [{'type': 'function', 'name': 'local', 'url': 'http://foreign'}]},
    {'tools': [{'type': 'function', 'name': 'local', 'parameters': {'$ref': 'https://foreign/schema'}}]},
    {'text': {'format': {'schema': {'$dynamicRef': 'file:///foreign'}}}},
    {'max_output_tokens': 8193}])
def test_guest_cannot_change_cockpit_policy_or_remote_capabilities(owner, extra):
    calls = []
    with channel(owner, lambda request: calls.append(request) or response()) as (server, _client, _adapter):
        with pytest.raises(ValueError):
            server._dispatch('inference', {'input': 'offline', **extra})
        assert calls == []
        assert owner[0].db._read_all("SELECT key FROM state_meta WHERE key LIKE 'guest.inference.v1:%' AND key NOT LIKE '%:cursor'") == []


@pytest.mark.parametrize('url', ['http://192.0.2.1/v1/responses', 'http://127.0.0.1/v1/models',
    'http://127.0.0.1/v1/responses?route=foreign', 'http://secret@127.0.0.1/v1/responses'])
def test_host_binding_is_single_local_responses_operation(url):
    with pytest.raises(ValueError):
        ResponsesPolicy(url, 'fixed', 'offline-policy')


@pytest.mark.parametrize('fault', ['redirect', 'status', 'mime', 'compressed', 'truncated', 'bad-json', 'failed'])
def test_bad_cockpit_response_is_not_retried_or_forwarded(owner, fault):
    calls = []
    def handler(request):
        calls.append(request)
        options = {'redirect': lambda: response(status=307, headers={'location': 'http://foreign'}),
                   'status': lambda: response(status=500),
                   'mime': lambda: response(headers={'content-type': 'application/json'}),
                   'compressed': lambda: response(headers={'content-type': 'text/event-stream', 'content-encoding': 'gzip'}),
                   'truncated': lambda: response([{'type': 'response.created'}]),
                   'bad-json': lambda: httpx.Response(200, headers={'content-type': 'text/event-stream'},
                       stream=httpx.ByteStream(b'data: INVALID\n\n')),
                   'failed': lambda: response([{'type': 'response.failed', 'error': {'message': 'DO_NOT_FORWARD'}}])}
        return options[fault]()
    with channel(owner, handler) as (server, _client, adapter):
        with pytest.raises(RuntimeStoreError, match='cockpit_request_unsettled'):
            server._dispatch('inference', {'input': 'offline'})
        assert len(calls) == 1
        assert receipt(owner)['status'] == 'STOP_UNCERTAIN'
        assert receipt(owner)['usage']['actual_cost_usd'] is None
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        with pytest.raises(RuntimeStoreError):
            adapter({'input': 'successor forbidden'})


def test_missing_usage_remains_unknown_not_zero(owner):
    with channel(owner, lambda _request: response([completed(usage=False)])) as (server, _client, _adapter):
        assert server._dispatch('inference', {'input': 'offline'})['events'] == [completed(usage=False)]
        usage = receipt(owner)['usage']
        assert usage == {'tokens_status': 'UNKNOWN', 'actual_cost_usd': None, 'cost_status': 'UNKNOWN'}


def test_host_deadline_rejects_late_result_and_keeps_pending_obligation(owner):
    entered, release = threading.Event(), threading.Event()
    def handler(_request):
        entered.set()
        assert release.wait(4)
        return response()
    with channel(owner, handler, deadline=.1) as (server, _client, adapter), ThreadPoolExecutor(1) as pool:
        future = pool.submit(server._dispatch, 'inference', {'input': 'offline'})
        try:
            assert entered.wait(2)
            with pytest.raises(RuntimeStoreError, match='unsettled'):
                future.result(timeout=2)
            assert receipt(owner)['status'] == 'STOP_UNCERTAIN'
            assert adapter.pending.done() is False
            with pytest.raises(RuntimeStoreError, match='unretired'):
                pool.submit(adapter.close).result(timeout=2)
        finally:
            release.set()
            adapter.pending.result(timeout=3)
        audit = receipt(owner)
        assert audit['status'] == 'STOP_UNCERTAIN' and audit['network_complete'] is True
        assert audit['usage']['total_tokens'] == 10
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'


def test_cancel_during_request_sends_stop_without_waiting_for_http(owner):
    entered, release = threading.Event(), threading.Event()
    def handler(_request):
        entered.set()
        assert release.wait(4)
        return response()
    with channel(owner, handler) as (server, client, adapter), ThreadPoolExecutor(2) as pool:
        serving = pool.submit(server.serve_one)
        waiting = pool.submit(client.call, 'inference', {'input': 'offline'})
        try:
            assert entered.wait(2)
            server.cancel()
            serving.result(timeout=2)
            with pytest.raises(WorkerPersistenceError, match='unsettled'):
                waiting.result(timeout=2)
            assert server.stop_sent.is_set() and server.unknown_persisted.is_set()
            with pytest.raises(RuntimeStoreError, match='unretired'):
                adapter.close()
        finally:
            release.set()
            adapter.pending.result(timeout=3)
        assert receipt(owner)['status'] == 'STOP_UNCERTAIN'


@pytest.mark.parametrize('damage', ['oversized-line', 'oversized-body', 'extra-event', 'bad-usage', 'headers'])
def test_sse_bounds_and_terminal_contract(damage):
    collector = EventCollector()
    event = completed()
    event['response']['usage']['input_tokens'] = -1
    fixtures = {
        'oversized-line': lambda: b'data: ' + b'x' * 65537,
        'oversized-body': lambda: b': bounded comment\n' * 140000,
        'extra-event': lambda: sse([completed(), {'type': 'response.created'}]),
        'headers': lambda: sse([{'type': 'response.created', 'headers': {'authorization': 'offline'}}]),
        'bad-usage': lambda: sse([event]),
    }
    raw = fixtures[damage]()
    with pytest.raises(RuntimeStoreError):
        collector.feed(raw)


def test_sse_handles_arbitrary_chunk_boundaries():
    raw = sse([{'type': 'response.output_text.delta', 'delta': 'offline'}, completed()]) + b'data: [DONE]\n\n'
    collector = EventCollector()
    for value in raw:
        collector.feed(bytes([value]))
    assert collector.finish()['events'][-1] == completed()


def test_request_snapshot_does_not_alias_guest_mutable_payload():
    payload = {'input': [{'role': 'user', 'content': 'offline'}]}
    body = request_body(payload, ResponsesPolicy('http://127.0.0.1/v1/responses', 'fixed', 'policy'))
    payload['input'][0]['content'] = 'changed'
    assert body['input'][0]['content'] == 'offline'


@pytest.mark.parametrize('damage', ['starting', 'malformed', 'wrong-policy', 'wrong-request-hash'])
def test_previous_unknown_or_damaged_receipt_blocks_new_request(owner, damage):
    calls = []
    with channel(owner, lambda request: calls.append(request) or response()) as (server, _client, _adapter):
        server._dispatch('inference', {'input': 'offline'})
        raw = receipt(owner)
        changes = {'starting': lambda: raw | {'status': 'STARTING'},
                   'malformed': list, 'wrong-policy': lambda: raw | {'policy_sha256': 'foreign'},
                   'wrong-request-hash': lambda: raw | {'request_sha256': 'f' * 64}}
        owner[0].db._execute_write(lambda conn: conn.execute(
            "UPDATE state_meta SET value=? WHERE key LIKE 'guest.inference.v1:%' AND key NOT LIKE '%:cursor'", (json.dumps(changes[damage](), sort_keys=True),)))
        with pytest.raises(RuntimeStoreError):
            server._dispatch('inference', {'input': 'new call forbidden'})
        assert len(calls) == 1


def test_owner_restart_while_cockpit_waits_cannot_deliver_or_resume(owner):
    from hermes_state_runtime import begin_runtime_epoch
    entered, release = threading.Event(), threading.Event()
    def handler(_request):
        entered.set()
        assert release.wait(4)
        return response()
    with channel(owner, handler) as (server, _client, adapter), ThreadPoolExecutor(1) as pool:
        request = pool.submit(server._dispatch, 'inference', {'input': 'offline'})
        try:
            assert entered.wait(2)
            begin_runtime_epoch(owner[0].db, instance_id='offline-new-owner')
            before = receipt(owner)
        finally:
            release.set()
        with pytest.raises(RuntimeStoreError):
            request.result(timeout=3)
        assert receipt(owner) == before
        with pytest.raises(RuntimeStoreError):
            adapter({'input': 'must not resume'})


def test_failed_http_stream_close_is_retained_and_not_declared_closed(owner):
    class BrokenClose(httpx.SyncByteStream):
        def __init__(self):
            self.allow_cleanup = False
        def __iter__(self):
            yield sse([completed()])
        def close(self):
            if not self.allow_cleanup:
                raise OSError('offline close failure')
    stream = BrokenClose()
    with channel(owner, lambda _request: httpx.Response(200,
            headers={'content-type': 'text/event-stream'}, stream=stream)) as (server, _client, adapter):
        with pytest.raises(RuntimeStoreError):
            server._dispatch('inference', {'input': 'offline'})
        assert receipt(owner)['status'] == 'STOP_UNCERTAIN'
        assert adapter.active_response is not None
        with pytest.raises(RuntimeStoreError, match='http_unretired'):
            adapter.close()
        assert adapter.closed is False
        assert adapter.client.is_closed is True
        assert adapter.cleanup_failures
        stream.allow_cleanup = True
        adapter.close()
        assert receipt(owner)['status'] == 'STOP_UNCERTAIN'


def test_storage_failure_cannot_skip_serial_fd_close_or_drop_http_obligation(owner, monkeypatch):
    import os
    import sqlite3
    entered, release = threading.Event(), threading.Event()
    def handler(_request):
        entered.set()
        assert release.wait(4)
        return response()
    with channel(owner, handler) as (server, _client, adapter), ThreadPoolExecutor(1) as pool:
        future = pool.submit(server._dispatch, 'inference', {'input': 'offline'})
        try:
            assert entered.wait(2)
            def busy_write(_callback):
                raise sqlite3.OperationalError('offline BUSY')
            monkeypatch.setattr(owner[0].db, '_execute_write', busy_write)
            fd = server.wire.fd
            with pytest.raises((RuntimeStoreError, sqlite3.Error)):
                server.close_transport()
            with pytest.raises(OSError):
                os.fstat(fd)
            with pytest.raises(RuntimeStoreError):
                future.result(timeout=2)
            assert not adapter.pending.done() and adapter.persistence_failure is not None
        finally:
            monkeypatch.undo()
            release.set()
            adapter.pending.result(timeout=3)
        assert receipt(owner)['status'] == 'STOP_UNCERTAIN'


def test_real_sdk_uses_fixed_owner_cockpit_path_without_a_socket(owner, monkeypatch):
    import socket
    from openai import OpenAI
    from agent.guest_inference import SerialHTTPTransport
    requests = []
    def handler(request):
        requests.append(json.loads(request.content))
        return response()
    def forbidden(*_args, **_kwargs):
        raise AssertionError('no real network or model allowed')
    with channel(owner, handler) as (server, client, _adapter), ThreadPoolExecutor(1) as pool:
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        serving = pool.submit(server.serve_one)
        with httpx.Client(transport=SerialHTTPTransport(client)) as http:
            with OpenAI(api_key='public-placeholder', base_url='http://guest.invalid/v1',
                        http_client=http, max_retries=0) as sdk:
                events = list(sdk.responses.create(model='guest-cannot-pick', input='offline SDK input', stream=True))
        serving.result(timeout=3)
        assert events[-1].type == 'response.completed'
        assert requests[0]['model'] == 'owner-fixed'
        assert requests[0]['input'] == 'offline SDK input'


def test_actual_request_byte_bound_includes_fixed_host_fields():
    policy = ResponsesPolicy('http://127.0.0.1/v1/responses', 'fixed', 'offline-policy')
    with pytest.raises(RuntimeStoreError, match='request_too_large'):
        request_body({'input': 'x' * (1024 * 1024 - 15)}, policy)


@pytest.mark.parametrize('damage', ['missing-last', 'missing-first', 'missing-cursor', 'reset-cursor', 'malformed-cursor', 'duplicate-cursor-key'])
def test_durable_high_water_refuses_deleted_history_before_serial_http(owner, damage):
    calls = []
    with channel(owner, lambda request: calls.append(request) or response()) as (server, client, adapter), ThreadPoolExecutor(1) as pool:
        for _ in range(2):
            serving = pool.submit(server.serve_one)
            assert client.call('inference', {'input': 'offline historical request'})['events']
            serving.result(timeout=3)
        def damage_history(conn):
            def remove(index):
                conn.execute('DELETE FROM state_meta WHERE key=?', (adapter.prefix + str(index),))
            def replace_cursor(value):
                conn.execute('UPDATE state_meta SET value=? WHERE key=?', (value, adapter.ledger_key))
            cursor = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (adapter.ledger_key,)).fetchone()[0])
            changes = {'missing-last': lambda: remove(2), 'missing-first': lambda: remove(1),
                       'missing-cursor': lambda: remove('cursor'),
                       'reset-cursor': lambda: replace_cursor(json.dumps(cursor | {'issued': 0}, sort_keys=True)),
                       'malformed-cursor': lambda: replace_cursor('null'),
                       'duplicate-cursor-key': lambda: replace_cursor(json.dumps(cursor, sort_keys=True).replace(
                           '"issued": 2', '"issued": 0, "issued": 2'))}
            changes[damage]()
        owner[0].db._execute_write(damage_history)
        serving = pool.submit(server.serve_one)
        with pytest.raises(WorkerPersistenceError):
            client.call('inference', {'input': 'must not spend a third operation'})
        serving.result(timeout=3)
        assert len(calls) == 2
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        assert owner[0].db._read_all('SELECT key FROM state_meta WHERE key=?', (adapter.prefix + '3',)) == []


def test_malformed_current_receipt_still_revokes_original_owner(owner):
    entered, release = threading.Event(), threading.Event()
    def handler(_request):
        entered.set()
        assert release.wait(4)
        return response()
    with channel(owner, handler) as (server, _client, adapter), ThreadPoolExecutor(1) as pool:
        future = pool.submit(server._dispatch, 'inference', {'input': 'offline'})
        try:
            assert entered.wait(2)
            owner[0].db._execute_write(lambda conn: conn.execute('UPDATE state_meta SET value=? WHERE key=?',
                ('null', adapter.prefix + '1')))
        finally:
            release.set()
        with pytest.raises(RuntimeStoreError):
            future.result(timeout=3)
        assert owner[0].db._read_one('SELECT status FROM worker_executions')[0] == 'unknown'
        assert owner[0].db.get_meta(adapter.prefix + '1') == 'null'
        assert adapter.persistence_failure is not None


def test_cockpit_operation_observes_committed_reservation_on_independent_connection(owner):
    from contextlib import closing
    import sqlite3
    observed = []
    def handler(_request):
        with closing(sqlite3.connect(owner[0].db.db_path)) as conn:
            cursor = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (adapter.ledger_key,)).fetchone()[0])
            reservation = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (adapter.prefix + '1',)).fetchone()[0])
            observed.append((cursor, reservation))
        return response()
    with channel(owner, handler) as (server, _client, adapter):
        server._dispatch('inference', {'input': 'offline'})
        cursor, reservation = observed[0]
        assert cursor['issued'] == 1
        assert reservation['status'] == 'STARTING' and reservation['network_complete'] is False
        assert cursor['scope'] == reservation['scope'] == owner[2]
