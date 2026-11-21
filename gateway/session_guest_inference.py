"""Original Owner's fixed Cockpit Responses operation; no live binding/selector.

A protected Host caller must supply a pinned policy, headers and HTTP transport.
There is deliberately no default network transport or credential/config discovery.
Only deterministic injected transport is qualified by the accompanying tests.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import sqlite3
import threading
import time
from urllib.parse import urlsplit

import httpx

from agent.guest_inference import validate_request
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from hermes_state_runtime import RuntimeStoreError


@dataclass(frozen=True)
class ResponsesPolicy:
    url: str
    model: str
    binding_id: str
    deadline: float = 120
    idle_timeout: float = 30
    max_output_tokens: int = 8192

    def __post_init__(self):
        parsed = urlsplit(self.url)
        if (parsed.scheme != 'http' or not ipaddress.ip_address(parsed.hostname).is_loopback
                or parsed.path != '/v1/responses' or parsed.query or parsed.fragment
                or parsed.username is not None or parsed.password is not None):
            raise ValueError('fixed_local_cockpit_responses_required')
        if (not isinstance(self.model, str) or not 0 < len(self.model) <= 256
                or not isinstance(self.binding_id, str) or not 0 < len(self.binding_id) <= 256
                or not 0 < self.deadline <= 120 or not 0 < self.idle_timeout <= 30
                or type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= 8192):
            raise ValueError('bounded_owner_policy_required')


def local_schema(value, depth=0):
    if depth > 32:
        raise RuntimeStoreError('cockpit_schema_too_deep')
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('$ref', '$dynamicRef') and (not isinstance(child, str) or not (child == '#' or child.startswith('#/'))):
                raise RuntimeStoreError('cockpit_remote_schema_forbidden')
            local_schema(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            local_schema(child, depth + 1)


def request_body(payload, policy):
    validate_request(payload)
    for tool in payload.get('tools', []):
        if set(tool) - {'type', 'name', 'description', 'parameters', 'strict'}:
            raise RuntimeStoreError('cockpit_local_function_required')
        local_schema(tool.get('parameters', {}))
    local_schema(payload.get('text', {}))
    maximum = payload.get('max_output_tokens', policy.max_output_tokens)
    if type(maximum) is not int or not 1 <= maximum <= policy.max_output_tokens:
        raise RuntimeStoreError('cockpit_output_budget_invalid')
    # JSON roundtrip takes an independent immutable-in-flight snapshot of Guest data.
    body = json.loads(json.dumps(payload, allow_nan=False))
    body.update(model=policy.model, stream=True, store=False, max_output_tokens=maximum)
    if len(json.dumps(body, separators=(',', ':'), allow_nan=False).encode()) > 1024 * 1024:
        raise RuntimeStoreError('cockpit_request_too_large')
    return body


def usage_receipt(event):
    usage = event.get('response', {}).get('usage')
    result = {'tokens_status': 'UNKNOWN', 'actual_cost_usd': None, 'cost_status': 'UNKNOWN'}
    if usage is None:
        return result
    if not isinstance(usage, dict):
        raise RuntimeStoreError('cockpit_usage_invalid')
    counters = {key: usage.get(key) for key in ('input_tokens', 'output_tokens', 'total_tokens')}
    if any(type(value) is not int or not 0 <= value <= 2**53 for value in counters.values()):
        raise RuntimeStoreError('cockpit_usage_invalid')
    return result | counters | {'tokens_status': 'REPORTED_BY_COCKPIT'}


class EventCollector:
    """Finite Responses SSE decoder; no HTTP headers/errors are forwarded."""
    def __init__(self):
        self.pending = bytearray()
        self.data = []
        self.events = []
        self.total = 0
        self.completed = False
        self.usage = usage_receipt({})

    def feed(self, chunk):
        self.total += len(chunk)
        if self.total > 2 * 1024 * 1024:
            raise RuntimeStoreError('cockpit_response_too_large')
        self.pending.extend(chunk)
        while b'\n' in self.pending:
            line, _, remainder = self.pending.partition(b'\n')
            self.pending = bytearray(remainder)
            if len(line) > 65536:
                raise RuntimeStoreError('cockpit_event_too_large')
            self.line(bytes(line).removesuffix(b'\r'))
        if len(self.pending) > 65536:
            raise RuntimeStoreError('cockpit_event_too_large')

    def line(self, line):
        if not line:
            if self.data:
                self.event(b'\n'.join(self.data))
                self.data.clear()
        elif line.startswith(b'data:'):
            self.data.append(line[5:].lstrip(b' '))
            if sum(map(len, self.data)) > 65536:
                raise RuntimeStoreError('cockpit_event_too_large')
        elif not (line.startswith(b':') or line.startswith(b'event:')):
            raise RuntimeStoreError('cockpit_sse_invalid')

    def event(self, data):
        if data == b'[DONE]' and self.completed:
            return
        if self.completed or len(self.events) >= 1024:
            raise RuntimeStoreError('cockpit_event_order_invalid')
        try:
            event = json.loads(data)
        except (ValueError, UnicodeError, RecursionError):
            raise RuntimeStoreError('cockpit_event_invalid') from None
        if not isinstance(event, dict) or not isinstance(event.get('type'), str):
            raise RuntimeStoreError('cockpit_event_invalid')
        kind = event['type']
        if (not kind.startswith('response.') or kind in ('response.failed', 'response.incomplete', 'response.cancelled')
                or set(event) & {'headers', 'authorization', 'api_key'}):
            raise RuntimeStoreError('cockpit_response_failed')
        if kind == 'response.completed':
            response = event.get('response')
            if not isinstance(response, dict) or response.get('status') != 'completed':
                raise RuntimeStoreError('cockpit_response_failed')
            self.usage = usage_receipt(event)
            self.completed = True
        json.dumps(event, allow_nan=False)
        self.events.append(event)

    def finish(self):
        if self.pending or self.data or not self.completed:
            raise RuntimeStoreError('cockpit_response_incomplete')
        return {'events': self.events}


def metadata_value(raw):
    try:
        value = json.loads(raw)
        if json.dumps(value, sort_keys=True, allow_nan=False) != raw:
            raise ValueError('noncanonical metadata')
    except (ValueError, TypeError, RecursionError):
        raise RuntimeStoreError('cockpit_metadata_invalid') from None
    return value


class OwnerResponses:
    """One finite HTTP operation, retained by the original Owner's serial slot.

    Timed-out network threads are never dropped or treated as retired. Their
    Future/client remains reachable here; transport close refuses until joined.
    Audit records use original SessionDB state_meta, not a second usage Store.
    """
    def __init__(self, endpoint, policy, *, transport, headers):
        if not isinstance(policy, ResponsesPolicy) or not isinstance(transport, httpx.BaseTransport):
            raise ValueError('explicit_host_binding_required')
        self.endpoint, self.policy = endpoint, policy
        self.transport = transport
        self.cleanup_failures = []
        self.client = httpx.Client(transport=transport, headers=headers, trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(policy.idle_timeout, connect=5, pool=5))
        self.client.headers['accept-encoding'] = 'identity'
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='hermes-owner-responses')
        self.stop = None
        self.lock = threading.Lock()
        self.pending = None
        self.persistence_failure = None
        self.active_response = None
        self.closed = False
        self.issued = 0
        self.expected_hashes = {}
        self.prefix = "guest.inference.v1:" + endpoint.scope["execution_id"] + ":"
        self.ledger_key = self.prefix + "cursor"
        self.policy_digest = hashlib.sha256(json.dumps(asdict(policy), sort_keys=True).encode()).hexdigest()

    def bind(self, endpoint, stop, conn):
        if endpoint is not self.endpoint or self.stop is not None:
            raise RuntimeStoreError('cockpit_owner_binding_mismatch')
        endpoint._verify(conn)
        if conn.execute('SELECT 1 FROM state_meta WHERE substr(key,1,?)=?',
                        (len(self.prefix), self.prefix)).fetchone():
            raise RuntimeStoreError('cockpit_ledger_already_bound')
        cursor = {'scope': endpoint.scope, 'policy_sha256': self.policy_digest, 'issued': 0}
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)',
                     (self.ledger_key, json.dumps(cursor, sort_keys=True)))
        self.stop = stop

    def _ledger(self, conn):
        rows = dict(conn.execute('SELECT key,value FROM state_meta WHERE substr(key,1,?)=?',
                                 (len(self.prefix), self.prefix)).fetchall())
        cursor = metadata_value(rows.pop(self.ledger_key, 'null'))
        expected = {'scope': self.endpoint.scope, 'policy_sha256': self.policy_digest, 'issued': self.issued}
        if (cursor != expected or not isinstance(cursor, dict) or type(cursor.get('issued')) is not int
                or not 0 <= self.issued <= 32
                or set(rows) != {self.prefix + str(index) for index in range(1, self.issued + 1)}):
            raise RuntimeStoreError('cockpit_ledger_unavailable')
        return {key: self._receipt(key, raw) for key, raw in rows.items()}

    def _receipt(self, key, raw):
        record = metadata_value(raw)
        fields = {'scope', 'policy_sha256', 'request_sha256', 'status', 'network_complete', 'usage'}
        if (not isinstance(record, dict) or set(record) != fields
                or record['scope'] != self.endpoint.scope or record['policy_sha256'] != self.policy_digest
                or record['request_sha256'] != self.expected_hashes.get(key)
                or record['status'] not in ('STARTING', 'RECEIVED', 'STOP_UNCERTAIN')
                or type(record['network_complete']) is not bool or not isinstance(record['usage'], dict)):
            raise RuntimeStoreError('cockpit_receipt_unavailable')
        return record

    def _reserve(self, body):
        encoded = json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False)
        def write(conn):
            self.endpoint._verify(conn)
            self.endpoint.require_host_operation()
            records = self._ledger(conn)
            if self.issued >= 32:
                raise RuntimeStoreError('guest_inference_budget_spent')
            if any(row['status'] != 'RECEIVED' or row['network_complete'] is not True for row in records.values()):
                raise RuntimeStoreError('cockpit_previous_request_unknown')
            issued = self.issued + 1
            key = self.prefix + str(issued)
            record = {'scope': self.endpoint.scope, 'policy_sha256': self.policy_digest,
                      'request_sha256': hashlib.sha256(encoded.encode()).hexdigest(),
                      'status': 'STARTING', 'network_complete': False, 'usage': usage_receipt({})}
            conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (key, json.dumps(record, sort_keys=True)))
            cursor = {'scope': self.endpoint.scope, 'policy_sha256': self.policy_digest, 'issued': issued}
            conn.execute('UPDATE state_meta SET value=? WHERE key=?',
                         (json.dumps(cursor, sort_keys=True), self.ledger_key))
            return key, issued
        key, self.issued = self.endpoint.authority.db._execute_write(write)
        self.expected_hashes[key] = hashlib.sha256(encoded.encode()).hexdigest()
        return key

    def _record(self, key, *, status, network_complete, usage=None):
        def write(conn):
            self.endpoint._verify(conn, allow_unknown=True)
            records = self._ledger(conn)
            if key not in records:
                raise RuntimeStoreError('cockpit_receipt_unavailable')
            record = records[key]
            record.update(status='STOP_UNCERTAIN' if self.stop.is_set() or record['status'] == 'STOP_UNCERTAIN' else status,
                          network_complete=record['network_complete'] or network_complete)
            if usage is not None:
                record['usage'] = usage
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (json.dumps(record, sort_keys=True), key))
        self.endpoint.authority.db._execute_write(write)

    def _exchange(self, body):
        collector = EventCollector()
        request = self.client.build_request('POST', self.policy.url, json=body)
        response = self.client.send(request, stream=True, follow_redirects=False)
        self.active_response = response
        try:
            if response.status_code != 200 or response.headers.get('content-encoding', 'identity') != 'identity':
                raise RuntimeStoreError('cockpit_response_rejected')
            if response.headers.get('content-type', '').split(';')[0].strip() != 'text/event-stream':
                raise RuntimeStoreError('cockpit_sse_required')
            for chunk in response.iter_raw(chunk_size=4096):
                collector.feed(chunk)
                if self.stop.is_set() and not collector.completed:
                    raise RuntimeStoreError('guest_channel_revoked')
            return collector.finish(), collector.usage
        finally:
            # Keep a strong reference if the real close raises. HTTPX's is_closed
            # flag is set before stream.close and is not proof that it succeeded.
            response.stream.close()
            self.active_response = None

    def _perform(self, body, key):
        token = set_hermes_home_override(self.endpoint.authority.profile_id)
        try:
            self.endpoint.require_host_operation()
            if self.stop.is_set():
                raise RuntimeStoreError('guest_channel_revoked')
            result, usage = self._exchange(body)
            self._record(key, status='RECEIVED', network_complete=True, usage=usage)
            return result
        finally:
            reset_hermes_home_override(token)

    def _uncertain(self, key):
        self.stop.set()
        try:
            if key is not None:
                self._record(key, status='STOP_UNCERTAIN', network_complete=False)
        except (ValueError, OSError, sqlite3.Error) as failure:
            self.persistence_failure = failure
        try:
            self.endpoint.revoke()
        except (ValueError, OSError, sqlite3.Error) as failure:
            self.persistence_failure = failure

    def __call__(self, payload):
        if self.stop is None or self.stop.is_set() or self.closed:
            raise RuntimeStoreError('cockpit_binding_unavailable')
        body = request_body(payload, self.policy)
        if not self.lock.acquire(blocking=False):
            raise RuntimeStoreError('cockpit_request_in_flight')
        key = None
        try:
            if self.pending is not None and not self.pending.done():
                raise RuntimeStoreError('cockpit_request_unretired')
            self.endpoint.require_host_operation()
            key = self._reserve(body)
            deadline = time.monotonic() + self.policy.deadline
            self.pending = self.executor.submit(self._perform, body, key)
            while True:
                remaining = deadline - time.monotonic()
                if self.stop.is_set() or remaining <= 0:
                    raise RuntimeStoreError('cockpit_request_cancelled_or_deadline')
                try:
                    result = self.pending.result(timeout=min(remaining, .05))
                    break
                except FutureTimeout:
                    continue
            if self.stop.is_set() or time.monotonic() >= deadline:
                raise RuntimeStoreError('cockpit_late_result')
            self.endpoint.require_host_operation()
            return result
        except (ValueError, TypeError, KeyError, OSError, RuntimeError, httpx.HTTPError, sqlite3.Error):
            self._uncertain(key)
            raise RuntimeStoreError('cockpit_request_unsettled') from None
        finally:
            self.lock.release()

    def close(self):
        if self.stop is not None:
            self.stop.set()
        if self.pending is not None and not self.pending.done():
            raise RuntimeStoreError('cockpit_request_unretired')
        self.executor.shutdown(wait=True, cancel_futures=True)
        resources = ([self.active_response.stream] if self.active_response is not None else [])
        resources.extend((self.client, self.transport))
        failures = []
        for resource in resources:
            try:
                resource.close()
            except (ValueError, OSError, RuntimeError, httpx.HTTPError) as failure:
                failures.append(failure)
        if failures:
            self.cleanup_failures.extend(failures)
            raise RuntimeStoreError('cockpit_http_unretired')
        self.active_response = None
        self.closed = True
