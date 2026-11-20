"""Original-Owner persistence endpoint for an exclusively bound Guest channel.

This does not launch a VM, qualify an adapter, or admit a Board claim. The native
Owner must authenticate the exact VM/channel before attaching this endpoint;
Guest-supplied PID, profile paths, Board handles and bearer secrets are absent.
"""
from dataclasses import asdict, dataclass
import json
import threading

from gateway.session_admission import admission_fingerprint
from hermes_state_runtime import (
    RuntimeStoreError, _admission, _epoch, _secret_digest, _session,
    _worker_public, apply_worker_receipt,
)


@dataclass(frozen=True)
class GuestBinding:
    """Non-secret identity pinned by the Owner, never selected by an RPC frame."""

    task_id: str
    run_id: int
    vm_id: str
    connection_generation: int
    image_digest: str
    policy_digest: str

    def __post_init__(self):
        if any(not isinstance(value, str) or not value or len(value) > 256
               for value in (self.task_id, self.vm_id)):
            raise RuntimeStoreError('invalid_guest_binding')
        if any(type(value) is not int or value < 1 for value in (self.run_id, self.connection_generation)):
            raise RuntimeStoreError('invalid_guest_binding')
        if any(not isinstance(value, str) or len(value) != 64
               or any(char not in '0123456789abcdef' for char in value)
               for value in (self.image_digest, self.policy_digest)):
            raise RuntimeStoreError('invalid_guest_binding')


def _guest_claim(scope, principal_id):
    return admission_fingerprint(canonical_target=scope['session_id'],
                                 payload=scope | {'principal_id': principal_id})


def reserve_guest_admission(authority, *, admission_id, principal_id, binding):
    """Reserve the existing started admission without inventing a Host PID.

    A durable Board start reservation and native qualification are separate
    prerequisites for physical launch. This function grants neither.
    """
    authority._require_admission_open()
    if not isinstance(binding, GuestBinding):
        raise RuntimeStoreError('invalid_guest_binding')

    def write(conn):
        _epoch(conn, authority.epoch)
        row = _admission(conn, admission_id)
        if row['status'] != 'started' or row['owner_epoch'] != authority.epoch:
            raise RuntimeStoreError('producer_not_started')
        if row['principal_id'] != principal_id:
            raise RuntimeStoreError('permission_denied')
        session_id, generation = row['target_session_id'], row['generation']
        if _session(conn, session_id)['runtime_generation'] != generation:
            raise RuntimeStoreError('stale_generation')
        from hermes_state_runtime_workers import worker_states
        if worker_states(conn, session_id):
            raise RuntimeStoreError('unknown_execution')
        if conn.execute('SELECT 1 FROM worker_executions WHERE execution_id=?',
                        ('admission-worker:' + admission_id,)).fetchone():
            raise RuntimeStoreError('admission_conflict')
        scope = {'session_id': session_id, 'generation': generation, 'epoch': authority.epoch,
                 'execution_id': 'admission-worker:' + admission_id, **asdict(binding)}
        # The established admission-worker prefix prevents cross-epoch adoption.
        claim = _guest_claim(scope, principal_id)
        conn.execute("INSERT INTO worker_executions"
                     "(execution_id,session_id,kind,owner_epoch,generation,status,adoption_digest) "
                     "VALUES(?,?,'kanban',?,?,'registered',?)",
                     (scope['execution_id'], session_id, authority.epoch, generation, _secret_digest(claim)))
        return scope
    return authority.db._execute_write(write)


def _result_ready(db, conn, session_id, payload):
    if payload:
        raise RuntimeStoreError('invalid_params')
    # A Guest's last frame does not establish that its execution domain stopped.
    # Keep the existing worker exclusion until the original Owner proves retirement.
    return {'status': 'pending_retirement'}


def _guest_handlers():
    from hermes_state_runtime import _worker_append, _worker_turn, _worker_usage
    return {
        'transcript.append': _worker_append,
        'usage.main': _worker_usage,
        'usage.auxiliary': lambda db, conn, sid, p: _worker_usage(db, conn, sid, p, auxiliary=True),
        'guest.result_ready': _result_ready,
        **{name: (lambda db, conn, sid, p, op=name: _worker_turn(db, conn, sid, p, op))
           for name in ('turn.acquire', 'turn.renew', 'turn.release')},
    }


class GuestOwnerEndpoint:
    """An Owner-owned endpoint attached to one previously authenticated channel.

    It is intentionally not a public WebSocket method or a general Host RPC.
    The transport must never dispatch frames from another VM to this instance.
    """

    def __init__(self, authority, scope, *, principal_id):
        self.authority = authority
        self.scope = dict(scope)
        self.principal_id = principal_id
        self.lock = threading.Lock()
        self.revoked = False

    def _verify(self, conn, *, allow_unknown=False):
        from hmac import compare_digest
        _epoch(conn, self.scope['epoch'])
        row = conn.execute('SELECT * FROM worker_executions WHERE execution_id=?',
                           (self.scope['execution_id'],)).fetchone()
        admission_id = self.scope['execution_id'].removeprefix('admission-worker:')
        admission = _admission(conn, admission_id)
        if (self.authority.epoch != self.scope['epoch'] or row is None
                or row['owner_epoch'] != self.scope['epoch']
                or admission['owner_epoch'] != self.scope['epoch']):
            raise RuntimeStoreError('stale_epoch')
        if (row['kind'] != 'kanban' or row['session_id'] != self.scope['session_id']
                or row['generation'] != self.scope['generation']
                or admission['target_session_id'] != self.scope['session_id']
                or admission['generation'] != self.scope['generation']
                or _session(conn, self.scope['session_id'])['runtime_generation'] != self.scope['generation']
                or admission['principal_id'] != self.principal_id
                or not compare_digest(row['adoption_digest'],
                                      _secret_digest(_guest_claim(self.scope, self.principal_id)))):
            raise RuntimeStoreError('permission_denied')
        admissions = ('started', 'unknown') if allow_unknown else ('started',)
        workers = ('registered', 'running', 'unknown') if allow_unknown else ('registered', 'running')
        if admission['status'] not in admissions or row['status'] not in workers:
            raise RuntimeStoreError('unknown_execution')
        return row, admission

    def __call__(self, frame):
        with self.lock:
            if self.revoked:
                raise RuntimeStoreError('guest_channel_revoked')
            if (not isinstance(frame, dict) or set(frame) != {'method', 'scope', 'params'}
                    or json.dumps(frame['scope'], sort_keys=True) != json.dumps(self.scope, sort_keys=True)):
                raise RuntimeStoreError('permission_denied')
            with self.authority.db._read_ctx() as conn:
                self._verify(conn)
            method, params = frame['method'], frame['params']
            assignment = {key: self.scope[key] for key in ('epoch', 'session_id', 'execution_id', 'generation')}
            if method == 'worker.adopt' and params == {}:
                return self._adopt()
            if (method != 'worker.persist' or not isinstance(params, dict)
                    or set(params) != {'sequence', 'operation', 'payload'}):
                raise RuntimeStoreError('invalid_params')
            # Use the existing transaction/sequence/digest receipts, including lost-ACK retries.
            operation = 'guest.result_ready' if params['operation'] == 'execution.finish' else params['operation']
            return apply_worker_receipt(self.authority.db, **assignment, sequence=params['sequence'],
                operation=operation, payload=params['payload'],
                handlers={key: self._guard(handler) for key, handler in _guest_handlers().items()})

    def _adopt(self):
        def write(conn):
            self._verify(conn)
            conn.execute("UPDATE worker_executions SET status='running' WHERE execution_id=?",
                         (self.scope['execution_id'],))
            row = conn.execute('SELECT * FROM worker_executions WHERE execution_id=?',
                               (self.scope['execution_id'],)).fetchone()
            return _worker_public(row)
        return self.authority.db._execute_write(write)

    def _guard(self, handler):
        def write(db, conn, session_id, payload):
            # Revalidate inside the receipt's actual writer transaction, not only
            # before a competing Owner transaction acquires the SQLite lock.
            self._verify(conn)
            previous = conn.execute(
                'SELECT result_json FROM worker_receipts WHERE execution_id=? '
                'ORDER BY sequence DESC LIMIT 1', (self.scope['execution_id'],)).fetchone()
            if previous and json.loads(previous[0]) == {'status': 'pending_retirement'}:
                raise RuntimeStoreError('guest_result_pending_retirement')
            return handler(db, conn, session_id, payload)
        return write

    def revoke(self):
        """Loss is durable UNKNOWN; channel close is never a retirement receipt."""
        with self.lock:
            self.revoked = True

            def write(conn):
                worker, admission = self._verify(conn, allow_unknown=True)
                if worker['status'] == 'unknown' and admission['status'] == 'unknown':
                    return
                conn.execute("UPDATE worker_executions SET status='unknown' WHERE execution_id=?",
                             (self.scope['execution_id'],))
                admission_id = self.scope['execution_id'].removeprefix('admission-worker:')
                conn.execute("UPDATE session_admissions SET status='unknown' WHERE admission_id=?", (admission_id,))
                conn.execute('UPDATE sessions SET runtime_revision=runtime_revision+1 WHERE id=?',
                             (self.scope['session_id'],))
            self.authority.db._execute_write(write)


def serve_guest_request(stream, endpoint):
    """Process one frame on the original Owner's authenticated VM stream.

    Transport loss must call endpoint.revoke in the Owner's acquisition/cleanup
    path; this function never treats EOF or a sent reply as physical retirement.
    """
    from agent.managed_worker import encode_frame, read_frame
    request = read_frame(stream)
    if (set(request) != {'version', 'id', 'request'} or type(request['version']) is not int
            or request['version'] != 1 or type(request['id']) is not int or request['id'] < 1):
        raise RuntimeStoreError('invalid_guest_frame')
    response = {'version': 1, 'id': request['id']}
    try:
        response['result'] = endpoint(request['request'])
    except RuntimeStoreError as exc:
        response['error'] = exc.reason
    stream.write(encode_frame(response))
    stream.flush()
