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


_ASSIGNMENT_PREFIX = 'guest.assignment.v1:'


def _guest_assignment_record(conn, scope, principal_id):
    instance = conn.execute('SELECT instance_id FROM runtime_epoch WHERE singleton=1').fetchone()[0]
    return json.dumps({'version': 'HERMES_GUEST_ASSIGNMENT_V1', 'scope': scope,
                       'principal_id': principal_id, 'owner_instance': instance},
                      sort_keys=True, separators=(',', ':'), allow_nan=False)


def _verify_guest_assignment(conn, scope, principal_id):
    row = conn.execute('SELECT value FROM state_meta WHERE key=?',
                       (_ASSIGNMENT_PREFIX + scope['execution_id'],)).fetchone()
    # Immutable canonical bytes: malformed, missing, duplicate-key or mismatched
    # identity cannot be normalized into a new assignment after Owner loss.
    if row is None or row[0] != _guest_assignment_record(conn, scope, principal_id):
        raise RuntimeStoreError('guest_assignment_unavailable')


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
        key = _ASSIGNMENT_PREFIX + scope['execution_id']
        if conn.execute('SELECT 1 FROM state_meta WHERE key=?', (key,)).fetchone():
            raise RuntimeStoreError('guest_assignment_conflict')
        # The established admission-worker prefix prevents cross-epoch adoption.
        claim = _guest_claim(scope, principal_id)
        conn.execute("INSERT INTO worker_executions"
                     "(execution_id,session_id,kind,owner_epoch,generation,status,adoption_digest) "
                     "VALUES(?,?,'kanban',?,?,'registered',?)",
                     (scope['execution_id'], session_id, authority.epoch, generation, _secret_digest(claim)))
        # Persist the exact non-secret VM/Task/Run/Owner identity before exposing
        # the reservation. A failure here rolls back the worker row as well.
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)',
                     (key, _guest_assignment_record(conn, scope, principal_id)))
        return scope
    return authority.db._execute_write(write)


def _result_ready(db, conn, session_id, payload):
    if payload:
        raise RuntimeStoreError('invalid_params')
    # A Guest's last frame does not establish that its execution domain stopped.
    # Keep the existing worker exclusion until the original Owner proves retirement.
    return {'status': 'pending_retirement'}


def _guest_handlers(scope):
    from hermes_state_runtime import _worker_append, _worker_turn, _worker_usage
    from gateway.session_worker_guest_context import guest_context_handlers, guest_compression_handlers
    return {
        **guest_context_handlers(scope), **guest_compression_handlers(),
        'transcript.append': _worker_append,
        'usage.main': _worker_usage,
        'usage.auxiliary': lambda db, conn, sid, p: _worker_usage(db, conn, sid, p, auxiliary=True),
        'guest.result_ready': _result_ready,
        # A Guest holder is an opaque lease identity, never a Host PID proof.
        **{name: (lambda db, conn, sid, p, op=name: _worker_turn(db, conn, sid, p, op,
                                                              holder_is_dead=lambda _holder: False))
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
        # Revocation can only remove authority: damaged assignment bytes must
        # not prevent the original, digest-bound endpoint from recording UNKNOWN.
        if not allow_unknown:
            _verify_guest_assignment(conn, self.scope, self.principal_id)
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
                handlers={key: self._guard(handler) for key, handler in _guest_handlers(self.scope).items()})

    def _adopt(self):
        def write(conn):
            self._verify(conn)
            conn.execute("UPDATE worker_executions SET status='running' WHERE execution_id=?",
                         (self.scope['execution_id'],))
            row = conn.execute('SELECT * FROM worker_executions WHERE execution_id=?',
                               (self.scope['execution_id'],)).fetchone()
            return _worker_public(row)
        return self.authority.db._execute_write(write)

    def prepare_work(self, policy):
        """Read an original claimed Task into non-secret Guest work data.

        This snapshot is not launch authority; the native acquisition path must
        revalidate its durable Board custody before any physical operation.
        """
        from pathlib import Path
        import time
        from agent.runtime_session_guest import validate_guest_work
        from hermes_cli import kanban_db as kb
        from hermes_cli.kanban_db_connect import connect_closing
        from hermes_cli.kanban_db_workspace import _created_workspace_admission
        with self.lock:
            if self.revoked:
                raise RuntimeStoreError('guest_channel_revoked')
            with self.authority.db._read_ctx() as conn:
                self._verify(conn)
                if _session(conn, self.scope['session_id'])['source'] != 'kanban' or policy.source != 'kanban':
                    raise RuntimeStoreError('guest_session_not_admitted')
            context = json.loads(policy.kanban_json)
            if (context['task_id'] != self.scope['task_id'] or context['run_id'] != self.scope['run_id']):
                raise RuntimeStoreError('stale_kanban_claim')
            path = Path(context['db']).resolve(strict=True)
            with connect_closing(path) as conn, kb.write_txn(conn):
                task = kb.get_task(conn, self.scope['task_id'])
                run = conn.execute('SELECT * FROM task_runs WHERE id=?', (self.scope['run_id'],)).fetchone()
                if (task is None or run is None or task.status != 'running' or run['status'] != 'running'
                        or task.current_run_id != self.scope['run_id'] or run['task_id'] != task.id
                        or task.claim_lock != context['claim_lock'] or run['claim_lock'] != task.claim_lock
                        or type(task.claim_expires) is not int or task.claim_expires <= int(time.time())):
                    raise RuntimeStoreError('stale_kanban_claim')
                admission = _created_workspace_admission(conn, task.id)
                if (admission is None or task.workspace_kind != 'worktree'
                        or task.workspace_path != admission['workspace_path']
                        or task.branch_name != admission['branch_name']):
                    raise RuntimeStoreError('guest_workspace_not_admitted')
                marker = conn.execute(
                    "SELECT payload FROM task_events WHERE task_id=? AND run_id=? AND kind='owner_admitted' "
                    "ORDER BY id DESC LIMIT 1", (task.id, run['id'])).fetchone()
                if marker is None or json.loads(marker[0]).get('session_id') != self.scope['session_id']:
                    raise RuntimeStoreError('guest_session_not_admitted')
                return validate_guest_work({
                    'version': 'HERMES_GUEST_WORK_V1', 'assignment': self.scope,
                    'title': task.title, 'body': task.body or '', 'repo': admission['repo'],
                    'base_commit': admission['base_commit'], 'branch': admission['branch_name'],
                    'workspace': '/task', 'model': policy.model, 'completion_contract': task.completion_contract or '',
                    'role': 'reviewer' if kb._retry_status_for_run(conn, task.id, run['id']) == 'review' else 'developer',
                })

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

    Wire loss durably revokes this assignment. The acquisition/cleanup path
    still owns physical Stop; EOF or a sent reply is never a retirement proof.
    """
    try:
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
    except (EOFError, OSError, ValueError):
        # An applied receipt may already be committed when reply delivery fails.
        # Never remove the assignment or infer retirement from a broken channel.
        endpoint.revoke()
        raise
