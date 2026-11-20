"""Guest channel binding for the existing durable RuntimeSessionStore.

The exchange callable is supplied by the scoped VM transport, not discovered
through a Host profile, WebSocket ticket, environment variable or SQLite path.
"""
import json
import threading

from agent.runtime_session_store import RuntimeSessionStore, WorkerPersistenceError


def validate_guest_work(frame):
    """Closed work-data projection; never hydrate a Host launch policy in Guest."""
    fields = {'version', 'assignment', 'title', 'body', 'repo', 'base_commit',
              'branch', 'workspace', 'role', 'model', 'completion_contract'}
    scope_fields = {'session_id', 'generation', 'epoch', 'execution_id', 'task_id', 'run_id',
                    'vm_id', 'connection_generation', 'image_digest', 'policy_digest'}
    if (not isinstance(frame, dict) or set(frame) != fields
            or frame['version'] != 'HERMES_GUEST_WORK_V1'
            or not isinstance(frame['assignment'], dict) or set(frame['assignment']) != scope_fields):
        raise WorkerPersistenceError('invalid_guest_work')
    scope = frame['assignment']
    if (any(type(scope[key]) is not int or scope[key] < 1
            for key in ('generation', 'epoch', 'run_id', 'connection_generation'))
            or any(not isinstance(scope[key], str) or not scope[key] or len(scope[key]) > 256
                   for key in scope_fields - {'generation', 'epoch', 'run_id', 'connection_generation'})):
        raise WorkerPersistenceError('invalid_guest_work')
    if (frame['workspace'] != '/task' or frame['role'] not in ('developer', 'reviewer')
            or any(not isinstance(frame[key], str) or len(frame[key]) > limit for key, limit in
                   (('title', 2000), ('body', 64000), ('repo', 256), ('base_commit', 64),
                    ('branch', 256), ('model', 256), ('completion_contract', 2048)))):
        raise WorkerPersistenceError('invalid_guest_work')
    import re
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', frame['repo'])
            or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', frame['base_commit'])
            or not frame['title'] or not frame['model'] or not frame['branch']):
        raise WorkerPersistenceError('invalid_guest_work')
    return json.loads(json.dumps(frame))


class GuestByteChannel:
    """Bounded request/reply over an already connected, VM-scoped binary stream.

    The native transport supplies the stream and its finite I/O deadline. There
    is no endpoint discovery, reconnect, ticket fallback or network listener.
    """

    def __init__(self, stream):
        self.stream = stream
        self.lock = threading.Lock()
        self.sequence = 0
        self.failure = None

    def __call__(self, request):
        from agent.managed_worker import encode_frame, read_frame
        with self.lock:
            if self.failure is not None:
                raise WorkerPersistenceError(self.failure)
            self.sequence += 1
            try:
                self.stream.write(encode_frame({'version': 1, 'id': self.sequence, 'request': request}))
                self.stream.flush()
                response = read_frame(self.stream)
                if (set(response) not in ({'version', 'id', 'result'}, {'version', 'id', 'error'})
                        or type(response['version']) is not int or response['version'] != 1
                        or type(response['id']) is not int or response['id'] != self.sequence):
                    raise WorkerPersistenceError('invalid_guest_reply')
            except (OSError, EOFError, ValueError, WorkerPersistenceError):
                self.failure = 'guest_transport_lost'
                raise
            if 'error' in response:
                reason = response['error']
                if not isinstance(reason, str) or not reason or len(reason) > 80:
                    self.failure = 'invalid_guest_reply'
                    raise WorkerPersistenceError(self.failure)
                raise WorkerPersistenceError(reason)
            return response['result']


class GuestWorkerRPC:
    def __init__(self, exchange, scope):
        self.exchange = exchange
        self.scope = json.loads(json.dumps(scope))

    def __call__(self, method, **params):
        extra = {'worker.adopt': set(), 'worker.persist': {'sequence', 'operation', 'payload'}}
        if method not in extra or set(params) != set(self.scope) | extra[method]:
            raise WorkerPersistenceError('unsupported_guest_operation')
        supplied = {key: params[key] for key in self.scope}
        if json.dumps(supplied, sort_keys=True) != json.dumps(self.scope, sort_keys=True):
            raise WorkerPersistenceError('guest_scope_mismatch')
        return self.exchange({'method': method, 'scope': self.scope,
                              'params': {key: params[key] for key in extra[method]}})


def guest_session_store(exchange, scope, outbox_dir):
    """Adopt one reserved VM assignment and reuse the existing retry journal."""
    rpc = GuestWorkerRPC(exchange, scope)
    adopted = rpc('worker.adopt', **scope)
    return GuestRuntimeSessionStore(rpc, scope, outbox_dir, adopted=adopted)


class GuestRuntimeSessionStore(RuntimeSessionStore):
    def _bind_process_ledger(self):
        """Guest delegation is unsupported; never bind its PID as a Host PID.

        The original worker ledger fails closed when no store is bound. The
        original managed runtime also removes delegation from its toolsets.
        """


def guest_worker_frame(work, *, inference_base_url):
    """Construct a Guest-only runtime policy, without restoring Host config.

    The approved native transport must supply a VM-local inference bridge. This
    function neither starts that bridge nor authenticates a physical channel.
    """
    from urllib.parse import urlsplit
    work = validate_guest_work(work)
    try:
        route = urlsplit(inference_base_url)
        port = route.port
    except (ValueError, TypeError):
        raise WorkerPersistenceError('invalid_guest_inference_route') from None
    if (not isinstance(inference_base_url, str) or route.scheme != 'http' or route.hostname != '127.0.0.1' or route.path != '/v1'
            or route.username is not None or route.password is not None or route.query or route.fragment
            or port is None or port < 1):
        raise WorkerPersistenceError('invalid_guest_inference_route')
    config = {
        'model': {'default': work['model'], 'provider': 'custom:guest-inference', 'base_url': inference_base_url,
                  'openai_runtime': 'codex_app_server'},
        'providers': {'guest-inference': {'base_url': inference_base_url, 'api_mode': 'codex_responses'}},
        'agent': {'max_turns': 32}, 'checkpoints': {'enabled': False},
        'auxiliary': {'title_generation': {'enabled': False}},
        'terminal': {'backend': 'local', 'cwd': '/task'},
    }
    policy = {
        'source': 'kanban', 'platform': 'cli', 'cwd': '/task', 'model': work['model'],
        'toolsets': ['terminal', 'file'], 'config_json': json.dumps(config),
        'request_json': json.dumps({'ignore_rules': True,
            'turn_v1': {'finite': True, 'unattended': True, 'yolo': False}}),
        'terminal_json': json.dumps({'TERMINAL_CWD': '/task', 'TERMINAL_ENV': 'local'}),
        'safe_mode': True, 'ignore_user_config': True,
    }
    text = '\n\n'.join(value for value in (
        work['title'], work['body'], 'Completion contract: ' + work['completion_contract'],
        'Assigned role: ' + work['role'],
        'Work in /task. Keep changes within the assigned task. Report failures honestly.',
    ) if value)
    return {'scope': work['assignment'], 'policy': policy, 'api_key': 'guest-transport',
            'text': text, 'route': 'guest:' + work['assignment']['execution_id'],
            'user_id': '', 'chat_id': '', 'turn_author': None,
            'safe_mode': True, 'ignore_user_config': True}


def execute_guest(work, channel, *, persistence_exchange, control_stream, inference_base_url, outbox_dir):
    """Private Guest bootstrap into the original managed AIAgent runtime.

    Called only by an approved Guest entry on preconnected, distinct persistence
    and control channels. It provides no Host launch or public dispatch route.
    """
    frame = guest_worker_frame(work, inference_base_url=inference_base_url)
    from agent.managed_worker import bind_worker_policy, run_adopted
    bind_worker_policy(frame)  # must precede all config/provider/runtime imports
    from agent import runtime_session_store
    runtime_session_store._worker_process = True
    store = guest_session_store(persistence_exchange, frame['scope'], outbox_dir)
    try:
        run_adopted(frame, channel, store, control_stream=control_stream,
                    ready_identity={'assignment': frame['scope']})
    finally:
        store.close()
