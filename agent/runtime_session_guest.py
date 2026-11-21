"""Guest channel binding for the existing durable RuntimeSessionStore.

The exchange callable is supplied by the scoped VM transport, not discovered
through a Host profile, WebSocket ticket, environment variable or SQLite path.
"""
import json

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


def guest_worker_frame(work):
    """Construct a Guest-only runtime policy, without restoring Host config.

    The placeholder URL is intercepted in-process; no Guest HTTP socket exists.
    """
    work = validate_guest_work(work)
    config = {
        'model': {'default': work['model'], 'provider': 'custom:guest-inference', 'base_url': 'http://guest.invalid/v1',
                  'openai_runtime': 'openai'},
        'providers': {'guest-inference': {'base_url': 'http://guest.invalid/v1', 'api_mode': 'codex_responses'}},
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


def execute_guest(work, channel, *, persistence_exchange, control_stream, outbox_dir):
    """Private Guest bootstrap into the original managed AIAgent runtime.

    Called by the Guest entry on the preconnected serial channel. No Host launch
    or public dispatch route is provided.
    """
    frame = guest_worker_frame(work)
    from agent.managed_worker import bind_worker_policy, run_adopted
    bind_worker_policy(frame)  # must precede all config/provider/runtime imports
    from agent import runtime_session_store
    runtime_session_store._worker_process = True
    store = guest_session_store(persistence_exchange, frame['scope'], outbox_dir)
    try:
        run_adopted(frame, channel, store, control_stream=control_stream,
                    ready_identity={'assignment': frame['scope']},
                    agent_factory=guest_agent_factory(channel))
    finally:
        store.close()


def guest_agent_factory(channel):
    """Reuse AIAgent with its SDK using a serial-only HTTP transport."""
    from run_agent import AIAgent
    from agent.guest_inference import SerialHTTPTransport
    import httpx
    from openai import OpenAI

    class GuestAgent(AIAgent):
        def __init__(self, **kwargs):
            kwargs.update(provider='custom', requested_provider='custom:guest-inference', api_mode='codex_responses')
            super().__init__(**kwargs)

        def _create_openai_client(self, kwargs, **_options):
            return OpenAI(api_key='guest-transport', base_url='http://guest.invalid/v1',
                          max_retries=0, http_client=httpx.Client(transport=SerialHTTPTransport(channel), trust_env=False))
    return GuestAgent
