"""Guest channel binding for the existing durable RuntimeSessionStore.

The exchange callable is supplied by the scoped VM transport, not discovered
through a Host profile, WebSocket ticket, environment variable or SQLite path.
"""
import json
import threading

from agent.runtime_session_store import RuntimeSessionStore, WorkerPersistenceError


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
    return RuntimeSessionStore(rpc, scope, outbox_dir, adopted=adopted)
