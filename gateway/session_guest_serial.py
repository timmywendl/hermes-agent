"""Original SessionAuthority's Q2 serial endpoint; never an alternative Owner.

No Native entry is enabled by this module. An approved physical acquisition must
supply the inherited socketpair endpoint bound to this exact reservation. Q1's
inert campaign, grant and helper are not extended or reused as launch authority.
"""
import json
import threading

from agent.guest_inference import validate_request
from agent.guest_serial import SerialError, SerialWire
from gateway.session_worker_guest import GuestOwnerEndpoint
from hermes_state_runtime import RuntimeStoreError


class OwnerSerialSession:
    def __init__(self, endpoint, fd, work, *, inference=None, activity=None):
        if not isinstance(endpoint, GuestOwnerEndpoint) or work['assignment'] != endpoint.scope:
            raise RuntimeStoreError('guest_scope_mismatch')
        from gateway.session_hvf_adapter import _require_owner
        _require_owner(endpoint.authority)
        from agent.runtime_session_guest import validate_guest_work
        self.endpoint, self.work = endpoint, validate_guest_work(work)
        # A future protected D2 binding supplies this fixed Responses callable;
        # no config flag or Guest request can enable real inference today.
        self.inference = inference
        self.activity = activity
        self.stop = threading.Event()
        self.io_lock = threading.Lock()
        self.inference_count = 0
        workers = getattr(endpoint.authority, '_q2_guest_channels', None)
        if workers is None:
            workers = endpoint.authority._q2_guest_channels = {}
        key = endpoint.scope['session_id']
        if key in workers:
            raise RuntimeStoreError('guest_unretired_channel')
        encoded = json.dumps(self.work, sort_keys=True, separators=(',', ':'), allow_nan=False)
        with endpoint.authority.db._read_ctx() as conn:
            endpoint._verify(conn)
            saved = conn.execute('SELECT value FROM state_meta WHERE key=?',
                                 ('guest.work.v1:' + endpoint.scope['execution_id'],)).fetchone()
            if saved is None or saved[0] != encoded or getattr(endpoint, '_prepared_work', None) != encoded:
                raise RuntimeStoreError('guest_work_not_prepared')
        self.wire = SerialWire(fd, endpoint.scope)
        workers[key] = self  # retained on EOF, cancel, result or Owner loss

    def serve_one(self):
        with self.io_lock:
            if self.wire.closed.is_set():
                raise SerialError('guest_transport_closed')
            self._serve_one()

    def _serve_one(self):
        try:
            frame = self.wire.receive()
            with self.endpoint.authority.db._read_ctx() as conn:
                self.endpoint._verify(conn)
            if frame['kind'] == 'event' and frame['channel'] == 'activity':
                self._activity(frame['payload'])
                return
            if frame['kind'] != 'request':
                raise SerialError('unexpected_guest_frame')
            try:
                result = self._dispatch(frame['channel'], frame['payload'])
                payload = {'result': result}
            except RuntimeStoreError as exc:
                payload = {'error': exc.reason}
            self.wire.send(frame['channel'], 'reply', payload, reply_to=frame['seq'])
        except (ValueError, TypeError, KeyError, OSError, EOFError):
            self.cancel(send=False)
            import os
            import socket
            with socket.socket(fileno=os.dup(self.wire.fd)) as connection:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError as exc:
                    import errno
                    if exc.errno != errno.ENOTCONN:
                        raise
            self.wire.close()
            raise

    def _dispatch(self, channel, payload):
        if self.stop.is_set():
            raise RuntimeStoreError('guest_channel_revoked')
        if channel == 'persistence':
            return self.endpoint(payload)
        if channel == 'context' and payload == {'operation': 'assignment'}:
            self.endpoint.require_host_operation()
            return self.work
        if channel == 'inference':
            validate_request(payload)
            if self.inference is None:
                raise RuntimeStoreError('d2_not_accepted')
            self.endpoint.require_host_operation()
            if self.inference_count >= 32:
                raise RuntimeStoreError('guest_inference_budget_spent')
            self.inference_count += 1
            # Callable contract is Owner's fixed Cockpit Responses route; headers,
            # account, model, fallback and HTTP destination are not Guest inputs.
            result = self.inference(payload)
            if self.stop.is_set():
                raise RuntimeStoreError('guest_channel_revoked')
            with self.endpoint.authority.db._read_ctx() as conn:
                self.endpoint._verify(conn)
            if len(json.dumps(result, allow_nan=False).encode()) > 2 * 1024 * 1024:
                raise RuntimeStoreError('guest_inference_result_too_large')
            return result
        raise RuntimeStoreError('unsupported_guest_operation')

    def _activity(self, payload):
        allowed = {'ready', 'delta', 'tool.start', 'tool.complete', 'result', 'finished'}
        if not isinstance(payload, dict) or payload.get('type') not in allowed:
            raise SerialError('unsupported_guest_activity')
        if self.activity is not None:
            self.activity(payload)  # untrusted display data; never a retirement receipt
        if payload['type'] == 'result':
            self.wire.send('lifecycle', 'control', {'type': 'finish'})

    def close_transport(self):
        """Join the synchronous service section and close our duplicated descriptor.

        This is transport cleanup only. Original Owner accounting and durable
        UNKNOWN remain until an independently qualified physical finalizer runs.
        """
        self.stop.set()
        self.wire.close()
        if not self.io_lock.acquire(timeout=2):
            raise RuntimeStoreError('guest_service_unretired')
        try:
            try:
                self.endpoint.revoke()
            finally:
                self.wire.release_fd()
        finally:
            self.io_lock.release()


    def cancel(self, *, send=True):
        self.stop.set()
        self.endpoint.revoke()
        if send:
            self.wire.send('lifecycle', 'control', {'type': 'stop'})
        # Physical Stop/wait/retirement stays with the original Owner's approved
        # HVF acquisition. This source-only phase cannot mint a Native proof.


def interrupt_guest(authority, session_id, generation):
    channel = getattr(authority, '_q2_guest_channels', {}).get(session_id)
    if channel is None:
        return False
    if channel.endpoint.scope['generation'] != generation:
        raise RuntimeStoreError('stale_generation')
    channel.cancel()
    return True


def stop_guest_channels(authority):
    import asyncio
    from gateway.session_runtime_workers import track_mutation
    for channel in getattr(authority, '_q2_guest_channels', {}).values():
        if not channel.stop.is_set():
            channel.stop.set()  # closes authorization before the off-loop writer waits
            channel.cancel_task = track_mutation(authority, asyncio.to_thread(channel.cancel))
