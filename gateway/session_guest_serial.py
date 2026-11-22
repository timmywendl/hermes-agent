"""Original SessionAuthority's Q2 serial endpoint; never an alternative Owner.

No Native entry is enabled by this module. An approved physical acquisition must
supply the inherited socketpair endpoint bound to this exact reservation. Q1's
inert campaign, grant and helper are not extended or reused as launch authority.
"""
import json
import hashlib
import struct
import sqlite3
import threading
import time
import queue
from concurrent.futures import Future, CancelledError

from agent.guest_inference import validate_request
from agent.guest_serial import MAX_FRAME, SerialError, SerialWire, _json, _read
from gateway.session_worker_guest import GuestOwnerEndpoint
from hermes_state_runtime import RuntimeStoreError


BOOT_FRAME_MAX = 192
BOOT_FRAME_COUNT = 16
BOOT_LAST_STAGE = 14


def boot_scope_sha256(scope):
    raw = json.dumps(scope, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


class BootSerialWire(SerialWire):
    """The existing sole reader, specialized for an optional bounded prelude."""

    def __init__(self, fd, scope, on_boot):
        super().__init__(fd, scope)
        self.boot_digest = boot_scope_sha256(self.scope)
        self.boot_hints = []
        self.boot_done = False
        self.boot_deadline = time.monotonic() + 60
        self.on_boot = on_boot

    def _boot_schema(self, frame, raw):
        keys = {'boot', 'errno', 'failed', 'scope_sha256', 'seq', 'stage'}
        if (not isinstance(frame, dict) or set(frame) != keys or len(raw) > BOOT_FRAME_MAX or
                json.dumps(frame, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() != raw or
                any(type(frame[key]) is not int for key in ('boot', 'errno', 'failed', 'seq', 'stage')) or
                frame['boot'] != 1 or frame['failed'] not in (0, 1) or
                not 0 <= frame['errno'] <= 4095 or (not frame['failed'] and frame['errno'] != 0)):
            raise SerialError('invalid_boot_prelude')

    def _boot(self, frame, raw):
        self._boot_schema(frame, raw)
        previous = self.boot_hints[-1]['stage'] if self.boot_hints else 0
        if (self.boot_done or self.pump is not None or frame['scope_sha256'] != self.boot_digest or
                frame['seq'] != len(self.boot_hints) + 1 or frame['seq'] > BOOT_FRAME_COUNT or
                not 1 <= frame['stage'] <= BOOT_LAST_STAGE or
                frame['stage'] not in (previous, previous + 1) or
                (not frame['failed'] and frame['stage'] != previous + 1)):
            raise SerialError('invalid_boot_prelude')
        # Persist on the existing service thread before accepting the next frame.
        self.on_boot(dict(frame))
        self.boot_hints.append(dict(frame))
        if frame['failed']:
            self.boot_done = True
            raise SerialError('guest_boot_failure_hint')

    def _receive_frame(self):
        if self.failed:
            raise SerialError('serial_failed')
        try:
            while True:
                timeout = self.timeout if self.boot_done else min(self.timeout, self.boot_deadline - time.monotonic())
                size = struct.unpack('!I', _read(self.fd, 4, timeout, self.closed))[0]
                if not 0 < size <= MAX_FRAME:
                    raise SerialError('serial_frame_too_large')
                timeout = self.timeout if self.boot_done else min(self.timeout, self.boot_deadline - time.monotonic())
                raw = _read(self.fd, size, timeout, self.closed)
                frame = _json(raw)
                if isinstance(frame, dict) and ('boot' in frame or 'scope_sha256' in frame):
                    self._boot(frame, raw)
                    continue
                self._validate(frame)
                self.received += 1
                self.boot_done = True
                return frame
        except (TypeError, KeyError, RecursionError) as error:
            self.failed = True
            raise SerialError('invalid_serial_frame') from error
        except (ValueError, OSError, EOFError):
            self.failed = True
            raise


class OwnerSerialSession:
    def __init__(self, endpoint, fd, work, *, inference=None, activity=None, heartbeat_interval=5, heartbeat_lease=90,
                 defer_heartbeat=False, boot_diagnostics=False, boot_hint=None):
        if not isinstance(endpoint, GuestOwnerEndpoint) or work['assignment'] != endpoint.scope:
            raise RuntimeStoreError('guest_scope_mismatch')
        from gateway.session_hvf_adapter import _require_owner
        _require_owner(endpoint.authority)
        from agent.runtime_session_guest import validate_guest_work
        if boot_diagnostics and (not defer_heartbeat or not callable(boot_hint)):
            raise RuntimeStoreError('boot_requires_original_owner_service_callback')
        self.boot_hint = boot_hint
        self.endpoint, self.work = endpoint, validate_guest_work(work)
        # Protected Host injection only; D2 policy acceptance does not enable
        # a live connector, credential discovery or a Guest-selected route.
        self.inference = inference
        self.activity = activity
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.result_ready = threading.Event()
        self.persisted_finish = threading.Event()
        self.finished = threading.Event()
        self.peer_eof = threading.Event()
        self.transport_joined = threading.Event()
        self.ready_at = self.result_at = self.finished_at = self.peer_eof_at = None
        self.cleanup_errors = []
        self.service_future = None
        self.service_observed = False
        self.service_failure = None
        self.stop_sent = threading.Event()
        self.unknown_persisted = threading.Event()
        self.stop_lock = threading.Lock()
        self.io_lock = threading.Lock()
        self.inference_count = 0
        self.wire = None
        self.heartbeat_options = dict(interval=heartbeat_interval, lease=heartbeat_lease, on_failure=self._wire_failure)
        self.heartbeat_deferred = defer_heartbeat
        from gateway.session_guest_inference import OwnerResponses
        encoded = json.dumps(self.work, sort_keys=True, separators=(',', ':'), allow_nan=False)
        def attach(conn):
            endpoint._verify(conn)
            workers = endpoint.authority.__dict__.setdefault('_q2_guest_channels', {})
            key = endpoint.scope['session_id']
            if key in workers:
                raise RuntimeStoreError('guest_unretired_channel')
            saved = conn.execute('SELECT value FROM state_meta WHERE key=?',
                                 ('guest.work.v1:' + endpoint.scope['execution_id'],)).fetchone()
            if saved is None or saved[0] != encoded or getattr(endpoint, '_prepared_work', None) != encoded:
                raise RuntimeStoreError('guest_work_not_prepared')
            if isinstance(inference, OwnerResponses):
                inference.bind(endpoint, self.stop, conn)
            self.wire = (BootSerialWire(fd, endpoint.scope, self._boot_hint) if boot_diagnostics
                         else SerialWire(fd, endpoint.scope))
            if defer_heartbeat:
                self.wire.timeout = 60
            workers[key] = self  # retained on EOF, cancel, result or Owner loss
        try:
            endpoint.authority.db._execute_write(attach)
            if not defer_heartbeat:
                self.wire.start_heartbeat(**self.heartbeat_options)
        except Exception as failure:
            self.stop.set()
            if self.wire is not None:
                self.wire.close()
                self.wire.release_fd()
                try:
                    endpoint.revoke()
                except (sqlite3.Error, OSError, RuntimeStoreError) as storage_failure:
                    failure.add_note('Guest attachment revocation persistence failed: ' + str(storage_failure))
            raise

    def _boot_hint(self, frame):
        if self.wire.pump is not None or self.ready.is_set():
            raise SerialError('boot_after_worker_traffic')
        self.boot_hint(frame)

    def serve_one(self):
        with self.io_lock:
            if self.wire.closed.is_set() and self.wire.failure is None:
                raise SerialError('guest_transport_closed')
            return self._serve_one()

    def _serve_one(self):
        try:
            frame = self._receive()
            if self.stop_sent.is_set() and self.unknown_persisted.is_set() and self.endpoint.revoked:
                # Drain to actual peer EOF without admitting late operations.
                # A denial wakes the unchanged Guest's outstanding RPC.
                if frame['kind'] == 'request':
                    self.wire.send(frame['channel'], 'reply', {'error': 'guest_channel_revoked'},
                                   reply_to=frame['seq'])
                return True
            with self.endpoint.authority.db._read_ctx() as conn:
                self.endpoint._verify(conn)
            if frame['kind'] == 'event' and frame['channel'] == 'activity':
                self._activity(frame['payload'])
                return True
            if frame['kind'] != 'request':
                raise SerialError('unexpected_guest_frame')
            try:
                result = self._dispatch(frame['channel'], frame['payload'])
                payload = {'result': result}
            except RuntimeStoreError as exc:
                payload = {'error': exc.reason}
            if self.stop.is_set() and 'result' in payload:
                payload = {'error': 'guest_channel_revoked'}
            self.wire.send(frame['channel'], 'reply', payload, reply_to=frame['seq'])
            return True
        except (ValueError, TypeError, KeyError, RecursionError, OSError, EOFError) as failure:
            if isinstance(failure, EOFError) and str(failure) == 'serial_eof':
                self.peer_eof_at = self.peer_eof_at or time.monotonic()
                self.peer_eof.set()
            if (isinstance(failure, EOFError) and str(failure) == 'serial_eof'
                    and self.stop_sent.is_set() and self.unknown_persisted.is_set() and self.endpoint.revoked):
                with self.endpoint.authority.db._read_ctx() as conn:
                    worker, admission = self.endpoint._verify(conn, allow_unknown=True)
                    if worker['status'] != 'unknown' or admission['status'] != 'unknown':
                        raise RuntimeStoreError('guest_cancel_unknown_unverified')
                self.peer_eof.set()
                self._close_io()
                return False
            if isinstance(failure, EOFError) and str(failure) == 'serial_eof' and self.finished.is_set():
                try:
                    self._verify_finished()
                except (ValueError, OSError, sqlite3.Error) as verification_failure:
                    failure.add_note('Healthy finish not verified: ' + str(verification_failure))
                else:
                    self.peer_eof.set()
                    self._close_io()
                    return False
            try:
                self.cancel(send=False)
            except (sqlite3.Error, OSError, RuntimeStoreError) as storage_failure:
                failure.add_note('UNKNOWN persistence failed: ' + str(storage_failure))
            finally:
                self._close_io()
            raise

    def _wire_failure(self):
        # EOF can race the final queued frame. Only a committed logical finish
        # permits the service reader to drain it; all other loss revokes now.
        failure = self.wire.failure
        if isinstance(failure, EOFError) and str(failure) == 'serial_eof':
            self.peer_eof_at = time.monotonic()
            self.peer_eof.set()
            if self.result_ready.is_set() and self.persisted_finish.is_set():
                return
        self.stop.set()

    def _receive(self):
        try:
            if self.heartbeat_deferred:
                # Do not transmit into the Guest's still-cooked UART. The
                # accepted Guest performs TCSAFLUSH before its first frame.
                frame = self.wire.receive()
                self.wire.timeout = 30
                self.heartbeat_deferred = False
                self.wire.start_heartbeat(**self.heartbeat_options)
                if frame['kind'] != 'heartbeat':
                    return frame
                self.wire._heartbeat(frame['payload'])
            return self.wire.receive()
        except EOFError:
            if (self.result_ready.is_set() and self.persisted_finish.is_set()
                    and isinstance(self.wire.failure, EOFError)
                    and str(self.wire.failure) == 'serial_eof'):
                try:
                    return self.wire.inbox.get_nowait()
                except queue.Empty:
                    pass
            raise

    def _verify_finished(self):
        if not (self.result_ready.is_set() and self.persisted_finish.is_set() and self.finished.is_set()):
            raise RuntimeStoreError('guest_logical_finish_unverified')
        with self.endpoint.authority.db._read_ctx() as conn:
            self.endpoint._verify(conn)
            row = conn.execute('SELECT result_json FROM worker_receipts WHERE execution_id=? '
                               'ORDER BY sequence DESC LIMIT 1', (self.endpoint.scope['execution_id'],)).fetchone()
            if row is None or json.loads(row[0]) != {'status': 'pending_retirement'}:
                raise RuntimeStoreError('guest_logical_finish_unverified')

    def _close_io(self):
        """Always close the descriptor even if shutdown or pump joining fails."""
        import os
        import socket
        import errno
        try:
            if self.wire.fd >= 0:
                with socket.socket(fileno=os.dup(self.wire.fd)) as connection:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError as exc:
                        if exc.errno != errno.ENOTCONN:
                            raise
        finally:
            self.wire.close()
            self.wire.release_fd()

    def _dispatch(self, channel, payload):
        if self.stop.is_set():
            raise RuntimeStoreError('guest_channel_revoked')
        if channel == 'persistence':
            result = self.endpoint(payload)
            if (isinstance(payload, dict) and payload.get('method') == 'worker.persist'
                    and payload.get('params', {}).get('operation') == 'execution.finish'
                    and result == {'status': 'pending_retirement'}):
                self.persisted_finish.set()
            return result
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
        if payload['type'] == 'ready':
            self.ready_at = time.monotonic()
            self.ready.set()
        elif payload['type'] == 'result':
            self.wire.send('lifecycle', 'control', {'type': 'finish'})
            self.result_at = time.monotonic()
            self.result_ready.set()
        elif payload['type'] == 'finished':
            if not (self.result_ready.is_set() and self.persisted_finish.is_set()):
                raise SerialError('guest_finished_before_canonical_receipt')
            self.finished_at = time.monotonic()
            self.finished.set()
            self._verify_finished()

    def bind_service(self, future):
        """Bind the original Owner's one physical service operation for joining."""
        if self.service_future is not None or not isinstance(future, Future):
            raise RuntimeStoreError('guest_service_binding_conflict')
        self.service_future = future

    def _join_service(self, deadline, *, revoke):
        if self.service_future is None:
            return None
        from concurrent.futures import TimeoutError as ServiceTimeout
        try:
            failure = self.service_future.exception(timeout=max(0, min(2, deadline - time.monotonic())))
        except ServiceTimeout:
            return RuntimeStoreError('guest_service_unretired')
        except CancelledError as cancelled:
            failure = cancelled
        self.service_observed = True
        if failure is None:
            self.service_future.result()  # completed successfully; never waits here
        else:
            self.service_failure = str(failure)
            if not revoke or not isinstance(failure, Exception):
                return failure
        return None

    def _cleanup_transport(self, *, deadline, revoke):
        self.stop.set()
        self.wire.close()
        failures = []
        if revoke:
            try:
                self.endpoint.revoke()
            except (ValueError, OSError, sqlite3.Error) as failure:
                failures.append(failure)
        try:
            self._close_io()
        except (ValueError, OSError) as failure:
            failures.append(failure)
        remaining = max(0, min(2, deadline - time.monotonic()))
        acquired = self.io_lock.acquire(timeout=remaining)
        if acquired:
            self.io_lock.release()
        else:
            failures.append(RuntimeStoreError('guest_service_unretired'))
        service_failure = self._join_service(deadline, revoke=revoke)
        if service_failure is not None:
            failures.append(service_failure)
        from gateway.session_guest_inference import OwnerResponses
        if isinstance(self.inference, OwnerResponses):
            try:
                self.inference.close()
            except (ValueError, OSError, RuntimeError) as failure:
                failures.append(failure)
        if time.monotonic() > deadline:
            failures.append(RuntimeStoreError('guest_transport_close_deadline'))
        if failures and not revoke:
            try:
                self.endpoint.revoke()
            except (ValueError, OSError, sqlite3.Error) as failure:
                failures.append(failure)
        self.cleanup_errors.extend(str(failure) for failure in failures)
        if failures:
            for additional in failures[1:]:
                failures[0].add_note('Additional Guest cleanup failure: ' + str(additional))
            raise failures[0]
        self.transport_joined.set()
        return self.physical_observation()

    def finish_transport(self, *, deadline=None):
        """Close a verified healthy result without claiming physical retirement.

        Only the original physical finalizer may release its accounting entry.
        This path cannot erase UNKNOWN or accept a Guest-provided retirement.
        """
        if self.endpoint.revoked or self.unknown_persisted.is_set():
            raise RuntimeStoreError('guest_healthy_finish_revoked')
        self._verify_finished()
        return self._cleanup_transport(deadline=deadline or time.monotonic() + 2, revoke=False)

    def close_transport(self, *, deadline=None):
        """Close all owned resources, preserving revoke and cleanup failures."""
        return self._cleanup_transport(deadline=deadline or time.monotonic() + 2, revoke=True)

    def physical_observation(self):
        """Read facts only: this neither opens serial nor releases exclusion."""
        from gateway.session_guest_inference import OwnerResponses
        pump = self.wire.pump
        writer = self.wire.lock.acquire(blocking=False)
        if writer:
            self.wire.lock.release()
        service = self.io_lock.acquire(blocking=False)
        if service:
            self.io_lock.release()
        inference = self.inference
        http_complete = (not isinstance(inference, OwnerResponses) or
                         (inference.closed and (inference.pending is None or inference.pending.done())
                          and all(not thread.is_alive() for thread in inference.executor._threads)))
        result = {'scope': dict(self.endpoint.scope), 'serial_observer': 'ORIGINAL_OWNER_SERIALWIRE',
                  'peer_eof': self.peer_eof.is_set(), 'descriptor_closed': self.wire.fd == -1,
                  'receive_pump_joined': pump is not None and not pump.is_alive(),
                  'receive_pump_started': pump is not None,
                  'frames_received': self.wire.received,
                  'frames_sent': self.wire.sent,
                  'boot_hints_untrusted': list(getattr(self.wire, 'boot_hints', [])),
                  'writer_joined': writer and self.wire.closed.is_set(),
                  'service_joined': service and self.service_observed and self.service_future is not None
                                    and self.service_future.done(),
                  'http_joined': http_complete, 'transport_joined': self.transport_joined.is_set(),
                  'logical_finished': self.finished.is_set() and self.persisted_finish.is_set(),
                  'ready': self.ready.is_set(), 'ready_at': self.ready_at, 'result_at': self.result_at,
                  'finished_at': self.finished_at, 'peer_eof_at': self.peer_eof_at,
                  'service_failure': self.service_failure,
                  'cleanup_errors': list(self.cleanup_errors)}
        fields = ('peer_eof', 'descriptor_closed', 'receive_pump_joined', 'writer_joined',
                  'service_joined', 'http_joined', 'transport_joined')
        result['complete'] = all(result[field] is True for field in fields) and not self.cleanup_errors
        return result

    def cancel(self, *, send=True):
        self.stop.set()  # authority closes immediately, before either independent action
        try:
            with self.stop_lock:
                if send and not self.stop_sent.is_set():
                    self.wire.send('lifecycle', 'control', {'type': 'stop'})
                    self.stop_sent.set()
        finally:
            self.endpoint.revoke()
            self.unknown_persisted.set()
        # STOP transmission does not prove retirement; the original Owner retains
        # its physical obligation even when UNKNOWN cannot yet be persisted.


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
        pending = getattr(channel, 'cancel_task', None)
        if (not (channel.stop_sent.is_set() and channel.unknown_persisted.is_set())
                and (pending is None or pending.done())):
            channel.stop.set()  # closes authorization before the off-loop writer waits
            channel.cancel_task = track_mutation(authority, asyncio.to_thread(channel.cancel))
