"""Finite Q2 RPC on inherited serial descriptors; no discovery or network sockets.

One receive pump admits ordered frames while the caller waits for an RPC. Control
is independent of persistence/inference completion. Wire loss is sticky, not resume.
"""
from __future__ import annotations

import json
import os
import queue
import select
import struct
import threading
import time

MAX_FRAME = 4 * 1024 * 1024
CHANNELS = frozenset({'persistence', 'context', 'inference', 'lifecycle', 'activity'})


class SerialError(ValueError):
    pass


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SerialError('duplicate_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(SerialError('nonfinite_json')))


def _read(fd, size, timeout, closed):
    pending = bytearray()
    deadline = time.monotonic() + timeout
    while len(pending) < size:
        remaining = deadline - time.monotonic()
        if closed.is_set():
            raise EOFError('serial_closed')
        if remaining <= 0:
            raise TimeoutError('serial_read_timeout')
        if not select.select([fd], [], [], min(remaining, .2))[0]:
            continue
        data = os.read(fd, size - len(pending))
        if not data:
            raise EOFError('serial_eof')
        pending.extend(data)
    return bytes(pending)


class SerialWire:
    """Length-prefixed canonical JSON, immutable binding, strict per-direction seq."""

    def __init__(self, fd, scope, *, timeout=30, request_timeout=300):
        if not 0 < timeout <= 60 or not 0 < request_timeout <= 300:
            raise SerialError('invalid_timeout')
        self.fd, self.timeout = os.dup(fd), timeout
        self.closed = threading.Event()
        self.scope = json.loads(json.dumps(scope, allow_nan=False))
        self.sent = self.received = 0
        self.lock = threading.Lock()
        self.failed = False
        self.failure = None
        self.request_timeout = request_timeout
        self.inbox = queue.Queue(maxsize=16)
        self.pump = None
        self.heartbeat_acks = 0
        self.pulse = 0
        self.pending_pulse = None
        self.on_failure = None

    def send(self, channel, kind, payload, *, reply_to=0):
        with self.lock:
            if self.failed or self.closed.is_set():
                raise SerialError('serial_failed')
            self.sent += 1
            frame = {'version': 2, 'scope': self.scope, 'seq': self.sent,
                     'channel': channel, 'kind': kind, 'reply_to': reply_to, 'payload': payload}
            raw = json.dumps(frame, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            if channel not in CHANNELS or kind not in ('request', 'reply', 'control', 'event', 'heartbeat') or len(raw) > MAX_FRAME:
                self.failed = True
                raise SerialError('invalid_serial_frame')
            try:
                self._write(struct.pack('!I', len(raw)) + raw)
            except (OSError, TimeoutError):
                self.failed = True
                raise
            return self.sent

    def _write(self, raw):
        view = memoryview(raw)
        deadline = time.monotonic() + self.timeout
        while view:
            remaining = deadline - time.monotonic()
            if self.closed.is_set():
                raise EOFError('serial_closed')
            if remaining <= 0:
                raise TimeoutError('serial_write_timeout')
            if not select.select([], [self.fd], [], min(remaining, .2))[1]:
                continue
            count = os.write(self.fd, view[:4096])
            if count <= 0:
                raise OSError('serial_short_write')
            view = view[count:]

    def close(self):
        self.closed.set()

    def release_fd(self):
        try:
            self.join_heartbeat()
        finally:
            self._release_fd()

    def _release_fd(self):
        with self.lock:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1

    def receive(self):
        if self.pump is None:
            return self._receive_frame()
        while True:
            if self.failure is not None:
                raise self.failure
            if self.closed.is_set():
                raise EOFError('serial_closed')
            try:
                frame = self.inbox.get(timeout=.2)
            except queue.Empty:
                continue
            if isinstance(frame, Exception):
                raise frame
            return frame

    def _receive_frame(self):
        if self.failed:
            raise SerialError('serial_failed')
        try:
            size = struct.unpack('!I', _read(self.fd, 4, self.timeout, self.closed))[0]
            if not 0 < size <= MAX_FRAME:
                raise SerialError('serial_frame_too_large')
            frame = _json(_read(self.fd, size, self.timeout, self.closed))
            self._validate(frame)
            self.received += 1
            return frame
        except (TypeError, KeyError, RecursionError) as exc:
            self.failed = True
            raise SerialError('invalid_serial_frame') from exc
        except (ValueError, OSError, EOFError):
            self.failed = True
            raise

    def _validate(self, frame):
        if (not isinstance(frame, dict) or set(frame) !=
                {'version', 'scope', 'seq', 'channel', 'kind', 'reply_to', 'payload'}
                or type(frame['version']) is not int or frame['version'] != 2
                or type(frame['seq']) is not int or frame['seq'] != self.received + 1
                or json.dumps(frame['scope'], sort_keys=True) != json.dumps(self.scope, sort_keys=True)
                or frame['channel'] not in CHANNELS or frame['kind'] not in ('request', 'reply', 'control', 'event', 'heartbeat')
                or (frame['kind'] == 'heartbeat' and frame['channel'] != 'lifecycle')
                or type(frame['reply_to']) is not int or frame['reply_to'] < 0
                or (frame['kind'] == 'reply') != (frame['reply_to'] > 0)):
            raise SerialError('invalid_serial_identity_or_sequence')


    def start_heartbeat(self, *, interval=5, lease=90, on_failure=None):
        """A private receive pump keeps liveness independent of long business work.

        Heartbeats never renew admission/epoch authority. Frame I/O remains timed;
        the acknowledged pulse lease and RPC deadline are independently bounded.
        """
        if self.pump is not None:
            return
        if not 0 < interval < lease <= 120:
            raise SerialError('invalid_heartbeat_lease')
        self.interval, self.lease = interval, lease
        self.next_pulse = time.monotonic() + interval
        self.on_failure = on_failure
        from agent.memory_provider import spawn_context_thread
        self.pump = spawn_context_thread(self._pump, name='serial-heartbeat', daemon=True)
        self.pump.start()

    def _tick(self):
        now = time.monotonic()
        if self.pending_pulse is not None:
            if now >= self.pending_pulse[1]:
                raise TimeoutError('serial_heartbeat_expired')
        elif now >= self.next_pulse:
            self.pulse += 1
            self.send('lifecycle', 'heartbeat', {'ping': self.pulse})
            self.pending_pulse = (self.pulse, time.monotonic() + self.lease)

    def _heartbeat(self, payload):
        if (not isinstance(payload, dict) or set(payload) not in ({'ping'}, {'ack'})
                or any(type(value) is not int or value < 1 for value in payload.values())):
            raise SerialError('invalid_heartbeat')
        if 'ping' in payload:
            self.send('lifecycle', 'heartbeat', {'ack': payload['ping']})
        else:
            if self.pending_pulse is None or payload['ack'] != self.pending_pulse[0]:
                raise SerialError('heartbeat_ack_mismatch')
            self.pending_pulse = None
            self.heartbeat_acks += 1
            self.next_pulse = time.monotonic() + self.interval

    def _pump(self):
        try:
            while not self.closed.is_set():
                self._tick()
                if not select.select([self.fd], [], [], .1)[0]:
                    continue
                frame = self._receive_frame()
                if frame['kind'] == 'heartbeat':
                    self._heartbeat(frame['payload'])
                else:
                    self.inbox.put_nowait(frame)
        except (ValueError, TypeError, KeyError, RecursionError, OSError, EOFError, queue.Full) as exc:
            self.failure = exc
            self.failed = True
            self.closed.set()
            if self.on_failure is not None:
                self.on_failure()  # latch only; no database I/O on the receive pump

    def join_heartbeat(self):
        if self.pump is not None:
            self.closed.set()
            self.pump.join(timeout=2)
            if self.pump.is_alive():
                raise SerialError('heartbeat_reader_unretired')


class ControlStream:
    """Bounded readline adapter for the original WorkerControls reader."""

    def __init__(self):
        self.queue = queue.Queue(maxsize=16)
        self.failure = None

    def push(self, payload):
        if payload not in ({'type': 'stop'}, {'type': 'finish'}):
            raise SerialError('unsupported_guest_control')
        self.queue.put_nowait(json.dumps(payload).encode() + b'\n')

    def close_reader(self):
        self.failure = SerialError('guest_control_closed')
        try:
            self.queue.put_nowait(self.failure)
        except queue.Full:
            return  # queued items wake the consumer; failure is checked first

    def readline(self, _limit=-1):
        if self.failure is not None:
            raise SerialError('guest_control_closed') from self.failure
        item = self.queue.get()  # liveness loss/close delivers an exception, independent of idle work
        if isinstance(item, Exception):
            # ValueError makes WorkerControls stop without sending a Host signal.
            raise SerialError('guest_control_lost') from item
        return item


class GuestSerialClient:
    """One outstanding RPC, with a separate cancellation receive pump."""

    def __init__(self, wire):
        self.wire = wire
        wire.start_heartbeat()
        self.controls = ControlStream()
        self.replies = queue.Queue(maxsize=1)
        self.lock = threading.Lock()
        self.failure = None
        from agent.memory_provider import spawn_context_thread
        self.reader = spawn_context_thread(self._receive, name='guest-serial', daemon=True)
        self.reader.start()

    def _receive(self):
        try:
            while True:
                frame = self.wire.receive()
                if frame['channel'] == 'lifecycle' and frame['kind'] == 'control':
                    self.controls.push(frame['payload'])
                elif frame['kind'] == 'reply':
                    self.replies.put_nowait(frame)
                else:
                    raise SerialError('unexpected_owner_frame')
        except (ValueError, TypeError, KeyError, RecursionError, OSError, EOFError, queue.Full) as exc:
            if self.failure is None:
                self.failure = exc
            self.controls.close_reader()
            try:
                self.replies.put_nowait(exc)
            except queue.Full:
                pass  # an earlier reply wakes the caller; failure stays sticky

    def call(self, channel, payload):
        with self.lock:
            if self.failure is not None:
                raise SerialError('guest_channel_lost') from self.failure
            seq = self.wire.send(channel, 'request', payload)
            try:
                result = self.replies.get(timeout=self.wire.request_timeout)
            except queue.Empty:
                self._invalid_reply('guest_reply_timeout')
            if isinstance(result, Exception):
                raise SerialError('guest_channel_lost') from result
            if result['reply_to'] != seq or result['channel'] != channel:
                self._invalid_reply('guest_reply_mismatch')
            body = result['payload']
            if not isinstance(body, dict) or set(body) not in ({'result'}, {'error'}):
                self._invalid_reply('invalid_guest_reply')
            if 'error' in body:
                reason = body['error']
                if not isinstance(reason, str) or not 0 < len(reason) <= 80 or not reason.isprintable():
                    self._invalid_reply('invalid_guest_error')
                from agent.runtime_session_store import WorkerPersistenceError
                raise WorkerPersistenceError(reason)
            return body['result']

    def _invalid_reply(self, reason):
        error = SerialError(reason)
        self.failure = error
        self.wire.failed = True
        self.wire.close()
        self.controls.close_reader()
        raise error

    def __call__(self, request):
        return self.call('persistence', request)

    def send(self, kind, **payload):
        self.wire.send('activity', 'event', {'type': kind, **payload})

    def close(self):
        self.controls.close_reader()
        self.wire.close()
        self.reader.join(timeout=2)
        if self.reader.is_alive():
            raise SerialError('guest_reader_unretired')
        self.wire.release_fd()
