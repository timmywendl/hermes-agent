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

    def __init__(self, fd, scope, *, timeout=30):
        if not 0 < timeout <= 60:
            raise SerialError('invalid_timeout')
        self.fd, self.timeout = os.dup(fd), timeout
        self.closed = threading.Event()
        self.scope = json.loads(json.dumps(scope, allow_nan=False))
        self.sent = self.received = 0
        self.lock = threading.Lock()
        self.failed = False

    def send(self, channel, kind, payload, *, reply_to=0):
        with self.lock:
            if self.failed or self.closed.is_set():
                raise SerialError('serial_failed')
            self.sent += 1
            frame = {'version': 2, 'scope': self.scope, 'seq': self.sent,
                     'channel': channel, 'kind': kind, 'reply_to': reply_to, 'payload': payload}
            raw = json.dumps(frame, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            if channel not in CHANNELS or kind not in ('request', 'reply', 'control', 'event') or len(raw) > MAX_FRAME:
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
        with self.lock:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1

    def receive(self):
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
        except (ValueError, TypeError, KeyError, OSError, EOFError):
            self.failed = True
            raise

    def _validate(self, frame):
        if (not isinstance(frame, dict) or set(frame) !=
                {'version', 'scope', 'seq', 'channel', 'kind', 'reply_to', 'payload'}
                or type(frame['version']) is not int or frame['version'] != 2
                or type(frame['seq']) is not int or frame['seq'] != self.received + 1
                or json.dumps(frame['scope'], sort_keys=True) != json.dumps(self.scope, sort_keys=True)
                or frame['channel'] not in CHANNELS or frame['kind'] not in ('request', 'reply', 'control', 'event')
                or type(frame['reply_to']) is not int or frame['reply_to'] < 0
                or (frame['kind'] == 'reply') != (frame['reply_to'] > 0)):
            raise SerialError('invalid_serial_identity_or_sequence')


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
        try:
            item = self.queue.get(timeout=65)
        except queue.Empty as exc:
            raise SerialError('guest_control_timeout') from exc
        if isinstance(item, Exception):
            # ValueError makes WorkerControls stop without sending a Host signal.
            raise SerialError('guest_control_lost') from item
        return item


class GuestSerialClient:
    """One outstanding RPC, with a separate cancellation receive pump."""

    def __init__(self, wire):
        self.wire = wire
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
        except (ValueError, OSError, EOFError, queue.Full) as exc:
            self.failure = exc
            for destination in (self.replies, self.controls.queue):
                try:
                    destination.put_nowait(exc)
                except queue.Full:
                    pass  # failure remains sticky even when an earlier item fills the queue

    def call(self, channel, payload):
        with self.lock:
            if self.failure is not None:
                raise SerialError('guest_channel_lost') from self.failure
            seq = self.wire.send(channel, 'request', payload)
            try:
                result = self.replies.get(timeout=self.wire.timeout + 1)
            except queue.Empty as exc:
                self.failure = exc
                raise SerialError('guest_reply_timeout') from exc
            if isinstance(result, Exception):
                raise SerialError('guest_channel_lost') from result
            if result['reply_to'] != seq or result['channel'] != channel:
                self.wire.failed = True
                raise SerialError('guest_reply_mismatch')
            body = result['payload']
            if not isinstance(body, dict) or set(body) not in ({'result'}, {'error'}):
                raise SerialError('invalid_guest_reply')
            if 'error' in body:
                from agent.runtime_session_store import WorkerPersistenceError
                raise WorkerPersistenceError(body['error'])
            return body['result']

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
