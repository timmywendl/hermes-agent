"""Finite original-Owner pipe control for the explicitly authorized inert HVF campaign.

No spawn/admission authority lives here. The registered SessionAuthority supplies
its actual child only after committing the durable reservation and PID booking.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import selectors
import signal
import time

import psutil

from hermes_state_runtime import RuntimeStoreError

RELEASE = b'HERMES_HVF_RELEASE_V1\n'
STOP = 'HERMES_HVF_STOP_V1\n'


def child_identity(process, executable):
    from hermes_cli.kanban_db_dispatch import _process_fingerprint
    child = psutil.Process(process.pid)
    identity = {'pid': child.pid, 'ppid': child.ppid(), 'pgid': os.getpgid(child.pid),
                'fingerprint': _process_fingerprint(child.pid), 'executable': child.exe(),
                'created': child.create_time(), 'boot_time': psutil.boot_time()}
    if (identity['ppid'] != os.getpid() or identity['pgid'] != child.pid
            or not identity['fingerprint'] or Path(identity['executable']).resolve() != Path(executable).resolve()):
        raise RuntimeStoreError('hvf_child_identity_unavailable')
    return identity


def verify_child(process, identity):
    if child_identity(process, identity['executable']) != identity:
        raise RuntimeStoreError('hvf_child_identity_changed')


def group_members(pgid):
    library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    function = library.proc_listpgrppids
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    function.restype = ctypes.c_int
    members = (ctypes.c_int * 4096)()
    ctypes.set_errno(0)
    count = function(pgid, members, ctypes.sizeof(members))
    error = ctypes.get_errno()
    if count < 0 or error or count >= len(members):
        raise RuntimeStoreError('hvf_process_group_unobservable', detail=str(error))
    return tuple(sorted(pid for pid in members[:count] if pid))


class ChildPipes:
    """One synchronous Owner task drains both pipes; no unjoined reader threads."""

    def __init__(self, process):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.pending = bytearray()
        self.responses = {}
        self.events = []
        self.greeting = None
        self.sequence = 0
        self.closed = False
        for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)

    def pump(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeStoreError('hvf_control_timeout')
        if not self.selector.get_map():
            return False
        for key, _mask in self.selector.select(min(remaining, 0.25)):
            try:
                data = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            target = self.buffers[key.data]
            target.extend(data)
            if len(target) > 4 * 1024 * 1024:
                raise RuntimeStoreError('hvf_control_overflow')
            if key.data == 'stdout':
                self.pending.extend(data)
                self._decode()
        return bool(self.selector.get_map())

    def _decode(self):
        while b'\n' in self.pending:
            line, _, tail = self.pending.partition(b'\n')
            self.pending = bytearray(tail)
            if not line.strip():
                continue
            message = json.loads(line)
            if not isinstance(message, dict):
                raise RuntimeStoreError('hvf_invalid_qmp')
            if 'QMP' in message:
                self.greeting = message['QMP']
            elif 'event' in message:
                self.events.append(message)
            elif 'id' in message:
                self.responses[message['id']] = message
            else:
                raise RuntimeStoreError('hvf_invalid_qmp')

    def until(self, predicate, deadline):
        while not predicate():
            if not self.pump(deadline):
                raise RuntimeStoreError('hvf_control_eof')

    def request(self, command, arguments=None, *, deadline):
        self.sequence += 1
        identity = f'hvf-{self.sequence}'
        message = {'execute': command, 'id': identity}
        if arguments is not None:
            message['arguments'] = arguments
        data = json.dumps(message, separators=(',', ':')).encode() + b'\n'
        written = os.write(self.process.stdin.fileno(), data)
        if written != len(data):
            raise RuntimeStoreError('hvf_control_partial_write')
        self.until(lambda: identity in self.responses, deadline)
        response = self.responses.pop(identity)
        if 'error' in response or 'return' not in response:
            raise RuntimeStoreError('hvf_qmp_error', detail=str(response))
        return response['return']

    def close(self):
        if self.closed:
            return
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        self.closed = True

    def drain_and_wait(self, deadline):
        self.process.stdin.close()
        while self.selector.get_map():
            self.pump(deadline)
        code = self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if self.pending.strip():
            raise RuntimeStoreError('hvf_partial_qmp_at_exit')
        self.close()
        return code


def _network_class(value):
    if isinstance(value, dict):
        category = value.get('class_info', {}).get('class')
        if type(category) is int and category >> 8 == 2:
            return True
        return any(_network_class(child) for child in value.values())
    return isinstance(value, list) and any(_network_class(child) for child in value)


def inventory(pipes, deadline):
    get = lambda name, args=None: pipes.request(name, args, deadline=deadline)
    result = {'cpus': get('query-cpus-fast'), 'memory': get('query-memory-size-summary'),
              'rx_filters': get('query-rx-filter'), 'pci': get('query-pci'),
              'network': get('human-monitor-command', {'command-line': 'info network'}),
              'blocks': get('query-block'), 'status': get('query-status')}
    blocks = result['blocks']
    if (len(result['cpus']) != 2 or result['memory'].get('base-memory') != 2 * 1024**3
            or result['rx_filters'] != [] or result['network'].strip() or _network_class(result['pci'])
            or len(blocks) != 1 or blocks[0].get('inserted', {}).get('ro') is not True
            or result['status'].get('running') is not True):
        raise RuntimeStoreError('hvf_runtime_inventory_mismatch')
    return result


def _markers(stderr, pid, mode):
    text = stderr.decode('utf-8', errors='strict')
    created = re.findall(r'^HERMES_HVF_VM_CREATE_V1 pid=(\d+) result=(-?\d+)$', text, re.MULTILINE)
    core = re.findall(r'^HERMES_HVF_CORE_LIMIT_V1 pid=(\d+) current=0 maximum=0$', text, re.MULTILINE)
    destroyed = re.findall(r'^HERMES_HVF_VM_DESTROY_V1 pid=(\d+) result=(-?\d+) joined=(\d+)$', text, re.MULTILINE)
    sandbox = [json.loads(line.removeprefix('HERMES_HVF_SANDBOX_V1 ')) for line in text.splitlines()
               if line.startswith('HERMES_HVF_SANDBOX_V1 ')]
    if (created != [(str(pid), '0')] or core != [str(pid)] or len(sandbox) != 1
            or sandbox[0].get('pass') is not True):
        raise RuntimeStoreError('hvf_backend_or_sandbox_unverified')
    if mode == 'normal' and destroyed != [(str(pid), '0', '2')]:
        raise RuntimeStoreError('hvf_destroy_unverified')
    if mode != 'normal' and destroyed:
        raise RuntimeStoreError('hvf_unexpected_normal_destroy')
    return {'vm_create_successes': 1, 'core_limit_zero': True, 'sandbox': sandbox[0],
            'explicit_vm_destroy': mode == 'normal', 'destroy_success': mode == 'normal'}


def guest_shutdown_seen(pipes):
    return any(event.get('event') == 'SHUTDOWN' and event.get('data', {}).get('guest') is True
               and event.get('data', {}).get('reason') == 'guest-shutdown' for event in pipes.events)


def observe_child(process, identity, mode, stop, output, started, deadline):
    """Returns physical evidence only; original Owner performs retirement/accounting."""
    pipes = ChildPipes(process)
    startup = min(started + 60, deadline)
    serial = ''
    try:
        pipes.until(lambda: pipes.greeting is not None, startup)
        pipes.request('qmp_capabilities', deadline=startup)
        while '"event":"READY"' not in serial:
            if stop.is_set():
                raise RuntimeStoreError('hvf_owner_stop_during_startup')
            serial += pipes.request('ringbuf-read', {'device': 'serial', 'size': 65536}, deadline=startup)
            if len(serial) > 2 * 1024 * 1024:
                raise RuntimeStoreError('hvf_guest_console_overflow')
            if '"event":"WINDOW_EXPIRED"' in serial or '"event":"POWEROFF_FAILED"' in serial:
                raise RuntimeStoreError('hvf_guest_startup_failed')
            if '"event":"READY"' not in serial:
                pipes.pump(min(startup, time.monotonic() + 0.25))
        actual = inventory(pipes, startup)
        verify_child(process, identity)
        if group_members(identity['pgid']) != (process.pid,):
            raise RuntimeStoreError('hvf_unapproved_descendant')
        if stop.is_set():
            raise RuntimeStoreError('hvf_owner_stop_requested')
        deadline = min(deadline, time.monotonic() + 30)
        if mode == 'normal':
            try:
                pipes.request('ringbuf-write', {'device': 'serial', 'data': STOP}, deadline=deadline)
            except RuntimeStoreError as exc:
                # A completed Guest poweroff may close QMP before the command's reply.
                # Only the authoritative expected terminal event makes that EOF normal.
                if exc.reason != 'hvf_control_eof' or not guest_shutdown_seen(pipes):
                    raise
        else:
            os.kill(process.pid, signal.Signals['SIGKILL'] if mode == 'sigkill' else signal.SIGABRT)
        code = pipes.drain_and_wait(deadline)
        expected = 0 if mode == 'normal' else -(signal.Signals['SIGKILL'] if mode == 'sigkill' else signal.SIGABRT)
        if code != expected or group_members(identity['pgid']):
            raise RuntimeStoreError('hvf_exit_or_group_unverified')
        shutdown = guest_shutdown_seen(pipes)
        if mode == 'normal' and not shutdown:
            raise RuntimeStoreError('hvf_guest_orderly_shutdown_unverified')
        evidence = _markers(pipes.buffers['stderr'], process.pid, mode)
        return {**evidence, 'exit_code': code, 'exact_child_waited': True,
                'process_group_empty': True, 'all_pipes_closed': True, 'guest_ready': True,
                'guest_orderly_shutdown': shutdown, 'runtime_inventory': actual,
                'elapsed_s': time.monotonic() - started, 'mode': mode,
                'backend_ownership': 'APPLE_PROCESS_OWNED_HYPERVISOR_CONTRACT'}
    finally:
        output.mkdir(parents=True, exist_ok=True)
        for label, data in pipes.buffers.items():
            (output / f'{label}.log').write_bytes(data)
        (output / 'serial.log').write_text(serial, encoding='utf-8')
        pipes.close()
