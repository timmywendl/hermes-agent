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


def child_identity(process, executable, observed=None):
    from hermes_cli.kanban_db_dispatch import _process_fingerprint
    identity = observed if observed is not None else {}
    identity.update(pid=process.pid, ppid=None, pgid=None, fingerprint=None,
                    executable=None, created=None, boot_time=None)
    child = psutil.Process(process.pid)
    identity['created'] = child.create_time()
    identity['boot_time'] = psutil.boot_time()
    identity['ppid'] = child.ppid()
    identity['pgid'] = os.getpgid(child.pid)
    identity['fingerprint'] = _process_fingerprint(child.pid)
    identity['executable'] = child.exe()
    if (identity['ppid'] != os.getpid() or identity['pgid'] != child.pid
            or not identity['fingerprint'] or Path(identity['executable']).resolve() != Path(executable).resolve()):
        raise RuntimeStoreError('hvf_child_identity_unavailable')
    return dict(identity)


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

    def __init__(self, process, serial=None, observation=None):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray(), 'serial': bytearray()}
        self.serial = serial
        self.observation = observation
        self.pending = bytearray()
        self.responses = {}
        self.events = []
        self.greeting = None
        self.sequence = 0
        self.closed = False
        self.eof = {'stdout': False, 'stderr': False, 'serial': serial is None}
        for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
        if serial is not None:
            serial.setblocking(False)
            self.selector.register(serial, selectors.EVENT_READ, 'serial')
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
                self.eof[key.data] = True
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
        if self.serial is not None:
            self.serial.close()
        self.closed = True

    def drain_and_wait(self, deadline, *, close_input=True):
        if close_input:
            self.process.stdin.close()
        while self.selector.get_map():
            self.pump(deadline)
        code = self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if self.observation is not None:
            self.observation.update(wait_result='REAPED_BY_ORIGINAL_OWNER', wait_returncode=code)
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


def observe_child(process, identity, mode, stop, output, started, deadline, serial_socket, observation=None):
    """Returns physical evidence only; original Owner performs retirement/accounting."""
    pipes = ChildPipes(process, serial_socket, observation)
    startup = min(started + 60, deadline)
    serial = ''
    try:
        pipes.until(lambda: pipes.greeting is not None, startup)
        pipes.request('qmp_capabilities', deadline=startup)
        while '"event":"READY"' not in serial:
            if stop.is_set():
                raise RuntimeStoreError('hvf_owner_stop_during_startup')
            pipes.pump(startup)
            serial = pipes.buffers['serial'].decode('utf-8', errors='replace')
            if '"event":"WINDOW_EXPIRED"' in serial or '"event":"POWEROFF_FAILED"' in serial:
                raise RuntimeStoreError('hvf_guest_startup_failed')
        actual = inventory(pipes, startup)
        verify_child(process, identity)
        if group_members(identity['pgid']) != (process.pid,):
            raise RuntimeStoreError('hvf_unapproved_descendant')
        if stop.is_set():
            raise RuntimeStoreError('hvf_owner_stop_requested')
        deadline = min(deadline, time.monotonic() + 30)
        if mode == 'normal':
            frame = STOP.encode('ascii')
            if serial_socket.send(frame) != len(frame):
                raise RuntimeStoreError('hvf_serial_stop_partial_write')
        else:
            os.kill(process.pid, signal.Signals['SIGKILL'] if mode == 'sigkill' else signal.SIGABRT)
        # Keep the QMP connection live until terminal events arrive. Closing its
        # input at serial STOP can disconnect the monitor before SHUTDOWN emits.
        code = pipes.drain_and_wait(deadline, close_input=False)
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
                'serial_stop_bytes': len(STOP.encode('ascii')) if mode == 'normal' else 0,
                'guest_console_orderly': b'"event":"ORDERLY_SHUTDOWN"' in pipes.buffers['serial'],
                'requested_signal': None if mode == 'normal' else int(signal.Signals['SIGKILL'] if mode == 'sigkill' else signal.SIGABRT),
                'backend_ownership': 'APPLE_PROCESS_OWNED_HYPERVISOR_CONTRACT'}
    finally:
        try:
            if observation is not None:
                observation.update(eof=dict(pipes.eof), selector_drained=not bool(pipes.selector.get_map()) if not pipes.closed else all(pipes.eof.values()))
            output.mkdir(parents=True, exist_ok=True)
            for label, data in pipes.buffers.items():
                (output / f'{label}.log').write_bytes(data)
        finally:
            pipes.close()


def contain_child(handle, deadline):
    """Bounded exact-child failure containment; never operate on a foreign PID."""
    import subprocess
    errors = []
    child = handle.process
    try:
        try:
            _wait_for_child(handle, 0.01)
            return errors
        except subprocess.TimeoutExpired:
            pass
        if handle.identity is None:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
        else:
            verify_child(child, handle.identity)
            os.kill(child.pid, signal.SIGTERM)
            handle.pipe_observation.setdefault('signals_sent', []).append(int(signal.SIGTERM))
        try:
            _wait_for_child(handle, max(0.01, min(15, (deadline - time.monotonic()) / 2)))
        except subprocess.TimeoutExpired:
            if handle.identity is None:
                raise RuntimeStoreError('hvf_no_verified_identity_for_escalation')
            verify_child(child, handle.identity)
            os.kill(child.pid, signal.Signals['SIGKILL'])
            handle.pipe_observation.setdefault('signals_sent', []).append(int(signal.Signals['SIGKILL']))
            _wait_for_child(handle, max(0.01, deadline - time.monotonic()))
    except (OSError, psutil.Error, RuntimeStoreError, subprocess.TimeoutExpired) as error:
        errors.append({'operation': 'contain_and_wait', 'error': repr(error)})
    return errors


def exit_observation(handle, *, errors=None):
    """Available physical facts; unknown fields stay explicit, even after reap."""
    errors = list(errors or [])
    child = handle.process
    identity = handle.identity
    members = None
    if identity is not None:
        try:
            members = list(group_members(identity['pgid']))
        except (OSError, RuntimeStoreError) as error:
            errors.append({'operation': 'process_group', 'error': repr(error)})
    pipes = {}
    for name in ('stdin', 'stdout', 'stderr', 'serial'):
        stream = handle.serial if name == 'serial' else getattr(child, name)
        if stream is None:
            pipes[name] = {'closed': None, 'error': 'ENDPOINT_UNAVAILABLE'}
            continue
        try:
            stream.close()
            pipes[name] = {'closed': stream.fileno() == -1 if name == 'serial' else stream.closed}
        except (OSError, ValueError) as error:
            pipes[name] = {'closed': None, 'error': repr(error)}
    pipes['child_serial_in_parent'] = {'closed': handle.guest_serial_closed}
    code = child.returncode
    return {'pid': child.pid, 'identity': identity if identity is not None else handle.observed_identity,
            'identity_status': 'VERIFIED' if identity else 'UNKNOWN',
            'returncode': code, 'exit_code': code if code is not None and code >= 0 else None,
            'terminating_signal': -code if code is not None and code < 0 else None,
            'wait_result': handle.pipe_observation.get('wait_result', 'UNKNOWN'),
            'process_group_members': members,
            'process_group_status': 'EMPTY' if members == [] else 'NONEMPTY' if members else 'UNKNOWN',
            'pipes': pipes, 'all_pipes_closed': all(p.get('closed') is True for p in pipes.values()),
            'drain_observation': dict(handle.pipe_observation), 'errors': errors}


def verify_prior_absent(identity):
    required = {'pid', 'created', 'fingerprint', 'executable', 'pgid', 'boot_time', 'ppid'}
    if (not isinstance(identity, dict) or not required <= identity.keys()
            or type(identity['pid']) is not int or identity['pid'] <= 1
            or identity['pgid'] != identity['pid'] or not identity['fingerprint']
            or not Path(identity['executable']).is_absolute()):
        raise RuntimeStoreError('hvf_prior_identity_incomplete')
    # A PID now occupied by another process is conservatively ambiguous here.
    # No argv inference, kill, wait, or mutation of the old Owner is permitted.
    try:
        psutil.Process(identity['pid']).create_time()
    except psutil.NoSuchProcess:
        pass
    except psutil.Error as error:
        raise RuntimeStoreError('hvf_prior_process_unobservable') from error
    else:
        raise RuntimeStoreError('hvf_prior_pid_still_present_or_reused')
    members = group_members(identity['pgid'])
    if members:
        raise RuntimeStoreError('hvf_prior_group_not_empty')
    return list(members)


def _wait_for_child(handle, timeout):
    code = handle.process.wait(timeout=timeout)
    handle.pipe_observation.update(wait_result='REAPED_BY_ORIGINAL_OWNER', wait_returncode=code)
    return code


def q2_inventory(pipes, deadline, expected_devices):
    """Q2 has three explicit block capabilities and no network device."""
    get = lambda name, args=None: pipes.request(name, args, deadline=deadline)
    result = {'cpus': get('query-cpus-fast'), 'memory': get('query-memory-size-summary'),
              'rx_filters': get('query-rx-filter'), 'pci': get('query-pci'),
              'network': get('human-monitor-command', {'command-line': 'info network'}),
              'blocks': get('query-block'), 'status': get('query-status')}
    blocks = {row.get('device'): row.get('inserted', {}) for row in result['blocks']}
    if (len(result['cpus']) != 2 or result['memory'].get('base-memory') != 2 * 1024**3
            or result['rx_filters'] != [] or result['network'].strip() or _network_class(result['pci'])
            or len(result['blocks']) != 3 or set(blocks) != set(expected_devices)
            or result['status'].get('running') is not True):
        raise RuntimeStoreError('q2_runtime_inventory_mismatch')
    total = 0
    for name, readonly in expected_devices.items():
        info = blocks[name]
        size = info.get('image', {}).get('virtual-size')
        if (type(readonly) is not bool or info.get('ro') is not readonly
                or type(size) is not int or not 0 < size <= 8 * 1024**3):
            raise RuntimeStoreError('q2_block_inventory_mismatch')
        total += size
    if total > 8 * 1024**3:
        raise RuntimeStoreError('q2_disk_budget_exhausted')
    return result


def q2_markers(stderr, pid):
    """Only original Helper API telemetry proves normal HVF creation/destroy."""
    text = stderr.decode('utf-8', errors='strict')
    created = re.findall(r'^HERMES_HVF_VM_CREATE_V1 pid=(\d+) result=(-?\d+)$', text, re.MULTILINE)
    core = re.findall(r'^HERMES_HVF_CORE_LIMIT_V1 pid=(\d+) current=0 maximum=0$', text, re.MULTILINE)
    destroyed = re.findall(r'^HERMES_HVF_VM_DESTROY_V1 pid=(\d+) result=(-?\d+) joined=(\d+)$', text, re.MULTILINE)
    prefix = 'HERMES_Q2_SANDBOX_RESULT_V1 '
    sandbox = [json.loads(line[len(prefix):]) for line in text.splitlines() if line.startswith(prefix)]
    if (created != [(str(pid), '0')] or core != [str(pid)] or destroyed != [(str(pid), '0', '2')]
            or len(sandbox) != 1 or sandbox[0].get('pid') != pid
            or sandbox[0].get('pass') is not True or sandbox[0].get('vm_created') is not False):
        raise RuntimeStoreError('q2_backend_or_sandbox_unverified')
    return {'vm_create_successes': 1, 'core_limit_zero': True, 'sandbox': sandbox[0],
            'explicit_vm_destroy': True, 'destroy_success': True}


class Q2ProcessObserver:
    """The original Owner's QMP/stdio observer; it has no serial descriptor.

    Q1 ChildPipes' serial=None means NOT_OBSERVED here. A separate actual Owner
    SerialWire observation is mandatory before any all-pipes-complete claim.
    """

    def __init__(self, process, identity, *, output, expected_devices, observation=None):
        if (set(expected_devices) != {'root', 'task', 'assignment'}
                or expected_devices['root'] is not True or expected_devices['assignment'] is not True
                or type(expected_devices['task']) is not bool):
            raise RuntimeStoreError('q2_exact_block_inventory_required')
        self.process, self.identity = process, dict(identity)
        self.output = Path(output)
        self.expected_devices = dict(expected_devices)
        self.observation = observation if observation is not None else {}
        self.pipes = ChildPipes(process, observation=self.observation)
        self.pipes.eof.pop('serial')
        self.actual = None

    def _exited(self, identity, code):
        self.observation['exact_child_exit'] = {
            'identity': dict(identity), 'returncode': code,
            'exit_code': code if code >= 0 else None,
            'terminating_signal': -code if code < 0 else None,
            'identity_source': 'PREVIOUSLY_VERIFIED_ORIGINAL_CHILD',
        }
        return False

    def check_child(self):
        """Natural exit is distinct from live identity ambiguity; neither retires."""
        historical = getattr(self.process, '_q2_verified_identity', None)
        try:
            actual = child_identity(self.process, self.identity['executable'])
        except (ProcessLookupError, psutil.NoSuchProcess) as error:
            code = self.process.poll()
            if historical != self.identity or code is None:
                raise RuntimeStoreError('q2_child_identity_unavailable') from error
            return self._exited(historical, code)
        if actual != self.identity:
            raise RuntimeStoreError('q2_child_identity_changed')
        self.process._q2_verified_identity = dict(actual)
        code = self.process.poll()
        return True if code is None else self._exited(actual, code)

    def start(self, deadline):
        if not self.check_child():
            raise RuntimeStoreError('q2_exit_before_inventory', detail=json.dumps(self.observation['exact_child_exit']))
        self.pipes.until(lambda: self.pipes.greeting is not None, deadline)
        self.pipes.request('qmp_capabilities', deadline=deadline)
        self.actual = q2_inventory(self.pipes, deadline, self.expected_devices)
        if not self.check_child():
            raise RuntimeStoreError('q2_exit_before_inventory', detail=json.dumps(self.observation['exact_child_exit']))
        if group_members(self.identity['pgid']) != (self.process.pid,):
            if not self.check_child():
                raise RuntimeStoreError('q2_exit_before_inventory', detail=json.dumps(self.observation['exact_child_exit']))
            raise RuntimeStoreError('q2_unapproved_descendant')
        return self.actual

    def poll(self, deadline):
        if self.check_child():
            members = group_members(self.identity['pgid'])
            if members != (self.process.pid,) and self.check_child():
                raise RuntimeStoreError('q2_unapproved_descendant')
            self.observation['last_observed_group_members'] = list(members)
        return self.pipes.pump(deadline)

    def finish(self, deadline, serial_observation):
        code = self.pipes.drain_and_wait(deadline, close_input=False)
        members = group_members(self.identity['pgid'])
        if code != 0 or members or not guest_shutdown_seen(self.pipes):
            raise RuntimeStoreError('q2_exit_or_shutdown_unverified')
        backend = q2_markers(self.pipes.buffers['stderr'], self.process.pid)
        serial = serial_observation() if callable(serial_observation) else serial_observation
        fields = ('peer_eof', 'descriptor_closed', 'receive_pump_joined', 'writer_joined',
                  'service_joined', 'http_joined', 'transport_joined', 'complete')
        if (not isinstance(serial, dict) or serial.get('serial_observer') != 'ORIGINAL_OWNER_SERIALWIRE'
                or any(serial.get(field) is not True for field in fields)
                or serial.get('cleanup_errors') != []):
            raise RuntimeStoreError('q2_owner_serial_unretired')
        pipes = {name: {'closed': getattr(self.process, name).closed} for name in ('stdin', 'stdout', 'stderr')}
        return {**backend, 'identity': dict(self.identity), 'pid': self.process.pid,
                'exit_code': code, 'returncode': code, 'terminating_signal': None,
                'exact_child_waited': True, 'wait_result': self.observation['wait_result'],
                'process_group_empty': True, 'process_group_members': list(members),
                'guest_orderly_shutdown': True, 'runtime_inventory': self.actual,
                'stdio_eof': dict(self.pipes.eof), 'pipes': pipes,
                'all_pipes_closed': all(value['closed'] for value in pipes.values()),
                'serial_observation': serial, 'serial_read_by_process_observer': False,
                'backend_ownership': 'APPLE_PROCESS_OWNED_HYPERVISOR_CONTRACT'}

    def close(self):
        self.output.mkdir(parents=True, exist_ok=True)
        try:
            for name in ('stdout', 'stderr'):
                with (self.output / (name + '.log')).open('xb') as stream:
                    stream.write(self.pipes.buffers[name])
        finally:
            self.observation['eof'] = dict(self.pipes.eof)
            self.observation['serial'] = 'NOT_OBSERVED_BY_PROCESS_OBSERVER'
            self.pipes.close()


def observe_q2_child(process, identity, stop, output, started, deadline, serial_observation,
                     *, expected_devices=None, observation=None):
    """Observe an already acquired original-Owner child; never spawn or own UART."""
    devices = {'root': True, 'task': False, 'assignment': True} if expected_devices is None else expected_devices
    observer = Q2ProcessObserver(process, identity, output=output, expected_devices=devices, observation=observation)
    try:
        observer.start(min(started + 60, deadline))
        while observer.pipes.selector.get_map():
            if stop.is_set():
                deadline = min(deadline, time.monotonic() + 30)
            observer.poll(deadline)
        return observer.finish(deadline, serial_observation)
    finally:
        observer.close()
