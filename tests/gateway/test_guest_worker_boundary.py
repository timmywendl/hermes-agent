"""Q1 native VZ qualification candidate; authoring is not execution authorization.

No import/collection action starts a process or opens a socket. Every test first
requires BOTH Q1_VZ_EXECUTION=HUMAN_AUTHORIZED_DISPOSABLE_V1 and a protected JSON
Q1_VZ_MANIFEST whose SHA256 equals Q1_VZ_MANIFEST_SHA256. The marker is deliberate
operator opt-in, not a cryptographic proof of Human approval. A future signed-off
execution record must bind the exact test HEAD and manifest before setting it.

Manifest v1 (all paths absolute/canonical; no real credentials):
  version=1; source_head=<40hex>; allow_unconfined_controls=true; authorization=STAGE3_Q1_NATIVE_VZ_EXECUTION_V1; decision_ref=GitHub URL;
  expires_at=Unix seconds; root=<private temporary directory>; namespace=q1-<32hex>;
  binaries={limactl,ssh,sandbox,python,lsof,git}: {path,sha256}; artifacts={image,policy,
  identity,known_hosts}: {path,sha256}; policies={M1..M6}: {path,sha256};
  guest_user; guest_python=/usr/bin/python3; ssh_port>1024; host_ipv6=<local ULA>;
  guest_gateway=192.168.5.2; resources={cpus:2,memory_gib:4,disk_gib:12};
  deadlines={start:180,stop:45,probe:5,total:2700}; allowed_nodeids=[exact nodeids].

Policies are externally approved frozen artifacts, NOT generated/compiled here
until a future authorized native execution. Mutant policies must also be approved.
M1 is deliberately unconfined, but still uses the closed offline VM config and
only disposable local canaries. No arbitrary internet target or model route.
Missing authorization/capability is NOT_RUN/UNAVAILABLE, never qualification PASS.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil
import pytest

# The finite disposable parent owns the actual foreground VMM. Killing THIS
# parent in E3 is distinct from killing SSH or pretending to kill production.
_EXEC = """
import json,os,sys
argv=json.loads(sys.argv[1])
assert sys.stdin.buffer.read(1)==b'G'
os.dup2(os.open('/dev/null',os.O_RDONLY),0)
os.execvpe(argv[0],argv,os.environ)
"""

_OWNER = """
import json, os, subprocess, sys
p = json.loads(sys.stdin.readline())
with open(p['stdout'], 'xb', buffering=0) as out, open(p['stderr'], 'xb', buffering=0) as err:
    child = subprocess.Popen([sys.executable,'-I','-c',p['exec'],json.dumps(p['argv'])], env=p['env'], stdin=subprocess.PIPE,
                             stdout=out, stderr=err, close_fds=True, start_new_session=True)
    print(json.dumps({'pid': child.pid}), flush=True)
    for line in sys.stdin:
        if line.strip() == 'go': child.stdin.write(b'G'); child.stdin.flush(); child.stdin.close()
        elif line.strip() == 'exit': break
    child.wait()
"""


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def protected_json(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_size <= 131072
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                assert key not in result, 'duplicate manifest key'
                result[key] = value
            return result
        data = json.load(stream, object_pairs_hook=unique)
    assert isinstance(data, dict)
    return data


def pinned(item: dict[str, str], *, private: bool = False) -> Path:
    path = Path(item['path'])
    assert path.is_absolute() and path.resolve() == path and not path.is_symlink()
    info = path.stat()
    assert stat.S_ISREG(info.st_mode) and not (info.st_mode & 0o022)
    if private:
        assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
    assert re.fullmatch('[0-9a-f]{64}', item['sha256'])
    assert digest(path) == item['sha256'], f'artifact drift: {path}'
    return path


def load_gate(nodeid: str) -> dict[str, Any]:
    # This branch precedes even reading the manifest/binaries or making a tempdir.
    if os.environ.get('Q1_VZ_EXECUTION') != 'HUMAN_AUTHORIZED_DISPOSABLE_V1':
        pytest.skip('NOT_RUN: Q1 native execution authorization absent')
    raw = os.environ.get('Q1_VZ_MANIFEST', '')
    expected = os.environ.get('Q1_VZ_MANIFEST_SHA256', '')
    if not raw or not re.fullmatch('[0-9a-f]{64}', expected):
        pytest.skip('UNAVAILABLE/NOT_RUN: complete manifest identity absent')
    path = Path(raw)
    assert path.resolve() == path and digest(path) == expected
    data = protected_json(path)
    required = {'version', 'authorization', 'decision_ref', 'expires_at', 'root', 'namespace',
                'binaries', 'artifacts', 'policies', 'guest_user', 'guest_python', 'ssh_port',
                'host_ipv6', 'guest_gateway', 'resources', 'deadlines', 'allowed_nodeids', 'allow_unconfined_controls', 'source_head'}
    assert set(data) == required and type(data['version']) is int and data['version'] == 1
    assert data['allow_unconfined_controls'] is True, 'native positive/mutant controls need explicit scope'
    assert data['authorization'] == 'STAGE3_Q1_NATIVE_VZ_EXECUTION_V1'
    assert re.fullmatch(r'https://github\.com/[^/]+/[^/]+/(issues|pull)/\d+#issuecomment-\d+',
                        data['decision_ref'])
    expiry = data['expires_at']
    assert type(expiry) in (int, float) and math.isfinite(expiry)
    assert 0 < expiry - time.time() <= 3600, 'expired or unbounded authority'
    assert isinstance(data['allowed_nodeids'], list)
    assert all(isinstance(item, str) for item in data['allowed_nodeids'])
    assert len(set(data['allowed_nodeids'])) == len(data['allowed_nodeids'])
    if nodeid not in data['allowed_nodeids']:
        pytest.skip('NOT_RUN: this exact native case is not authorized')
    assert sys.platform == 'darwin' and os.uname().machine == 'arm64'
    root = Path(data['root'])
    assert path.is_relative_to(root), 'authorization manifest must be in its disposable root'
    assert root.resolve() == root and root.is_relative_to(Path(tempfile.gettempdir()).resolve())
    assert not (root / 'STOP_UNCERTAIN').exists(), 'UNKNOWN custody retained; no new VM'
    assert root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert re.fullmatch('q1-[0-9a-f]{32}', data['namespace'])
    assert data['resources'] == {'cpus': 2, 'memory_gib': 4, 'disk_gib': 12}
    assert re.fullmatch('[a-z_][a-z0-9_-]{0,30}', data['guest_user'])
    assert data['guest_python'] == '/usr/bin/python3'
    assert type(data['ssh_port']) is int and 1024 < data['ssh_port'] < 65536
    assert data['guest_gateway'] == '192.168.5.2'
    ipv6 = ipaddress.IPv6Address(data['host_ipv6'])
    assert ipv6.is_private and not (ipv6.is_loopback or ipv6.is_unspecified or ipv6.is_multicast)
    local = {a.address.split('%')[0] for rows in psutil.net_if_addrs().values() for a in rows}
    assert str(ipv6) in local, 'UNAVAILABLE: controlled Host IPv6 witness not local'
    assert set(data['deadlines']) == {'start', 'stop', 'probe', 'total'}
    for name, limit in {'start': 300, 'stop': 90, 'probe': 10, 'total': 2700}.items():
        value = data['deadlines'][name]
        assert type(value) in (int, float) and math.isfinite(value) and 2 <= value <= limit
    assert set(data['binaries']) == {'limactl', 'ssh', 'sandbox', 'python', 'lsof', 'git'}
    for item in data['binaries'].values():
        assert os.access(pinned(item), os.X_OK)
    assert re.fullmatch('[0-9a-f]{40}', data['source_head'])
    repo = Path(__file__).resolve().parents[2]
    safe_env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1'}
    git = str(pinned(data['binaries']['git']))
    head = subprocess.run([git, 'rev-parse', 'HEAD'], cwd=repo, env=safe_env,
                          capture_output=True, text=True, timeout=5, check=True)
    assert head.stdout.strip() == data['source_head'], 'execution source HEAD drift'
    clean = subprocess.run([git, 'status', '--porcelain', '--untracked-files=no'], cwd=repo,
                           env=safe_env, capture_output=True, text=True, timeout=5, check=True)
    assert not clean.stdout, 'tracked source differs from frozen HEAD'
    assert pinned(data['binaries']['python']) == Path(sys.executable).resolve()
    assert set(data['artifacts']) == {'image', 'policy', 'identity', 'known_hosts'}
    for name, item in data['artifacts'].items():
        assert pinned(item, private=name in {'identity', 'known_hosts'}).is_relative_to(root), 'only disposable staged artifacts'
    assert set(data['policies']) == {f'M{i}' for i in range(1, 7)}
    for item in data['policies'].values():
        assert pinned(item).is_relative_to(root)
    return data


@dataclass
class Lab:
    gate: dict[str, Any]
    root: Path
    instance: str
    process: subprocess.Popen[str] | None = None
    driver_pid: int = 0
    boot_id: str = ''
    retired: bool = False
    verified_stop: bool = False
    uncertain: str = ''
    transport_processes: list[subprocess.Popen[str]] = field(default_factory=list)
    process_identities: dict[int, float] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    attempt: int = 0
    started: float = field(default_factory=time.monotonic)
    _baseline: dict[str, Any] = field(default_factory=dict)
    _stop_at: float | None = None
    _events_path: Path = field(default_factory=Path)
    _exec_watch: Any = None
    _stop_receipt: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(self.root),
                    'LANG': 'C.UTF-8', 'LIMA_HOME': str(self.root / 'lima-unused')}
        self.gate['deadlines']['command'] = self.gate['deadlines']['probe']
        self.gate['known_hosts'] = self.gate['artifacts']['known_hosts']['path']
        self.gate['identity_file'] = self.gate['artifacts']['identity']['path']

    def binary(self, name: str) -> str:
        return str(pinned(self.gate['binaries'][name]))

    def check_budget(self) -> None:
        assert time.time() < self.gate['expires_at'], 'authorization expired'
        assert time.monotonic() - self.started < self.gate['deadlines']['total'], 'total budget'

    def record(self, name: str, value: Any) -> None:
        path = self.root / (name + '.json')
        with path.open('x') as stream:
            json.dump(value, stream, default=str)

    def run(self, argv: list[str], timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        self.check_budget()
        return subprocess.run(argv, env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, close_fds=True, timeout=timeout or self.gate['deadlines']['probe'],
                              check=False)

    def config(self, over_vsock: bool) -> Path:
        # Closed config: no user-supplied hooks, downloads, template, extra NIC,
        # mounts, agent forwarding, HostResolver or proxy inheritance.
        image = pinned(self.gate['artifacts']['image'])
        value = {'vmType': 'vz', 'arch': 'aarch64', 'os': 'Linux', 'cpus': 2,
                 'memory': '4GiB', 'disk': '12GiB', 'plain': True,
                 'images': [{'location': str(image), 'arch': 'aarch64',
                             'digest': 'sha256:' + self.gate['artifacts']['image']['sha256']}],
                 'mounts': [], 'networks': [], 'provision': [], 'portForwards': [],
                 'containerd': {'system': False, 'user': False},
                 'hostResolver': {'enabled': False}, 'propagateProxyEnv': False,
                 'rosetta': {'enabled': False},
                 'user': {'name': self.gate['guest_user']},
                 'ssh': {'localPort': self.gate['ssh_port'], 'overVsock': over_vsock,
                         'forwardAgent': False, 'loadDotSSHPubKeys': False}}
        path = self.root / f'config-{self.attempt}.json'
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def start(self, policy: str = 'baseline', over_vsock: bool = True) -> None:
        self.check_budget()
        assert self.process is None or (self.verified_stop and not self.uncertain)
        self.attempt += 1
        self.verified_stop = self.retired = False
        self._stop_at = None
        home = self.root / f'lima-{self.attempt}'
        home.mkdir(mode=0o700)  # Never adopts an existing directory/instance.
        self.env['LIMA_HOME'] = str(home)
        self.instance = f"{self.gate['namespace']}-{self.root.name[-8:]}-{self.attempt}"
        argv = [self.binary('limactl'), 'start', '--foreground', '--tty=false',
                '--name=' + self.instance, str(self.config(over_vsock))]
        if policy != 'M1':
            artifact = self.gate['artifacts']['policy'] if policy == 'baseline' else self.gate['policies'][policy]
            argv = [self.binary('sandbox'), '-f', str(pinned(artifact)),
                    '-D', 'ROOT=' + str(self.root), '-D', 'LIMA_HOME=' + str(home),
                    '-D', 'SSH_PORT=' + str(self.gate['ssh_port']), *argv]
        out, err = self.root / f'events-{self.attempt}.log', self.root / f'stderr-{self.attempt}.log'
        self.process = subprocess.Popen([self.binary('python'), '-I', '-c', _OWNER],
                                        env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, close_fds=True,
                                        start_new_session=True)
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps({'argv': argv, 'env': self.env,
                                            'stdout': str(out), 'stderr': str(err), 'exec': _EXEC}) + '\n')
        self.process.stdin.flush()
        readable, _, _ = select.select([self.process.stdout], [], [], self.gate['deadlines']['probe'])
        assert readable, 'UNAVAILABLE: test-owner did not acquire foreground process'
        self.driver_pid = json.loads(self.process.stdout.readline())['pid']
        driver = psutil.Process(self.driver_pid)
        assert driver.ppid() == self.process.pid
        self.process_identities = {driver.pid: driver.create_time()}
        self._exec_watch = select.kqueue()
        self._exec_watch.control([select.kevent(driver.pid, filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
            fflags=select.KQ_NOTE_EXEC | select.KQ_NOTE_EXIT)], 0, 0)
        self.process.stdin.write('go\n')
        self.process.stdin.flush()
        self._events_path = home / self.instance / 'ha.stdout.log'
        self._wait_ready()
        initial_events = self._exec_watch.control(None, 8, 0)
        assert any(e.fflags & select.KQ_NOTE_EXEC for e in initial_events), 'UNAVAILABLE: missing pre-exec custody'
        if not over_vsock:
            raise AssertionError('vsock fallback must never be admitted')
        info = self.ssh_code("import json,os; print(json.dumps({'boot':open('/proc/sys/kernel/random/boot_id').read().strip(),'uid':os.getuid()}))")
        assert info['uid'] != 0 and re.fullmatch('[0-9a-f-]{36}', info['boot'])
        self.boot_id = info['boot']
        self._baseline = self.identity_snapshot()
        self.assert_identity()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.gate['deadlines']['start']
        while time.monotonic() < deadline:
            self.check_budget()
            events = self._events_path.read_text() if self._events_path.exists() else ''
            # Parse native structured HostAgent events, not a Guest hello/log substring.
            # Ignore only an incomplete final line; malformed complete events fail.
            rows = [json.loads(line)['status'] for line in events.splitlines(keepends=True)
                    if line.endswith('\n') and line.startswith('{')]
            vsocks = [r['vsock'] for r in rows if isinstance(r.get('vsock'), dict)]
            assert not any(v.get('type') in {'failed', 'skipped'} for v in vsocks), 'vsock unavailable/fallback'
            good = [v for v in vsocks if v.get('type') == 'started' and v.get('vsockPort') == 22]
            if good and any(r.get('running') and not r.get('degraded') for r in rows):
                assert good[-1]['hostAddr'] == f"127.0.0.1:{self.gate['ssh_port']}"
                return
            assert psutil.pid_exists(self.driver_pid), 'UNAVAILABLE: driver exited before vsock'
            threading.Event().wait(.1)
        raise AssertionError('UNAVAILABLE: native vsock readiness deadline; not qualification PASS')

    def ssh_argv(self, extra: tuple[str, ...] = ()) -> list[str]:
        options = ['-F', '/dev/null', '-T', '-p', str(self.gate['ssh_port']),
                   '-i', str(pinned(self.gate['artifacts']['identity'], private=True))]
        for key, value in {'BatchMode': 'yes', 'IdentitiesOnly': 'yes', 'StrictHostKeyChecking': 'yes',
                           'UserKnownHostsFile': str(pinned(self.gate['artifacts']['known_hosts'], private=True)),
                           'GlobalKnownHostsFile': '/dev/null', 'ControlMaster': 'no', 'ControlPath': 'none',
                           'ForwardAgent': 'no', 'ForwardX11': 'no', 'PermitLocalCommand': 'no',
                           'ExitOnForwardFailure': 'yes', 'ConnectTimeout': '5',
                           'ServerAliveInterval': '2', 'ServerAliveCountMax': '2'}.items():
            options.extend(['-o', f'{key}={value}'])
        return [self.binary('ssh'), *options, *extra, f"{self.gate['guest_user']}@127.0.0.1"]

    def ssh_code(self, code: str) -> dict[str, Any]:
        self.check_budget()
        result = subprocess.run([*self.ssh_argv(), self.gate['guest_python'], '-'], input=code,
                                env=self.env, text=True, capture_output=True, close_fds=True,
                                timeout=self.gate['deadlines']['probe'], check=False)
        assert result.returncode == 0, f'UNAVAILABLE: actual SSH probe failed: {result.stderr}'
        value = json.loads(result.stdout)
        assert isinstance(value, dict), 'protocol stdout pollution'
        return value

    def spawn_transport(self, argv: list[str]) -> subprocess.Popen[str]:
        self.assert_identity()
        child = subprocess.Popen(argv, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, close_fds=True, start_new_session=True)
        self.transport_processes.append(child)
        self.process_identities[child.pid] = psutil.Process(child.pid).create_time()
        return child

    def identity_snapshot(self) -> dict[str, Any]:
        driver = psutil.Process(self.driver_pid)
        assert driver.create_time() == self.process_identities[self.driver_pid]
        assert Path(driver.exe()).resolve() == Path(self.binary('limactl'))
        listeners = [c for c in driver.net_connections(kind='tcp')
                     if c.status == psutil.CONN_LISTEN and c.laddr.port == self.gate['ssh_port']]
        assert len(listeners) == 1 and listeners[0].laddr.ip == '127.0.0.1'
        assert listeners[0].fd >= 0, 'UNAVAILABLE: listener FD ownership unobservable'
        for proc in driver.children(recursive=True):
            self.process_identities.setdefault(proc.pid, proc.create_time())
        boot = self.ssh_code("import json;print(json.dumps({'boot':open('/proc/sys/kernel/random/boot_id').read().strip()}))")['boot']
        assert boot == self.boot_id, 'actual Guest boot identity drift'
        return {'pid': driver.pid, 'birth': driver.create_time(), 'listener_fd': listeners[0].fd,
                'instance': self.instance, 'boot_id': self.boot_id, 'listener_pid': driver.pid,
                'image': self.gate['artifacts']['image']['sha256'],
                'policy_digest': digest(Path(self.gate['artifacts']['policy']['path'])), 'port': self.gate['ssh_port']}

    def assert_identity(self, expected: dict[str, Any] | None = None) -> None:
        assert not self.uncertain and not self.retired
        assert not self._exec_watch.control(None, 8, 0), 'unexpected exec/exit invalidates custody'
        actual = self.identity_snapshot()
        assert actual == (expected or self._baseline), 'joint VM/boot/process/FD/policy identity drift'

    def mark_uncertain(self, reason: str) -> None:
        self.uncertain = reason
        self.retired = True

    def assert_no_successor(self) -> None:
        assert self.verified_stop and not self.uncertain, 'UNKNOWN custody blocks successor'

    def state(self) -> dict[str, Any]:
        tracked = []
        endpoints: list[tuple[int, int, str]] = []
        for pid, birth in self.process_identities.items():
            try:
                proc = psutil.Process(pid)
                assert proc.create_time() == birth, 'PID reuse is UNKNOWN, not proof of old death'
                if proc.status() != psutil.STATUS_ZOMBIE:
                    tracked.append(pid)
                    endpoints.extend((pid, c.fd, str(c.laddr)) for c in proc.net_connections(kind='all'))
            except psutil.NoSuchProcess:
                continue
        return {'vm_running': self.driver_pid in tracked, 'tracked_processes': tracked,
                'open_endpoints': endpoints, 'writers': tracked}

    def stop(self) -> dict[str, Any]:
        if self.verified_stop:
            return dict(self._stop_receipt)
        if self._stop_at is None:
            self._stop_at = time.monotonic() + self.gate['deadlines']['stop']
        self.retired = True
        for child in self.transport_processes:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=max(.1, self._stop_at - time.monotonic()))
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
        if self.driver_pid:
            # Scoped fresh LIMA_HOME + exact own instance; never stop-all/delete/adopt.
            result = subprocess.run([self.binary('limactl'), 'stop', self.instance],
                env=self.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                close_fds=True, timeout=max(.1, self._stop_at - time.monotonic()), check=False)
            assert result.returncode == 0, 'UNKNOWN: exact VM stop failed'
        if self.process is not None:
            assert self.process.stdin is not None
            if self.process.poll() is None:
                self.process.stdin.write('exit\n')
                self.process.stdin.flush()
                self.process.wait(timeout=max(.1, self._stop_at - time.monotonic()))
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
        # CLI state is corroboration, not sole proof. Scan only our dedicated
        # instance files for external VZ/helper holders, never unrelated files.
        state = subprocess.run([self.binary('limactl'), 'list', '--json', self.instance],
            env=self.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            close_fds=True, timeout=max(.1, self._stop_at - time.monotonic()), check=False)
        assert state.returncode == 0 and json.loads(state.stdout)['status'] == 'Stopped', 'UNKNOWN: native VZ state'
        files = [str(p) for p in Path(self.env['LIMA_HOME']).rglob('*') if p.is_file() and not p.is_symlink()]
        assert files, 'UNKNOWN: no instance file custody'
        holders = subprocess.run([self.binary('lsof'), '-Fpf', '--', *files], env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, close_fds=True,
            timeout=max(.1, self._stop_at - time.monotonic()), check=False)
        assert holders.returncode == 1 and not holders.stdout and not holders.stderr, 'UNKNOWN: file holders/delegate visibility'
        end = self.state()
        assert not any(end[k] for k in ('vm_running', 'tracked_processes', 'open_endpoints', 'writers')), 'UNKNOWN: writers/endpoints survive'
        if self._exec_watch is not None:
            self._exec_watch.close()
            self._exec_watch = None
        self.verified_stop = True
        self._stop_receipt = {'verified': True, 'vm_stopped': True, 'processes_gone': True,
                              'endpoints_closed': True, 'writers_quiescent': True,
                              'identities': dict(self.process_identities), 'state': end}
        self.record(f'stop-{self.attempt}', self._stop_receipt)
        return dict(self._stop_receipt)


@pytest.fixture
def native_lab(request: pytest.FixtureRequest) -> Iterator[Lab]:
    gate = load_gate(request.node.nodeid)
    import fcntl
    parent = Path(gate['root'])
    lock = (parent / 'native.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        root = parent / ('case-' + uuid.uuid4().hex)
        root.mkdir(mode=0o700)
        lab = Lab(gate, root, gate['namespace'])
        lab.record('execution-manifest', gate)
        try:
            yield lab
        finally:
            if lab.process is not None:
                try:
                    lab.stop()
                except Exception:
                    lab.mark_uncertain('teardown_failed')
                    (parent / 'STOP_UNCERTAIN').touch(exist_ok=True)
                    raise
    finally:
        lock.close()


@contextmanager
def witness(family: int, kind: int, address: str) -> Iterator[tuple[socket.socket, bytes]]:
    """A live disposable listener, never a real Host service or internet target."""
    token = uuid.uuid4().hex.encode()
    with socket.socket(family, kind) as server:
        server.bind((address, 0))
        server.settimeout(3)
        if kind == socket.SOCK_STREAM:
            server.listen(5)
        yield server, token


def guest_connect(lab: Lab, address: str, port: int, family: int, kind: int, token: bytes) -> bool:
    # Literal addresses only: never resolves arbitrary public DNS in a generic probe.
    ipaddress.ip_address(address)
    code = f"""import socket,json
s=socket.socket({family},{kind}); s.settimeout(2)
try:
 s.connect(({address!r},{port})); s.sendall({token!r}); ok=True
except OSError: ok=False
finally: s.close()
print(json.dumps({{'sent':ok}}))
"""
    return lab.ssh_code(code)['sent'] is True


def assert_denied_with_witness(lab: Lab, address: str, host: str, family: int, kind: int) -> None:
    with witness(family, kind, host) as (server, token):
        # A Host-side positive proves the listener actually works. A separate M1
        # Guest positive below is additionally mandatory for route availability.
        with socket.socket(family, kind) as control:
            control.connect((host, server.getsockname()[1]))
            control.sendall(token)
        if kind == socket.SOCK_STREAM:
            conn, _ = server.accept()
            with conn:
                assert conn.recv(128) == token
        else:
            assert server.recvfrom(128)[0] == token
        sent = guest_connect(lab, address, server.getsockname()[1], family, kind, token)
        with pytest.raises(socket.timeout):
            if kind == socket.SOCK_STREAM:
                conn, _ = server.accept()
                conn.close()
            else:
                server.recvfrom(128)
        assert not sent, 'forbidden Guest network capability'


@pytest.mark.platforms('macos', arch='arm64')
def test_native_a1_a2_boundary(native_lab: Lab) -> None:
    lab = native_lab
    lab.start()
    lab.assert_identity()
    canary = lab.root / 'host-only-canary'
    canary.write_text(uuid.uuid4().hex)
    observed = lab.ssh_code(f"""import json,os,tempfile
p={str(canary)!r}
with tempfile.TemporaryFile() as f:
 f.write(b'GUEST_RW');f.seek(0);rw=f.read()==b'GUEST_RW'
print(json.dumps({{'host_visible':os.path.exists(p),'guest_rw':rw,
 'mounts':open('/proc/mounts').read()}}))
""")
    assert observed['guest_rw'] and not observed['host_visible']
    assert 'virtiofs' not in observed['mounts']  # Q1 intentionally admits zero Host shares.
    assert all(f.path != str(canary) for f in psutil.Process(lab.driver_pid).open_files())
    assert lab.ssh_code("import json; print(json.dumps({'positive':'Q1_NATIVE_GUEST'}))") == {'positive': 'Q1_NATIVE_GUEST'}


@pytest.mark.platforms('macos', arch='arm64')
@pytest.mark.parametrize(('family', 'kind'), [(socket.AF_INET, socket.SOCK_STREAM),
                         (socket.AF_INET, socket.SOCK_DGRAM),
                         (socket.AF_INET6, socket.SOCK_STREAM), (socket.AF_INET6, socket.SOCK_DGRAM)])
def test_native_d1_d2_network(native_lab: Lab, family: int, kind: int) -> None:
    lab = native_lab
    host = '127.0.0.1' if family == socket.AF_INET else lab.gate['host_ipv6']
    target = lab.gate['guest_gateway'] if family == socket.AF_INET else host
    # Same test, same live listener and Guest route: establish native positive
    # before applying baseline denial on a NEW isolated boot. No skip-as-PASS.
    lab.start(policy='M1')
    with witness(family, kind, host) as (server, token):
        assert guest_connect(lab, target, server.getsockname()[1], family, kind, token), 'UNAVAILABLE: Guest route positive missing'
        if kind == socket.SOCK_STREAM:
            conn, _ = server.accept()
            with conn:
                assert conn.recv(128) == token
        else:
            assert server.recvfrom(128)[0] == token
    lab.stop()
    lab.start()
    assert_denied_with_witness(lab, target, host, family, kind)



# Fixed Host probe code: no arbitrary shell, destination URL, resolver query,
# Keychain or ambient credential. It only handles test-owned canaries.
_HOST_PROBE = """
import ctypes,json,os,socket,subprocess,sys
p=json.loads(sys.argv[1]); kind=p['kind']; allowed=False
try:
 if kind in ('read','child_read'):
  if kind=='read': allowed=open(p['path']).read()==p['token']
  else:
   r=subprocess.run([sys.executable,'-I','-c','import sys;print(open(sys.argv[1]).read())',p['path']],capture_output=True,text=True,timeout=3)
   allowed=r.returncode==0 and r.stdout.strip()==p['token']
 elif kind=='fd': allowed=os.read(p['fd'],128).decode()==p['token']
 elif kind=='fd_write': allowed=os.write(p['fd'],p['token'].encode())==len(p['token'])
 elif kind=='mach':
  lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib'); port=ctypes.c_uint.in_dll(lib,'bootstrap_port')
  out=ctypes.c_uint(); status=lib.bootstrap_look_up(port.value,b'com.apple.mDNSResponder',ctypes.byref(out))
  allowed=status==0
 else:
  family=socket.AF_UNIX if kind=='unix' else (socket.AF_INET6 if kind=='ipv6' else socket.AF_INET)
  stype=socket.SOCK_DGRAM if kind=='dns_udp' else socket.SOCK_STREAM
  s=socket.socket(family,stype); s.settimeout(2)
  target=p['path'] if kind=='unix' else (p['address'],p['port'])
  s.connect(target); s.sendall(bytes.fromhex(p['payload'])); allowed=True; s.close()
except (OSError,ValueError): pass
print(json.dumps({'ran':True,'allowed':allowed,'kind':kind}))
"""


def host_probe(lab: Lab, values: dict[str, Any], policy: str = 'baseline',
               pass_fds: tuple[int, ...] = ()) -> dict[str, Any]:
    argv = [lab.binary('python'), '-I', '-c', _HOST_PROBE, json.dumps(values)]
    if policy != 'M1':
        item = lab.gate['artifacts']['policy'] if policy == 'baseline' else lab.gate['policies'][policy]
        argv = [lab.binary('sandbox'), '-f', str(pinned(item)), '-D', 'ROOT=' + str(lab.root),
                '-D', 'LIMA_HOME=' + lab.env['LIMA_HOME'],
                '-D', 'SSH_PORT=' + str(lab.gate['ssh_port']), *argv]
    result = subprocess.run(argv, env=lab.env, capture_output=True, text=True, close_fds=True,
                            pass_fds=pass_fds, timeout=lab.gate['deadlines']['probe'], check=False)
    assert result.returncode == 0, f'UNAVAILABLE: Host probe not executed: {result.stderr}'
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    assert value['ran'] is True and value['kind'] == values['kind']
    return value


@pytest.mark.platforms('macos', arch='arm64')
def test_native_a2_closed_fds_and_exec_descendants(native_lab: Lab) -> None:
    lab = native_lab
    lab.start()
    canary = lab.root / 'fd-canary'
    token = uuid.uuid4().hex
    canary.write_text(token)
    with canary.open('r+') as stream:
        values = {'kind': 'fd', 'fd': stream.fileno(), 'token': token}
        # Native preopened-FD positive: policy cannot retroactively revoke it.
        assert host_probe(lab, values, pass_fds=(stream.fileno(),))['allowed']
        stream.seek(0)
        assert not host_probe(lab, values)['allowed']
    with canary.open('r+') as stream:
        values = {'kind': 'fd_write', 'fd': stream.fileno(), 'token': 'TEST_WRITE_ONLY'}
        before = canary.read_text()
        assert not host_probe(lab, values)['allowed'] and canary.read_text() == before
        assert host_probe(lab, values, pass_fds=(stream.fileno(),))['allowed']
        assert canary.read_text().startswith('TEST_WRITE_ONLY')
    canary.write_text(token)
    for kind in ('read', 'child_read'):
        values = {'kind': kind, 'path': str(canary), 'token': token}
        assert host_probe(lab, values, policy='M1')['allowed'], 'UNAVAILABLE: native file positive'
        assert not host_probe(lab, values)['allowed'], 'Host policy read/child escape'


@pytest.mark.platforms('macos', arch='arm64')
def test_native_d1_dns_and_resolver_mach(native_lab: Lab) -> None:
    lab = native_lab
    lab.start()
    # bootstrap lookup establishes the actual resolver-service acquisition
    # boundary without submitting a DNS query to the production resolver.
    values = {'kind': 'mach'}
    assert host_probe(lab, values, policy='M1')['allowed'], 'UNAVAILABLE: Mach positive missing'
    assert not host_probe(lab, values)['allowed'], 'resolver Mach acquisition bypass'
    # DNS-format bytes go ONLY to this local disposable receiver, which never
    # forwards. No public hostname or system nameserver is used by the probe.
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02q1\x04test\x00\x00\x10\x00\x01'
    with witness(socket.AF_INET, socket.SOCK_DGRAM, '127.0.0.1') as (server, _):
        values = {'kind': 'dns_udp', 'address': '127.0.0.1',
                  'port': server.getsockname()[1], 'payload': query.hex()}
        assert host_probe(lab, values, policy='M1')['allowed']
        assert server.recvfrom(128)[0] == query
        assert not host_probe(lab, values)['allowed']
        with pytest.raises(socket.timeout):
            server.recvfrom(128)
    # This Host acquisition proof is a subgate, not proof that every VZ/XPC
    # delegate is confined. Native Guest IP/UDP/DNS paths have separate witnesses.


@pytest.mark.platforms('macos', arch='arm64')
@pytest.mark.parametrize('mutation', [f'M{i}' for i in range(1, 7)])
def test_native_m1_m6_policy_sensitivity(native_lab: Lab, mutation: str) -> None:
    lab = native_lab
    lab.start(policy=mutation)
    token = uuid.uuid4().hex
    canary = lab.root / 'mutant-canary'
    canary.write_text(token)
    values: dict[str, Any]
    if mutation in {'M1', 'M6'}:
        kind = 'read' if mutation == 'M1' else 'child_read'
        values = {'kind': kind, 'path': str(canary), 'token': token}
        assert not host_probe(lab, values)['allowed']
        assert host_probe(lab, values, policy=mutation)['allowed'], f'UNKNOWN: {mutation} no file witness'
    elif mutation == 'M5':
        with canary.open() as stream:
            values = {'kind': 'fd', 'fd': stream.fileno(), 'token': token}
            assert not host_probe(lab, values)['allowed']
            assert host_probe(lab, values, pass_fds=(stream.fileno(),))['allowed'], 'M5 inherited FD not detected'
    elif mutation == 'M4':
        path = lab.root / 'host-socket-canary'
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            server.listen(2)
            server.settimeout(3)
            values = {'kind': 'unix', 'path': str(path), 'payload': token.encode().hex()}
            assert not host_probe(lab, values)['allowed']
            assert host_probe(lab, values, policy=mutation)['allowed'], 'UNKNOWN: M4 no UDS witness'
            connection, _ = server.accept()
            with connection:
                assert connection.recv(128) == token.encode()
    else:
        family = socket.AF_INET6 if mutation == 'M2' else socket.AF_INET
        socket_kind = socket.SOCK_STREAM if mutation == 'M2' else socket.SOCK_DGRAM
        host = '::1' if family == socket.AF_INET6 else '127.0.0.1'
        with witness(family, socket_kind, host) as (server, _):
            values = {'kind': 'ipv6' if mutation == 'M2' else 'dns_udp', 'address': host,
                      'port': server.getsockname()[1], 'payload': token.encode().hex()}
            assert not host_probe(lab, values)['allowed']
            assert host_probe(lab, values, policy=mutation)['allowed'], f'UNKNOWN: {mutation} no network witness'
            if socket_kind == socket.SOCK_STREAM:
                connection, _ = server.accept()
                with connection:
                    assert connection.recv(128) == token.encode()
            else:
                assert server.recvfrom(128)[0] == token.encode()


@pytest.mark.platforms('macos', arch='arm64')
def test_native_d2_host_browser_docker_and_uds_are_not_guest_capabilities(native_lab: Lab) -> None:
    lab = native_lab
    lab.start()
    # Each is a real disposable listener, not a test against absent production
    # CDP/Docker or a claim based on their conventional port numbers.
    for label in ('browser-cdp', 'docker-api'):
        assert_denied_with_witness(lab, lab.gate['guest_gateway'], '127.0.0.1',
                                   socket.AF_INET, socket.SOCK_STREAM)
        lab.record(label, {'controlled_listener': True, 'guest_denied': True})
    path = lab.root / 'fake-docker.sock'
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen(2)
        server.settimeout(2)
        with socket.socket(socket.AF_UNIX) as control:
            control.connect(str(path))
            control.sendall(b'LOCAL_UDS_WITNESS')
        conn, _ = server.accept()
        with conn:
            assert conn.recv(128) == b'LOCAL_UDS_WITNESS'
        result = lab.ssh_code(f"""import json,socket
s=socket.socket(socket.AF_UNIX);s.settimeout(2)
try: s.connect({str(path)!r}); reached=True
except OSError: reached=False
finally: s.close()
print(json.dumps({{'reached':reached}}))
""")
        assert not result['reached']
        with pytest.raises(socket.timeout):
            conn, _ = server.accept()
            conn.close()
