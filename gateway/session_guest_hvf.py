"""Finite Q2 qualification through the registered original SessionAuthority.

No public dispatch backend, network service, Worker runtime or manifest-issued
authority. The protected Host operator must separately record an exact Human
grant before this module can create a QEMU process. Source/offline preparation
does not record such a grant.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import threading
import time
import uuid

import httpx
import psutil

from gateway.session_hvf_adapter import _require_owner
from hermes_state_runtime import RuntimeStoreError

PACKAGE = 'HERMES_Q2_ORIGINAL_OWNER_NATIVE_QUALIFICATION_V1'
NAMESPACE = 'q2_hvf_v1'
PREFIX = 'q2.hvf.attempt:'
GRANTS = 'q2.hvf.grant:'
APPROVALS = 'q2.hvf.human:'
SOURCES = {
    'guest': '9a270a78b421565a64901182062b18a0d3b2e673',
    'builder': '2232de50d163c5a1d630220922642983437ab9ac',
    'host_baseline': '13c096f01f4d65726d89e36f9985959f8c6fcb73',
    'q1': '48c4c94bec337d1fca48876280f9655e4800c961',
}
BUDGET = {'slots': ['developer', 'reviewer', 'cancellation'], 'processes': 3,
          'concurrency': 1, 'vcpus': 2, 'ram_bytes': 2 * 1024**3,
          'disk_bytes': 8 * 1024**3, 'startup_seconds': 60,
          'stop_seconds': 30, 'slot_seconds': 300, 'batch_seconds': 900,
          'retries': 0, 'reboots': 0, 'resume': False}
SCOPE_KEYS = ('session_id', 'generation', 'epoch', 'execution_id', 'task_id', 'run_id',
              'vm_id', 'connection_generation', 'image_digest', 'policy_digest')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _pairs(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise RuntimeStoreError('q2_duplicate_metadata')
        values[key] = value
    return values


def metadata(raw, *, canonical_required=True):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(value, dict) or (canonical_required and canonical(value) != raw):
            raise ValueError('canonical object required')
        canonical(value)
        return value
    except (TypeError, ValueError) as error:
        raise RuntimeStoreError('q2_metadata_unavailable') from error


def read_json(path):
    return metadata(Path(path).read_bytes().decode('utf-8').rstrip('\n'))


def write_receipt(path, body, *, newline=True):
    """Append-only diagnostic evidence; never execution authority."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = (canonical(body) + ('\n' if newline else '')).encode()
    with target.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def _hex(value, size=64):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{' + str(size) + '}', value) is not None


@dataclass(frozen=True)
class Q2Batch:
    path: Path
    body: dict

    @classmethod
    def load(cls, path):
        path = Path(path).resolve(strict=True)
        return cls(path, read_json(path))

    @property
    def sha256(self):
        return digest(self.body)

    @property
    def profile(self):
        return Path(self.body['profile'])

    @property
    def board(self):
        return self.profile / 'kanban/boards/q2-qualification/kanban.db'

    @property
    def output(self):
        return Path(self.body['output'])

    def verify(self, authority, *, source=True):
        _require_owner(authority)
        b = self.body
        required = {'package', 'accepted_sources', 'source_head', 'profile', 'output',
                    'original_artifacts', 'helper_package', 'sandbox_receipt',
                    'fixture_source', 'fixture_identity', 'mke2fs', 'artifact_python',
                    'tool_inventory', 'root_copy', 'sandbox_fixture_identity', 'budget', 'recipe_sha256'}
        if (set(b) != required or b['package'] != PACKAGE or b['accepted_sources'] != SOURCES
                or b['budget'] != BUDGET or not _hex(b['source_head'], 40)
                or b['recipe_sha256'] != digest(read_json(Path(__file__).resolve().parents[1] / 'native/qemu_guest/qualification-fixture.json'))):
            raise RuntimeStoreError('q2_batch_contract_changed')
        home = Path(authority.profile_id).resolve(strict=True)
        if (home.name != 'q2-qualification' or home != self.profile.resolve(strict=True)
                or Path(authority.db.db_path).resolve() != home / 'state.db'
                or not self.output.is_absolute() or self.output.parent != home.parent
                or not Path(b['fixture_source']).resolve(strict=True).is_relative_to(home.parent / 'fixtures')):
            raise RuntimeStoreError('q2_disposable_scope_required')
        self.verify_artifacts()
        self.verify_inputs()
        self.verify_sandbox_fixtures()
        from native.qemu_guest.qualification_package import verify_sandbox_controls
        verify_sandbox_controls(read_json(b['sandbox_receipt']), b['helper_package'])
        if source:
            self.verify_source()

    def verify_source(self):
        root = Path(__file__).resolve().parents[1]
        observed = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True, encoding='utf-8', timeout=30).strip()
        dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True, encoding='utf-8', timeout=30)
        if observed != self.body['source_head'] or dirty:
            raise RuntimeStoreError('q2_source_not_frozen')

    def verify_artifacts(self):
        from native.qemu_guest.artifact_inventory import ARTIFACTS, file_record
        rows = self.body['original_artifacts']
        if not isinstance(rows, dict) or set(rows) != set(ARTIFACTS):
            raise RuntimeStoreError('q2_original_inventory_incomplete')
        identities = set()
        for row in rows.values():
            if file_record(Path(row['path'])) != row:
                raise RuntimeStoreError('q2_original_artifact_changed')
            identity = row['st_dev'], row['st_ino']
            if identity in identities:
                raise RuntimeStoreError('q2_original_inode_alias')
            identities.add(identity)
        copied = self.body['root_copy']
        if (file_record(Path(copied['path'])) != copied
                or copied['sha256'] != rows['root.raw']['sha256']
                or (copied['st_dev'], copied['st_ino']) in identities
                or not Path(copied['path']).resolve().is_relative_to(self.profile.parent)):
            raise RuntimeStoreError('q2_root_copy_unavailable')

    def verify_inputs(self):
        """The protected grant binds tool dependencies and the public fixture."""
        tools = self.body['tool_inventory']
        if (not isinstance(tools, dict) or not tools
                or self.body['mke2fs'] not in tools or self.body['artifact_python']['path'] not in tools):
            raise RuntimeStoreError('q2_tool_inventory_missing')
        for name, expected in tools.items():
            if not Path(name).is_absolute() or not _hex(expected) or hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
                raise RuntimeStoreError('q2_build_tool_changed')
        source = Path(self.body['fixture_source']).resolve(strict=True)
        identity = self.body['fixture_identity']
        actual = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in source.rglob('*') if path.is_file()}
        if (any(path.is_symlink() or (path.is_file() and path.stat().st_nlink != 1) for path in source.rglob('*'))
                or actual != identity.get('inventory') or not _hex(identity.get('head'), 40)
                or not _hex(identity.get('tree'), 40) or identity.get('common_dir') != str(source / '.git')):
            raise RuntimeStoreError('q2_fixture_identity_changed')

    def verify_sandbox_fixtures(self):
        """Bind existing public socket fixtures, without connecting or listening."""
        policy = read_json(self.body['helper_package']['static_policy'])
        fixtures = self.body['sandbox_fixture_identity']
        if not isinstance(fixtures, dict) or set(fixtures) != set(policy['unix'].values()):
            raise RuntimeStoreError('q2_sandbox_fixture_missing')
        for path, expected in fixtures.items():
            info = Path(path).lstat()
            if (not stat.S_ISSOCK(info.st_mode)
                    or {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode')} != expected):
                raise RuntimeStoreError('q2_sandbox_fixture_changed')


def record_human_grant(authority, actor, ref, *, batch, decision_uri):
    """Protected Host control only; no Guest RPC/JSON file can mint this row."""
    authority.authorize(actor, ref, 'session:operator')
    batch.verify(authority)
    if (not isinstance(decision_uri, str)
            or not re.fullmatch(r'https://github.com/spareribes/ai-colleague/issues/139#issuecomment-[0-9]+', decision_uri)):
        raise RuntimeStoreError('q2_explicit_human_decision_required')
    key = APPROVALS + batch.sha256
    body = {'payload_sha256': batch.sha256, 'decision_uri': decision_uri,
            'subject': actor.subject, 'profile': authority.profile_id, 'budget': BUDGET}
    def write(conn):
        _require_owner(authority, conn)
        if conn.execute('SELECT 1 FROM state_meta WHERE key=?', (key,)).fetchone():
            raise RuntimeStoreError('q2_grant_already_recorded')
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (key, canonical(body)))
    authority.db._execute_write(write)
    return body


def _approval(authority, batch):
    raw = authority.db.get_meta(APPROVALS + batch.sha256)
    if raw is None:
        raise RuntimeStoreError('q2_native_not_authorized')
    body = metadata(raw)
    if (body.get('payload_sha256') != batch.sha256 or body.get('profile') != authority.profile_id
            or body.get('budget') != BUDGET or not body.get('subject') or not body.get('decision_uri')):
        raise RuntimeStoreError('q2_native_grant_changed')
    return body


def begin_batch(authority, batch):
    _approval(authority, batch)
    batch.verify(authority)
    key = GRANTS + batch.sha256
    def write(conn):
        _require_owner(authority, conn)
        if conn.execute('SELECT 1 FROM state_meta WHERE key LIKE ?', (GRANTS + '%',)).fetchone():
            raise RuntimeStoreError('q2_grant_spent_or_uncertain')
        if conn.execute('SELECT 1 FROM worker_executions LIMIT 1').fetchone():
            raise RuntimeStoreError('q2_fresh_profile_required')
        record = {'payload_sha256': batch.sha256, 'status': 'IN_PROGRESS', 'spent': 0,
                  'epoch': authority.epoch, 'instance': authority.instance_id,
                  'started_monotonic': time.monotonic(), 'boot_time': psutil.boot_time()}
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (key, canonical(record)))
        return record
    record = authority.db._execute_write(write)
    authority._q2_active_grant = key
    return record


def _grant(conn, authority, batch, slot):
    _require_owner(authority, conn)
    raw = conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANTS + batch.sha256,)).fetchone()
    grant = metadata(raw[0]) if raw else {}
    if (grant.get('status') != 'IN_PROGRESS' or grant.get('spent') != slot - 1
            or grant.get('epoch') != authority.epoch or grant.get('instance') != authority.instance_id
            or grant.get('boot_time') != psutil.boot_time()):
        raise RuntimeStoreError('q2_native_budget_unavailable')
    if (slot > 1 and (grant.get('phase') != 'SLOT_COMPLETE' or grant.get('handoff') != slot)):
        raise RuntimeStoreError('q2_previous_slot_not_complete')
    if not 1 <= slot <= 3 or time.monotonic() - grant['started_monotonic'] >= 900:
        raise RuntimeStoreError('q2_native_budget_exhausted')
    return grant


@dataclass
class Q2Attempt:
    authority: object
    batch: Q2Batch
    record: dict
    endpoint: object
    closed: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    service_done: threading.Event = field(default_factory=threading.Event)
    process: object = None
    identity: dict | None = None
    observed_identity: dict = field(default_factory=dict)
    serial: object = None
    guest_serial_closed: bool | None = None
    pipe_observation: dict = field(default_factory=dict)
    channel: object = None
    service: object = None
    executor: object = None
    work: dict = field(default_factory=dict)
    spawned_at: float = 0
    batch_deadline: float = 0
    slot_deadline: float = 0
    device_record: dict = field(default_factory=dict)
    parent_device_observation: dict = field(default_factory=dict)
    bootstrap_closed: bool = False
    task_checkpoint_fd: int | None = None
    errors: list = field(default_factory=list)
    proof: dict | None = None

    @property
    def key(self):
        return PREFIX + self.record['attempt']

    @property
    def scope(self):
        return self.endpoint.scope


def _history(board, authority, current=None):
    if board.execute('SELECT 1 FROM tasks WHERE worker_pid IS NOT NULL LIMIT 1').fetchone():
        raise RuntimeStoreError('q2_legacy_pid_unretired')
    if board.execute('SELECT 1 FROM tasks t WHERE NOT EXISTS(SELECT 1 FROM task_runs r WHERE r.task_id=t.id) LIMIT 1').fetchone():
        raise RuntimeStoreError('q2_execution_history_missing')
    for row in board.execute('SELECT id,metadata,worker_pid FROM task_runs'):
        data = metadata(row['metadata'], canonical_required=False)
        saved = data.get(NAMESPACE)
        if not isinstance(saved, dict) or row['worker_pid'] is not None:
            raise RuntimeStoreError('q2_execution_history_missing')
        if current is not None and saved == current:
            continue
        if saved.get('state') != 'RETIRED' or not _valid_proof(saved):
            raise RuntimeStoreError('q2_previous_execution_uncertain')
        indexed = authority.db.get_meta(PREFIX + saved['attempt'])
        if indexed != canonical(saved):
            raise RuntimeStoreError('q2_retirement_index_unavailable')


def _board_guard(board, handle):
    from hermes_cli import kanban_db as kb
    task = kb.get_task(board, handle.scope['task_id'])
    run = board.execute('SELECT * FROM task_runs WHERE id=?', (handle.scope['run_id'],)).fetchone()
    if (task is None or run is None or task.current_run_id != run['id'] or task.status != 'running'
            or run['status'] != 'running' or task.claim_lock != run['claim_lock']
            or not task.claim_lock or hashlib.sha256(task.claim_lock.encode()).hexdigest() != handle.record['claim_digest']
            or type(task.claim_expires) is not int or task.claim_expires <= int(time.time())):
        raise RuntimeStoreError('q2_board_claim_changed')
    _history(board, handle.authority, handle.record)
    if metadata(run['metadata'], canonical_required=False).get(NAMESPACE) != handle.record:
        raise RuntimeStoreError('q2_board_reservation_changed')
    with handle.authority.db._read_ctx() as conn:
        handle.endpoint._verify(conn, allow_unknown=handle.record.get('mode') == 'cancellation')
    raw = handle.authority.db.get_meta(GRANTS + handle.batch.sha256)
    grant = metadata(raw) if raw is not None else {}
    if (grant.get('status') != 'IN_PROGRESS' or grant.get('spent') != handle.record['slot']
            or grant.get('epoch') != handle.authority.epoch or grant.get('instance') != handle.authority.instance_id
            or grant.get('boot_time') != psutil.boot_time()
            or time.monotonic() - grant.get('started_monotonic', 0) >= 900):
        raise RuntimeStoreError('q2_native_grant_changed')
    _approval(handle.authority, handle.batch)
    return run


def _persist(board, handle, record):
    """Two existing stores, fail-closed on every partial commit; not cross-DB atomic."""
    row = board.execute('SELECT metadata FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()
    data = metadata(row[0], canonical_required=False)
    data[NAMESPACE] = record
    board.execute('UPDATE task_runs SET metadata=? WHERE id=?', (canonical(data), record['run_id']))
    def write(conn):
        _require_owner(handle.authority, conn)
        old = conn.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()
        if old is None or old[0] != canonical(handle.record):
            raise RuntimeStoreError('q2_owner_reservation_changed')
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(record), handle.key))
    handle.authority.db._execute_write(write)
    handle.record = record


def _new_board_task(authority, batch, slot, source, head):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    from gateway.session_guest_workspace import prepare_workspace
    source = Path(source).resolve(strict=True)
    fixture_root = batch.profile.parent / 'fixtures'
    admitted_source = fixture_root / ('admission-source-' + str(slot))
    prepare_workspace(source, admitted_source, head=head, role='developer')
    subprocess.run(['git', '-C', str(admitted_source), 'remote', 'add', 'origin',
                    'https://github.com/fixture/q2-qualification.git'],
                   check=True, capture_output=True, timeout=30)
    destination = fixture_root / 'worktrees' / ('admitted-slot-' + str(slot))
    workspace = prepare_workspace(admitted_source, destination, head=head, role='reviewer' if slot == 2 else 'developer')
    contract = {'version': 1, 'repo': 'fixture/q2-qualification', 'source_root': str(admitted_source),
                'common_dir': str(admitted_source / '.git'), 'remote_url': 'https://github.com/fixture/q2-qualification.git',
                'base_commit': head, 'branch_name': 'task/guest', 'workspace_root': str(fixture_root),
                'workspace_path': str(workspace.root)}
    now, session = int(time.time()), 'q2-qualification-' + str(slot)
    authority.db.create_session(session, source='kanban')
    with connect_closing(batch.board) as board, write_txn(board):
        _history(board, authority)
        task = kb.create_task(board, title='Q2 qualification ' + BUDGET['slots'][slot - 1],
            body='Disposable qualification only. No production, credentials or network.',
            project_id='', session_id=session, workspace_kind='worktree', workspace_path=str(workspace.root),
            branch_name='task/guest', workspace_admission=contract, completion_contract='local-only')
        run = kb._claim_and_open_run(board, task, 'ready', uuid.uuid4().hex, now + 3600, now,
                                    event_extra={'source_status': 'review' if slot == 2 else 'ready'})
        if run is None:
            raise RuntimeStoreError('q2_fixture_claim_failed')
        claimed = kb.get_task(board, task)
        kb._append_event(board, task, 'owner_admitted', {'session_id': session}, run_id=run)
        context = {'db': str(batch.board), 'task_id': task, 'run_id': run, 'claim_lock': claimed.claim_lock}
        return context, session


def reserve_attempt(authority, batch, slot, *, source, head):
    from types import SimpleNamespace
    from gateway.session_worker_guest import GuestBinding, GuestOwnerEndpoint, reserve_guest_admission
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    from hermes_state_runtime import admit_session_input, claim_session_input
    _require_owner(authority)
    _approval(authority, batch)
    if any(not h.closed.is_set() for h in getattr(authority, '_q2_hvf_workers', {}).values()):
        raise RuntimeStoreError('q2_no_successor')
    def consume(conn):
        grant = _grant(conn, authority, batch, slot)
        grant.update(spent=slot, phase='RESERVING', handoff=None)
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(grant), GRANTS + batch.sha256))
    authority.db._execute_write(consume)
    context, sid = _new_board_task(authority, batch, slot, source, head)
    admit_session_input(authority.db, epoch=authority.epoch, principal_id='q2-human-grant',
                        session_id=sid, request_id='qualification-slot-' + str(slot), payload={'text': 'Q2 fixture'})
    row = claim_session_input(authority.db, epoch=authority.epoch, session_id=sid)
    image = digest({name: batch.body['original_artifacts'][name]['sha256']
                    for name in ('kernel.Image', 'initramfs.cpio.gz', 'root.raw')})
    binding = GuestBinding(context['task_id'], context['run_id'], str(uuid.uuid4()), 1,
                           image, digest({'budget': BUDGET, 'role': BUDGET['slots'][slot - 1]}))
    scope = reserve_guest_admission(authority, admission_id=row['admission_id'],
                                    principal_id='q2-human-grant', binding=binding)
    endpoint = GuestOwnerEndpoint(authority, scope, principal_id='q2-human-grant')
    work = endpoint.prepare_work(SimpleNamespace(source='kanban', kanban_json=json.dumps(context), model='q2-fixture-only'),
                                 reviewer_head=head if slot == 2 else None)
    record = {'version': PACKAGE, 'state': 'STARTING', 'phase': 'RESERVED', 'attempt': str(uuid.uuid4()),
              'slot': slot, 'mode': BUDGET['slots'][slot - 1], **scope, 'instance': authority.instance_id,
              'owner_pid': os.getpid(),
              'claim_digest': hashlib.sha256(context['claim_lock'].encode()).hexdigest(),
              'board_path': str(batch.board), 'batch_sha256': batch.sha256, 'native_spawned': False}
    handle = Q2Attempt(authority, batch, record, endpoint, work=work)
    authority.__dict__.setdefault('_q2_hvf_workers', {})[scope['execution_id']] = handle
    with connect_closing(batch.board) as board, write_txn(board):
        authority.db._execute_write(lambda conn: conn.execute(
            'INSERT INTO state_meta(key,value) VALUES(?,?)', (handle.key, canonical(record))))
        data = metadata(board.execute('SELECT metadata FROM task_runs WHERE id=?', (scope['run_id'],)).fetchone()[0] or '{}',
                        canonical_required=False)
        data[NAMESPACE] = record
        board.execute('UPDATE task_runs SET metadata=? WHERE id=?', (canonical(data), scope['run_id']))
    return handle, work


def _booked_readback(handle):
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(handle.batch.board) as board, write_txn(board):
        _board_guard(board, handle)
        if handle.authority.db.get_meta(handle.key) != canonical(handle.record):
            raise RuntimeStoreError('q2_booking_readback_failed')


def _service(handle):
    token = None
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    try:
        token = set_hermes_home_override(handle.authority.profile_id)
        while handle.channel.serve_one():
            pass
    except (ValueError, OSError, sqlite3.Error, RuntimeError) as error:
        handle.errors.append(error)
        handle.stop.set()
    finally:
        if token is not None:
            reset_hermes_home_override(token)
        handle.service_done.set()


def _error(handle):
    if handle.errors:
        raise RuntimeStoreError('q2_service_failed', detail=repr(handle.errors[0]))


def _serve_until(handle, observer, predicate, deadline):
    while not predicate():
        _error(handle)
        if time.monotonic() >= deadline:
            raise RuntimeStoreError('q2_execution_timeout')
        observer.poll(deadline)


def _bootstrap(handle, devices, child_fd, path):
    from native.qemu_guest.qualification_package import make_bootstrap
    descriptors = {name: {key: row[key] for key in ('fd', 'st_dev', 'st_ino', 'size')}
                   for name, row in devices.descriptors().items()}
    owner = {key: handle.record[key] for key in ('task_id', 'run_id', 'epoch', 'vm_id', 'attempt', 'instance')}
    plan = make_bootstrap(handle.batch.body['helper_package'], descriptors, child_fd,
                          'reviewer' if handle.record['slot'] == 2 else 'developer', owner)
    checksum = write_receipt(path, plan, newline=False)
    return plan, checksum


def acquire_child(handle, image, inference, bootstrap_path):
    """The acquisition thread owns the final writer guard and gated Popen."""
    from gateway.session_hvf_process import RELEASE, child_identity
    from gateway.session_guest_serial import OwnerSerialSession
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    batch = handle.batch
    batch.verify(handle.authority)
    devices, bootstrap = None, None
    try:
        with image.open_devices() as devices:
            host, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            handle.serial = host
            try:
                plan, checksum = _bootstrap(handle, devices, child_socket.fileno(), bootstrap_path)
                handle.parent_device_observation = {'descriptors': devices.descriptors(), 'closed': False}
                handle.task_checkpoint_fd = os.dup(devices.fds['task'])
                with Path(bootstrap_path).open('rb') as bootstrap:
                    argv = [batch.body['helper_package']['helper'], '--hermes-hvf-q2',
                            '/dev/fd/' + str(bootstrap.fileno()), *plan['qemu_argv']]
                    inherited = (*devices.pass_fds, child_socket.fileno(), bootstrap.fileno())
                    with connect_closing(batch.board) as board, write_txn(board):
                        _board_guard(board, handle)
                        devices.verify()
                        _persist(board, handle, {**handle.record, 'phase': 'SPAWN_INTENT',
                                                 'bootstrap_sha256': checksum})
                        handle.spawned_at = time.monotonic()
                        handle.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True, close_fds=True, pass_fds=inherited,
                            cwd=batch.profile.parent, env={'PATH': '/usr/bin:/bin', 'HOME': str(batch.profile / 'host-home')},
                            bufsize=0)
                        handle.identity = child_identity(handle.process, argv[0], handle.observed_identity)
                        _persist(board, handle, {**handle.record, 'phase': 'CHILD_BOOKED', 'native_spawned': True,
                                                 'identity': handle.identity})
                    _booked_readback(handle)
                    handle.channel = OwnerSerialSession(handle.endpoint, host.fileno(), handle.work,
                                                        inference=inference, defer_heartbeat=True)
                    host.close()  # SerialWire owns the only Host protocol descriptor now.
                    handle.executor = ThreadPoolExecutor(1, thread_name_prefix='q2-original-owner-rpc')
                    handle.service = handle.executor.submit(_service, handle)
                    handle.channel.bind_service(handle.service)
                    with connect_closing(batch.board) as board, write_txn(board):
                        _board_guard(board, handle)
                        devices.verify()
                        _persist(board, handle, {**handle.record, 'phase': 'RELEASED'})
                        if os.write(handle.process.stdin.fileno(), RELEASE) != len(RELEASE):
                            raise RuntimeStoreError('q2_partial_release_frame')
            finally:
                child_socket.close()
                handle.guest_serial_closed = child_socket.fileno() == -1
    finally:
        if devices is not None:
            handle.parent_device_observation['closed'] = devices.closed
        handle.bootstrap_closed = bootstrap is not None and bootstrap.closed
    return handle.process


def _valid_identity(record):
    identity = record.get('identity')
    if not isinstance(identity, dict):
        return False
    integers = ('pid', 'ppid', 'pgid')
    return (all(type(identity.get(key)) is int and identity[key] > 1 for key in integers)
            and identity['pid'] == identity['pgid'] and identity['ppid'] == record.get('owner_pid')
            and all(type(identity.get(key)) in (int, float) and identity[key] > 0 for key in ('created', 'boot_time'))
            and isinstance(identity.get('fingerprint'), str) and bool(identity['fingerprint'])
            and isinstance(identity.get('executable'), str) and Path(identity['executable']).is_absolute())


def _valid_proof(record, *, accounted=True):
    if not isinstance(record, dict):
        return False
    proof = record.get('proof')
    if (not isinstance(proof, dict) or not _valid_identity(record)
            or not isinstance(proof.get('parent_device_capabilities'), dict)
            or not isinstance(proof.get('pipes'), dict)
            or any(not isinstance(proof['pipes'].get(name), dict) for name in ('stdin', 'stdout', 'stderr'))):
        return False
    required = ('exact_child_waited', 'process_group_empty', 'all_pipes_closed',
                'guest_orderly_shutdown', 'explicit_vm_destroy', 'destroy_success',
                'owner_work_completed')
    serial = proof.get('serial_observation', {}) if isinstance(proof, dict) else {}
    serial_fields = ('peer_eof', 'descriptor_closed', 'receive_pump_joined', 'writer_joined',
                     'service_joined', 'http_joined', 'transport_joined', 'complete')
    return (isinstance(proof, dict) and isinstance(record.get('identity'), dict)
            and record.get('native_spawned') is True
            and all(proof.get(key) is True for key in required)
            and (not accounted or proof.get('owner_accounting_complete') is True)
            and type(proof.get('exit_code')) is int and proof['exit_code'] == 0
            and type(proof.get('vm_create_successes')) is int and proof['vm_create_successes'] == 1
            and proof.get('guest_ready') is True and proof.get('bootstrap_fd_closed') is True
            and proof.get('child_serial_in_parent_closed') is True
            and proof.get('task_checkpoint_closed') is True and proof.get('device_exit_verified') is True
            and proof.get('parent_device_capabilities', {}).get('closed') is True
            and isinstance(serial, dict) and all(serial.get(key) is True for key in serial_fields)
            and all(key in record for key in SCOPE_KEYS)
            and serial.get('scope') == {key: record[key] for key in SCOPE_KEYS}
            and serial.get('serial_observer') == 'ORIGINAL_OWNER_SERIALWIRE' and serial.get('cleanup_errors') == []
            and proof.get('process_group_members') == [] and proof.get('terminating_signal') is None
            and proof.get('stdio_eof') == {'stdout': True, 'stderr': True}
            and all(proof.get('pipes', {}).get(name, {}).get('closed') is True
                    for name in ('stdin', 'stdout', 'stderr'))
            and type(proof.get('owner_fds_before')) is int and type(proof.get('owner_fds_after')) is int
            and proof['owner_fds_after'] <= proof['owner_fds_before']
            and proof.get('core_limit_zero') is True
            and proof.get('pid') == record.get('identity', {}).get('pid')
            and proof.get('serial_read_by_process_observer') is False
            and proof.get('wait_result') == 'REAPED_BY_ORIGINAL_OWNER'
            and proof.get('identity') == record.get('identity') and isinstance(record.get('identity'), dict))


def require_physical_handle(endpoint, handle):
    if (type(handle) is not Q2Attempt or handle.authority is not endpoint.authority
            or handle.endpoint is not endpoint
            or getattr(endpoint.authority, '_q2_hvf_workers', {}).get(endpoint.scope['execution_id']) is not handle
            or handle.proof is None or not _valid_proof({**handle.record, 'proof': handle.proof}, accounted=False)
            or handle.process is None or handle.process.returncode != 0
            or not handle.service_done.is_set() or not handle.service.done()
            or any(thread.is_alive() for thread in handle.executor._threads)):

        raise RuntimeStoreError('q2_physical_retirement_incomplete')
    return handle.proof


def mark_uncertain(handle, error):
    """Every sink is attempted independently; corrupt raw metadata is never normalized."""
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    handle.stop.set()
    record = {**handle.record, 'state': 'STOP_UNCERTAIN', 'phase': 'FAILED',
              'failure': type(error).__name__, 'detail': str(error)[:1000]}
    errors = []
    try:
        if handle.channel is not None:
            handle.channel.cancel()
        else:
            handle.endpoint.revoke()
    except (ValueError, OSError, sqlite3.Error) as failure:
        errors.append(repr(failure))
    try:
        with connect_closing(handle.batch.board) as board, write_txn(board):
            _persist(board, handle, record)
    except (ValueError, OSError, sqlite3.Error) as failure:
        errors.append(repr(failure))
    try:
        def write(conn):
            raw = conn.execute('SELECT value FROM state_meta WHERE key=?',
                               (GRANTS + handle.batch.sha256,)).fetchone()
            grant = metadata(raw[0])
            grant.update(status='STOP_UNCERTAIN', failure=record['failure'])
            conn.execute('UPDATE state_meta SET value=? WHERE key=?',
                         (canonical(grant), GRANTS + handle.batch.sha256))
        handle.authority.db._execute_write(write)
    except (ValueError, OSError, sqlite3.Error) as failure:
        errors.append(repr(failure))
    write_receipt(handle.batch.output / (handle.record['attempt'] + '-failure.json'),
                  {'record': record, 'sink_failures': errors, 'observed_identity': handle.observed_identity,
                   'pipes': handle.pipe_observation})
    return record


def stop_batch(authority, batch, error):
    """Reservation/handoff failures spend the entire batch even without a handle."""
    failures = []
    try:
        def write(conn):
            raw = conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANTS + batch.sha256,)).fetchone()
            if raw is None:
                return
            grant = metadata(raw[0])
            grant.update(status='STOP_UNCERTAIN', failure=type(error).__name__)
            conn.execute('UPDATE state_meta SET value=? WHERE key=?',
                         (canonical(grant), GRANTS + batch.sha256))
        authority.db._execute_write(write)
    except (ValueError, OSError, sqlite3.Error) as failure:
        failures.append(repr(failure))
    write_receipt(batch.output / ('batch-failure-' + uuid.uuid4().hex + '.json'),
                  {'failure': repr(error), 'sink_failures': failures, 'payload_sha256': batch.sha256})


def recover_q2_reservations(authority):
    """Read-only recovery never infers retirement from a reboot or missing PID."""
    retained = []
    for row in authority.db._read_all('SELECT key,value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',)):
        try:
            record = metadata(row['value'])
            if record.get('state') != 'RETIRED' or not _valid_proof(record) or not matching_board(authority, record):
                retained.append(row['key'])
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            retained.append(row['key'])
    for row in authority.db._read_all('SELECT key,value FROM state_meta WHERE key LIKE ?', (GRANTS + '%',)):
        try:
            grant = metadata(row['value'])
            if grant.get('status') == 'COMPLETE_CANCELLED_UNKNOWN_RETAINED':
                continue
            active = (getattr(authority, '_q2_active_grant', None) == row['key']
                      and grant.get('epoch') == authority.epoch
                      and grant.get('instance') == authority.instance_id)
            if not active:
                retained.append(row['key'])
        except (ValueError, TypeError):
            retained.append(row['key'])
    authority._q2_hvf_retained = tuple(retained)
    return authority._q2_hvf_retained


def matching_board(authority, record):
    from contextlib import closing
    path = Path(authority.profile_id) / 'kanban/boards/q2-qualification/kanban.db'
    if str(path) != record.get('board_path') or not path.is_file():
        return False
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as conn:
        row = conn.execute('SELECT metadata FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()
        return row is not None and metadata(row[0], canonical_required=False).get(NAMESPACE) == record


def physical_pending(authority):
    return len({*getattr(authority, '_q2_hvf_retained', ()),
                *(h.key for h in getattr(authority, '_q2_hvf_workers', {}).values() if not h.closed.is_set())})


class FixtureResponses:
    """Deterministic in-process HTTPX fixture, never a model/provider or Worker."""
    def __init__(self, mode):
        self.mode = mode
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.late_returned = False
        self.fixture = read_json(Path(__file__).resolve().parents[1] / 'native/qemu_guest/qualification-fixture.json')

    def __call__(self, request):
        self.calls += 1
        data = json.loads(request.content)
        if self.mode == 'cancellation':
            if self.calls != 1:
                raise RuntimeStoreError('q2_unexpected_fake_operation')
            self.entered.set()
            if not self.release.wait(30):
                raise RuntimeStoreError('q2_held_fake_deadline')
            self.late_returned = True
            return self.response(self.message('late qualification response must be suppressed'))
        if self.calls == 1:
            command = self.fixture[self.mode]['command']
            item = {'id': 'fc_qualification', 'type': 'function_call', 'call_id': 'q2-call-1',
                    'name': 'terminal', 'arguments': json.dumps({'command': command, 'timeout': 20}),
                    'status': 'completed'}
            return self.response(item)
        outputs = [item for item in data.get('input', []) if isinstance(item, dict)
                   and item.get('type') == 'function_call_output' and item.get('call_id') == 'q2-call-1']
        marker = self.fixture[self.mode]['required_output']
        if self.calls != 2 or len(outputs) != 1 or marker not in str(outputs[0].get('output')):
            raise RuntimeStoreError('q2_actual_tool_result_required')
        return self.response(self.message('Disposable qualification completed; not real engineering delivery.'))

    @staticmethod
    def message(text):
        return {'id': 'msg_q2', 'type': 'message', 'role': 'assistant', 'status': 'completed',
                'content': [{'type': 'output_text', 'text': text, 'annotations': []}]}

    @staticmethod
    def response(item):
        response = {'id': 'resp_q2_fixture', 'object': 'response', 'created_at': 1795305600,
                    'model': 'q2-fixture-only', 'status': 'completed', 'output': [item],
                    'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}
        events = [{'type': 'response.output_item.added', 'output_index': 0, 'item': item},
                  {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                  {'type': 'response.completed', 'response': response}]
        body = b''.join(('data: ' + json.dumps(event) + '\n\n').encode() for event in events)
        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=httpx.ByteStream(body))


def _close_serial(handle, deadline):
    remaining = max(0, deadline - time.monotonic())
    handle.service.result(timeout=remaining)
    handle.executor.shutdown(wait=True, cancel_futures=True)
    if handle.record['mode'] == 'cancellation':
        handle.channel.close_transport(deadline=deadline)
    else:
        _error(handle)
        handle.channel.finish_transport(deadline=deadline)
    return handle.channel.physical_observation()


def _cancel_from_owner(handle, loop):
    from gateway.session_contract import Principal, SessionRef
    actor = Principal('q2-human-grant', handle.authority.profile_id,
                      frozenset({'session:operator', 'session:control'}), 'protected-q2-qualification')
    ref = SessionRef(handle.authority.profile_id, handle.scope['session_id'])
    pending = asyncio.run_coroutine_threadsafe(
        handle.authority.interrupt(actor, ref, handle.scope['generation']), loop)
    pending.result(timeout=5)


def _close_task_checkpoint(handle):
    fd = handle.task_checkpoint_fd
    if fd is None:
        return
    expected = handle.parent_device_observation['descriptors']['task']
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size) != (expected['st_dev'], expected['st_ino'], expected['size']):
        raise RuntimeStoreError('q2_task_checkpoint_identity_changed')
    try:
        if not expected['readonly']:
            os.fsync(fd)
    finally:
        os.close(fd)
        handle.task_checkpoint_fd = None


def _device_exit_facts(handle, image):
    """Verify actual stopped devices; a writable Developer disk may change bytes only."""
    from native.qemu_guest.artifact_inventory import file_record
    _close_task_checkpoint(handle)
    facts = {}
    for name, before in handle.parent_device_observation['descriptors'].items():
        after = file_record(getattr(image, name))
        if (any(after[key] != before[key] for key in ('st_dev', 'st_ino', 'size'))
                or (before['readonly'] and after['sha256'] != before['sha256'])):
            raise RuntimeStoreError('q2_stopped_device_changed')
        facts[name] = after
    return facts


def execute_attempt(handle, image, fake, loop):
    from gateway.session_hvf_process import Q2ProcessObserver, contain_child, exit_observation
    from gateway.session_guest_inference import OwnerResponses, ResponsesPolicy
    deadline = min(handle.slot_deadline, handle.batch_deadline)
    baseline = psutil.Process().num_fds()
    inference = OwnerResponses(handle.endpoint,
        ResponsesPolicy('http://127.0.0.1:51837/v1/responses', 'q2-fixture-only',
                        'qualification-mock-transport', deadline=30),
        transport=httpx.MockTransport(fake), headers={'X-Hermes-Qualification': 'public-fixture'})
    observer = None
    try:
        acquire_child(handle, image, inference, handle.batch.output / handle.record['attempt'] / 'bootstrap.json')
        observer = Q2ProcessObserver(handle.process, handle.identity,
            output=handle.batch.output / handle.record['attempt'] / 'process',
            expected_devices={'root': True, 'task': image.role == 'reviewer', 'assignment': True},
            observation=handle.pipe_observation)
        startup = min(handle.spawned_at + 60, deadline)
        observer.start(startup)
        _serve_until(handle, observer, handle.channel.ready.is_set, startup)
        if handle.channel.ready_at is None or handle.channel.ready_at > startup:
            raise RuntimeStoreError('q2_real_worker_startup_deadline')
        with handle.authority.db._read_ctx() as conn:
            worker, _admission = handle.endpoint._verify(conn)
            receipt = conn.execute('SELECT 1 FROM worker_receipts WHERE execution_id=? LIMIT 1',
                                   (handle.scope['execution_id'],)).fetchone()
            if worker['status'] != 'running' or receipt is None or time.monotonic() > startup:
                raise RuntimeStoreError('q2_canonical_worker_startup_unverified')
        if handle.record['mode'] == 'cancellation':
            _serve_until(handle, observer, fake.entered.is_set, deadline)
            stop_deadline = min(deadline, time.monotonic() + 30)
            _cancel_from_owner(handle, loop)
            fake.release.set()
        else:
            _serve_until(handle, observer, handle.channel.result_ready.is_set, deadline)
            stop_deadline = min(deadline, handle.channel.result_at + 30)
        _serve_until(handle, observer, handle.service_done.is_set, stop_deadline)
        proof = observer.finish(stop_deadline, lambda: _close_serial(handle, stop_deadline))
        observer.close()
        observer = None
        stopped_devices = _device_exit_facts(handle, image)
        if handle.record['mode'] == 'cancellation':
            if (not handle.channel.stop_sent.is_set() or not handle.endpoint.revoked
                    or handle.channel.result_ready.is_set()):
                raise RuntimeStoreError('q2_cancel_or_late_result_unverified')
            proof.update(cancel_stop_sent=True, guest_result_suppressed=True,
                         endpoint_revoked=True)
        proof.update(parent_device_capabilities=handle.parent_device_observation, bootstrap_fd_closed=handle.bootstrap_closed,
                     guest_ready=True, ready_at=handle.channel.ready_at, spawned_at=handle.spawned_at,
                     child_serial_in_parent_closed=handle.guest_serial_closed,
                     owner_work_completed=True, owner_accounting_complete=False,
                     task_checkpoint_closed=handle.task_checkpoint_fd is None,
                     device_exit_verified=True, stopped_devices=stopped_devices,
                     owner_fds_before=baseline, owner_fds_after=psutil.Process().num_fds(),
                     fake_requests=fake.calls, fake_late_returned=fake.late_returned)
        if (proof['owner_fds_after'] > baseline or not handle.guest_serial_closed
                or not handle.bootstrap_closed or handle.parent_device_observation.get('closed') is not True
                or (handle.record['mode'] == 'cancellation' and not fake.late_returned)):
            raise RuntimeStoreError('q2_owner_resources_unretired')
        return proof
    except BaseException as error:
        fake.release.set()
        stop_deadline = min(deadline, time.monotonic() + 30)
        errors = contain_child(handle, stop_deadline) if handle.process is not None else []
        if handle.channel is not None:
            try:
                handle.channel.close_transport(deadline=stop_deadline)
                if handle.service is not None and handle.service.done():
                    handle.executor.shutdown(wait=True, cancel_futures=True)
            except (ValueError, OSError, RuntimeError) as cleanup_error:
                errors.append({'operation': 'serial_and_http_close', 'error': repr(cleanup_error)})
        try:
            _close_task_checkpoint(handle)
        except (ValueError, OSError) as cleanup_error:
            errors.append({'operation': 'task_checkpoint_close', 'error': repr(cleanup_error)})
        observation = exit_observation(handle, errors=errors) if handle.process is not None else {'spawned': False}
        observation['owner_serial'] = handle.channel.physical_observation() if handle.channel is not None else None
        observation['service_done'] = handle.service_done.is_set()
        try:
            write_receipt(handle.batch.output / (handle.record['attempt'] + '-exit-failure.json'), observation)
        finally:
            mark_uncertain(handle, error)
        raise
    finally:
        fake.release.set()
        if observer is not None:
            observer.close()
        if handle.channel is None:
            inference.close()
        if handle.serial is not None:
            handle.serial.close()


def finish_attempt(handle, proof):
    """Original Owner accounting is last, after actual executor and physical proof."""
    from gateway.session_worker_guest import retire_guest_physical
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    handle.proof = proof
    require_physical_handle(handle.endpoint, handle)
    cancelled = handle.record['mode'] == 'cancellation'
    try:
        with connect_closing(handle.batch.board) as board, write_txn(board):
            _board_guard(board, handle)
            # Exclusion stays durable throughout cross-database accounting.
            _persist(board, handle, {**handle.record, 'phase': 'ACCOUNTING', 'proof': proof})
            retire_guest_physical(handle.endpoint, handle)
        if not cancelled:
            from hermes_state_runtime import settle_session_input
            settle_session_input(handle.authority.db, epoch=handle.authority.epoch,
                admission_id=handle.scope['execution_id'].removeprefix('admission-worker:'),
                generation=handle.scope['generation'], outcome='completed',
                result={'status': 'qualification_only', 'text': 'No real engineering delivery.'})
            with connect_closing(handle.batch.board) as board:
                raw = metadata(board.execute('SELECT metadata FROM task_runs WHERE id=?',
                                             (handle.scope['run_id'],)).fetchone()[0], canonical_required=False)
                if not kb.complete_task(board, handle.scope['task_id'], expected_run_id=handle.scope['run_id'],
                                        metadata=raw, result='Q2 disposable qualification only',
                                        fire_lifecycle_hook=False):
                    raise RuntimeStoreError('q2_fixture_settlement_failed')
        proof = {**proof, 'owner_accounting_complete': True}
        record = {**handle.record, 'state': 'STOP_UNCERTAIN' if cancelled else 'RETIRED',
                  'phase': 'CANCELLATION_PHYSICALLY_CLOSED' if cancelled else 'RETIRED', 'proof': proof}
        with connect_closing(handle.batch.board) as board, write_txn(board):
            saved = board.execute('SELECT metadata FROM task_runs WHERE id=?', (handle.scope['run_id'],)).fetchone()
            if saved is None or metadata(saved[0], canonical_required=False).get(NAMESPACE) != handle.record:
                raise RuntimeStoreError('q2_accounting_reservation_changed')
            _persist(board, handle, record)
        handle.proof = proof
        if not matching_board(handle.authority, record) or handle.authority.db.get_meta(handle.key) != canonical(record):
            raise RuntimeStoreError('q2_final_readback_failed')
        handle.authority._q2_guest_channels.pop(handle.scope['session_id'])
        handle.closed.set()
        _complete_slot(handle.authority, handle.batch, handle.record['slot'], cancelled=cancelled)
        return record
    except (ValueError, OSError, sqlite3.Error) as error:
        handle.closed.clear()
        handle.authority.__dict__.setdefault('_q2_guest_channels', {})[handle.scope['session_id']] = handle.channel
        mark_uncertain(handle, error)
        raise


def _complete_slot(authority, batch, slot, *, cancelled):
    def write(conn):
        _require_owner(authority, conn)
        raw = conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANTS + batch.sha256,)).fetchone()
        grant = metadata(raw[0])
        if grant['spent'] != slot or grant['status'] != 'IN_PROGRESS':
            raise RuntimeStoreError('q2_grant_changed_at_completion')
        grant.update(status='COMPLETE_CANCELLED_UNKNOWN_RETAINED' if cancelled else 'IN_PROGRESS',
                     phase='SLOT_COMPLETE', handoff=None if cancelled else slot + 1)
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(grant), GRANTS + batch.sha256))
    authority.db._execute_write(write)


def _fixture_source(batch):
    source = Path(batch.body['fixture_source'])
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True, encoding='utf-8', timeout=30).strip()
    tree = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD^{tree}'], text=True, encoding='utf-8', timeout=30).strip()
    common = subprocess.check_output(['git', '-C', str(source), 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                                     text=True, encoding='utf-8', timeout=30).strip()
    if (head != batch.body['fixture_identity']['head'] or tree != batch.body['fixture_identity']['tree']
            or common != batch.body['fixture_identity']['common_dir']):
        raise RuntimeStoreError('q2_fixture_git_changed')
    return source, head


def prepare_attempt_devices(handle, work, source, candidate):
    from native.qemu_guest.qualification_artifacts import prepare_slot_devices, slot_image
    record = prepare_slot_devices(work, source, handle.batch.output / ('slot-' + str(handle.record['slot'])),
        mke2fs=handle.batch.body['mke2fs'], parent_candidate=candidate)
    package = handle.batch.body['helper_package']
    image = slot_image(record, kernel=Path(package['resources']) / 'kernel.Image',
                       initramfs=Path(package['resources']) / 'initramfs.cpio.gz',
                       root=Path(handle.batch.body['root_copy']['path']))
    handle.device_record = record
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(handle.batch.board) as board, write_txn(board):
        _board_guard(board, handle)
        _persist(board, handle, {**handle.record, 'device_manifest_sha256': record['manifest_sha256'],
                                'parent_candidate_sha256': record['parent_candidate_sha256']})
    _booked_readback(handle)
    return image


def freeze_actual_candidate(handle, expected_base):
    interpreter = handle.batch.body['artifact_python']
    if hashlib.sha256(Path(interpreter['path']).read_bytes()).hexdigest() != interpreter['sha256']:
        raise RuntimeStoreError('q2_artifact_verifier_changed')
    output = handle.batch.output / 'actual-slot1-candidate'
    args = [interpreter['path'], '-m', 'native.qemu_guest.qualification_artifacts',
            'freeze', '--task-disk', handle.device_record['task']['path'], '--output', str(output),
            '--expected-base', expected_base]
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(handle.batch.profile / 'host-tool-home'),
           'HERMES_HOME': handle.authority.profile_id, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
    result = subprocess.check_output(args, env=env, text=True, encoding='utf-8',
        cwd=Path(__file__).resolve().parents[1], timeout=max(1, min(30, handle.slot_deadline - time.monotonic())))
    from native.qemu_guest.qualification_artifacts import load_candidate
    candidate = metadata(result.strip())
    checked = load_candidate(candidate['manifest_path'])
    if checked != candidate:
        raise RuntimeStoreError('q2_actual_candidate_changed')
    recipe = read_json(Path(__file__).resolve().parents[1] / 'native/qemu_guest/qualification-fixture.json')
    for name, expected in recipe['developer']['required_files'].items():
        actual = candidate['content'].get(name, {})
        if actual.get('sha256') != hashlib.sha256(expected.encode()).hexdigest():
            raise RuntimeStoreError('q2_actual_candidate_content_missing')
    def write(conn):
        _require_owner(handle.authority, conn)
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)',
                     ('q2.hvf.candidate:' + handle.record['attempt'], canonical(candidate)))
    handle.authority.db._execute_write(write)
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(handle.batch.board) as board, write_txn(board):
        _board_guard(board, handle)
        _persist(board, handle, {**handle.record, 'candidate_manifest_sha256': candidate['manifest_sha256'],
                                'candidate_head': candidate['candidate_head']})
    return candidate


def _reviewer_candidate(authority, batch, path):
    from native.qemu_guest.qualification_artifacts import load_candidate
    actual = load_candidate(path)
    records = [metadata(row['value']) for row in authority.db._read_all(
        'SELECT value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))]
    parents = [row for row in records if row.get('batch_sha256') == batch.sha256 and row.get('slot') == 1]
    if len(parents) != 1:
        raise RuntimeStoreError('q2_candidate_parent_missing')
    parent = parents[0]
    saved = authority.db.get_meta('q2.hvf.candidate:' + parent['attempt'])
    if (parent.get('state') != 'RETIRED' or not _valid_proof(parent) or not matching_board(authority, parent)
            or saved != canonical(actual) or parent.get('candidate_manifest_sha256') != actual['manifest_sha256']
            or parent.get('candidate_head') != actual['candidate_head']
            or not isinstance(actual.get('source_disk'), dict)
            or parent['proof'].get('stopped_devices', {}).get('task') != actual['source_disk']):
        raise RuntimeStoreError('q2_candidate_parent_changed')
    return actual


async def qualify_slot(authority, batch, slot, *, candidate=None, batch_deadline=None):
    """One slot, invoked only by the finite original-Owner batch call."""
    slot_deadline = time.monotonic() + 300
    batch.verify(authority)
    source, head = _fixture_source(batch)
    if slot == 2:
        actual = await asyncio.to_thread(_reviewer_candidate, authority, batch, candidate)
        source, head = Path(actual['snapshot_path']), actual['candidate_head']
    handle, work = await asyncio.to_thread(reserve_attempt, authority, batch, slot, source=source, head=head)
    handle.slot_deadline = slot_deadline
    handle.batch_deadline = min(handle.slot_deadline, batch_deadline or time.monotonic() + 900)
    from gateway.session_authority import LiveSession
    authority.sessions[handle.scope['session_id']] = LiveSession(None, 'q2:' + handle.scope['execution_id'])
    try:
        image = await asyncio.to_thread(prepare_attempt_devices, handle, work, source, candidate)
        proof = await asyncio.to_thread(execute_attempt, handle, image,
                                       FixtureResponses(handle.record['mode']), asyncio.get_running_loop())
        snapshot = await asyncio.to_thread(freeze_actual_candidate, handle, head) if slot == 1 else None
        record = await asyncio.to_thread(finish_attempt, handle, proof)
        if time.monotonic() > handle.batch_deadline:
            raise RuntimeStoreError('q2_slot_complete_deadline')
        return {'record': record, 'candidate': snapshot}
    except BaseException as error:
        if handle.record.get('state') != 'STOP_UNCERTAIN':
            await asyncio.to_thread(mark_uncertain, handle, error)
        raise


def _next_epoch_allowed(authority, batch, slot):
    rows = authority.db._read_all('SELECT value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))
    if len(rows) != slot:
        raise RuntimeStoreError('q2_handoff_history_incomplete')
    for row in rows:
        record = metadata(row['value'])
        if record.get('state') != 'RETIRED' or not _valid_proof(record) or not matching_board(authority, record):
            raise RuntimeStoreError('q2_handoff_uncertain')
    raw = metadata(authority.db.get_meta(GRANTS + batch.sha256))
    if raw.get('handoff') != slot + 1 or raw.get('phase') != 'SLOT_COMPLETE':
        raise RuntimeStoreError('q2_handoff_missing')


async def _reinitialize_epoch(authority, batch, slot, *, cancelled=False):
    from gateway.session_authority import initialize_session_authority
    if cancelled:
        grant = metadata(authority.db.get_meta(GRANTS + batch.sha256))
        if slot != 3 or grant.get('status') != 'COMPLETE_CANCELLED_UNKNOWN_RETAINED' or grant.get('spent') != 3:
            raise RuntimeStoreError('q2_cancel_recovery_not_complete')
    else:
        _next_epoch_allowed(authority, batch, slot)
    if any(not handle.closed.is_set() for handle in authority._q2_hvf_workers.values()):
        raise RuntimeStoreError('q2_handoff_physical_work')
    authority.retired = True
    registry = authority.runner.session_authorities
    # The original registry has no launch-slot removal API. A new canonical
    # runtime initialization will replace the whole registry, never add a peer.
    from gateway.session_authorities import SessionAuthorities
    authority.runner.session_authorities = SessionAuthorities(batch.profile)
    try:
        new = await initialize_session_authority(authority.runner, profile_id=authority.profile_id,
            instance_id=str(uuid.uuid4()), db=authority.db)
        authority.runner.session_authorities.add(batch.profile, new)
        if cancelled:
            rows = new.db._read_all('SELECT value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))
            if len(rows) != 3:
                raise RuntimeStoreError('q2_cancel_history_missing')
            for row in rows:
                record = metadata(row['value'])
                if not _valid_proof(record) or not matching_board(new, record):
                    raise RuntimeStoreError('q2_cancel_physical_recovery_missing')
                if record.get('mode') == 'cancellation':
                    worker = new.db._read_one('SELECT status FROM worker_executions WHERE execution_id=?',
                                              (record['execution_id'],))
                    admission = new.db._read_one('SELECT status FROM session_admissions WHERE admission_id=?',
                        (record['execution_id'].removeprefix('admission-worker:'),))
                    if record['state'] != 'STOP_UNCERTAIN' or worker[0] != 'unknown' or admission[0] != 'unknown':
                        raise RuntimeStoreError('q2_cancel_unknown_lost')
                elif record['state'] != 'RETIRED':
                    raise RuntimeStoreError('q2_cancel_prior_retirement_lost')
            return new
        def transfer(conn):
            _require_owner(new, conn)
            grant = metadata(conn.execute('SELECT value FROM state_meta WHERE key=?',
                                         (GRANTS + batch.sha256,)).fetchone()[0])
            if grant['epoch'] != authority.epoch or grant['handoff'] != slot + 1:
                raise RuntimeStoreError('q2_unplanned_epoch_change')
            grant.update(epoch=new.epoch, instance=new.instance_id)
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(grant), GRANTS + batch.sha256))
        new.db._execute_write(transfer)
        new._q2_active_grant = GRANTS + batch.sha256
        if recover_q2_reservations(new):
            raise RuntimeStoreError('q2_handoff_recovery_incomplete')
        return new
    except BaseException:
        authority.runner.session_authorities = registry
        raise


async def qualify_batch(authority, batch):
    """One protected finite batch; no production Dispatcher or resume loop."""
    begin_batch(authority, batch)
    deadline = time.monotonic() + 900
    results, candidate = [], None
    current = authority
    try:
        for slot in (1, 2, 3):
            result = await current.qualify_q2(batch, slot=slot, candidate_snapshot=candidate, batch_deadline=deadline)
            results.append(result)
            if slot == 1:
                candidate = result['candidate']['manifest_path']
            if slot < 3:
                current = await _reinitialize_epoch(current, batch, slot)
            else:
                current = await _reinitialize_epoch(current, batch, slot, cancelled=True)
    except BaseException as error:
        await asyncio.to_thread(stop_batch, current, batch, error)
        raise
    finally:
        original_status = 'UNKNOWN'
        try:
            await asyncio.to_thread(batch.verify_artifacts)
            original_status = 'EXACT_IDENTITY_AND_SHA256_MATCH'
        except (ValueError, OSError, KeyError, TypeError) as error:
            await asyncio.to_thread(stop_batch, current, batch, error)
            raise
        finally:
            await asyncio.to_thread(write_receipt,
                batch.output / ('original-artifacts-final-' + uuid.uuid4().hex + '.json'),
                {'original_artifacts': batch.body['original_artifacts'],
                 'verification': original_status})
    retained = recover_q2_reservations(current)
    return {'package': PACKAGE, 'status': 'QUALIFICATION_ONLY', 'slots': results,
            'cancelled_unknown_retained': list(retained), 'first_worker_owned_delivery': 'NOT_ACHIEVED'}


async def bootstrap_owner(home):
    """Canonical original Gateway runtime; no listeners, Agent or Worker start."""
    from gateway.config import GatewayConfig
    from gateway.run import GatewayRunner, _profile_runtime_scope
    from gateway.run_runtime import initialize_gateway_runtime
    from gateway.runtime_ownership import process_ownership
    home = await asyncio.to_thread(Path(home).resolve)
    configured_home = await asyncio.to_thread(Path(os.environ.get('HERMES_HOME', '')).resolve)
    if home.name != 'q2-qualification' or configured_home != home:
        raise RuntimeStoreError('q2_explicit_disposable_profile_required')
    process_ownership.reserve([home])
    with _profile_runtime_scope(home, hydrate_secrets=False):
        runner = GatewayRunner(config=GatewayConfig(platforms={}, multiplex_profiles=False,
                               sessions_dir=home / 'sessions', loop_watchdog=False))
        await initialize_gateway_runtime(runner)
    authority = runner.session_authorities.for_home(home)
    _require_owner(authority)
    from hermes_cli.kanban_db_connect import connect_closing
    board = home / 'kanban/boards/q2-qualification/kanban.db'
    def ensure_board():
        board.parent.mkdir(parents=True, exist_ok=True)
        with connect_closing(board):
            pass
    await asyncio.to_thread(ensure_board)
    return authority


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--run-batch', action='store_true')
    args = parser.parse_args()
    if not args.run_batch:
        parser.error('Only the protected full batch entry exists; no per-slot/resume mode.')
    batch = Q2Batch.load(args.manifest)
    async def run():
        owner = await bootstrap_owner(batch.profile)
        return await qualify_batch(owner, batch)
    print(canonical(asyncio.run(run())))


if __name__ == '__main__':
    main()
