"""Original Owner's finite Q1 HVF qualification; never a product dispatch backend."""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import re
from pathlib import Path
import signal
import socket
import sqlite3
import sys
import subprocess
import threading
import time
import uuid
from types import MappingProxyType

import psutil

from hermes_state_runtime import RuntimeStoreError, _epoch

NAMESPACE = 'q1_hvf_v1'
PREFIX = 'q1.hvf.attempt:'
GRANT_ID = 'PR15_HVF_RERUN_20261121_A'
GRANT_KEY = 'q1.hvf.grant:' + GRANT_ID
MODES = ('normal', 'normal', 'normal', 'sigkill', 'sigabrt')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeStoreError('hvf_duplicate_metadata')
        result[key] = value
    return result


def metadata(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique) if raw is not None else {}
        if not isinstance(value, dict):
            raise ValueError('object required')
        canonical(value)
        return value
    except (TypeError, ValueError) as exc:
        raise RuntimeStoreError('hvf_metadata_unavailable') from exc


def _require_owner(authority, conn=None):
    from gateway.session_authority import SessionAuthority
    registry = getattr(authority.runner, 'session_authorities', None)
    if not isinstance(authority, SessionAuthority) or registry is None or registry.for_home(authority.profile_id) is not authority:
        raise RuntimeStoreError('hvf_original_owner_required')
    authority._require_admission_open()
    if conn is not None:
        _epoch(conn, authority.epoch)
        row = conn.execute('SELECT instance_id FROM runtime_epoch WHERE singleton=1').fetchone()
        if row is None or row[0] != authority.instance_id:
            raise RuntimeStoreError('hvf_owner_instance_changed')


@dataclass(frozen=True)
class HVFCandidate:
    """Frozen artifact inventory, not an authorization issued by a JSON file."""

    profile: Path
    board: Path
    helper: Path
    plan: Path
    kernel: Path
    initramfs: Path
    disk: Path
    output: Path
    files: dict[str, str]
    source_head: str
    prior_profile: Path | None = None
    prior_snapshot_sha256: str | None = None

    def __post_init__(self):
        paths = (self.profile, self.board, self.helper, self.plan, self.kernel,
                 self.initramfs, self.disk, self.output)
        if (not re.fullmatch(r'[0-9a-f]{40}', self.source_head)
                or any(not p.is_absolute() or any(c in str(p) for c in ',\n\r\x00') for p in paths)
                or self.output.parent != self.profile.parent):
            raise RuntimeStoreError('hvf_invalid_candidate_paths')
        if not isinstance(self.files, dict) or any(
                not isinstance(name, str) or not Path(name).is_absolute()
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                for name, digest in self.files.items()):
            raise RuntimeStoreError('hvf_invalid_artifact_inventory')
        object.__setattr__(self, 'files', MappingProxyType(dict(self.files)))

    def verify(self, authority):
        if sys.platform != 'darwin':
            raise RuntimeStoreError('hvf_macos_required')
        _require_owner(authority)
        _verify_source_head(self.source_head)
        _verify_authorization(self)
        home = Path(authority.profile_id).resolve(strict=True)
        if home.name != 'hvf-qualification' or home != self.profile.resolve(strict=True):
            raise RuntimeStoreError('hvf_disposable_profile_required')
        expected_board = home / 'kanban/boards/hvf-qualification/kanban.db'
        if self.board.resolve(strict=True) != expected_board or Path(authority.db.db_path).resolve(strict=True) != home / 'state.db':
            raise RuntimeStoreError('hvf_disposable_board_required')
        if authority.db._read_one('SELECT 1 FROM worker_executions LIMIT 1') is not None:
            raise RuntimeStoreError('hvf_non_diagnostic_history')
        required = {str(p) for p in (self.helper, self.plan, self.kernel, self.initramfs, self.disk)}
        if not required <= self.files.keys() or self.disk.stat().st_size > 8 * 1024**3:
            raise RuntimeStoreError('hvf_artifact_manifest_incomplete')
        app = self.helper.parents[2]
        app_paths = tuple(app.rglob('*'))
        if any(path.is_symlink() for path in app_paths) or {str(path) for path in app_paths if path.is_file()} != set(self.files):
            raise RuntimeStoreError('hvf_signed_app_inventory_incomplete')
        for name, digest in self.files.items():
            path = Path(name)
            if path.is_symlink() or path.stat().st_nlink != 1 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeStoreError('hvf_artifact_changed', detail=name)
        _verify_signature(self.helper)
        if self.prior_profile is None or self.prior_snapshot_sha256 is None:
            raise RuntimeStoreError('hvf_prior_child_reconciliation_required')
        if self.profile.resolve() == self.prior_profile.resolve():
            raise RuntimeStoreError('hvf_fresh_profile_required')
        reconcile_prior(self.prior_profile, self.prior_snapshot_sha256)

    def argv(self, serial_fd):
        return [str(self.helper), '--hermes-hvf-q1', str(self.plan), '-L', str(self.plan.parent),
                '-nodefaults', '-display', 'none', '-monitor', 'none', '-qmp', 'stdio',
                '-chardev', f'socket,id=serial,fd={serial_fd}', '-serial', 'chardev:serial',
                '-nic', 'none', '-accel', 'hvf', '-machine', 'virt', '-cpu', 'host',
                '-smp', '2', '-m', '2048', '-no-reboot',
                '-kernel', str(self.kernel), '-initrd', str(self.initramfs),
                '-append', 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4',
                '-drive', f'file={self.disk},format=raw,if=none,id=inert,readonly=on',
                '-device', 'virtio-blk-pci,drive=inert']


def _verify_authorization(candidate):
    lock_path = Path(__file__).resolve().parents[1] / 'native/qemu_hvf/rerun-authorization.json'
    lock = metadata(lock_path.read_text(encoding='utf-8-sig'))
    names = ('profile', 'board', 'helper', 'plan', 'kernel', 'initramfs', 'disk', 'output', 'prior_profile')
    binding = {name: str(getattr(candidate, name)) for name in names}
    binding.update(files=dict(candidate.files), prior_snapshot_sha256=candidate.prior_snapshot_sha256)
    if lock.get('grant') != GRANT_ID or lock.get('candidate') != binding or lock.get('modes') != list(MODES):
        raise RuntimeStoreError('hvf_exact_grant_candidate_binding_changed')


def _verify_signature(helper):
    import plistlib
    subprocess.run(['codesign', '--verify', '--strict', str(helper.parent.parent.parent)],
                   check=True, capture_output=True, timeout=20)
    result = subprocess.run(['codesign', '--display', '--entitlements', '-', '--xml', str(helper)],
                            check=True, capture_output=True, timeout=20)
    if plistlib.loads(result.stdout) != {'com.apple.security.app-sandbox': True, 'com.apple.security.hypervisor': True}:
        raise RuntimeStoreError('hvf_helper_entitlements_changed')


def _verify_source_head(expected):
    root = Path(__file__).resolve().parents[1]
    actual = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True, encoding='utf-8', timeout=10).strip()
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True, encoding='utf-8', timeout=10)
    if actual != expected or dirty.strip():
        raise RuntimeStoreError('hvf_source_not_frozen_at_reviewed_head')


def _valid_retirement(record):
    if not isinstance(record, dict) or record.get('version') != 'HERMES_Q1_HVF_V1':
        return False
    proof = record.get('proof', {})
    if not isinstance(proof, dict) or record.get('native_spawned') is not True:
        return False
    common = ('exact_child_waited', 'process_group_empty', 'all_pipes_closed', 'guest_ready',
              'core_limit_zero', 'owner_work_completed', 'owner_accounting_complete')
    if (record.get('state') != 'RETIRED' or any(proof.get(key) is not True for key in common)
            or type(proof.get('vm_create_successes')) is not int or proof['vm_create_successes'] != 1):
        return False
    if not _valid_exit_observation(record, proof):
        return False
    if record.get('mode') == 'normal':
        return (proof.get('destroy_success') is True and proof.get('explicit_vm_destroy') is True
                and proof.get('guest_orderly_shutdown') is True and type(proof.get('exit_code')) is int
                and proof['exit_code'] == 0)
    expected = {'sigkill': -signal.Signals['SIGKILL'], 'sigabrt': -signal.SIGABRT}.get(record.get('mode'))
    return expected is not None and proof.get('exit_code') == expected and proof.get('backend_ownership') == 'APPLE_PROCESS_OWNED_HYPERVISOR_CONTRACT'


def _valid_identity(identity):
    if not isinstance(identity, dict):
        return False
    required = ('pid', 'ppid', 'pgid', 'created', 'boot_time', 'fingerprint', 'executable')
    return (all(key in identity for key in required) and type(identity['pid']) is int
            and identity['pid'] > 1 and identity['pgid'] == identity['pid']
            and isinstance(identity['fingerprint'], str) and bool(identity['fingerprint'])
            and isinstance(identity['executable'], str) and Path(identity['executable']).is_absolute()
            and type(identity['created']) in (int, float) and identity['created'] > 0
            and type(identity['boot_time']) in (int, float) and identity['boot_time'] > 0)


def _valid_exit_observation(record, proof):
    observed = record.get('exit_observation')
    identity = record.get('identity')
    if not isinstance(observed, dict) or not _valid_identity(identity):
        return False
    endpoints = observed.get('pipes', {})
    drain = observed.get('drain_observation', {})
    if not isinstance(endpoints, dict) or not isinstance(drain, dict) or any(not isinstance(p, dict) for p in endpoints.values()):
        return False
    return (observed == proof.get('exit_observation') and observed.get('identity') == identity
            and observed.get('pid') == identity.get('pid') and observed.get('identity_status') == 'VERIFIED'
            and type(observed.get('returncode')) is int and observed.get('returncode') == proof.get('exit_code')
            and observed.get('terminating_signal') == (-proof['exit_code'] if proof['exit_code'] < 0 else None)
            and observed.get('wait_result') == 'REAPED_BY_ORIGINAL_OWNER'
            and observed.get('process_group_status') == 'EMPTY' and observed.get('process_group_members') == []
            and observed.get('all_pipes_closed') is True
            and set(endpoints) == {'stdin', 'stdout', 'stderr', 'serial', 'child_serial_in_parent'}
            and all(part.get('closed') is True for part in endpoints.values())
            and drain.get('selector_drained') is True
            and drain.get('eof') == {'stdout': True, 'stderr': True, 'serial': True})


def recover_hvf_reservations(authority):
    retained = []
    for row in authority.db._read_all('SELECT key,value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',)):
        try:
            record = metadata(row['value'])
            retired = _valid_retirement(record) and _matching_board_retirement(authority, record)
        except (RuntimeStoreError, OSError, sqlite3.Error, KeyError, TypeError):
            retired = False
        if not retired:
            retained.append(row['key'])
    grant_row = authority.db._read_one('SELECT value FROM state_meta WHERE key=?', (GRANT_KEY,))
    if grant_row is not None:
        try:
            grant = metadata(grant_row[0])
            live_campaign = (getattr(authority, '_hvf_campaign_active', False)
                             and grant.get('epoch') == authority.epoch and grant.get('instance') == authority.instance_id)
            if grant.get('status') != 'COMPLETE' and not live_campaign and not retained:
                retained.append(GRANT_KEY)
        except RuntimeStoreError:
            retained.append(GRANT_KEY)
    authority._hvf_retained = tuple(retained)
    return authority._hvf_retained


def _matching_board_retirement(authority, record):
    expected = Path(authority.profile_id).resolve() / 'kanban/boards/hvf-qualification/kanban.db'
    if Path(record.get('board_path', '')).resolve() != expected or not expected.is_file():
        return False
    with closing(sqlite3.connect(expected.as_uri() + '?mode=ro', uri=True)) as conn:
        row = conn.execute('SELECT task_id,metadata,status FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()
        return (row is not None and row[0] == record['task_id'] and row[2] == 'done'
                and metadata(row[1]).get(NAMESPACE) == record)


class HVFHandle:
    """One original-Owner reservation; closed means proven/accounted retirement."""

    def __init__(self, authority, record):
        self.authority = authority
        self.record = record
        self.key = PREFIX + record['attempt']
        self.closed = threading.Event()
        self.stop = threading.Event()
        self.process = None
        self.identity = None
        self.observed_identity = {}
        self.serial = None
        self.guest_serial_closed = None
        self.pipe_observation = {}

    def control(self, frame):
        if frame != {'type': 'stop'}:
            raise RuntimeStoreError('hvf_control_denied')
        self.stop.set()


def _grant(authority, candidate):
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    body = {'grant': GRANT_ID, 'epoch': authority.epoch, 'instance': authority.instance_id,
            'modes': list(MODES), 'reserved': 0, 'status': 'IN_PROGRESS',
            'helper_sha256': candidate.files[str(candidate.helper)],
            'source_head': candidate.source_head, 'profile': str(candidate.profile),
            'board': str(candidate.board), 'output': str(candidate.output),
            'artifacts': dict(candidate.files), 'prior_profile': str(candidate.prior_profile),
            'prior_snapshot_sha256': candidate.prior_snapshot_sha256}
    def write(conn):
        _require_owner(authority, conn)
        if conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANT_KEY,)).fetchone() is not None:
            raise RuntimeStoreError('hvf_grant_already_reserved_no_resume')
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (GRANT_KEY, canonical(body)))
    with connect_closing(candidate.board) as board, write_txn(board):
        _history(board, authority)
        if board.execute('SELECT 1 FROM tasks LIMIT 1').fetchone():
            raise RuntimeStoreError('hvf_fresh_qualification_board_required')
        candidate.output.mkdir(parents=True, exist_ok=False)
        authority.db._execute_write(write)


def _history(conn, authority, reservation=None):
    if conn.execute('SELECT 1 FROM tasks WHERE worker_pid IS NOT NULL LIMIT 1').fetchone():
        raise RuntimeStoreError('hvf_unretired_local_execution')
    if conn.execute('SELECT 1 FROM tasks t WHERE NOT EXISTS(SELECT 1 FROM task_runs r WHERE r.task_id=t.id) LIMIT 1').fetchone():
        raise RuntimeStoreError('hvf_legacy_execution_evidence_missing')
    for row in conn.execute('SELECT id,metadata,worker_pid FROM task_runs'):
        old = metadata(row['metadata'])
        if NAMESPACE not in old:
            raise RuntimeStoreError('hvf_legacy_execution_evidence_missing')
        if row['worker_pid'] is not None or any(k in old for k in ('vz_custody_v1', 'local_launch_v1', 'owner_launch_v1', 'q1_native_v1')):
            raise RuntimeStoreError('hvf_unretired_execution')
        current = reservation is not None and row['id'] == reservation['run_id'] and old.get(NAMESPACE) == reservation
        if not current:
            record = old[NAMESPACE]
            if not _valid_retirement(record):
                raise RuntimeStoreError('hvf_unretired_execution')
            indexed = authority.db._read_one('SELECT value FROM state_meta WHERE key=?',
                                              (PREFIX + record['attempt'],))
            if indexed is None or indexed[0] != canonical(record):
                raise RuntimeStoreError('hvf_retirement_index_missing_or_changed')


def _reserve(authority, candidate, slot):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    _require_owner(authority)
    if authority._hvf_campaign_stop.is_set():
        raise RuntimeStoreError('hvf_campaign_stopped')
    if any(not h.closed.is_set() for h in getattr(authority, '_hvf_workers', {}).values()) or recover_hvf_reservations(authority):
        raise RuntimeStoreError('hvf_no_successor')
    session = f'hvf-diagnostic-{slot}'
    with connect_closing(candidate.board) as board, write_txn(board):
        _history(board, authority)
        authority.db.create_session(session, source='q1_hvf_diagnostic')
        task_id = kb.create_task(board, title=f'Q1 inert HVF qualification slot {slot}',
                                 session_id=session, workspace_kind='scratch')
        now = int(time.time())
        # Dedicated diagnostic task: compose the existing claim primitive without
        # invoking product dispatch hooks before the reservation commits.
        run_id = kb._claim_and_open_run(board, task_id, 'ready', uuid.uuid4().hex, now + 3600, now)
        if run_id is None:
            raise RuntimeStoreError('hvf_diagnostic_claim_failed')
        task = kb.get_task(board, task_id)
        record = {'version': 'HERMES_Q1_HVF_V1', 'state': 'STOP_UNCERTAIN', 'phase': 'STARTING',
                  'grant': GRANT_ID, 'slot': slot, 'mode': MODES[slot - 1], 'attempt': uuid.uuid4().hex,
                  'task_id': task.id, 'run_id': task.current_run_id, 'session_id': session,
                  'claim_digest': hashlib.sha256(task.claim_lock.encode()).hexdigest(),
                  'epoch': authority.epoch, 'instance': authority.instance_id,
                  'owner_pid': os.getpid(), 'helper_sha256': candidate.files[str(candidate.helper)],
                  'board_path': str(candidate.board.resolve()),
                  'source_head': candidate.source_head, 'native_spawned': False}
        handle = HVFHandle(authority, record)
        def write(conn):
            _require_owner(authority, conn)
            grant = metadata(conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANT_KEY,)).fetchone()[0])
            if grant['reserved'] != slot - 1 or grant['status'] != 'IN_PROGRESS' or grant['epoch'] != authority.epoch or grant['instance'] != authority.instance_id:
                raise RuntimeStoreError('hvf_native_budget_unavailable')
            grant['reserved'] = slot
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(grant), GRANT_KEY))
            conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (handle.key, canonical(record)))
            authority.__dict__.setdefault('_hvf_workers', {})[handle.key] = handle
        authority.db._execute_write(write)
        old = metadata(board.execute('SELECT metadata FROM task_runs WHERE id=?', (task.current_run_id,)).fetchone()[0])
        old[NAMESPACE] = record
        board.execute('UPDATE task_runs SET metadata=? WHERE id=?', (canonical(old), task.current_run_id))
    return handle


def _guard(board, handle):
    from hermes_cli import kanban_db as kb
    task = kb.get_task(board, handle.record['task_id'])
    run = board.execute('SELECT * FROM task_runs WHERE id=?', (handle.record['run_id'],)).fetchone()
    if (task is None or run is None or task.status != 'running' or run['status'] != 'running'
            or task.current_run_id != run['id'] or task.session_id != handle.record['session_id']
            or not task.claim_lock or run['claim_lock'] != task.claim_lock
            or hashlib.sha256(task.claim_lock.encode()).hexdigest() != handle.record['claim_digest']
            or type(task.claim_expires) is not int or task.claim_expires <= time.time()
            or metadata(run['metadata']).get(NAMESPACE) != handle.record or handle.stop.is_set()):
        raise RuntimeStoreError('hvf_claim_or_reservation_changed')
    _history(board, handle.authority, handle.record)
    with handle.authority.db._read_ctx() as owner:
        _require_owner(handle.authority, owner)
        grant_row = owner.execute('SELECT value FROM state_meta WHERE key=?', (GRANT_KEY,)).fetchone()
        grant = metadata(grant_row[0]) if grant_row else {}
        if (grant.get('status') != 'IN_PROGRESS' or grant.get('reserved') != handle.record['slot']
                or grant.get('epoch') != handle.authority.epoch or grant.get('instance') != handle.authority.instance_id
                or grant.get('helper_sha256') != handle.record['helper_sha256']
                or grant.get('source_head') != handle.record['source_head']):
            raise RuntimeStoreError('hvf_native_grant_changed')
        row = owner.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()
        if row is None or row[0] != canonical(handle.record):
            raise RuntimeStoreError('hvf_recovery_index_changed')


def _persist(board, handle, record):
    def write(conn):
        _require_owner(handle.authority, conn)
        previous = conn.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()
        if previous is None or previous[0] != canonical(handle.record):
            raise RuntimeStoreError('hvf_recovery_index_changed')
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(record), handle.key))
    handle.authority.db._execute_write(write)
    row = board.execute('SELECT metadata FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()
    body = metadata(row[0]); body[NAMESPACE] = record
    board.execute('UPDATE task_runs SET metadata=? WHERE id=?', (canonical(body), record['run_id']))
    handle.record = record


def _contain_failed_child(handle, deadline):
    """Observe/reap only our exact child; evidence never grants retirement."""
    from gateway.session_hvf_process import contain_child, exit_observation
    errors = contain_child(handle, deadline)
    return exit_observation(handle, errors=errors)


def _write_exit_receipt(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        stream.write(body + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _persist_exit(candidate, handle, observation, *, failure=None):
    record = {**handle.record, 'state': 'STOP_UNCERTAIN', 'native_spawned': True,
              'phase': 'FAILED' if failure is not None else 'PHYSICAL_OBSERVED',
              'exit_observation': observation}
    if failure is not None:
        record['failure'] = str(failure)[:500]
    # A diagnostic receipt survives even if a damaged/unavailable ledger cannot
    # accept facts. It has no admission, recovery or retirement authority.
    directory = candidate.output / f'slot-{record["slot"]}'
    path = directory / ('failure-observation.json' if failure is not None else 'exit-observation.json')
    def receipt(status):
        body = canonical({'attempt': record['attempt'], 'run_id': record['run_id'],
                          'grant': GRANT_ID, 'state': 'STOP_UNCERTAIN',
                          'ledger_persistence': status, 'observation': observation})
        _write_exit_receipt(path, body)
    receipt_error = None
    try:
        receipt('PENDING')
    except OSError as error:
        receipt_error = error
    ledger_errors = []
    for writer in (_write_owner_exit, _write_board_exit):
        try:
            writer(candidate, handle, record)
        except (RuntimeStoreError, sqlite3.Error, OSError) as error:
            ledger_errors.append(error)
    try:
        status = 'UNKNOWN: ' + '; '.join(str(e) for e in ledger_errors) if ledger_errors else 'BOTH_LEDGERS_COMMITTED'
        receipt(status)
    except OSError as error:
        receipt_error = error
    if ledger_errors:
        for additional_error in [*ledger_errors[1:], *([receipt_error] if receipt_error is not None else [])]:
            ledger_errors[0].add_note(f'additional evidence sink failure: {additional_error}')
        raise ledger_errors[0]
    if receipt_error is not None:
        raise receipt_error


def _write_owner_exit(candidate, handle, record):
    def write(conn):
        _require_owner(handle.authority, conn)
        previous = conn.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()
        if previous is None or previous[0] != canonical(handle.record):
            raise RuntimeStoreError('hvf_recovery_index_changed')
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(record), handle.key))
    handle.authority.db._execute_write(write)
    handle.record = record


def _write_board_exit(candidate, handle, record):
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    binding = ('attempt', 'task_id', 'run_id', 'session_id', 'claim_digest', 'epoch', 'instance',
               'owner_pid', 'grant', 'helper_sha256', 'source_head')
    with connect_closing(candidate.board) as board, write_txn(board):
        row = board.execute('SELECT task_id,metadata FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()
        if row is None or row[0] != record['task_id']:
            raise RuntimeStoreError('hvf_exit_run_changed')
        body = metadata(row[1])
        existing = body.get(NAMESPACE)
        if not isinstance(existing, dict) or any(existing.get(key) != record.get(key) for key in binding):
            raise RuntimeStoreError('hvf_exit_reservation_changed')
        body[NAMESPACE] = record
        board.execute('UPDATE task_runs SET metadata=? WHERE id=?', (canonical(body), record['run_id']))


def _execute(authority, candidate, handle, campaign_deadline):
    from gateway.session_hvf_process import RELEASE, child_identity, observe_child
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    candidate.verify(authority)
    started = time.monotonic()
    deadline = min(started + 300, campaign_deadline)
    if deadline - started < 60:
        raise RuntimeStoreError('hvf_campaign_budget_exhausted')
    with authority.db._read_ctx() as owner:
        _require_owner(authority, owner)
    baseline_fds = psutil.Process().num_fds()
    try:
        with connect_closing(candidate.board) as board, write_txn(board):
            _guard(board, handle)
            handle.serial, guest_serial = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                child = subprocess.Popen(candidate.argv(guest_serial.fileno()), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, bufsize=0, start_new_session=True, close_fds=True,
                                         pass_fds=(guest_serial.fileno(),), cwd=candidate.plan.parent,
                                         env={'PATH': '/usr/bin:/bin', 'HOME': str(candidate.profile / 'host-home')})
                handle.process = child
            finally:
                guest_serial.close()
                handle.guest_serial_closed = guest_serial.fileno() == -1
            handle.identity = child_identity(child, candidate.helper, handle.observed_identity)
            _persist(board, handle, {**handle.record, 'phase': 'CHILD_BOOKED', 'native_spawned': True,
                                     'identity': handle.identity})
        # Both stores commit/read back before the child can enter Hypervisor.framework.
        with connect_closing(candidate.board) as board, write_txn(board):
            _guard(board, handle)
            _persist(board, handle, {**handle.record, 'phase': 'VM_RELEASE_STARTING'})
            if os.write(child.stdin.fileno(), RELEASE) != len(RELEASE):
                raise RuntimeStoreError('hvf_partial_release_frame')
        proof = observe_child(child, handle.identity, handle.record['mode'], handle.stop,
                              candidate.output / f'slot-{handle.record["slot"]}', started, deadline, handle.serial, handle.pipe_observation)
        candidate.verify(authority)
        proof['owner_fds_before'] = baseline_fds
        proof['owner_fds_after'] = psutil.Process().num_fds()
        if proof['owner_fds_after'] > baseline_fds:
            raise RuntimeStoreError('hvf_owner_fd_retirement_incomplete')
        from gateway.session_hvf_process import exit_observation
        observation = exit_observation(handle)
        _persist_exit(candidate, handle, observation)
        proof['exit_observation'] = observation
        return proof
    except BaseException as failure:
        if handle.process is not None:
            observation = _contain_failed_child(handle, min(deadline, time.monotonic() + 30))
            try:
                _persist_exit(candidate, handle, observation, failure=failure)
            except (RuntimeStoreError, sqlite3.Error, OSError) as persistence_error:
                failure.add_note(f'exit evidence ledger update unavailable: {persistence_error}')
        raise
    finally:
        if handle.serial is not None:
            handle.serial.close()


def _retire(candidate, handle, proof):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    with connect_closing(candidate.board) as board, write_txn(board):
        _guard(board, handle)
        record = {**handle.record, 'state': 'RETIRED', 'phase': 'RETIRED', 'proof': proof}
        if not _valid_retirement(record):
            raise RuntimeStoreError('hvf_physical_retirement_incomplete')
        _persist(board, handle, record)
        body = metadata(board.execute('SELECT metadata FROM task_runs WHERE id=?', (record['run_id'],)).fetchone()[0])
    with connect_closing(candidate.board) as board:
        if not kb.complete_task(board, record['task_id'], expected_run_id=record['run_id'], metadata=body,
                                result='Q1 inert HVF lifecycle qualified; no Worker execution.', fire_lifecycle_hook=False):
            raise RuntimeStoreError('hvf_native_task_settlement_failed')
    with handle.authority.db._read_ctx() as conn:
        if conn.execute('SELECT value FROM state_meta WHERE key=?', (handle.key,)).fetchone()[0] != canonical(record):
            raise RuntimeStoreError('hvf_retirement_readback_failed')
    if not _matching_board_retirement(handle.authority, record):
        raise RuntimeStoreError('hvf_board_retirement_readback_failed')


def signal_hvf_stop(authority):
    authority.__dict__.setdefault('_hvf_campaign_stop', threading.Event()).set()
    for handle in getattr(authority, '_hvf_workers', {}).values():
        if not handle.closed.is_set():
            handle.stop.set()


def _finish_grant(authority, *, failure=None):
    def write(conn):
        _require_owner(authority, conn)
        row = conn.execute('SELECT value FROM state_meta WHERE key=?', (GRANT_KEY,)).fetchone()
        if row is None:
            return
        grant = metadata(row[0])
        if failure is None:
            records = [metadata(r[0]) for r in conn.execute('SELECT value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))]
            if grant['reserved'] != 5 or len(records) != 5 or not all(_valid_retirement(record) for record in records):
                raise RuntimeStoreError('hvf_campaign_completion_incomplete')
            grant['status'] = 'COMPLETE'
        else:
            grant['status'] = 'STOP_UNCERTAIN'
            grant['failure'] = str(failure)[:500]
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (canonical(grant), GRANT_KEY))
    authority.db._execute_write(write)


async def qualify_hvf(authority, candidate):
    from gateway.session_runtime_workers import track_mutation, tracked_write, persist_work_count
    stop = authority.__dict__.setdefault('_hvf_campaign_stop', threading.Event())
    if stop.is_set() or getattr(authority, '_hvf_campaign_active', False):
        raise RuntimeStoreError('hvf_campaign_stopped_or_active')
    authority._hvf_campaign_active = True
    results = []
    try:
        await tracked_write(authority, lambda: candidate.verify(authority))
        await tracked_write(authority, lambda: _grant(authority, candidate))
        campaign_start = time.monotonic()
        campaign_deadline = campaign_start + 1800
        for slot in range(1, 6):
            if stop.is_set() or time.monotonic() - campaign_start >= 1800:
                raise RuntimeStoreError('hvf_campaign_stopped_or_deadline')
            handle = await tracked_write(authority, lambda: _reserve(authority, candidate, slot))
            work = track_mutation(authority, asyncio.to_thread(_execute, authority, candidate, handle, campaign_deadline))
            proof = await asyncio.shield(work)
            proof.update(owner_work_completed=True, owner_accounting_complete=True)
            await tracked_write(authority, lambda: _retire(candidate, handle, proof))
            handle.closed.set()
            handle.process = None
            persist_work_count(authority)
            results.append(handle.record)
        await tracked_write(authority, lambda: _finish_grant(authority))
        return {'status': 'FIVE_LIFECYCLES_PASS_INERT_ONLY', 'records': results,
                'worker_dispatch': 'NOT_AUTHORIZED', 'source_head': candidate.source_head}
    except BaseException as failure:
        signal_hvf_stop(authority)
        for handle in getattr(authority, '_hvf_workers', {}).values():
            if handle.process is not None and handle.record.get('phase') != 'FAILED' and not handle.closed.is_set():
                from gateway.session_hvf_process import exit_observation
                try:
                    await tracked_write(authority, lambda handle=handle, failure=failure: _persist_exit(
                        candidate, handle, exit_observation(handle), failure=failure))
                except (RuntimeStoreError, sqlite3.Error, OSError) as evidence_error:
                    failure.add_note(f'campaign failure evidence unavailable: {evidence_error}')
        try:
            await tracked_write(authority, lambda failure=failure: _finish_grant(authority, failure=failure))
        except (RuntimeStoreError, sqlite3.Error, OSError) as diagnostic_error:
            failure.add_note(f'uncertainty record update failed: {diagnostic_error}')
        raise
    finally:
        authority._hvf_campaign_active = False
        recover_hvf_reservations(authority)
        persist_work_count(authority)


def load_candidate(path):
    body = metadata(Path(path).read_text(encoding='utf-8-sig'))
    if body.get('package') != 'HERMES_Q1_HVF_PROCESS_OWNED_GUEST_FEASIBILITY_V1' or body.get('grant') != GRANT_ID:
        raise RuntimeStoreError('hvf_wrong_qualification_package')
    values = body['candidate']
    fields = ('profile', 'board', 'helper', 'plan', 'kernel', 'initramfs', 'disk', 'output')
    return HVFCandidate(**{key: Path(values[key]) for key in fields}, files=values['files'],
                        source_head=values['source_head'], prior_profile=Path(values['prior_profile']),
                        prior_snapshot_sha256=values['prior_snapshot_sha256'])


def _unused_profile(home):
    if home.name != 'hvf-qualification':
        raise RuntimeStoreError('hvf_disposable_profile_required')
    path = home / 'state.db'
    if not path.exists():
        return
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute("SELECT 1 FROM state_meta WHERE key LIKE 'q1.hvf.grant:%'").fetchone():
            raise RuntimeStoreError('hvf_grant_already_reserved_no_resume')
        if db.execute('SELECT 1 FROM worker_executions LIMIT 1').fetchone():
            raise RuntimeStoreError('hvf_non_diagnostic_history')


def _prepare_board(board):
    from hermes_cli.kanban_db_connect import connect_closing
    board.parent.mkdir(parents=True, exist_ok=True)
    with connect_closing(board):
        pass


async def bootstrap_qualification_owner(home):
    """Canonical original Owner bootstrap, without adapter/API/Agent startup."""
    from gateway.config import GatewayConfig
    from gateway.run import GatewayRunner, _profile_runtime_scope
    from gateway.runtime_ownership import process_ownership
    from gateway.run_runtime import initialize_gateway_runtime
    scoped_home = await asyncio.to_thread(Path(os.environ.get('HERMES_HOME', '')).resolve)
    if scoped_home != home:
        raise RuntimeStoreError('hvf_explicit_profile_scope_required')
    _unused_profile(home)
    process_ownership.reserve([home])
    with _profile_runtime_scope(home, hydrate_secrets=False):
        runner = GatewayRunner(config=GatewayConfig(platforms={}, multiplex_profiles=False,
                                                    sessions_dir=home / 'sessions', loop_watchdog=False))
        await initialize_gateway_runtime(runner)
    authority = runner.session_authorities.for_home(home)
    if authority is not runner.session_authority:
        raise RuntimeStoreError('hvf_original_owner_required')
    board = home / 'kanban/boards/hvf-qualification/kanban.db'
    await asyncio.to_thread(_prepare_board, board)
    return runner, authority


def _canary_servers(candidate, stack):
    """Disposable qualification controls, never VM transport or a broker."""
    import socket
    plan = metadata(candidate.plan.read_text(encoding='utf-8-sig'))
    for path in plan['unix'].values():
        server = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        if Path(path).exists():
            raise RuntimeStoreError('hvf_canary_socket_path_in_use')
        server.bind(path)
        server.listen(8)
    for name, kind in (('tcp_port', socket.SOCK_STREAM), ('udp_port', socket.SOCK_DGRAM)):
        server = stack.enter_context(socket.socket(socket.AF_INET, kind))
        server.bind(('127.0.0.1', plan[name]))
        if kind == socket.SOCK_STREAM:
            server.listen(8)


def _final_wait_and_record(candidate, handle):
    from gateway.session_hvf_process import _wait_for_child, exit_observation
    wait_error = None
    try:
        # A live unknown child is never abandoned by its original Owner. This
        # is the retained-custody path, not a successful bounded qualification.
        _wait_for_child(handle, None)
    except (OSError, subprocess.SubprocessError) as error:
        wait_error = error
    errors = [] if wait_error is None else [{'operation': 'final_wait', 'error': repr(wait_error)}]
    _persist_exit(candidate, handle, exit_observation(handle, errors=errors),
                  failure=handle.record.get('failure', 'hvf_late_finalizer_wait'))
    if wait_error is not None:
        raise wait_error


async def _qualification_main(args):
    from contextlib import ExitStack
    candidate = None if args.prepare_home else await asyncio.to_thread(load_candidate, args.manifest)
    selected = Path(args.prepare_home) if args.prepare_home else candidate.profile
    home = await asyncio.to_thread(selected.resolve)
    await asyncio.to_thread(home.mkdir, parents=True, exist_ok=True)
    runner, authority = await bootstrap_qualification_owner(home)
    actor = {'owner_class': type(authority).__module__ + '.' + type(authority).__name__,
             'runner_class': type(runner).__name__, 'owner_pid': os.getpid(),
             'owner_epoch': authority.epoch, 'owner_instance': authority.instance_id,
             'profile': str(home), 'services_started': False, 'worker_executions': 0}
    try:
        if args.prepare_home:
            return {'status': 'ORIGINAL_OWNER_PREPARED_NO_VM', 'actor': actor}
        with ExitStack() as controls:
            _canary_servers(candidate, controls)
            result = await authority.qualify_hvf(candidate)
        result['actor'] = actor
        return result
    finally:
        await _finish_qualification_owner(candidate, authority, home)


async def _finish_qualification_owner(candidate, authority, home):
    from gateway.runtime_ownership import process_ownership
    from gateway.session_runtime_workers import tracked_write
    pending_error = None
    pending = getattr(authority, '_hvf_campaign_task', None)
    if pending is not None and not pending.done():
        signal_hvf_stop(authority)
        try:
            await asyncio.shield(pending)
        except BaseException as error:
            # Joining a failed campaign must not bypass late-child observations.
            logging.getLogger(__name__).exception('Campaign join failed; retaining late-child cleanup')
            pending_error = error
    live = [h for h in getattr(authority, '_hvf_workers', {}).values()
            if h.process is not None and h.process.returncode is None]
    try:
        for handle in live:
            await tracked_write(authority, lambda handle=handle: _final_wait_and_record(candidate, handle))
    except BaseException as error:
        if pending_error is not None:
            error.add_note(f'campaign join also failed: {pending_error!r}')
        raise
    authority.db.close()
    process_ownership.release(home)
    if pending_error is not None:
        raise pending_error


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Original-Owner inert HVF qualification only; no dispatch')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare-home')
    mode.add_argument('--manifest')
    args = parser.parse_args()
    try:
        result = asyncio.run(_qualification_main(args))
        print(canonical(result), flush=True)
    except BaseException as error:
        print(canonical({'status': 'STOP_UNCERTAIN', 'error': repr(error),
                         'worker_dispatch': 'NOT_AUTHORIZED'}), flush=True)
        raise




def prior_snapshot(profile):
    """Stable logical snapshot of the spent original grant/attempt and Board."""
    profile = Path(profile).resolve(strict=True)
    with closing(sqlite3.connect((profile / 'state.db').as_uri() + '?mode=ro', uri=True)) as conn:
        rows = list(conn.execute("SELECT key,value FROM state_meta WHERE key LIKE 'q1.hvf.%' ORDER BY key"))
    board = profile / 'kanban/boards/hvf-qualification/kanban.db'
    with closing(sqlite3.connect(board.as_uri() + '?mode=ro', uri=True)) as conn:
        runs = list(conn.execute('SELECT id,task_id,status,metadata FROM task_runs ORDER BY id'))
        tasks = list(conn.execute('SELECT id,status,current_run_id,worker_pid FROM tasks ORDER BY id'))
    return {'owner_records': rows, 'runs': runs, 'tasks': tasks}


def reconcile_prior(profile, expected_digest):
    from gateway.session_hvf_process import verify_prior_absent
    snapshot = prior_snapshot(profile)
    if hashlib.sha256(canonical(snapshot).encode()).hexdigest() != expected_digest:
        raise RuntimeStoreError('hvf_prior_history_changed')
    grants = [metadata(value) for key, value in snapshot['owner_records'] if key == 'q1.hvf.grant:7058818518']
    attempts = [metadata(value) for key, value in snapshot['owner_records'] if key.startswith(PREFIX)]
    if (len(grants) != 1 or grants[0].get('status') != 'STOP_UNCERTAIN' or grants[0].get('reserved') != 1
            or len(attempts) != 1 or attempts[0].get('state') != 'STOP_UNCERTAIN'):
        raise RuntimeStoreError('hvf_prior_failed_campaign_not_exact')
    result = verify_prior_absent(attempts[0]['identity'])
    return {'prior_child_not_live': 'VERIFIED', 'identity': attempts[0]['identity'],
            'snapshot_sha256': expected_digest, 'group_members': result,
            'prior_retirement': 'STOP_UNCERTAIN_PRESERVED'}


if __name__ == '__main__':
    main()
