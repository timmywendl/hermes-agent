"""Finite Q1 custody held by the original SessionAuthority.

This candidate has no protected Host-policy verifier or independent per-VM
observer. Its native gate therefore stays closed. A persisted reservation is
never converted into retirement by adapter EOF, a PID probe or a Guest result.
The future Worker protocol is deliberately absent from this Q1 entry point.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import threading
import time
import uuid

from hermes_state_runtime import RuntimeStoreError, _admission, _epoch, _session

PREFIX = 'q1.native.v1:'
NAMESPACE = 'q1_native_v1'
MISSING_NATIVE_GATES = (
    'HOST_POLICY_DENIAL_WITNESS',
    'INDEPENDENT_PER_VM_OBSERVER',
    'PROTECTED_HASH_BOUND_APPROVAL',
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeStoreError('q1_metadata_unavailable')
        result[key] = value
    return result


def _metadata(raw):
    if raw is None:
        return {}
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (TypeError, ValueError) as exc:
        raise RuntimeStoreError('q1_metadata_unavailable') from exc
    if not isinstance(value, dict):
        raise RuntimeStoreError('q1_metadata_unavailable')
    return value


@dataclass(frozen=True)
class Q1Binding:
    """Non-secret identity of one inert diagnostic VM, never a Worker scope."""

    task_id: str
    run_id: int
    vm_id: str
    connection_generation: int
    image_digest: str
    policy_digest: str

    def __post_init__(self):
        if any(not isinstance(value, str) or not value or len(value) > 256
               for value in (self.task_id, self.vm_id)):
            raise RuntimeStoreError('invalid_q1_binding')
        if any(type(value) is not int or value < 1 for value in (self.run_id, self.connection_generation)):
            raise RuntimeStoreError('invalid_q1_binding')
        if any(not isinstance(value, str) or len(value) != 64
               or any(char not in '0123456789abcdef' for char in value)
               for value in (self.image_digest, self.policy_digest)):
            raise RuntimeStoreError('invalid_q1_binding')


@dataclass(frozen=True)
class Q1Diagnostic:
    """An inert disposable assignment, never a product dispatch selector."""

    board_path: Path
    binding: Q1Binding
    manifest_digest: str
    witness_plan_digest: str

    def __post_init__(self):
        if not isinstance(self.binding, Q1Binding) or not isinstance(self.board_path, Path):
            raise RuntimeStoreError('invalid_q1_assignment')
        for digest in (self.manifest_digest, self.witness_plan_digest):
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(c not in '0123456789abcdef' for c in digest)):
                raise RuntimeStoreError('invalid_q1_assignment')


def _require_owner(authority):
    from gateway.session_authority import SessionAuthority
    registry = getattr(authority.runner, 'session_authorities', None)
    if (not isinstance(authority, SessionAuthority) or registry is None
            or registry.for_home(authority.profile_id) is not authority):
        raise RuntimeStoreError('q1_original_owner_required')
    authority._require_admission_open()


def _board_claim(conn, diagnostic, session_id):
    from hermes_cli import kanban_db as kb
    task = kb.get_task(conn, diagnostic.binding.task_id)
    run = conn.execute('SELECT * FROM task_runs WHERE id=?', (diagnostic.binding.run_id,)).fetchone()
    if (task is None or run is None or run['task_id'] != task.id
            or task.current_run_id != run['id'] or task.status != 'running'
            or run['status'] != 'running' or task.session_id != session_id
            or not task.claim_lock or run['claim_lock'] != task.claim_lock
            or type(task.claim_expires) is not int or task.claim_expires <= int(time.time())):
        raise RuntimeStoreError('stale_kanban_claim')
    return task, run


def _check_history(conn, task, reservation=None):
    if task.worker_pid is not None:
        raise RuntimeStoreError('q1_unretired_execution')
    for row in conn.execute('SELECT * FROM task_runs WHERE task_id=?', (task.id,)):
        if row['worker_pid'] is not None:
            raise RuntimeStoreError('q1_unretired_execution')
        metadata = _metadata(row['metadata'])
        # A state label by itself is not retirement proof. This candidate has
        # no authority to validate historical physical-retirement witnesses.
        if any(key in metadata for key in ('vz_custody_v1', 'local_launch_v1', 'owner_launch_v1')):
            raise RuntimeStoreError('q1_unretired_execution')
        if NAMESPACE in metadata and (reservation is None or metadata[NAMESPACE] != reservation):
            raise RuntimeStoreError('q1_unretired_execution')
        if row['id'] != task.current_run_id:
            raise RuntimeStoreError('q1_historical_execution_unqualified')


def _reserve_board(authority, row, diagnostic, attempt):
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    home = Path(authority.profile_id).resolve(strict=True)
    board = diagnostic.board_path.resolve(strict=True)
    if (board != home / 'kanban' / 'boards' / 'q1-qualification' / 'kanban.db'
            or board.stat().st_nlink != 1
            or Path(authority.db.db_path).resolve(strict=True) != home / 'state.db'):
        raise RuntimeStoreError('q1_disposable_board_required')
    with connect_closing(board) as conn, write_txn(conn):
        task, run = _board_claim(conn, diagnostic, row['target_session_id'])
        _check_history(conn, task)
        record = {
            'version': 'HERMES_Q1_NATIVE_V1', 'state': 'STOP_UNCERTAIN', 'phase': 'RESERVED',
            'task_id': task.id, 'run_id': run['id'], 'claim_digest':
                hashlib.sha256(task.claim_lock.encode()).hexdigest(),
            'session_id': row['target_session_id'], 'admission_id': row['admission_id'],
            'principal_id': row['principal_id'],
            'generation': row['generation'], 'owner_epoch': authority.epoch,
            'owner_instance': authority.instance_id, 'launch_attempt': attempt,
            'binding': asdict(diagnostic.binding), 'board_path': str(board),
            'manifest_digest': diagnostic.manifest_digest,
            'witness_plan_digest': diagnostic.witness_plan_digest,
            'native': 'NOT_RUN', 'retirement': 'UNVERIFIED',
        }
        metadata = _metadata(run['metadata'])
        metadata[NAMESPACE] = record
        conn.execute('UPDATE task_runs SET metadata=? WHERE id=?', (_canonical(metadata), run['id']))
        handle = Q1OwnerHandle(authority, record)
        with authority.db._read_ctx() as owner_conn:
            handle._check_admission(owner_conn)
        # Commit the recovery index before the Board transaction can commit.
        # Either commit failing leaves the other store's conservative fence;
        # crash between commits can never leave an undiscoverable reservation.
        handle._persist()
    return handle


class Q1OwnerHandle:
    """Retained by the original authority until independently proven retirement.

    ``closed`` is physical retirement accounting, not a transport flag. There
    is intentionally no PID-based close/kill fallback or public clear method.
    """

    def __init__(self, authority, record):
        self.authority = authority
        self.record = record
        self.closed = threading.Event()
        self.stop = threading.Event()
        self.revocation_task = None

    @property
    def key(self):
        return PREFIX + self.record['launch_attempt']

    def _persist(self):
        encoded = _canonical(self.record)

        def write(conn):
            self._check_admission(conn)
            # Publish only after the actual writer validated admission.
            # Earlier read validation is insufficient: a competing writer can
            # invalidate it while this transaction waits for SQLite.
            self.authority._q1_native_workers[self.record['launch_attempt']] = self
            prior = conn.execute('SELECT value FROM state_meta WHERE key=?', (self.key,)).fetchone()
            if prior is None:
                conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (self.key, encoded))
            elif prior[0] != encoded:
                raise RuntimeStoreError('q1_reservation_changed')
        self.authority.db._execute_write(write)
        with self.authority.db._read_ctx() as conn:
            if conn.execute('SELECT value FROM state_meta WHERE key=?', (self.key,)).fetchone()[0] != encoded:
                raise RuntimeStoreError('q1_reservation_unavailable')

    def _check_admission(self, conn, *, revoking=False):
        if not revoking:
            _require_owner(self.authority)
        _epoch(conn, self.record['owner_epoch'])
        instance = conn.execute('SELECT instance_id FROM runtime_epoch WHERE singleton=1').fetchone()[0]
        if instance != self.record['owner_instance']:
            raise RuntimeStoreError('stale_epoch')
        admission = _admission(conn, self.record['admission_id'])
        session = _session(conn, self.record['session_id'])
        allowed = ('started', 'unknown') if revoking else ('started',)
        if (admission['status'] not in allowed
                or admission['owner_epoch'] != self.record['owner_epoch']
                or admission['target_session_id'] != self.record['session_id']
                or admission['generation'] != self.record['generation']
                or admission['principal_id'] != self.record['principal_id']
                or session['runtime_generation'] != self.record['generation']
                or session['source'] != 'q1_diagnostic'):
            raise RuntimeStoreError('q1_disposable_admission_required')

    def verify_acquisition(self, conn):
        self._check_admission(conn)
        row = conn.execute('SELECT value FROM state_meta WHERE key=?', (self.key,)).fetchone()
        if row is None or row[0] != _canonical(self.record):
            raise RuntimeStoreError('q1_reservation_unavailable')

    def revoke(self):
        self.stop.set()
        # Downgrade the original Owner's admission, without a Worker execution,
        # Guest persistence endpoint or result protocol. Custody stays in its
        # immutable recovery index and Board record, even after logical Discard.
        def write(conn):
            self._check_admission(conn, revoking=True)
            changed = conn.execute(
                "UPDATE session_admissions SET status='unknown' WHERE admission_id=? AND status='started'",
                (self.record['admission_id'],)).rowcount
            if changed:
                conn.execute('UPDATE sessions SET runtime_revision=runtime_revision+1 WHERE id=?',
                             (self.record['session_id'],))
        self.authority.db._execute_write(write)

    def control(self, frame):
        if frame != {'type': 'stop'}:
            raise RuntimeStoreError('q1_channel_denied')
        # Stop's synchronous signaling phase must never block on SQLite.
        self.stop.set()

    def retirement_receipt(self):
        """Adapter/VZ stopped observations cannot satisfy the missing witness."""
        return {
            'launch_attempt': self.record['launch_attempt'],
            'vm_id': self.record['binding']['vm_id'],
            'state': 'STOP_UNCERTAIN', 'stop_verified': False,
            'native': 'NOT_RUN', 'missing': list(MISSING_NATIVE_GATES),
        }


def reserve_q1_diagnostic(authority, ref, row, diagnostic):
    """Durably bind before acquisition; a split-store failure leaves a fence.

    SessionDB's recovery index commits while the Board writer is held, before
    the Board commit. No physical operation is attempted until both stores
    commit and read back. No callback passed to SessionDB may spawn or open a
    VM: that store retries its callback on BUSY.
    """
    _require_owner(authority)
    if (not isinstance(diagnostic, Q1Diagnostic) or ref.profile_id != authority.profile_id
            or row['target_session_id'] != ref.session_id):
        raise RuntimeStoreError('invalid_q1_assignment')
    lock = authority.__dict__.setdefault('_q1_native_lock', threading.Lock())
    with lock:
        workers = authority.__dict__.setdefault('_q1_native_workers', {})
        if workers or getattr(authority, '_q1_native_retained', ()):
            raise RuntimeStoreError('q1_unretired_execution')
        handle = _reserve_board(authority, row, diagnostic, str(uuid.uuid4()))
        if handle.stop.is_set():
            handle.revoke()
        return handle


def recover_q1_reservations(authority):
    """Keep restart-left bindings; never resume, rebind or infer retirement."""
    retained = []
    rows = authority.db._read_all('SELECT key,value FROM state_meta WHERE key LIKE ?', (PREFIX + '%',))
    for row in rows:
        # Retain the key even if its bytes are damaged; normalizing corruption
        # into an empty assignment would hide ownership from shutdown.
        retained.append(row['key'])
    authority._q1_native_retained = tuple(retained)
    return authority._q1_native_retained


def require_native_readiness():
    """No caller-controlled JSON can grant the absent protected capabilities."""
    raise RuntimeStoreError('q1_native_preconditions_unavailable',
                            detail=','.join(MISSING_NATIVE_GATES))
