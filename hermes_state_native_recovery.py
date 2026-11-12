"""Private, raw-free response-use selectors on the existing SessionDB writer.

No transcript foreign key: deleting a Session cannot delete unsettled effects.
After thirty days selectors are redacted to a project blocking marker, never
silently dropped. Only Control's exact completed receipt settles a request.
"""
import math
import time
from pathlib import Path

FIELDS = (
    'project_id', 'request_id', 'result_ref', 'projection_digest',
    'original_session_id', 'original_turn_id', 'original_control_epoch',
    'original_channel_ref', 'original_host_generation',
)
WINDOW = 600
RETENTION = 30 * 86400
LIMIT = 16


def _identifier(value):
    return (type(value) is str and bool(value.strip())
            and len(value.encode('utf8')) <= 256)


def _validate_hint(payload):
    if type(payload) is not dict or set(payload) != set(FIELDS):
        raise ValueError('invalid native recovery selector')
    if not all(_identifier(payload[k]) for k in FIELDS):
        raise ValueError('invalid native recovery selector')
    digest = payload['projection_digest']
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('invalid native recovery digest')


def _age(conn, now):
    conn.execute("UPDATE native_response_use_hints SET state='EXPIRED' "
                 "WHERE state='PENDING' AND recovery_expires_at<=?", (now,))
    projects = conn.execute("SELECT DISTINCT project_id FROM native_response_use_hints "
                            "WHERE state!='BLOCKED' AND retained_until<=?", (now,)).fetchall()
    for (project,) in projects:
        # A fixed-size marker outlives retention. It cannot authorize or select a
        # request, and requires explicit operator reconciliation outside this API.
        conn.execute("DELETE FROM native_response_use_hints WHERE project_id=? "
                     "AND state!='BLOCKED' AND retained_until<=?", (project, now))
        conn.execute("INSERT OR IGNORE INTO native_response_use_hints "
                     "VALUES(?, '', '', '', '', '', '', '', '', ?, ?, ?, 'BLOCKED')",
                     (project, now, now, now))


def apply_native_recovery(conn, action, payload, now):
    """Called inside the owner's one bounded transaction; never commits itself."""
    _age(conn, now)
    if action == 'persist':
        _validate_hint(payload)
        key = tuple(payload[k] for k in FIELDS[:4])
        old = conn.execute('SELECT * FROM native_response_use_hints WHERE '
                           'project_id=? AND request_id=? AND result_ref=? AND projection_digest=?', key).fetchone()
        if old is not None:
            if old['state'] != 'PENDING':
                raise ValueError('native recovery selector conflict')
            return {'state': 'PERSISTED'}
        if conn.execute('SELECT count(*) FROM native_response_use_hints').fetchone()[0] >= LIMIT:
            raise ValueError('native recovery capacity')
        blocked = conn.execute("SELECT 1 FROM native_response_use_hints WHERE project_id=? "
                               "AND state!='PENDING'", (payload['project_id'],)).fetchone()
        if blocked:
            raise ValueError('native recovery blocked')
        conn.execute('INSERT INTO native_response_use_hints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                     tuple(payload[k] for k in FIELDS) + (now, now + WINDOW, now + RETENTION, 'PENDING'))
        return {'state': 'PERSISTED'}
    if action == 'read':
        if set(payload) != {'project_id'} or not _identifier(payload['project_id']):
            raise ValueError('invalid native recovery project')
        rows = conn.execute('SELECT * FROM native_response_use_hints WHERE project_id=? LIMIT ?',
                            (payload['project_id'], LIMIT + 1)).fetchall()
        if any(r['state'] != 'PENDING' for r in rows):
            return {'state': 'EXPIRED'}
        # Several historical results of the SAME request are ambiguous too: do
        # not guess which exact receipt Control might have committed.
        if len(rows) > 1:
            return {'state': 'AMBIGUOUS'}
        if not rows:
            return {'state': 'NONE'}
        return {'state': 'ONE', 'selector': {k: rows[0][k] for k in FIELDS[1:4]}}
    if action == 'clear':
        if set(payload) != {'project_id', 'request_id'} or not all(_identifier(v) for v in payload.values()):
            raise ValueError('invalid native recovery request')
        conn.execute('DELETE FROM native_response_use_hints WHERE project_id=? AND request_id=?',
                     (payload['project_id'], payload['request_id']))
        return {'state': 'CLEARED'}
    raise ValueError('invalid native recovery operation')


class NativeRecoveryMixin:
    def native_response_use(self, profile, action, payload, *, deadline, _guard=None):
        """Private Core API; the existing owner supplies the sole connection.

        Response-critical write patience is capped at the existing activity
        budget. Unknown commit errors propagate; callers must not send use RPCs.
        """
        if (str(Path(self.db_path).resolve().parent) != profile or self.read_only
                or type(deadline) not in (float, int) or not math.isfinite(deadline)):
            raise PermissionError('native recovery owner unavailable')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('native recovery deadline')
        def write(conn):
            if time.monotonic() >= deadline:
                raise TimeoutError('native recovery deadline')
            if _guard is not None:
                _guard(conn)
            return apply_native_recovery(conn, action, payload, time.time())
        return self._execute_write(write, patience_s=min(self._ACTIVITY_WRITE_PATIENCE_S, remaining))
