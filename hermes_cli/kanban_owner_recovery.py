"""Read-only canonical admission fences for dispatcher reclaim paths."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import psutil


def owner_reclaim_paused(conn, task_id):
    """Missing/ambiguous owner receipts never authorize another attempt."""
    marker = conn.execute(
        "SELECT e.payload FROM task_events e JOIN tasks t ON t.current_run_id=e.run_id "
        "WHERE t.id=? AND e.task_id=t.id AND e.kind='owner_admitted' ORDER BY e.id DESC LIMIT 1",
        (task_id,)).fetchone()
    if marker is None:
        return False
    try:
        binding = json.loads(marker['payload'])
        with closing(sqlite3.connect(Path(binding['db']).as_uri() + '?mode=ro', uri=True)) as owner:
            row = owner.execute('SELECT status,outcome FROM session_admissions WHERE target_session_id=? AND request_id=?',
                                (binding['session_id'], binding['request_id'])).fetchone()
        if row is not None and row[0] == 'terminal':
            # Discard acknowledges uncertainty, not permission to repeat effects.
            return row[1] == 'interrupted'
        if row is None or row[0] in {'queued', 'unknown'}:
            return True
        return psutil.Process(binding['pid']).create_time() != binding['birth']
    except (OSError, ValueError, KeyError, sqlite3.Error):
        return True
    except psutil.Error:
        return True



def bound_interpreter_gone(conn, task_id):
    """True when the owner bound an interpreter to the task's current run and it is dead."""
    from hermes_cli.kanban_db_dispatch import _worker_alive
    row = conn.execute(
        "SELECT e.payload FROM task_events e JOIN tasks t ON t.current_run_id=e.run_id "
        "WHERE t.id=? AND e.task_id=t.id AND e.kind='worker_bound' ORDER BY e.id DESC LIMIT 1",
        (task_id,)).fetchone()
    if row is None:
        return False
    bound = json.loads(row['payload'])
    return not _worker_alive(bound.get('pid'), bound.get('started_at'))


def managed_run_exit_code(conn, task_id, worker_pid, claim_lock):
    """The exit code a managed run's authority recorded for the task's CURRENT run, else None.

    Managed interpreters are children of the authority, not the dispatcher, so their result is
    read from the run's ``worker_result`` event (it survives a dispatcher restart and cannot be
    reaped here). It speaks for the run only under the same claim and from a pid of this run:
    the dispatcher's own worker, or the owner-side interpreter ``worker_bound`` recorded under
    that claim — ``session_kanban._record_worker_result`` writes the interpreter's pid, never the
    spawned submitter's ``tasks.worker_pid``."""
    def latest(kind):
        row = conn.execute(
            "SELECT e.payload FROM task_events e JOIN tasks t ON t.current_run_id=e.run_id "
            "WHERE t.id=? AND e.task_id=t.id AND e.kind=? ORDER BY e.id DESC LIMIT 1", (task_id, kind)).fetchone()
        try:
            payload = json.loads(row['payload']) if row else {}
        except ValueError:
            return {}
        return payload if isinstance(payload, dict) else {}

    result, bound = latest('worker_result'), latest('worker_bound')
    pids = {worker_pid, *([bound.get('pid')] if bound.get('claim_lock') == claim_lock else [])}
    return result.get('exit_code') if result.get('claim_lock') == claim_lock and result.get('pid') in pids else None


def _matching_profile_home(profile_home, run_profile):
    from hermes_cli.profiles import normalize_profile_name, profile_root_for_env_home, resolve_profile_env, validate_profile_name
    from hermes_constants import get_default_hermes_root, get_hermes_home
    home = Path(profile_home).resolve(strict=True)
    if Path(get_hermes_home()).resolve(strict=True) != home:
        return None
    name = normalize_profile_name(run_profile)
    validate_profile_name(name)
    root = profile_root_for_env_home(str(home), get_default_hermes_root()).resolve(strict=True)
    expected = root if name == 'default' else root / 'profiles' / name
    resolved = Path(resolve_profile_env(name)).resolve(strict=True)
    return resolved if resolved == expected else None


def _endpoint_profile_matches(endpoint, home):
    return Path(endpoint.profile_id).resolve() == home


def _owner_identity_matches(marker, endpoint, home):
    import math
    try:
        pid, birth = marker['pid'], marker['birth']
        instance, epoch = marker['instance_id'], marker['authority_epoch']
        db = marker['db']
        return (type(pid) is int and pid > 0 and type(birth) in (int, float)
                and math.isfinite(birth) and birth > 0
                and isinstance(instance, str) and bool(instance) and instance == endpoint.instance_id
                and type(epoch) is int and epoch > 0
                and isinstance(db, str) and Path(db).is_absolute()
                and Path(db).resolve(strict=True) == (home / 'state.db').resolve(strict=True)
                and psutil.Process(pid).create_time() == birth)
    except (KeyError, AttributeError, TypeError, ValueError, OSError, psutil.Error):
        return False


def _matches_native_board(actual_path, slug):
    from hermes_cli import kanban_db as kb
    return bool(actual_path) and Path(actual_path).resolve(strict=True) == kb.kanban_db_path(board=slug).resolve(strict=True)


def _finish_snapshot(conn, task_id, run_id):
    # Compare across awaits, including early exits; reject an externally held snapshot.
    if conn.in_transaction:
        return None
    version = conn.execute('PRAGMA data_version').fetchone()[0]
    task = conn.execute('SELECT status,current_run_id FROM tasks WHERE id=?', (task_id,)).fetchone()
    run = conn.execute('SELECT id,profile,outcome FROM task_runs WHERE id=? AND task_id=?', (run_id, task_id)).fetchone()
    latest = conn.execute('SELECT max(id) FROM task_runs WHERE task_id=?', (task_id,)).fetchone()[0]
    rows = conn.execute("SELECT id,kind,payload FROM task_events WHERE task_id=? AND run_id=? AND kind IN ('owner_admitted','owner_admission_bound') ORDER BY id", (task_id, run_id)).fetchall()
    if version != conn.execute('PRAGMA data_version').fetchone()[0]:
        return None
    return version, tuple(task) if task else None, tuple(run) if run else None, latest, tuple(map(tuple, rows))


async def read_owner_finish(conn, task_id, run_id, *, profile_home):
    unknown = dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
    try:
        before = _finish_snapshot(conn, task_id, run_id)
        if before is None:
            return unknown
        result = await _read_owner_finish(conn, task_id, run_id, profile_home=profile_home)
        if 'RECORDED' in result.values() and _finish_snapshot(conn, task_id, run_id) != before:
            return unknown
        return result
    except sqlite3.Error:
        return unknown


async def _read_owner_finish(conn, task_id, run_id, *, profile_home):
    """Read the exact original Owner's receipt without starting or switching gateways.

    The caller must already have authorized the Board and profile. Unknown custody is
    never upgraded from a missing binding, unreachable owner, or a terminal card.
    """
    import asyncio
    from hermes_cli import kanban_db as kb
    from hermes_cli.gateway_client import connect_gateway
    from hermes_cli.gateway_runtime import discover_gateway_endpoint
    from urllib.parse import urlsplit
    import ipaddress
    from websockets.exceptions import WebSocketException

    result = dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
    try:
        task = conn.execute('SELECT status,current_run_id FROM tasks WHERE id=?', (task_id,)).fetchone()
        run = conn.execute('SELECT id,profile,outcome FROM task_runs WHERE id=? AND task_id=?', (run_id, task_id)).fetchone()
        latest = conn.execute('SELECT max(id) FROM task_runs WHERE task_id=?', (task_id,)).fetchone()[0]
        if task is None or run is None:
            return result
        if task['status'] in {'done', 'archived'} and run['outcome'] == 'completed' and latest == run_id:
            result['board_terminal'] = 'RECORDED'
        home = await asyncio.to_thread(_matching_profile_home, profile_home, run['profile'])
        if home is None:
            return result
        rows = conn.execute("SELECT kind,payload FROM task_events WHERE task_id=? AND run_id=? AND kind IN ('owner_admitted','owner_admission_bound') ORDER BY id", (task_id, run_id)).fetchall()
        admitted = [json.loads(r['payload']) for r in rows if r['kind'] == 'owner_admitted']
        bound = [json.loads(r['payload']) for r in rows if r['kind'] == 'owner_admission_bound']
        if (len(admitted) != 1 or len(bound) != 1 or not isinstance(admitted[0], dict) or not isinstance(bound[0], dict)
                or not isinstance(admitted[0].get('request_id'), str)
                or not admitted[0]['request_id'].startswith('kanban:')
                or admitted[0]['request_id'] != bound[0].get('request_id')
                or not isinstance(bound[0].get('admission_id'), str) or not bound[0]['admission_id']
                or not isinstance(bound[0].get('session_id'), str) or not bound[0]['session_id']
                or bound[0]['session_id'] != admitted[0].get('session_id')):
            return result
        identity = json.loads(admitted[0]['request_id'][len('kanban:'):])
        if (not isinstance(identity, list) or len(identity) != 3 or identity[1:] != [task_id, run_id]
                or kb._require_slug(identity[0]) != identity[0]
                or admitted[0]['request_id'] != 'kanban:' + json.dumps(identity, separators=(',', ':'))):
            return result
        db_row = next((r for r in conn.execute('PRAGMA database_list') if r[1] == 'main'), None)
        if db_row is None or not await asyncio.to_thread(_matches_native_board, db_row[2], identity[0]):
            return result
        from hermes_constants import reset_hermes_home_override, set_hermes_home_override
        token = set_hermes_home_override(home)
        try:
            observed = await asyncio.to_thread(discover_gateway_endpoint, home)
            endpoint = observed.endpoint
            if (observed.state != 'ready' or endpoint is None
                    or not await asyncio.to_thread(_endpoint_profile_matches, endpoint, home)
                    or not await asyncio.to_thread(_owner_identity_matches, admitted[0], endpoint, home)):
                return result
            host = urlsplit(endpoint.api_origin).hostname
            if not host or not ipaddress.ip_address(host).is_loopback:
                return result
            async with connect_gateway(endpoint=endpoint) as client:
                response = await client.rpc('prompt.receipt', session_id=bound[0]['session_id'],
                                            admission_id=bound[0]['admission_id'], include_worker_finish=True)
            if (type(response.get('authority_epoch')) is not int
                    or response['authority_epoch'] != admitted[0]['authority_epoch']
                    or not await asyncio.to_thread(_owner_identity_matches, admitted[0], endpoint, home)):
                return result
        finally:
            reset_hermes_home_override(token)
        current = conn.execute('SELECT status,current_run_id FROM tasks WHERE id=?', (task_id,)).fetchone()
        latest_after = conn.execute('SELECT max(id) FROM task_runs WHERE task_id=?', (task_id,)).fetchone()[0]
        events_after = conn.execute("SELECT kind,payload FROM task_events WHERE task_id=? AND run_id=? AND kind IN ('owner_admitted','owner_admission_bound') ORDER BY id", (task_id, run_id)).fetchall()
        if current is None or tuple(current) != tuple(task) or latest_after != latest or [tuple(r) for r in events_after] != [tuple(r) for r in rows]:
            return dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
        finish = response.get('worker_finish')
        if isinstance(finish, dict) and finish.get('receipt') == 'RECORDED':
            result['receipt'] = 'RECORDED'
            if finish.get('ack') == 'RECORDED':
                result['ack'] = 'RECORDED'
        return result
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, ImportError, WebSocketException):
        return result
