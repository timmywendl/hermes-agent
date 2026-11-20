"""Tests for the kanban dispatcher single-writer lock (issue #35240).

A ``hermes gateway run --replace`` / ``gateway restart`` from a shell on a
systemd/launchd host can leave an orphan dispatcher that escapes the
service cgroup, survives ``systemctl restart``, and becomes a second
long-lived writer on the same ``kanban.db`` — the documented root cause of
multi-writer SQLite WAL corruption. ``dispatch_once`` now wraps each tick in
a non-blocking, board-scoped dispatch lock so two dispatchers can never run
a reclaim/spawn/write tick concurrently. The losing dispatcher returns an
empty ``DispatchResult`` with ``skipped_locked=True`` and does no DB writes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as kbd


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    db_path = kb.kanban_db_path(board="default")
    kb._INITIALIZED_PATHS.discard(str(db_path.resolve()))
    kb.init_db()
    return home


@pytest.fixture
def conn(kanban_home):
    with kbc.connect() as c:
        yield c




def test_held_lock_skips_the_tick_without_writes(conn):
    """While another holder owns the board lock, dispatch_once must skip and
    must NOT invoke spawn_fn (no DB writes happen on a skipped tick)."""
    kb.create_task(conn, title="t", assignee="w")
    db_path = kb.kanban_db_path(board="default")

    spawn_calls: list = []

    def spy_spawn(task, workspace_path, board=None):
        spawn_calls.append(getattr(task, "id", task))
        return 999999

    # Hold the lock, then attempt a contended tick.
    with kbc._dispatch_tick_lock(db_path) as held:
        assert held is True  # we genuinely acquired it
        result = kbd.dispatch_once(conn, spawn_fn=spy_spawn)

    assert result.skipped_locked is True
    assert result.spawned == []
    assert spawn_calls == [], "spawn_fn must not run while the tick is locked out"




def test_lock_is_board_scoped(conn):
    """Holding board A's dispatch lock must not block a tick on board B —
    distinct boards have distinct DB files and tick independently."""
    db_default = kb.kanban_db_path(board="default")
    db_other = db_default.with_name("other-board-kanban.db")

    # Two different lock files → both acquirable simultaneously.
    with kbc._dispatch_tick_lock(db_default) as held_a:
        assert held_a is True
        with kbc._dispatch_tick_lock(db_other) as held_b:
            assert held_b is True, "a lock on a different board must be independent"




@pytest.mark.parametrize('journal', ['WAL', 'DELETE'])
@pytest.mark.parametrize('dry_run', [False, True])
def test_board_pause_preserves_all_rows_before_any_tick_work(conn, journal, dry_run, monkeypatch):
    """Real Board storage is unchanged even with expired work and UNKNOWN history."""
    import json
    import sqlite3
    conn.execute('PRAGMA journal_mode=' + journal)
    monkeypatch.setattr('hermes_cli.profiles.profile_exists', lambda name: True)
    review = kb.create_task(conn, title='review work', assignee='w')
    conn.execute("UPDATE tasks SET status='review' WHERE id=?", (review,))
    ready = kb.create_task(conn, title='future work', assignee='w')
    held = kb.create_task(conn, title='uncertain work', assignee='w')
    kb.recompute_ready(conn)
    task = kb.claim_task(conn, held, ttl_seconds=1)
    marker = json.dumps({'local_launch_v1': {'phase': 'STOP_UNCERTAIN'},
                         'vz_custody_v1': {'phase': 'STOP_UNCERTAIN'},
                         'managed_launch_v1': {'phase': 'STOP_UNCERTAIN'}})
    conn.execute('UPDATE task_runs SET metadata=?,worker_pid=424242 WHERE id=?', (marker, task.current_run_id))
    conn.execute('UPDATE tasks SET claim_expires=1 WHERE id=?', (held,))
    conn.commit()
    before = list(conn.iterdump())
    changes = conn.total_changes
    calls = []
    def spawn(*args, **kwargs):
        calls.append(args)
        raise AssertionError('Board spawn reached')
    def readonly(action, *_args):
        return sqlite3.SQLITE_DENY if action in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE} else sqlite3.SQLITE_OK
    def forbidden_reclaim(*args, **kwargs):
        raise AssertionError('paused dispatcher entered reclaim phase')
    monkeypatch.setattr(kbd, '_run_reclaim_phase', forbidden_reclaim)
    monkeypatch.setattr(kbc, '_dispatch_tick_lock', forbidden_reclaim)
    conn.set_authorizer(readonly)
    try:
        for entry in (kbd.dispatch_once, kbd._dispatch_once_locked):
            result = entry(conn, spawn_fn=spawn, dry_run=dry_run, default_assignee='w', stale_timeout_seconds=1)
            assert result.disabled == kbd.BOARD_EXECUTION_PAUSE_REASON
            assert result.spawned == [] and result.reclaimed == result.promoted == 0
            assert kbd.BOARD_EXECUTION_PAUSE_REASON in kbd.describe_suppression([result])
        assert not kbd.has_spawnable_ready(conn)
        assert not kbd.has_spawnable_review(conn)
    finally:
        conn.set_authorizer(None)
    assert calls == [] and conn.total_changes == changes
    assert list(conn.iterdump()) == before
    assert kb.get_task(conn, ready).status == 'ready'
    with pytest.raises(RuntimeError, match='execution paused'):
        kbd._default_spawn(None, '')


def test_board_pause_standalone_never_opens_board(monkeypatch):
    results = []
    def forbidden(*args, **kwargs):
        raise AssertionError('paused standalone opened storage')
    monkeypatch.setattr(kbc, 'connect', forbidden)
    import threading
    stopped = threading.Event()
    stopped.set()
    kbd.run_daemon(on_tick=results.append, stop_event=stopped)
    assert len(results) == 1 and results[0].disabled == kbd.BOARD_EXECUTION_PAUSE_REASON
