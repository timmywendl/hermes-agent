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




@pytest.mark.parametrize("lane", ["ready", "review"])
def test_target_dispatch_does_not_touch_sibling_or_run_board_reclaim(conn, monkeypatch, lane):
    """An explicitly selected task must not promote/reap other Board rows."""
    target = _task_in_lane(conn, lane)
    monkeypatch.setattr(kbd, "review_dispatch_enabled", lambda: True)
    sibling = kb.create_task(conn, title="sibling", assignee="w", initial_status="blocked")
    before = tuple(conn.execute("SELECT * FROM tasks WHERE id=?", (sibling,)).fetchone())
    events = [tuple(r) for r in conn.execute("SELECT * FROM task_events WHERE task_id=?", (sibling,))]
    monkeypatch.setattr(kbd, "_profile_exists_fn", lambda: lambda _: True)
    monkeypatch.setattr(kbd, "_run_reclaim_phase", lambda *a, **k: pytest.fail("board-wide reclaim"))
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda: "normal")
    spawned = []
    result = kbd.dispatch_once(conn, target_task_id=target,
                               spawn_fn=lambda task, workspace: spawned.append(task.id))
    assert spawned == [target]
    assert [r[0] for r in result.spawned] == [target]
    assert tuple(conn.execute("SELECT * FROM tasks WHERE id=?", (sibling,)).fetchone()) == before
    assert [tuple(r) for r in conn.execute("SELECT * FROM task_events WHERE task_id=?", (sibling,))] == events


@pytest.mark.parametrize("lane", ["ready", "review"])
@pytest.mark.parametrize("change", ["assignee", "lane"])
def test_target_dispatch_rechecks_selection_inside_claim(conn, monkeypatch, lane, change):
    target = _task_in_lane(conn, lane)
    monkeypatch.setattr(kbd, "review_dispatch_enabled", lambda: True)
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda: "normal")

    def profile_exists(profile):
        assert profile == "w"
        with kbc.connect() as other, kb.write_txn(other):
            assert other is not conn
            if change == "assignee":
                other.execute("UPDATE tasks SET assignee='other' WHERE id=?", (target,))
            else:
                other.execute("UPDATE tasks SET status=? WHERE id=?",
                              ("review" if lane == "ready" else "ready", target))
        return True

    monkeypatch.setattr(kbd, "_profile_exists_fn", lambda: profile_exists)
    result = kbd.dispatch_once(conn, target_task_id=target,
                               spawn_fn=lambda *args: pytest.fail("spawned stale selection"))
    assert not result.spawned
    assert kb.get_task(conn, target).claim_lock is None
    assert conn.execute("SELECT count(*) FROM task_runs WHERE task_id=?", (target,)).fetchone()[0] == 0


def _task_in_lane(conn, lane):
    target = kb.create_task(conn, title="target", assignee="w")
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET status=? WHERE id=?", (lane, target))
    return target


def test_target_dispatch_rejects_unretired_run_and_contended_lock(conn, monkeypatch):
    target = kb.create_task(conn, title="target", assignee="w")
    monkeypatch.setattr(kbd, "_profile_exists_fn", lambda: lambda _: True)
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda: "normal")
    calls = []
    with kbc._dispatch_tick_lock(kb.kanban_db_path()) as held:
        assert held
        res = kbd.dispatch_once(conn, target_task_id=target, spawn_fn=lambda *a: calls.append(a))
    assert res.skipped_locked and not calls
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET current_run_id=123 WHERE id=?", (target,))
    res = kbd.dispatch_once(conn, target_task_id=target, spawn_fn=lambda *a: calls.append(a))
    assert not res.spawned and not calls


def test_target_dispatch_refuses_wrong_board_connection(conn, tmp_path):
    import sqlite3
    other = sqlite3.connect(tmp_path / "foreign.db")
    try:
        with pytest.raises(RuntimeError, match="connection does not match"):
            kbd.dispatch_once(other, target_task_id="t_example")
    finally:
        other.close()


@pytest.mark.parametrize("journal", ["WAL", "DELETE"])
@pytest.mark.parametrize("lane", ["ready", "review"])
def test_board_pause_target_dispatch_leaves_both_lanes_untouched(conn, journal, lane):
    """The current --task path cannot bypass the shipped Board pause."""
    conn.execute("PRAGMA journal_mode=" + journal)
    target = _task_in_lane(conn, lane)
    sibling = _task_in_lane(conn, "ready")
    with kbc.connect() as observer:
        before = [tuple(row) for row in observer.execute("SELECT * FROM tasks ORDER BY id")]
        events = [tuple(row) for row in observer.execute("SELECT * FROM task_events ORDER BY id")]
        runs = [tuple(row) for row in observer.execute("SELECT * FROM task_runs ORDER BY id")]
        result = kbd.dispatch_once(conn, target_task_id=target,
                                   spawn_fn=lambda *args: pytest.fail("paused spawn"))
        assert result.disabled == kbd.BOARD_EXECUTION_PAUSE_REASON
        assert not result.spawned
        assert [tuple(row) for row in observer.execute("SELECT * FROM tasks ORDER BY id")] == before
        assert [tuple(row) for row in observer.execute("SELECT * FROM task_events ORDER BY id")] == events
        assert [tuple(row) for row in observer.execute("SELECT * FROM task_runs ORDER BY id")] == runs
        assert kb.get_task(observer, sibling).status == "ready"


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
