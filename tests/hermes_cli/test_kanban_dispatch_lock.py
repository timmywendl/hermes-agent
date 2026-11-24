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


def test_review_handoff_does_not_authorize_successor_before_owner_retirement(conn, monkeypatch):
    target = _task_in_lane(conn, "ready")
    sibling = _task_in_lane(conn, "ready")
    assert kb.request_review(conn, target, reviewer="reviewer")
    review = kb.claim_review_task(conn, target)
    assert review is not None
    assert kb.request_changes(conn, target, reason="fixture finding",
                              expected_run_id=review.current_run_id,
                              expected_claim_lock=review.claim_lock)[0]
    def profile_exists(_profile):
        # Commit the Owner marker after selection, before the claim transaction.
        with kbc.connect() as owner, kb.write_txn(owner):
            kb._append_event(owner, target, "owner_admitted", {}, run_id=review.current_run_id)
        return True
    monkeypatch.setattr(kbd, "_profile_exists_fn", lambda: profile_exists)
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda: "normal")
    calls = []
    result = kbd.dispatch_once(conn, target_task_id=target,
                               spawn_fn=lambda *args: calls.append(args))
    assert not result.spawned and not calls
    assert kb.claim_task(conn, target) is None
    assert kb.get_task(conn, target).status == "ready"
    assert kb.claim_task(conn, sibling) is not None
