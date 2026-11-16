"""Retention bounds for ``kanban gc``: a negative window builds a future cutoff
that matches every row; zero disables the sweep rather than deleting all.

Structural ``created``/``decomposed`` rows survive ordinary age-based GC for
the owning Task's lifetime; ordinary events keep expiring by age."""
import argparse
import json
import os
import shutil
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_ops

@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    return tmp_path

def _done_task_with_old_event(conn):
    """A done Task with a closed Run and aged events, including one ordinary
    comment event, so a sweep must choose row kinds rather than drop all."""
    tid = kb.create_task(conn, title="finished")
    assert kb.claim_task(conn, tid) is not None
    assert kb.complete_task(conn, tid, result="finished")
    kb.add_comment(conn, tid, "probe", "ordinary history")
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET status='done' WHERE id=?", (tid,))
        conn.execute("UPDATE task_events SET created_at=0 WHERE task_id=?", (tid,))
    return tid

def _event_rows(conn, tid):
    return conn.execute(
        "SELECT count(*) FROM task_events WHERE task_id=?", (tid,)
    ).fetchone()[0]

def _event_kind_rows(conn, tid, kind):
    return conn.execute(
        "SELECT count(*) FROM task_events WHERE task_id=? AND kind=?", (tid, kind)
    ).fetchone()[0]

def _task_row_count(conn):
    return conn.execute("SELECT count(*) FROM tasks").fetchone()[0]

def _task_run_count(conn):
    return conn.execute("SELECT count(*) FROM task_runs").fetchone()[0]

def _old_log_file() -> Path:
    log_dir = kb.worker_logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    p = log_dir / "worker-1.log"
    p.write_text("log line")
    os.utime(p, (0, 0))
    return p

def _args(event_days=30, log_days=30):
    return argparse.Namespace(event_retention_days=event_days,
                              log_retention_days=log_days)

def test_gc_events_rejects_negative_window(board):
    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
        tasks_before = _task_row_count(conn)
        runs_before = _task_run_count(conn)
        with pytest.raises(ValueError, match="older_than_seconds"):
            kb.gc_events(conn, older_than_seconds=-86400)
        # Nothing is deleted: ordinary history and structural identity stay.
        assert _event_kind_rows(conn, tid, "created") == 1
        assert _event_kind_rows(conn, tid, "commented") == 1
        assert _task_row_count(conn) == tasks_before
        assert _task_run_count(conn) == runs_before

def test_gc_events_zero_window_sweeps_ordinary_but_retains_created(board):
    """Library ``0`` is a real sweep (everything older than now), not the CLI
    "disabled" spelling; ``created`` still survives its owning Task."""
    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
        tasks_before = _task_row_count(conn)
        runs_before = _task_run_count(conn)
        assert kb.gc_events(conn, older_than_seconds=0) > 0
        assert _event_kind_rows(conn, tid, "created") == 1
        assert _event_kind_rows(conn, tid, "commented") == 0
        assert _event_kind_rows(conn, tid, "claimed") == 0
        assert _event_kind_rows(conn, tid, "completed") == 0
        assert _task_row_count(conn) == tasks_before
        assert _task_run_count(conn) == runs_before

def test_gc_events_positive_window_retains_created_and_decomposed(board):
    """Ordinary events expire for done/archived Tasks; both structural kinds
    (``created`` origin and ``decomposed`` graph identity) remain."""
    from hermes_cli.kanban_db_graph import decompose_triage_task

    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
        root = kb.create_task(conn, title="decomposed root", triage=True)
        assert decompose_triage_task(
            conn, root, root_assignee="default", children=[{"title": "child"}]
        )
        kb.add_comment(conn, root, "probe", "ordinary history")
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='done' WHERE id=?", (root,))
            conn.execute(
                "UPDATE task_events SET created_at=0 WHERE task_id IN (?, ?)",
                (tid, root),
            )
        tasks_before = _task_row_count(conn)
        runs_before = _task_run_count(conn)

        assert kb.gc_events(conn, older_than_seconds=86400) > 0

        # The done Work Item keeps only its structural creation row.
        assert _event_kind_rows(conn, tid, "created") == 1
        assert _event_kind_rows(conn, tid, "commented") == 0
        assert _event_rows(conn, tid) == 1
        # The decomposed Root keeps both structural rows.
        assert _event_kind_rows(conn, root, "created") == 1
        assert _event_kind_rows(conn, root, "decomposed") == 1
        assert _event_kind_rows(conn, root, "commented") == 0
        assert _event_rows(conn, root) == 2
        # GC prunes event rows only: Tasks and Runs are untouched.
        assert _task_row_count(conn) == tasks_before
        assert _task_run_count(conn) == runs_before

def test_gc_events_repeated_sweep_is_idempotent(board):
    """A second sweep finds nothing eligible and leaves structural counts and
    Task/Run rows exactly as the first sweep left them."""
    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
        assert kb.gc_events(conn, older_than_seconds=0) > 0
        assert _event_kind_rows(conn, tid, "created") == 1
        snapshot = (
            _task_row_count(conn),
            _task_run_count(conn),
            _event_kind_rows(conn, tid, "created"),
            _event_kind_rows(conn, tid, "decomposed"),
            _event_rows(conn, tid),
        )

        assert kb.gc_events(conn, older_than_seconds=0) == 0

        assert snapshot == (
            _task_row_count(conn),
            _task_run_count(conn),
            _event_kind_rows(conn, tid, "created"),
            _event_kind_rows(conn, tid, "decomposed"),
            _event_rows(conn, tid),
        )

def test_gc_worker_logs_rejects_negative_window(board):
    log = _old_log_file()
    with pytest.raises(ValueError, match="older_than_seconds"):
        kb.gc_worker_logs(older_than_seconds=-86400)
    assert log.exists()

def _archived_scratch_workspace(conn) -> Path:
    tid = kb.create_task(conn, title="archived with workspace")
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET status='archived', workspace_kind='scratch' WHERE id=?",
            (tid,),
        )
    ws = kb.workspaces_root() / tid
    ws.mkdir(parents=True)
    (ws / "scratch.txt").write_text("keep me")
    return ws

@pytest.mark.parametrize(
    ("days", "expect_rc", "expect_events_expired"),
    [
        pytest.param(-1, 2, False, id="negative-refuses"),
        pytest.param(0, 0, False, id="zero-disables"),
        pytest.param(30, 0, True, id="positive-collects"),
    ],
)
def test_cmd_gc_retention_bounds(board, days, expect_rc, expect_events_expired):
    """Invalid retention must refuse before ANY sweep: the (unconditional)
    workspace collection runs first in the command body, so the archived
    scratch workspace surviving the negative case proves ordering, not just
    event/log preservation. Valid values (0 or positive) let it run.

    The ordinary comment follows the sweep toggle, but ``created`` survives
    either way; GC never touches Task or Run rows."""
    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
        ws = _archived_scratch_workspace(conn)
        tasks_before = _task_row_count(conn)
        runs_before = _task_run_count(conn)
    log = _old_log_file()
    assert kanban_ops._cmd_gc(_args(event_days=days, log_days=days)) == expect_rc
    with kbc.connect_closing() as conn:
        assert _event_kind_rows(conn, tid, "created") == 1
        ordinary = 0 if expect_events_expired else 1
        assert _event_kind_rows(conn, tid, "commented") == ordinary
        assert _event_kind_rows(conn, tid, "claimed") == ordinary
        assert _event_kind_rows(conn, tid, "completed") == ordinary
        assert _task_row_count(conn) == tasks_before
        assert _task_run_count(conn) == runs_before
    assert log.exists() is not expect_events_expired
    assert (ws / "scratch.txt").exists() is (expect_rc != 0)

@pytest.mark.parametrize(
    ("days", "expected"),
    [
        pytest.param("-1", "must be >= 0", id="negative-blocked"),
        pytest.param("0", "GC complete", id="zero-disables"),
    ],
)
def test_slash_kanban_gc_retention_bounds(board, days, expected):
    """``/kanban gc`` from a chat session uses the same argparse type as the
    shell command: ``-1`` is rejected by the parser type before ``_cmd_gc``
    runs (usage error); ``0`` parses, reaches ``_cmd_gc``, and disables the
    sweep."""
    from hermes_cli import kanban
    with kbc.connect_closing() as conn:
        tid = _done_task_with_old_event(conn)
    log = _old_log_file()
    out = kanban.run_slash(f"gc --event-retention-days {days} --log-retention-days {days}")
    assert expected in out
    with kbc.connect_closing() as conn:
        # Neither path deletes anything: the structural row and ordinary
        # history both survive.
        assert _event_kind_rows(conn, tid, "created") == 1
        assert _event_kind_rows(conn, tid, "commented") == 1
    assert log.exists()


def test_cmd_gc_never_removes_the_workspaces_root_itself(board):
    # A scratch task whose workspace_path is the managed root itself (reachable via
    # kanban_create) must never make gc wipe every other task's scratch dir.
    root = kb.workspaces_root()
    sibling = root / "t_other"
    sibling.mkdir(parents=True)
    (sibling / "work.txt").write_text("another task's scratch", encoding="utf-8")
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="archived scratch")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status='archived', workspace_kind='scratch', "
                "workspace_path=? WHERE id=?",
                (str(root), tid),
            )
    assert kanban_ops._cmd_gc(_args()) == 0
    assert (sibling / "work.txt").exists()


def _shared_scratch(conn) -> tuple[str, str, Path]:
    archived = kb.create_task(conn, title="archived sharer")
    live = kb.create_task(conn, title="live sharer")
    shared = kb.workspaces_root() / "shared-scratch"
    shared.mkdir(parents=True)
    (shared / "note.txt").write_text("still needed", encoding="utf-8")
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET status='archived', workspace_kind='scratch', "
            "workspace_path=? WHERE id=?",
            (str(shared), archived),
        )
        conn.execute(
            "UPDATE tasks SET status='ready', workspace_kind='scratch', "
            "workspace_path=? WHERE id=?",
            (str(shared), live),
        )
    return archived, live, shared


def _deferred_reasons(conn, task_id: str) -> list:
    rows = conn.execute(
        "SELECT payload FROM task_events WHERE task_id=? AND kind=? ORDER BY id",
        (task_id, "workspace_cleanup_deferred_shared"),
    ).fetchall()
    return [json.loads(r["payload"])["reason"] for r in rows]


def test_cmd_gc_keeps_a_scratch_dir_a_live_task_still_uses(board):
    from hermes_cli import kanban_db_workspace as kbw

    with kbc.connect_closing() as conn:
        archived, _live, shared = _shared_scratch(conn)
    assert kanban_ops._cmd_gc(_args()) == 0
    assert (shared / "note.txt").read_text(encoding="utf-8") == "still needed"
    with kbc.connect_closing() as conn:
        assert _deferred_reasons(conn, archived) == ["shared"]
    # Once the dir is gone there is nothing to defer: no scan, no new event.
    shutil.rmtree(shared)
    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, archived)
        assert _deferred_reasons(conn, archived) == ["shared"]


def test_cleanup_workspace_keeps_scratch_when_other_boards_cannot_be_listed(board, monkeypatch):
    """A named board's live task uses the dir; if boards cannot be listed, refuse the delete."""
    from hermes_cli import kanban_db_workspace as kbw

    kb.create_board("other")
    shared = kb.workspaces_root() / "cross-board"
    shared.mkdir(parents=True)
    (shared / "note.txt").write_text("still needed", encoding="utf-8")
    with kbc.connect_closing() as conn:
        archived = kb.create_task(conn, title="archived on default")
    with kbc.connect_closing(board="other") as other:
        live = kb.create_task(other, title="live on other")
    for board_slug, task_id, status in ((None, archived, "archived"), ("other", live, "ready")):
        with kbc.connect_closing(board=board_slug) as conn, kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status=?, workspace_kind='scratch', workspace_path=? WHERE id=?",
                (status, str(shared), task_id),
            )
    # Real scan: the other board's live task holds the dir, under a different
    # id and under the very id being cleaned up (boards mint ids independently).
    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, archived)
    assert (shared / "note.txt").exists()
    with kbc.connect_closing(board="other") as other, kb.write_txn(other):
        other.execute("UPDATE tasks SET id=? WHERE id=?", (archived, live))
    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, archived)
        assert _deferred_reasons(conn, archived) == ["shared", "shared"]
    assert (shared / "note.txt").exists()

    # Nobody holds it any more, but the boards cannot be listed: fail closed.
    with kbc.connect_closing(board="other") as other, kb.write_txn(other):
        other.execute("UPDATE tasks SET status='done' WHERE id=?", (archived,))
    real_iterdir = Path.iterdir

    def iterdir(self):
        if self.name == "boards":
            raise PermissionError("boards dir unreadable")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    with kbc.connect_closing() as conn:
        kbw._cleanup_workspace(conn, archived)
        assert _deferred_reasons(conn, archived) == ["shared", "shared", "unknown"]
    assert (shared / "note.txt").read_text(encoding="utf-8") == "still needed"
