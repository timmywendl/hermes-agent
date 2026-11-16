"""Graph identity is completion history, not prerequisite edges."""
import json
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_graph import decompose_triage_task
from hermes_cli import kanban_db_connect as kbc


def test_completed_decomposition_survives_retriage(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    with kbc.connect_closing() as conn:
        prerequisite = kb.create_task(conn, title="prerequisite", tenant="business-a")
        root = kb.create_task(conn, title="root", triage=True, tenant="business-a", parents=[prerequisite])
        downstream = kb.create_task(conn, title="downstream", parents=[root], tenant="business-a")
        specs = [{"title": "work", "assignee": "default"}]
        first = decompose_triage_task(conn, root, root_assignee="default", children=specs)
        assert first and kb.get_task(conn, first[0]).tenant == "business-a"
        assert conn.execute("SELECT 1 FROM task_links WHERE parent_id=? AND child_id=?", (prerequisite, root)).fetchone()
        assert conn.execute("SELECT 1 FROM task_links WHERE parent_id=? AND child_id=?", (root, downstream)).fetchone()
        # Ordinary history must still age out; only completion identity is retained.
        kb.add_comment(conn, root, "probe", "ordinary history")
        # Retention must not erase the identity of a completed fan-out.
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='done' WHERE id=?", (root,))
            conn.execute("UPDATE task_events SET created_at=0 WHERE task_id=?", (root,))
        assert kb.gc_events(conn, older_than_seconds=1) > 0
        event_counts = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT kind, count(*) FROM task_events WHERE task_id=? GROUP BY kind", (root,)
            )
        }
        assert event_counts.get("commented", 0) == 0
        assert event_counts.get("created", 0) == 1
        assert event_counts.get("decomposed", 0) == 1
        task_snapshot = [tuple(row) for row in conn.execute("SELECT * FROM tasks ORDER BY id")]
        run_snapshot = [tuple(row) for row in conn.execute("SELECT * FROM task_runs ORDER BY id")]
        assert run_snapshot == []
        assert kb.gc_events(conn, older_than_seconds=1) == 0
        event_counts = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT kind, count(*) FROM task_events WHERE task_id=? GROUP BY kind", (root,)
            )
        }
        assert event_counts.get("created", 0) == 1
        assert event_counts.get("decomposed", 0) == 1
        assert [tuple(row) for row in conn.execute("SELECT * FROM tasks ORDER BY id")] == task_snapshot
        assert [tuple(row) for row in conn.execute("SELECT * FROM task_runs ORDER BY id")] == run_snapshot
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='triage' WHERE id=?", (root,))
        before = list(conn.execute("SELECT id FROM tasks ORDER BY id"))
        assert decompose_triage_task(conn, root, root_assignee="default", children=specs) is None
        assert list(conn.execute("SELECT id FROM tasks ORDER BY id")) == before
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='decomposed'", (root,)).fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_parent_tenant_is_inherited_at_creation_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.delenv("HERMES_TENANT", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    from tools.kanban_tools import _handle_create
    with kbc.connect_closing() as conn:
        unscoped = kb.create_task(conn, title="unscoped")
        parent = kb.create_task(conn, title="parent", tenant="business-a")
        for explicit, expected in [(None, "business-a"), ("business-b", "business-b")]:
            child = kb.create_task(conn, title="child", parents=[unscoped, parent], tenant=explicit)
            assert kb.get_task(conn, child).tenant == expected
        result = json.loads(_handle_create({"title": "tool child", "assignee": "default", "parents": [parent]}))
        assert result["ok"]
        assert kb.get_task(conn, result["task_id"]).tenant == "business-a"
        with pytest.raises(ValueError, match="unknown parent"):
            kb.create_task(conn, title="invalid", parents=["missing"])
        assert kb.get_task(conn, unscoped).tenant is None
