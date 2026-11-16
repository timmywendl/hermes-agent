"""All explicit creator paths share durable lineage without graph coupling."""
import json
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


@pytest.mark.parametrize("surface", ["db", "builtin", "cli"])
def test_creator_origin_survives_without_dependency_parent(tmp_path, monkeypatch, capsys, surface):
    from hermes_cli import kanban_db as kb, kanban_db_connect as kbc, kanban_db_notify as kn
    from hermes_cli.kanban_db_graph import decompose_triage_task

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    kb.init_db()
    with kbc.connect_closing() as conn:
        owner = kb.create_task(conn, title="owner", session_id="durable", triage=True)
        kn.add_notify_sub(conn, task_id=owner, platform="telegram", chat_id="chat",
                         delivery_mode="wake", notifier_profile="default")
        if surface == "builtin":
            tid = decompose_triage_task(conn, owner, root_assignee="default",
                                       children=[{"title": "child"}])[0]
        elif surface == "db":
            tid = kb.create_task(conn, title="child", creator_task_id=owner)
        else:
            import json
            import argparse
            from hermes_cli.kanban import kanban_command
            from hermes_cli.kanban_parser import build_parser
            parser = argparse.ArgumentParser()
            build_parser(parser.add_subparsers())
            monkeypatch.setenv("HERMES_KANBAN_TASK", owner)
            assert kanban_command(parser.parse_args(["kanban", "create", "child", "--json"])) == 0
            tid = json.loads(capsys.readouterr().out)["id"]
        assert kb.get_task(conn, tid).session_id == "durable"
        subs = kn.list_notify_subs(conn, tid)
        assert len(subs) == 1 and subs[0]["delivery_mode"] == "wake"
        assert not conn.execute("SELECT 1 FROM task_links WHERE child_id = ?", (tid,)).fetchone()
        # No ambient identity guessing in the storage API.
        plain = kb.create_task(conn, title="plain", session_id="explicit")
        assert kb.get_task(conn, plain).session_id == "explicit"
        assert not kn.list_notify_subs(conn, plain)


# --- Task-lifetime retention of the structural ``created`` origin ---------
#
# ``created`` (like ``decomposed``) records lineage, not ordinary event
# history, so it must outlive age-based GC for as long as its owning Task
# exists. Explicit Task deletion is the only boundary: the retained row and the
# recorded ``creator_task_id`` disappear with the Task itself.

CREATED_PAYLOAD_KEYS = {
    "assignee", "status", "parents", "creator_task_id", "tenant",
    "workspace_kind", "workspace_path", "branch_name", "project_id",
    "skills", "goal_mode", "model_override", "provider_override",
}


@pytest.fixture
def conn(tmp_path, monkeypatch):
    """Disposable HERMES_HOME board, one connection per test."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for name in (
        "HERMES_KANBAN_HOME", "HERMES_KANBAN_DB", "HERMES_KANBAN_TASK",
        "HERMES_KANBAN_WORKSPACES_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)
    kb.init_db()
    with kbc.connect_closing() as connection:
        yield connection


def _created_event(conn, task_id):
    row = conn.execute(
        "SELECT * FROM task_events WHERE task_id = ? AND kind = 'created' "
        "ORDER BY id DESC LIMIT 1",
        (task_id,),
    ).fetchone()
    assert row is not None, f"created event missing for {task_id}"
    return row


def _created_payload(conn, task_id):
    return json.loads(_created_event(conn, task_id)["payload"])


def _assert_created_origin(conn, task_id, creator_task_id):
    payload = _created_payload(conn, task_id)
    assert set(payload) == CREATED_PAYLOAD_KEYS
    assert payload["creator_task_id"] == creator_task_id
    assert payload["status"] == "ready"
    assert payload["parents"] == []
    return payload


def _age_events(conn, task_id):
    with kb.write_txn(conn):
        conn.execute("UPDATE task_events SET created_at = 0 WHERE task_id = ?", (task_id,))


def _event_counts(conn, task_id):
    return {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT kind, count(*) FROM task_events WHERE task_id = ? GROUP BY kind",
            (task_id,),
        )
    }


def _completed_work_item(conn, *, creator_task_id):
    """A Work Item with one closed Run: creator lineage but no dependency edge."""
    task_id = kb.create_task(
        conn, title="work item", creator_task_id=creator_task_id, parents=(),
    )
    assert kb.claim_task(conn, task_id) is not None
    run_id = kb.get_task(conn, task_id).current_run_id
    assert run_id is not None
    assert kb.complete_task(conn, task_id, result="finished", expected_run_id=run_id)
    return task_id


def test_created_origin_survives_done_gc(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    _age_events(conn, item)

    assert kb.gc_events(conn, older_than_seconds=1) > 0

    assert kb.get_task(conn, item).status == "done"
    _assert_created_origin(conn, item, root)
    assert len(kb.list_runs(conn, item)) == 1


def test_created_origin_survives_archived_gc(conn):
    root = kb.create_task(conn, title="root")
    item = kb.create_task(conn, title="work item", creator_task_id=root, parents=())
    assert kb.archive_task(conn, item)
    _age_events(conn, item)

    assert kb.gc_events(conn, older_than_seconds=1) > 0

    assert kb.get_task(conn, item).status == "archived"
    _assert_created_origin(conn, item, root)


def test_created_origin_survives_repeated_gc(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    kb.add_comment(conn, item, "probe", "ordinary history")
    _age_events(conn, item)

    assert kb.gc_events(conn, older_than_seconds=1) > 0

    created_before = tuple(_created_event(conn, item))
    task_before = tuple(conn.execute("SELECT * FROM tasks WHERE id = ?", (item,)).fetchone())
    runs_before = [tuple(r) for r in conn.execute(
        "SELECT * FROM task_runs WHERE task_id = ? ORDER BY id", (item,)
    )]

    assert kb.gc_events(conn, older_than_seconds=1) == 0

    assert tuple(_created_event(conn, item)) == created_before
    assert tuple(conn.execute("SELECT * FROM tasks WHERE id = ?", (item,)).fetchone()) == task_before
    assert [tuple(r) for r in conn.execute(
        "SELECT * FROM task_runs WHERE task_id = ? ORDER BY id", (item,)
    )] == runs_before
    _assert_created_origin(conn, item, root)


def test_created_origin_full_payload_survives_first_positive_gc(conn, tmp_path):
    """The complete created row/payload survives the FIRST positive-window sweep.

    The repeated-GC snapshot above is taken after the first sweep, so it cannot
    prove that sweep left every populated metadata value byte-for-byte intact.
    This fixture carries representative non-default metadata, snapshots the whole
    event row and decoded payload *before* the first GC, and compares both after.
    """
    root = kb.create_task(conn, title="root")
    workspace = tmp_path / "creator-origin-worktree"
    workspace.mkdir()
    item = kb.create_task(
        conn,
        title="metadata-rich work item",
        creator_task_id=root,
        parents=(),
        assignee="Retention-Probe",  # stored canonical lowercase
        tenant="tenant-probe",
        workspace_kind="worktree",
        workspace_path=str(workspace),
        branch_name="wt/retention-probe",
        skills=("retention-probe-skill-a", "retention-probe-skill-b"),
        goal_mode=True,
        model_override="probe-model",
        provider_override="probe-provider",
    )
    assert kb.claim_task(conn, item) is not None
    run_id = kb.get_task(conn, item).current_run_id
    assert run_id is not None
    assert kb.complete_task(conn, item, result="finished", expected_run_id=run_id)
    kb.add_comment(conn, item, "probe", "ordinary history")
    _age_events(conn, item)

    # Before the first sweep: the whole row (not a key set) and decoded payload.
    created_row = _created_event(conn, item)
    created_before = tuple(created_row)
    payload_before = _created_payload(conn, item)
    # The row was inside the sweep window (aging set every event's created_at=0).
    assert created_row["created_at"] == 0

    # The fixture must really exercise representative non-default metadata,
    # not merely compare two equally empty payloads.
    assert set(payload_before) == CREATED_PAYLOAD_KEYS
    assert payload_before["creator_task_id"] == root
    assert payload_before["status"] == "ready"
    assert payload_before["parents"] == []
    assert payload_before["project_id"] is None
    assert payload_before["assignee"] == "retention-probe"
    assert payload_before["tenant"] == "tenant-probe"
    assert payload_before["workspace_kind"] == "worktree"
    assert payload_before["workspace_path"] == str(workspace)
    assert payload_before["branch_name"] == "wt/retention-probe"
    assert payload_before["skills"] == [
        "retention-probe-skill-a",
        "retention-probe-skill-b",
    ]
    assert payload_before["goal_mode"] is True
    assert payload_before["model_override"] == "probe-model"
    assert payload_before["provider_override"] == "probe-provider"
    task = kb.get_task(conn, item)
    assert (
        task.assignee,
        task.tenant,
        task.workspace_kind,
        task.workspace_path,
        task.branch_name,
        task.skills,
        task.goal_mode,
        task.model_override,
        task.provider_override,
    ) == (
        "retention-probe",
        "tenant-probe",
        "worktree",
        str(workspace),
        "wt/retention-probe",
        ["retention-probe-skill-a", "retention-probe-skill-b"],
        True,
        "probe-model",
        "probe-provider",
    )

    ordinary_before = _event_counts(conn, item)
    assert {"created", "claimed", "completed", "commented"} <= set(ordinary_before)
    ordinary = sum(
        count for kind, count in ordinary_before.items() if kind not in ("created", "decomposed")
    )
    assert ordinary > 0

    # First positive-window sweep: it really prunes ordinary history on this
    # done Task, so the created row below is retained rather than out of scope.
    assert kb.gc_events(conn, older_than_seconds=1) == ordinary

    assert tuple(_created_event(conn, item)) == created_before
    assert _created_payload(conn, item) == payload_before
    assert _event_counts(conn, item) == {"created": 1}


def test_created_origin_survives_zero_window(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    kb.add_comment(conn, item, "probe", "ordinary history")
    _age_events(conn, item)

    # Library zero is a live sweep (the CLI maps 0 to "disabled"): ordinary
    # history still ages out, but structural lineage does not.
    assert kb.gc_events(conn, older_than_seconds=0) > 0

    counts = _event_counts(conn, item)
    assert counts.get("created") == 1
    assert counts.get("claimed", 0) == 0
    assert counts.get("completed", 0) == 0
    assert counts.get("commented", 0) == 0
    _assert_created_origin(conn, item, root)


def test_ordinary_events_expire_while_created_remains(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    kb.add_comment(conn, item, "probe", "ordinary history")
    _age_events(conn, item)

    before = _event_counts(conn, item)
    assert {"created", "claimed", "completed", "commented"} <= set(before)
    ordinary = sum(
        count for kind, count in before.items() if kind not in ("created", "decomposed")
    )
    assert ordinary > 0

    assert kb.gc_events(conn, older_than_seconds=1) == ordinary

    assert _event_counts(conn, item) == {"created": 1}


def test_task_and_run_rows_unchanged_by_gc(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    kb.add_comment(conn, item, "probe", "ordinary history")
    _age_events(conn, item)
    task_snapshot = [tuple(r) for r in conn.execute("SELECT * FROM tasks ORDER BY id")]
    run_snapshot = [tuple(r) for r in conn.execute("SELECT * FROM task_runs ORDER BY id")]
    assert run_snapshot, "fixture needs one closed Run"

    assert kb.gc_events(conn, older_than_seconds=1) > 0

    assert [tuple(r) for r in conn.execute("SELECT * FROM tasks ORDER BY id")] == task_snapshot
    assert [tuple(r) for r in conn.execute("SELECT * FROM task_runs ORDER BY id")] == run_snapshot


def test_explicit_work_item_delete_removes_created(conn):
    root = kb.create_task(conn, title="root")
    item = _completed_work_item(conn, creator_task_id=root)
    _age_events(conn, item)
    assert _event_counts(conn, item).get("created") == 1

    assert kb.delete_task(conn, item) is True

    assert kb.get_task(conn, item) is None
    assert _event_counts(conn, item) == {}
    assert conn.execute(
        "SELECT count(*) FROM task_runs WHERE task_id = ?", (item,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM task_links WHERE parent_id = ? OR child_id = ?", (item, item)
    ).fetchone()[0] == 0
    # No retained tombstone on any surviving Task records the deletion.
    assert conn.execute(
        "SELECT count(*) FROM task_events WHERE payload LIKE ?", (f"%{item}%",)
    ).fetchone()[0] == 0
    assert [row[0] for row in conn.execute("SELECT id FROM tasks ORDER BY id")] == [root]


def test_root_delete_leaves_dangling_creator_id(conn):
    root = kb.create_task(conn, title="root")
    item = kb.create_task(conn, title="work item", creator_task_id=root, parents=())
    _assert_created_origin(conn, item, root)

    assert kb.delete_task(conn, root) is True

    assert kb.get_task(conn, root) is None
    # The surviving child keeps the deleted id: lineage is UNKNOWN, not empty
    # and not silently rebound to another Root that happened to appear later.
    assert _created_payload(conn, item)["creator_task_id"] == root
    other_root = kb.create_task(conn, title="unrelated root")
    payload = _created_payload(conn, item)
    assert payload["creator_task_id"] == root
    assert payload["creator_task_id"] != other_root
    assert conn.execute(
        "SELECT count(*) FROM task_links WHERE parent_id = ? OR child_id = ?", (item, item)
    ).fetchone()[0] == 0


def test_creator_origin_has_no_dependency_edge(conn):
    root = kb.create_task(conn, title="root")
    item = kb.create_task(conn, title="work item", creator_task_id=root, parents=())

    _assert_created_origin(conn, item, root)
    # Creator lineage neither links nor gates: the item stays ready while the
    # creator is still open.
    assert kb.get_task(conn, item).status == "ready"
    assert conn.execute(
        "SELECT count(*) FROM task_links WHERE parent_id = ? OR child_id = ?", (item, item)
    ).fetchone()[0] == 0
