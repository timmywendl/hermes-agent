"""Per-task worktree isolation for decompose siblings.

Decompose children used to inherit the root's literal ``workspace_path``,
so every sibling of a worktree-kind root pointed at the SAME checkout —
and ``_resolve_worktree_workspace``'s existing-checkout shortcut reused it
on whatever branch was there, letting sibling workers run concurrently in
one directory on one branch (cross-task provenance corruption, no lock).

Two-part fix under test:
- ``decompose_triage_task`` leaves worktree children's ``workspace_path``
  unset so each child materializes its own ``<repo>/.worktrees/<child-id>``.
- ``_resolve_worktree_workspace`` refuses an occupied wrong-branch checkout;
  trusted native admission binds central paths to the exact source and claim.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_graph import decompose_triage_task
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_workspace as kbw


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME with an empty kanban DB."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git", "-C", str(cwd),
            "-c", "user.name=Test User",
            "-c", "user.email=test@example.com",
            "-c", "commit.gpgsign=false",
            *args,
        ],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)],
        check=True, capture_output=True, text=True,
    )
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "init")
    return repo


def _add_worktree(repo: Path, target: Path, branch: str) -> Path:
    _git(repo, "worktree", "add", str(target), "-b", branch, "HEAD")
    return target


def test_decompose_worktree_children_get_own_workspace(kanban_home):
    with kbc.connect() as conn:
        root = kb.create_task(conn, title="build the feature", triage=True)
        conn.execute(
            "UPDATE tasks SET workspace_kind='worktree', "
            "workspace_path='/repo/.worktrees/root' WHERE id = ?",
            (root,),
        )
        conn.commit()

        child_ids = decompose_triage_task(
            conn,
            root,
            root_assignee="orchestrator",
            children=[
                {"title": "spec it", "assignee": "alice", "parents": []},
                {"title": "implement it", "assignee": "bob", "parents": [0]},
            ],
            author="decomposer",
        )
        assert child_ids is not None and len(child_ids) == 2

        for cid in child_ids:
            row = conn.execute(
                "SELECT workspace_kind, workspace_path FROM tasks WHERE id = ?",
                (cid,),
            ).fetchone()
            assert row["workspace_kind"] == "worktree"
            # Each child resolves its own <repo>/.worktrees/<child-id> at
            # dispatch; the root's literal path must never be shared.
            assert row["workspace_path"] is None




def test_resolve_worktree_refuses_wrong_branch_without_fallback(kanban_home: Path, tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    occupied = _add_worktree(repo, repo / ".worktrees" / "sibling", "wt/sibling")

    with kbc.connect() as conn:
        tid = kb.create_task(
            conn,
            title="second sibling",
            workspace_kind="worktree",
            workspace_path=str(occupied),  # inherited shared/stale path
        )
        task = kb.get_task(conn, tid)
        assert task is not None

    with pytest.raises(ValueError, match="wrong branch"):
        kbw._resolve_worktree_workspace(task)
    assert not (repo / ".worktrees" / tid).exists()
    # The sibling's checkout is untouched, still on its own branch.
    assert (occupied / "README.md").exists()
    head = subprocess.run(
        ["git", "-C", str(occupied), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert head == "wt/sibling"


@pytest.fixture
def admission(tmp_path: Path) -> dict[str, Any]:
    repo = _make_repo(tmp_path).resolve()
    _git(repo, "remote", "add", "origin", "https://github.com/fixture/project.git")
    return {
        "version": 1, "repo": "fixture/project", "source_root": str(repo),
        "common_dir": _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"),
        "remote_url": "https://github.com/fixture/project.git",
        "base_commit": _git(repo, "rev-parse", "HEAD"), "branch_name": "stage3/fixture",
        "workspace_root": str(tmp_path.resolve()),
        "workspace_path": str(tmp_path.resolve() / "worktrees" / "mission-fixture-dev-01"),
    }


def _admitted_task(conn: sqlite3.Connection, admission: dict[str, Any]) -> kb.Task:
    tid = kb.create_task(
        conn, title="admitted work", workspace_kind="worktree", project_id="",
        workspace_path=admission["workspace_path"], branch_name=admission["branch_name"],
        workspace_admission=admission,
    )
    task = kb.claim_task(conn, tid)
    assert task is not None
    return task


def test_central_exact_repo_base_branch_task_run_binding(kanban_home: Path, admission: dict[str, Any]) -> None:
    repo = Path(admission["source_root"])
    (repo / "later.txt").write_text("new source HEAD\n")
    _git(repo, "add", "later.txt")
    _git(repo, "commit", "-m", "advance source after admitted base")
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        target = kbw.resolve_workspace(task, conn=conn)
        assert target == Path(admission["workspace_path"])
        assert _git(target, "rev-parse", "HEAD") == admission["base_commit"]
        assert _git(target, "branch", "--show-current") == admission["branch_name"]
        assert _git(target, "rev-parse", "--path-format=absolute", "--git-common-dir") == admission["common_dir"]
        row = conn.execute("SELECT metadata FROM task_runs WHERE id=?", (task.current_run_id,)).fetchone()
        binding = json.loads(row["metadata"])["workspace_binding"]
        assert (binding["task_id"], binding["run_id"], binding["claim_lock"]) == (
            task.id, task.current_run_id, task.claim_lock,
        )
        assert binding["admission"]["task_id"] == task.id
        assert binding["admission"]["board_db"] == str(kb.kanban_db_path().resolve())
        # Current binding can be read back without creating another checkout.
        assert kbw.resolve_workspace(task, conn=conn) == target
        assert not (repo / ".worktrees").exists()
        assert kb.complete_task(conn, task.id, summary="offline complete", expected_run_id=task.current_run_id,
                                metadata={"workspace_binding": {"forged": True}, "artifact": "receipt"})
        stored = json.loads(conn.execute("SELECT metadata FROM task_runs WHERE id=?", (task.current_run_id,)).fetchone()[0])
        assert stored["workspace_binding"] == binding
        assert stored["artifact"] == "receipt"
        assert target.is_dir(), "admitted trees remain retained pending cleanup qualification"


@pytest.mark.parametrize("field,value", [
    ("version", True), ("base_commit", "HEAD"), ("repo", "other/project"),
    ("common_dir", "/missing/.git"), ("remote_url", "https://github.com/other/project.git"),
    ("workspace_path", "relative"), ("source_root", "/missing/repository"),
])
def test_admission_identity_conflicts_fail_before_creation(
    kanban_home: Path, admission: dict[str, Any], field: str, value: object,
) -> None:
    admission[field] = value
    with kbc.connect_closing() as conn:
        with pytest.raises(ValueError):
            _admitted_task(conn, admission)
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0


@pytest.mark.parametrize("occupant", ["plain", "same_branch", "wrong_repo"])
def test_central_occupied_checkout_is_never_adopted(
    kanban_home: Path, admission: dict[str, Any], tmp_path: Path, occupant: str,
) -> None:
    target = Path(admission["workspace_path"])
    if occupant == "plain":
        target.mkdir(parents=True)
        (target / "evidence.txt").write_text("keep")
    else:
        source = Path(admission["source_root"])
        if occupant == "wrong_repo":
            other = tmp_path / "other"
            other.mkdir()
            source = _make_repo(other)
        _add_worktree(source, target, admission["branch_name"])
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        with pytest.raises(ValueError, match="occupied"):
            kbw.resolve_workspace(task, conn=conn)
        assert conn.execute("SELECT COUNT(*) FROM task_events WHERE kind='workspace_bound'").fetchone()[0] == 0
    assert target.is_dir()


def test_bound_checkout_wrong_branch_and_wrong_repo_fail_closed(
    kanban_home: Path, admission: dict[str, Any], tmp_path: Path,
) -> None:
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        target = kbw.resolve_workspace(task, conn=conn)
        _git(target, "checkout", "-b", "wrong-branch")
        with pytest.raises(ValueError, match="repo/common-dir/branch"):
            kbw.resolve_workspace(task, conn=conn)
        _git(Path(admission["source_root"]), "worktree", "remove", str(target))
        other = tmp_path / "other"
        other.mkdir()
        wrong_repo = _make_repo(other)
        # Same commit/branch, different common-dir: ancestry cannot mask repo identity.
        _git(wrong_repo, "fetch", admission["source_root"], admission["base_commit"])
        _git(wrong_repo, "reset", "--hard", admission["base_commit"])
        _add_worktree(wrong_repo, target, admission["branch_name"])
        with pytest.raises(ValueError, match="repo/common-dir/branch"):
            kbw.resolve_workspace(task, conn=conn)
        assert not (Path(admission["source_root"]) / ".worktrees").exists()


def test_another_task_checkout_even_terminal_is_refused(kanban_home: Path, admission: dict[str, Any]) -> None:
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        target = kbw.resolve_workspace(task, conn=conn)
        other = kb.create_task(conn, title="other", workspace_kind="dir", project_id="",
                               workspace_path=str(target))
        assert kb.archive_task(conn, other)
        with pytest.raises(ValueError, match="another Task"):
            kbw.resolve_workspace(task, conn=conn)


def test_existing_branch_must_match_exact_admitted_base(kanban_home: Path, admission: dict[str, Any]) -> None:
    source = Path(admission["source_root"])
    (source / "later").write_text("later")
    _git(source, "add", "later")
    _git(source, "commit", "-m", "later")
    _git(source, "branch", admission["branch_name"])
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        with pytest.raises(ValueError, match="exact base"):
            kbw.resolve_workspace(task, conn=conn)
    assert not Path(admission["workspace_path"]).exists()


@pytest.mark.parametrize("drift", ["current_run_id", "claim_lock", "branch_name"])
def test_current_task_run_claim_drift_refused(
    kanban_home: Path, admission: dict[str, Any], drift: str,
) -> None:
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        with kbc.write_txn(conn):
            conn.execute(f"UPDATE tasks SET {drift} = NULL WHERE id = ?", (task.id,))
        with pytest.raises(ValueError, match="exact current Task/Run/claim"):
            kbw.resolve_workspace(task, conn=conn)
    assert not Path(admission["workspace_path"]).exists()


def test_task_prose_cannot_authorize_a_central_checkout(kanban_home: Path, admission: dict[str, Any]) -> None:
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="untrusted", body=json.dumps({"workspace_admission": admission}),
                             workspace_kind="worktree", workspace_path=admission["workspace_path"],
                             branch_name=admission["branch_name"], project_id="")
        task = kb.claim_task(conn, tid)
        assert task is not None
        with pytest.raises(ValueError, match="trusted source admission"):
            kbw.resolve_workspace(task, conn=conn)
        with pytest.raises(ValueError, match="Board connection"):
            kbw.resolve_workspace(task)


@pytest.mark.parametrize("reason", ["OPEN", "UNMERGED", "UNKNOWN", "ACTIVE", "IGNORED", "UNTRACKED"])
def test_admitted_terminal_and_gc_retain_unqualified_checkout(
    kanban_home: Path, admission: dict[str, Any], reason: str,
) -> None:
    from argparse import Namespace
    from hermes_cli import kanban_ops
    process = None
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        target = kbw.resolve_workspace(task, conn=conn)
        if reason == "IGNORED":
            exclude = Path(admission["common_dir"]) / "info" / "exclude"
            exclude.write_text("retained-evidence\n")
            (target / "retained-evidence").write_text("keep ignored evidence")
        if reason == "UNTRACKED":
            (target / "retained-evidence").write_text("keep untracked evidence")
        if reason == "ACTIVE":
            process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"],
                                       cwd=target, stdin=subprocess.PIPE)
        try:
            assert kb.complete_task(conn, task.id, summary="terminal does not imply cleanup",
                                    expected_run_id=task.current_run_id,
                                    metadata={"publication_state": reason})
            assert target.is_dir()
            assert kb.archive_task(conn, task.id)
            assert kanban_ops._cmd_gc(Namespace(event_retention_days=0, log_retention_days=0)) == 0
            assert target.is_dir()
            assert _git(target, "branch", "--show-current") == admission["branch_name"]
            if reason in {"IGNORED", "UNTRACKED"}:
                assert (target / "retained-evidence").is_file()
            if process is not None:
                assert process.poll() is None
        finally:
            if process is not None:
                process.terminate()
                process.communicate(timeout=10)


def test_original_task_board_and_duplicate_admission_refused(kanban_home: Path, admission: dict[str, Any]) -> None:
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        original = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='created'",
                                (task.id,)).fetchone()[0]
        for field in ("task_id", "board_db"):
            payload = json.loads(original)
            payload["workspace_admission"][field] = "wrong"
            with kbc.write_txn(conn):
                conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='created'",
                             (json.dumps(payload), task.id))
            with pytest.raises(ValueError, match="another Task/Board"):
                kbw.resolve_workspace(task, conn=conn)
        with kbc.write_txn(conn):
            conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='created'", (original, task.id))
            kb._append_event(conn, task.id, "created", json.loads(original))
        with pytest.raises(ValueError, match="ambiguous"):
            kbw.resolve_workspace(task, conn=conn)
    assert not Path(admission["workspace_path"]).exists()


def test_post_creation_claim_drift_rolls_back_binding_and_preserves_checkout(
    kanban_home: Path, admission: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_git = kbw._required_git
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        def drift_after_add(path: Path, *args: str) -> str:
            output = real_git(path, *args)
            if args[:2] == ("worktree", "add"):
                conn.execute("UPDATE tasks SET claim_lock='drift' WHERE id=?", (task.id,))
            return output
        monkeypatch.setattr(kbw, "_required_git", drift_after_add)
        with pytest.raises(ValueError, match="exact current Task/Run/claim"):
            kbw.resolve_workspace(task, conn=conn)
        assert Path(admission["workspace_path"]).is_dir()
        assert conn.execute("SELECT COUNT(*) FROM task_events WHERE kind='workspace_bound'").fetchone()[0] == 0
        current = kb.get_task(conn, task.id)
        assert current is not None and current.claim_lock == task.claim_lock
        with pytest.raises(ValueError, match="occupied"):
            kbw.resolve_workspace(task, conn=conn)


def test_binding_survives_gc_and_free_metadata_is_not_ownership(kanban_home: Path, admission: dict[str, Any]) -> None:
    with kbc.connect_closing() as conn:
        task = _admitted_task(conn, admission)
        target = kbw.resolve_workspace(task, conn=conn)
        with kbc.write_txn(conn):
            conn.execute("UPDATE task_events SET created_at=1 WHERE task_id=?", (task.id,))
        kb.gc_events(conn, older_than_seconds=1)
        assert kbw.resolve_workspace(task, conn=conn) == target
        with kbc.write_txn(conn):
            conn.execute("DELETE FROM task_events WHERE task_id=? AND kind='workspace_bound'", (task.id,))
        with pytest.raises(ValueError, match="occupied"):
            kbw.resolve_workspace(task, conn=conn)






@pytest.mark.parametrize("occupied", [False, True])
def test_dispatch_central_admission_binds_before_inert_spawn(
    kanban_home: Path, admission: dict[str, Any], all_assignees_spawnable: None, occupied: bool,
) -> None:
    from hermes_cli import kanban_db_dispatch as kbd
    repo, target = Path(admission["source_root"]), Path(admission["workspace_path"])
    spawns: list[int | None] = []
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="offline dispatch", assignee="alice", project_id="",
                             workspace_kind="worktree", workspace_path=str(target),
                             branch_name=admission["branch_name"], workspace_admission=admission)
        if occupied:
            target.mkdir(parents=True)
            (target / "evidence").write_text("retain")
        def inert_spawn(task: kb.Task, workspace: str, board: str | None = None) -> None:
            # This is the existing real dispatch seam, with no subprocess/Worker.
            row = conn.execute("SELECT metadata FROM task_runs WHERE id=?", (task.current_run_id,)).fetchone()
            binding = json.loads(row["metadata"])["workspace_binding"]
            assert binding["task_id"] == tid
            assert binding["run_id"] == task.current_run_id
            assert binding["claim_lock"] == task.claim_lock
            assert workspace == str(target)
            stored = kb.get_task(conn, tid)
            assert stored is not None
            assert stored.workspace_path == workspace
            assert stored.branch_name == admission["branch_name"]
            spawns.append(task.current_run_id)
        result = kbd.dispatch_once(conn, spawn_fn=inert_spawn, reconcile_orphans=False)
        assert len(spawns) == (0 if occupied else 1)
        assert len(result.spawned) == len(spawns)
        if occupied:
            assert (target / "evidence").read_text() == "retain"
        assert not (repo / ".worktrees").exists()


def test_completion_metadata_cannot_inject_native_workspace_binding(kanban_home: Path) -> None:
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="unbound task")
        task = kb.claim_task(conn, tid)
        assert task is not None
        assert kb.complete_task(conn, tid, summary="done", expected_run_id=task.current_run_id,
                                metadata={"workspace_binding": {"forged": True}, "receipt": "kept"})
        stored = json.loads(conn.execute("SELECT metadata FROM task_runs WHERE id=?", (task.current_run_id,)).fetchone()[0])
        assert stored == {"receipt": "kept"}


def test_creation_contract_snapshot_survives_later_publication_binding(kanban_home: Path) -> None:
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="contract custody", completion_contract="fixture/project")
        original = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='created'", (tid,)).fetchone()[0]
        assert json.loads(original)["completion_contract"] == "fixture/project"
        with kbc.write_txn(conn):
            conn.execute("UPDATE tasks SET completion_contract=? WHERE id=?", ("https://github.com/fixture/project/pull/1", tid))
            conn.execute("UPDATE task_events SET created_at=1 WHERE task_id=?", (tid,))
        kb.gc_events(conn, older_than_seconds=1)
        assert conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='created'", (tid,)).fetchone()[0] == original


