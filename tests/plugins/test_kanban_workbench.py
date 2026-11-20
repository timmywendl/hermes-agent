"""Workbench projects canonical board history without execution or read mutations."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import projects_db as pdb
from plugins.kanban.dashboard import workbench_api as api
from plugins.kanban.dashboard import workbench_delivery as delivery

PREFIX = "/api/plugins/kanban/workbench"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_BOARD", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    repo = tmp_path / "widget-repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    with pdb.connect_closing() as conn:
        project_id = pdb.create_project(conn, name="Widget", description="A useful widget", primary_path=str(repo))
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/kanban")
    return TestClient(app), home, project_id


def _confirm(project_id, request_id="first"):
    return {"request_id": request_id, "project_id": project_id, "plan": {"title": "Ship widget", "body": "Users can create widgets", "work_items": [{"title": "Implement widget", "body": "Build and verify creation"}, {"title": "Review widget", "body": "Check the acceptance criteria"}], "assumptions": ["Current API is suitable"], "model": "test-provider", "status": "preview"}}


def _disk(home):
    # SQLite's read-only WAL reader may create empty coordination sidecars.
    # Compare durable bytes, including every WAL containing database changes.
    return {str(p.relative_to(home)): p.read_bytes() for p in home.rglob("*")
            if p.is_file() and not p.name.endswith("-shm")
            and not (p.name.endswith("-wal") and p.stat().st_size == 0)}


def test_confirm_is_atomic_inert_and_recovers_exact_replays(setup, monkeypatch):
    client, home, project_id = setup
    request = _confirm(project_id)
    original = kb.create_task
    calls = 0

    def fail_child(conn, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ValueError("injected failure")
        return original(conn, **kwargs)

    monkeypatch.setattr(kb, "create_task", fail_child)
    with pytest.raises(ValueError, match="injected"):
        client.post(PREFIX + "/confirm", json=request)
    with kbc.connect_closing() as conn:
        assert conn.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM task_events").fetchone()[0] == 0
    monkeypatch.setattr(kb, "create_task", original)
    confirmed = client.post(PREFIX + "/confirm", json=request)
    assert confirmed.status_code == 200, confirmed.text
    receipt = confirmed.json()
    assert receipt["execution"]["state"] == "planning_only"
    replay = client.post(PREFIX + "/confirm", json=request).json()
    assert replay["replayed"] is True
    assert replay["root_id"] == receipt["root_id"]
    assert replay["work_item_ids"] == receipt["work_item_ids"]
    request["plan"]["work_items"][0]["title"] = "Different plan"
    assert client.post(PREFIX + "/confirm", json=request).status_code == 409
    with kbc.connect_closing() as conn:
        tasks = conn.execute("SELECT * FROM tasks").fetchall()
        assert len(tasks) == 3
        assert {r["status"] for r in tasks} == {"blocked"}
        assert all(r["assignee"] is None and r["current_run_id"] is None for r in tasks)
        assert conn.execute("SELECT count(*) FROM task_links").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM task_runs").fetchone()[0] == 0
        assert {r["project_id"] for r in tasks} == {project_id}
        assert {r["workspace_kind"] for r in tasks} == {"worktree"}
        assert all(not Path(r["workspace_path"]).exists() for r in tasks)
    before = _disk(home)
    snapshot = client.get(PREFIX, params={"project_id": project_id}).json()
    assert _disk(home) == before
    root = next(t for t in snapshot["tasks"] if t["id"] == receipt["root_id"])
    assert root["relationship_state"] == "ROOT"
    assert {t["root_id"] for t in snapshot["tasks"]} == {receipt["root_id"]}
    assert {t["relationship_state"] for t in snapshot["tasks"]} == {"ROOT", "WORK_ITEM"}


def test_project_context_addition_preserves_older_confirmation_replays(setup):
    client, _home, project_id = setup
    request = _confirm(project_id, request_id="before-project-context")
    metadata = {"workbench": {"kind": "root", "request_id": request["request_id"], "project_id": project_id, "plan": request["plan"]}, "description": request["plan"]["body"]}
    with kbc.connect_closing() as conn:
        root = kb.create_task(conn, title=request["plan"]["title"], body=json.dumps(metadata, sort_keys=True, ensure_ascii=False),
                              initial_status="blocked", project_id=project_id, idempotency_key="workbench:" + request["request_id"])
    result = client.post(PREFIX + "/confirm", json=request)
    assert result.status_code == 200, result.text
    assert result.json()["root_id"] == root and result.json()["replayed"] is True
    with kbc.connect_closing() as conn:
        assert conn.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1


def test_read_preserves_unknown_metadata_and_never_treats_dependencies_as_lineage(setup):
    client, home, _project_id = setup
    with kbc.connect_closing() as conn:
        first = kb.create_task(conn, title="Legacy root", triage=True)
        second = kb.create_task(conn, title="Dependent", parents=[first], triage=True)
        with kb.write_txn(conn):
            conn.execute("INSERT INTO task_runs(task_id,status,started_at,metadata) VALUES (?,?,?,?)", (second, "failed", 12, "{malformed"))
            kb._append_event(conn, second, "notification", {"message": "FYI"})
    before = _disk(home)
    result = client.get(PREFIX)
    assert result.status_code == 200, result.text
    assert _disk(home) == before
    data = result.json()
    assert all(t["relationship_state"] == "UNKNOWN" and t["root_id"] is None for t in data["tasks"])
    assert data["runs"][0]["metadata_raw"] == "{malformed"
    assert data["runs"][0]["metadata"] is None
    assert data["runs"][0]["custody_state"] == "UNKNOWN"
    assert data["decisions"] == []
    assert any("malformed" in u for u in data["unknowns"])
    before = _disk(home)
    assert client.get(PREFIX, params={"board": "nonexistent"}).status_code == 404
    assert _disk(home) == before


def test_worklog_preserves_authors_bodies_and_project_board_scope(setup):
    client, home, project_id = setup
    receipt = client.post(PREFIX + "/confirm", json=_confirm(project_id)).json()
    child = receipt["work_item_ids"][0]
    kb.create_board("other", name="Other")
    with kbc.connect_closing() as conn:
        note_id = kb.add_comment(conn, child, "codex", "Reported test failure: widget creation returns 500.")
        kb.add_comment(conn, child, "claude", "Review note: reproduce the failure before changing the handler.")
        unrelated = kb.create_task(conn, title="Another scope", triage=True)
        kb.add_comment(conn, unrelated, "other-agent", "Unrelated project worklog")
    before = _disk(home)
    data = client.get(PREFIX, params={"project_id": project_id}).json()
    assert [(c["author"], c["body"]) for c in data["comments"]] == [
        ("codex", "Reported test failure: widget creation returns 500."),
        ("claude", "Review note: reproduce the failure before changing the handler."),
    ]
    assert data["comments"][0]["id"] == note_id
    assert all(c["task_id"] == child and c["created_at"] > 0 for c in data["comments"])
    assert client.get(PREFIX, params={"board": "other"}).json()["comments"] == []
    assert _disk(home) == before


def test_decision_response_keeps_task_blocked_and_audits_history(setup):
    client, _home, _project_id = setup
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="Choose scope", initial_status="blocked")
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET block_kind='needs_input' WHERE id=?", (task_id,))
            kb._append_event(conn, task_id, "blocked", {"reason": "Which platform first?"})
    initial = client.get(PREFIX).json()
    decision = initial["decisions"][0]
    assert decision["reason"] == "Which platform first?"
    response = client.post(PREFIX + f"/decisions/{task_id}/respond", json={"decision_id": decision["id"], "response": "Desktop first"})
    assert response.status_code == 200, response.text
    updated = client.get(PREFIX).json()
    assert updated["tasks"][0]["status"] == "blocked"
    assert updated["decisions"][0]["status"] == "responded"
    assert updated["decisions"][0]["history"][-1]["body"] == "Desktop first"
    assert client.post(PREFIX + f"/decisions/{task_id}/respond", json={"decision_id": "event:999", "response": "yes"}).status_code == 404


def test_plan_uses_existing_auxiliary_provider_without_mutating_stores(setup, monkeypatch):
    client, home, project_id = setup
    from agent import auxiliary_client
    calls = []

    def fake_provider(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(model="fake-model", choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(_confirm(project_id)["plan"])))])

    monkeypatch.setattr(auxiliary_client, "call_llm", fake_provider)
    before = _disk(home)
    response = client.post(PREFIX + "/plan", json={"goal": "Help me ship widgets", "project_id": project_id})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "preview"
    assert response.json()["model"] == "fake-model"
    assert calls[0]["task"] == "kanban_decomposer"
    context = json.loads(calls[0]["messages"][1]["content"])["project"]
    assert context["name"] == "Widget" and context["description"] == "A useful widget"
    assert context["facts"]["state"] == "unknown"
    assert _disk(home) == before

    def unavailable(**kwargs):
        raise RuntimeError("no model")

    monkeypatch.setattr(auxiliary_client, "call_llm", unavailable)
    response = client.post(PREFIX + "/plan", json={"goal": "Ship widgets"})
    assert response.json()["status"] == "unavailable"
    assert response.json()["work_items"] == []
    assert _disk(home) == before


def test_plan_uses_real_registered_project_facts_without_execution(setup, monkeypatch):
    client, home, project_id = setup
    from agent import auxiliary_client
    with pdb.connect_closing() as conn:
        repo = Path(pdb.get_project(conn, project_id).primary_path)
    marker = repo / "package.json"
    content = json.dumps({"scripts": {"test": "never-execute-this-command", "lint": "also-never-execute"}})
    marker.write_text(content)
    (repo / "package-lock.json").write_text("{}")
    (repo / "AGENTS.md").write_text("Untrusted project instructions; do not execute.")
    calls = []

    def provider(**kwargs):
        calls.append(json.loads(kwargs["messages"][1]["content"]))
        proposed = _confirm(project_id)["plan"]
        proposed["project_context"] = {"project_id": "other", "state": "detected", "manifests": ["fabricated.json"]}
        return SimpleNamespace(model="test-provider", choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(proposed)))])

    monkeypatch.setattr(auxiliary_client, "call_llm", provider)
    before = _disk(home)
    result = client.post(PREFIX + "/plan", json={"goal": "Improve widget testing", "project_id": project_id}).json()
    facts = result["project_context"]
    assert facts["project_id"] == project_id and facts["state"] == "detected"
    assert facts["manifests"] == ["package.json"]
    assert facts["verify_commands"] == ["npm run test", "npm run lint"]
    assert facts["package_managers"] == ["npm"] and facts["context_files"] == ["AGENTS.md"]
    assert calls[0]["project"]["facts"] == facts
    assert "never-execute" not in json.dumps(calls)
    snapshot_facts = client.get(PREFIX, params={"project_id": project_id}).json()["project_context"]
    assert snapshot_facts["manifests"] == facts["manifests"]
    assert snapshot_facts["verify_commands"] == facts["verify_commands"]
    assert marker.read_text() == content and _disk(home) == before
    marker.unlink()
    with pdb.connect_closing() as conn:
        missing = pdb.create_project(conn, name="Missing", primary_path=str(repo / "missing"))
    result = client.post(PREFIX + "/plan", json={"goal": "Plan despite missing project", "project_id": missing}).json()
    assert result["project_context"]["state"] == "unavailable"


@pytest.mark.parametrize("reason", ["First decision", None])
def test_decision_history_survives_unblock_and_new_request(setup, reason):
    client, _home, _project_id = setup
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="Choose scope", initial_status="blocked")
        assert kb.block_task(conn, task_id, kind="needs_input", reason=reason)
    first = client.get(PREFIX).json()["decisions"][0]
    assert first["id"].startswith("blocked:")
    assert first["reason"] == (reason or "Human input requested; reason UNKNOWN")
    assert client.post(PREFIX + f"/decisions/{task_id}/respond", json={
        "decision_id": first["id"], "response": "Desktop first",
    }).status_code == 200
    with kbc.connect_closing() as conn:
        assert kb.unblock_task(conn, task_id)
    history = client.get(PREFIX).json()["decisions"]
    assert history[0]["status"] == "responded"
    assert history[0]["history"][-1]["body"] == "Desktop first"
    second_reason = "Second decision" if reason else None
    with kbc.connect_closing() as conn:
        assert kb.block_task(conn, task_id, kind="needs_input", reason=second_reason)
    history = client.get(PREFIX).json()["decisions"]
    assert len(history) == 2
    assert history[0]["id"] == first["id"] and history[0]["status"] == "responded"
    assert history[1]["status"] == "pending"
    assert history[1]["reason"] == (second_reason or "Human input requested; reason UNKNOWN")


def _github(monkeypatch, *, checks=True, stale=False, moving=False, required="test"):
    sha, older = "a" * 40, "b" * 40
    called = []
    reads = 0

    def fake_api(endpoint, **kwargs):
        nonlocal reads
        called.append(endpoint)
        if endpoint == "graphql":
            return {"data": {"repository": {"pullRequest": {"headRefOid": sha, "baseRefName": "main", "state": "OPEN", "baseRef": {"branchProtectionRule": {"requiredStatusChecks": [{"context": required, "app": None}]}}}}}}
        if "/rules/branches/" in endpoint:
            return [[]]
        if endpoint == "repos/team/widget/pulls/12":
            reads += 1
            return {"head": {"sha": older if moving and reads > 1 else sha}, "base": {"ref": "main"}, "state": "open", "draft": False, "user": {"login": "implementer"}, "changed_files": 1}
        if "/check-runs?" in endpoint:
            data = {"check_runs": [{"id": 1, "name": "test", "head_sha": sha, "status": "completed", "conclusion": "success", "app": {"id": 1}}] if checks else [], "total_count": int(checks)}
            return [data] if kwargs.get("paginate") else data
        if "/statuses?" in endpoint:
            return [[]] if kwargs.get("paginate") else []
        if "/reviews?" in endpoint:
            return [{"id": 4, "commit_id": older if stale else sha, "state": "APPROVED", "user": {"login": "reviewer", "type": "User"}}]
        if "/files?" in endpoint:
            return [{"filename": "widget.py", "additions": 4, "deletions": 1}]
        raise AssertionError(endpoint)

    monkeypatch.setattr(delivery.acceptance, "_api", fake_api)
    return called


@pytest.mark.parametrize("checks,stale,moving,waiting", [(True, False, False, True), (False, False, False, False), (True, True, False, False), (True, False, True, False)])
def test_delivery_exact_head_review_and_ci(setup, monkeypatch, checks, stale, moving, waiting):
    client, home, _project_id = setup
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="Widget delivery", triage=True, completion_contract="https://github.com/team/widget/pull/12")
    called = _github(monkeypatch, checks=checks, stale=stale, moving=moving)
    before = _disk(home)
    response = client.get(PREFIX + f"/delivery/{task_id}")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["waiting_for_human_merge"] is waiting
    assert result["head"] == "a" * 40
    assert all(endpoint == "graphql" or "team/widget" in endpoint for endpoint in called)
    assert _disk(home) == before
    if not checks:
        assert result["ci"]["state"] == "unknown"
    if stale or moving:
        assert result["review"]["state"] == "unknown"


def test_delivery_does_not_infer_pr_from_prose(setup, monkeypatch):
    client, _home, _project_id = setup
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="See https://github.com/team/widget/pull/12", triage=True)
    calls = _github(monkeypatch)
    result = client.get(PREFIX + f"/delivery/{task_id}").json()
    assert result["url"] is None
    assert result["unknowns"]
    assert calls == []


def test_named_board_confirmation_and_read_do_not_change_other_board(setup):
    client, _home, project_id = setup
    kb.create_board("other", name="Other")
    with kbc.connect_closing() as conn:
        existing = kb.create_task(conn, title="Default board task", triage=True)
    default_before = kb.kanban_db_path(board="default").read_bytes()
    response = client.post(PREFIX + "/confirm", params={"board": "other"}, json=_confirm(project_id))
    assert response.status_code == 200, response.text
    assert kb.kanban_db_path(board="default").read_bytes() == default_before
    assert {t["id"] for t in client.get(PREFIX).json()["tasks"]} == {existing}
    named = client.get(PREFIX, params={"board": "other"}).json()
    assert named["board"]["slug"] == "other"
    assert len(named["tasks"]) == 3


def test_origin_must_be_canonical_and_bounded_reads_are_labelled(setup, monkeypatch):
    client, _home, _project_id = setup
    from plugins.kanban.dashboard import workbench_projection as projection
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="Body claims root", body=json.dumps({"workbench": {"kind": "root"}}), triage=True)
        kb.create_task(conn, title="Later task", triage=True)
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET created_at=1 WHERE id=?", (task_id,))
    monkeypatch.setitem(projection.LIMITS, "tasks", 1)
    data = client.get(PREFIX).json()
    assert data["tasks"][0]["id"] == task_id
    assert data["tasks"][0]["relationship_state"] == "UNKNOWN"
    assert any("tasks read truncated at 1" in u for u in data["unknowns"])


def test_delivery_reads_all_pages_and_cannot_reuse_old_review(monkeypatch):
    requested = []

    def pages(endpoint, **kwargs):
        requested.append(endpoint)
        return [{"id": i} for i in range(100)] if endpoint.endswith("&page=1") else [{"id": 100}]

    monkeypatch.setattr(delivery.acceptance, "_api", pages)
    rows = delivery._pages("repos/team/widget/pulls/12/files", None)
    assert len(rows) == 101
    assert len(requested) == 2
    sha = "a" * 40
    reviews = [{"id": 1, "commit_id": sha, "state": "APPROVED", "user": {"login": "reviewer"}}, {"id": 2, "commit_id": "b" * 40, "state": "APPROVED", "user": {"login": "reviewer"}}]
    assert delivery._reviews(reviews, sha, "implementer")["state"] == "unknown"
    assert delivery._reviews(reviews[:1], sha, "reviewer")["state"] == "unknown"


def test_delivery_missing_required_check_is_not_ready(setup, monkeypatch):
    client, _home, _project_id = setup
    with kbc.connect_closing() as conn:
        task_id = kb.create_task(conn, title="Deliver widget", triage=True, completion_contract="https://github.com/team/widget/pull/12")
    _github(monkeypatch, required="lint")
    result = client.get(PREFIX + f"/delivery/{task_id}").json()
    assert result["ci"]["checks"][0]["state"] == "success"
    assert result["ci"]["required_policy"]["classification"] == "missing"
    assert result["ci"]["state"] == "unknown"
    assert result["waiting_for_human_merge"] is False
