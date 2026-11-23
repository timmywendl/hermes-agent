"""Cross-surface regressions for the complete Kanban review lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


@pytest.fixture
def review_worker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_PROFILE", "builder")
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    # kanban_request_review now rejects reviewers that are not installed profiles (#106163).
    (home / "profiles" / "reviewer").mkdir(parents=True)
    (home / "profiles" / "reviewer" / "config.yaml").write_text("{}\n")  # identity marker
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    with kbc.connect() as conn:
        task_id = kb.create_task(conn, title="Review tool contract", assignee="builder")
        task = kb.claim_task(conn, task_id, claimer="builder:1")
        assert task is not None
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(task.current_run_id))
    return task_id


def test_review_tools_redact_handoff_and_route_changes(
    review_worker: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import kanban_tools as tools

    secret = "ghp_" + "A" * 40
    requested = json.loads(
        tools._handle_request_review({
            "summary": f"Ready; temporary token was {secret}",
            "metadata": {"token": secret, "tests_run": 7},
            "reviewer": "reviewer",
        })
    )
    assert requested["ok"] is True

    with kbc.connect() as conn:
        task = kb.get_task(conn, review_worker)
        assert task is not None
        assert task.status == "review"
        assert task.assignee == "reviewer"
        handoff = kb.latest_run(conn, review_worker)
        assert handoff is not None
        assert secret not in (handoff.summary or "")
        assert secret not in json.dumps(handoff.metadata)
        review = kb.claim_review_task(conn, review_worker, claimer="reviewer:1")
        assert review is not None

    monkeypatch.setenv("HERMES_PROFILE", "reviewer")
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(review.current_run_id))
    change_secret = "sk-" + "B" * 32
    changed = json.loads(
        tools._handle_request_changes({
            "reason": f"Add a boundary assertion; leaked={change_secret}",
        })
    )
    assert changed["ok"] is True
    assert changed["implementer"] == "builder"

    with kbc.connect() as conn:
        task = kb.get_task(conn, review_worker)
        assert task is not None
        assert task.status == "ready"
        assert task.assignee == "builder"
        event = [
            item
            for item in kb.list_events(conn, review_worker)
            if item.kind == "changes_requested"
        ][-1]
        assert event.payload is not None
        assert change_secret not in event.payload["reason"]
        assert event.payload["reason"] != (
            "Add a boundary assertion; leaked=" + change_secret
        )


def test_review_tools_are_gated_and_visible_to_kanban_workers(
    review_worker: str,
) -> None:
    import tools.kanban_tools
    from tools.registry import invalidate_check_fn_cache, registry
    from toolsets import resolve_toolset

    invalidate_check_fn_cache()
    definitions = registry.get_definitions(
        set(resolve_toolset("hermes-cli")), quiet=True
    )
    names = {
        definition["function"]["name"]
        for definition in definitions
        if "function" in definition
    }
    assert "kanban_request_review" in names
    assert "kanban_request_changes" in names

    from agent.transports.hermes_tools_mcp_server import EXPOSED_TOOLS

    assert "kanban_request_changes" in EXPOSED_TOOLS
    assert "kanban_request_changes" in resolve_toolset("kanban")




def test_review_cli_round_trip_preserves_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()

    with kbc.connect() as conn:
        task_id = kb.create_task(conn, title="CLI review", assignee="builder")
        implementation = kb.claim_task(conn, task_id, claimer="builder:1")
        assert implementation is not None
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(implementation.current_run_id))

    output = kc.run_slash(
        f"request-review {task_id} --summary 'ready for review' "
        "--reviewer reviewer --metadata '{\"tests_run\": 3}'"
    )
    assert "Requested review" in output

    with kbc.connect() as conn:
        task = kb.get_task(conn, task_id)
        assert task is not None
        assert task.assignee == "reviewer"
        handoff = kb.latest_run(conn, task_id)
        assert handoff is not None
        assert handoff.metadata == {"tests_run": 3}
        review = kb.claim_review_task(conn, task_id, claimer="reviewer:1")
        assert review is not None
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(review.current_run_id))

    output = kc.run_slash(
        f"request-changes {task_id} 'cover the malformed payload case'"
    )
    assert "Requested changes" in output
    with kbc.connect() as conn:
        task = kb.get_task(conn, task_id)
        assert task is not None
        assert task.status == "ready"
        assert task.assignee == "builder"


def test_domain_and_cli_review_handoffs_redact_before_persistence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    secret = "ghp_" + "R" * 40

    with kbc.connect() as conn:
        direct_id = kb.create_task(conn, title="direct redaction", assignee="builder")
        direct_run = kb.claim_task(conn, direct_id)
        assert direct_run is not None
        assert kb.request_review(
            conn,
            direct_id,
            summary=f"direct {secret}",
            metadata={"nested": [secret]},
            expected_run_id=direct_run.current_run_id,
        )
        run = kb.latest_run(conn, direct_id)
        event = [
            item for item in kb.list_events(conn, direct_id)
            if item.kind == "review_requested"
        ][-1]
        assert run is not None
        assert secret not in str(run.summary)
        assert secret not in json.dumps(run.metadata)
        assert secret not in json.dumps(event.payload)

        review = kb.claim_review_task(conn, direct_id)
        assert review is not None
        assert kb.request_changes(
            conn,
            direct_id,
            reason=f"change {secret}",
            expected_run_id=review.current_run_id,
        ) == (True, "builder")
        run = kb.latest_run(conn, direct_id)
        event = [
            item for item in kb.list_events(conn, direct_id)
            if item.kind == "changes_requested"
        ][-1]
        assert run is not None
        assert secret not in str(run.summary)
        assert secret not in json.dumps(event.payload)

        cli_id = kb.create_task(conn, title="CLI redaction", assignee="builder")
    cli_output = kc.run_slash(
        f'request-review {cli_id} --summary "cli {secret}" '
        f"--metadata '{{\"token\":\"{secret}\"}}'"
    )
    assert "Requested review" in cli_output
    assert secret not in cli_output
    with kbc.connect() as conn:
        run = kb.latest_run(conn, cli_id)
        event = [
            item for item in kb.list_events(conn, cli_id)
            if item.kind == "review_requested"
        ][-1]
        assert run is not None
        assert secret not in str(run.summary)
        assert secret not in json.dumps(run.metadata)
        assert secret not in json.dumps(event.payload)




def test_cli_reopen_review_is_transition_first_and_redacts_reason(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    secret = "ghp_" + "Q" * 40
    with kbc.connect() as conn:
        invalid_id = kb.create_task(conn, title="not review", assignee="builder")
        review_id = kb.create_task(conn, title="review", assignee="builder")
        assert kb.request_review(conn, review_id, summary="ready")

    invalid_output = kc.run_slash(
        f'reopen-review {invalid_id} --reason "invalid {secret}"'
    )
    assert "cannot reopen" in invalid_output
    with kbc.connect() as conn:
        assert kb.list_comments(conn, invalid_id) == []

    success_output = kc.run_slash(
        f'reopen-review {review_id} --reason "revise {secret}"'
    )
    assert "Reopened" in success_output
    assert secret not in success_output
    with kbc.connect() as conn:
        task = kb.get_task(conn, review_id)
        assert task is not None
        assert task.status == "ready"
        comments = kb.list_comments(conn, review_id)
        assert len(comments) == 1
        assert secret not in comments[0].body


def test_goal_mode_review_handoff_cannot_bypass_judge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()

    with kbc.connect() as conn:
        tool_task = kb.create_task(
            conn,
            title="Goal-mode tool task",
            assignee="builder",
            goal_mode=True,
        )
        claimed = kb.claim_task(conn, tool_task, claimer="builder:1")
        assert claimed is not None
    monkeypatch.setenv("HERMES_KANBAN_TASK", tool_task)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))

    from tools import kanban_tools as tools

    monkeypatch.setattr(tools, "_goal_judge_available", lambda: True)
    monkeypatch.setattr(
        tools,
        "judge_goal",
        lambda *args, **kwargs: (
            "continue",
            "acceptance evidence is missing",
            False,
            None,
            False,
        ),
    )
    rejected = json.loads(tools._handle_request_review({"summary": "Looks ready."}))
    assert "error" in rejected
    assert "rejected by judge" in rejected["error"]
    with kbc.connect() as conn:
        tool_after = kb.get_task(conn, tool_task)
        assert tool_after is not None
        assert tool_after.status == "running"

    # The shell/CLI path applies the same gate and must not bypass the tool.
    with kbc.connect() as conn:
        cli_task = kb.create_task(
            conn,
            title="Goal-mode CLI task",
            assignee="builder",
            goal_mode=True,
        )
        cli_claimed = kb.claim_task(conn, cli_task, claimer="builder:2")
        assert cli_claimed is not None
    monkeypatch.setenv("HERMES_KANBAN_TASK", cli_task)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(cli_claimed.current_run_id))

    from agent import auxiliary_client
    from hermes_cli import goals

    monkeypatch.setattr(
        auxiliary_client,
        "get_text_auxiliary_client",
        lambda purpose: (object(), "judge-model"),
    )
    monkeypatch.setattr(
        goals,
        "judge_goal",
        lambda *args, **kwargs: ("continue", "tests are missing", False, None, False),
    )
    output = kc.run_slash(f"request-review {cli_task} --summary 'Looks ready.'")
    assert "rejected by judge" in output
    with kbc.connect() as conn:
        cli_after = kb.get_task(conn, cli_task)
        assert cli_after is not None
        assert cli_after.status == "running"


def test_goal_loop_stops_after_reviewer_requests_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hermes_cli import goals

    monkeypatch.setattr(
        goals,
        "judge_goal",
        lambda *args, **kwargs: pytest.fail(
            "a terminal review verdict must not be judged"
        ),
    )
    result = goals.run_kanban_goal_loop(
        task_id="t_review",
        goal_text="review the change",
        run_turn=lambda prompt: pytest.fail("must not run another reviewer turn"),
        task_status_fn=lambda: "changes_requested",
        block_fn=lambda reason: pytest.fail("must not block"),
        first_response="Changes requested.",
    )
    assert result["outcome"] == "changes_requested_by_reviewer"
    assert result["turns_used"] == 1


def test_cli_and_dashboard_receive_graph_aware_deadlock_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()

    with kbc.connect() as conn:
        parent_id = kb.create_task(conn, title="Implementation", assignee="builder")
        child_id = kb.create_task(
            conn,
            title="Review",
            assignee="reviewer",
            parents=[parent_id],
        )
        parent = kb.claim_task(conn, parent_id, claimer="builder:1")
        assert parent is not None
        assert kb.block_task(
            conn,
            parent_id,
            reason="review-required: ready",
            expected_run_id=parent.current_run_id,
        )

    payload = json.loads(kc.run_slash(f"diagnostics --task {parent_id} --json"))
    assert any(
        item["kind"] == "review_dependency_deadlock"
        for item in payload[0]["diagnostics"]
    )

    from plugins.kanban.dashboard.plugin_api import _compute_task_diagnostics

    with kbc.connect() as conn:
        dashboard = _compute_task_diagnostics(conn, task_ids=[parent_id])
    assert dashboard[parent_id][0]["kind"] == "review_dependency_deadlock"
    assert dashboard[parent_id][0]["data"]["waiting_child_ids"] == [child_id]


def test_wave2_publication_cli_requires_remote_read_and_never_retries(monkeypatch, tmp_path, capsys):
    import argparse
    import hashlib
    import os
    import subprocess
    import sys
    from hermes_cli import kanban_pr_acceptance as acceptance

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    with kbc.connect() as conn:
        root_key = "project-status-next-legal-step/v1"
        root_identity = {"repo": "acme/repo", "objective_id": "fixture", "work_key": root_key}
        root_hash = hashlib.sha256(json.dumps(list(root_identity.values()), separators=(',', ':')).encode()).hexdigest()
        root = kb.create_task(conn, title="root", body=json.dumps(root_identity), initial_status="blocked",
                              created_by="ai-colleague-k1", idempotency_key="colleague-k1:" + root_hash)
        target = {"repo": "acme/repo", "base": "main", "branch": "topic"}
        work = {"enabled": True, "repo": "acme/repo", "objective_id": "fixture", "work_key": "work",
                "root_id": root, "decision_ref": "approved", "completion_contract": "acme/repo",
                "title": "publish", "instructions": "fixture", "acceptance_criteria": "offline", "publication_target": target}
        spec = {k: work[k] for k in ("title", "instructions", "acceptance_criteria", "publication_target")}
        spec["publication_instructions"] = "fixture"
        digest = hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        key = hashlib.sha256(json.dumps([work[k] for k in ("repo", "objective_id", "work_key")], separators=(',', ':')).encode()).hexdigest()
        body = {**work, "publication_protocol": "wave2_v1", "task_spec": spec, "task_spec_digest": digest}
        tid = kb.create_task(conn, title="publish", body=json.dumps(body), creator_task_id=root,
            created_by="ai-colleague-stage3", assignee="builder", workspace_kind="worktree",
            branch_name="topic", completion_contract="acme/repo", idempotency_key="colleague-stage3:" + key)
        task = kb.claim_task(conn, tid, claimer="builder:test")
    grant = {"enabled": True, "allow_read": True, "repo": "acme/repo", "objective_id": "fixture",
             "decision_ref": "approved", "profile_home": str(home.resolve()), "db_path": str(kb.kanban_db_path().resolve()), "work_item": work}
    config_path = home / 'config.yaml'
    def save_grant(value):
        config_path.write_text(json.dumps({"plugins": {"enabled": ["ai-colleague-k1"], "entries": {"ai-colleague-k1": {"settings": {"grant": value}}}}}))
    save_grant(grant)
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(task.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", task.claim_lock)
    monkeypatch.setattr(acceptance, "_assignee_profile_home", lambda assignee: None)
    reads = []
    state = {"created": False, "ambiguous": False, "race": False, "grant_race": False}

    def fake_api(endpoint, **kwargs):
        reads.append(endpoint)
        if "/git/ref/" in endpoint:
            if state["grant_race"]:
                state["grant_race"] = False
                grant["decision_ref"] = "changed during read"
            if state["race"]:
                state["race"] = False
                with kbc.connect() as rival:
                    rival.execute("UPDATE tasks SET status='blocked' WHERE id=?", (tid,))
            return {"object": {"sha": "a" * 40}}
        if not state["created"]:
            return [[]]
        pr = {"html_url": "https://github.com/acme/repo/pull/7", "state": "open", "draft": True,
                  "head": {"sha": "a" * 40, "ref": "topic", "repo": {"full_name": "acme/repo"}},
                  "base": {"ref": "main"}}
        return [[pr, pr] if state["ambiguous"] else [pr]]

    monkeypatch.setattr(acceptance, "_api", fake_api)
    parser = argparse.ArgumentParser()
    kc.build_parser(parser.add_subparsers(dest="top"))
    argv = ["kanban", "publication-intent", tid, "--repo", "acme/repo", "--base", "main",
            "--branch", "topic", "--head", "a" * 40]
    assert kc.kanban_command(parser.parse_args(argv)) == 0
    assert reads == []
    assert kc.kanban_command(parser.parse_args(argv + ["--attempt"])) == 0
    assert len(reads) == 2
    assert kc.kanban_command(parser.parse_args(argv + ["--attempt"])) == 1
    assert len(reads) == 2
    assert "already attempted" in capsys.readouterr().err
    # A response lost after remote success is resolved only by readback.
    state["created"] = True
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    for name in ("HERMES_KANBAN_TASK", "HERMES_KANBAN_RUN_ID", "HERMES_KANBAN_CLAIM_LOCK"):
        monkeypatch.delenv(name)
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET claim_expires=0 WHERE id=?", (tid,))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 0
    assert json.loads(capsys.readouterr().out)['original_run_id'] == task.current_run_id
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET status='blocked', claim_lock=NULL, claim_expires=0 WHERE id=?", (tid,))
        conn.execute("UPDATE task_runs SET status='crashed', outcome='crashed' WHERE id=?", (task.current_run_id,))
    monkeypatch.setenv('WAVE2_EMPTY_DECISION', '')
    for invalid in ({**grant, 'allow_read': False}, {**grant, 'db_path': str(home / 'other.db')},
                    {**grant, 'decision_ref': '${WAVE2_EMPTY_DECISION}'},
                    {**grant, 'work_item': {**work, 'unexpected': True}},
                    {**grant, 'work_item': {**work, 'root_id': 'other'}}):
        save_grant(invalid)
        assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    config_path.write_text(json.dumps({"plugins": {"enabled": [], "entries": {"ai-colleague-k1": {"settings": {"grant": grant}}}}}))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    config_path.write_text('plugins: [invalid')
    before_files = {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')}
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    assert {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')} == before_files
    save_grant(grant)
    from hermes_cli import managed_scope
    class InaccessiblePolicy:
        def __truediv__(self, _name):
            return self
        def stat(self):
            raise PermissionError('policy inaccessible')
    with monkeypatch.context() as scoped:
        scoped.setattr(managed_scope, 'get_managed_dir', lambda: InaccessiblePolicy())
        assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET completion_contract=? WHERE id=?", (b'bad-contract', tid))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET completion_contract='acme/repo' WHERE id=?", (tid,))
        conn.execute("UPDATE tasks SET created_by='foreign' WHERE id=?", (root,))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET created_by='ai-colleague-k1' WHERE id=?", (root,))
        conn.execute("UPDATE tasks SET id='missing-root' WHERE id=?", (root,))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    with kbc.connect() as conn:
        conn.execute("UPDATE tasks SET id=? WHERE id='missing-root'", (root,))
    for index in (argv.index("main"), argv.index("topic")):
        bad = argv.copy()
        bad[index] = "unapproved"
        assert kc.kanban_command(parser.parse_args(bad + ["--reconcile"])) == 1
    assert len(reads) == 4  # reject before the remote read
    before_files = {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')}
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 0
    assert {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')} == before_files
    observed = json.loads(capsys.readouterr().out)
    assert observed['pr_url'] == "https://github.com/acme/repo/pull/7"
    assert observed['original_run_id'] == task.current_run_id
    assert observed['intent_id'] < observed['attempt_id'] and observed['status'] == 'MATCHED_READ_ONLY'
    assert len(reads) == 6
    # A fresh CLI process uses an inert gh executable, including the real _api
    # subprocess path, without initializing or changing the profile or Board.
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    gh = bin_dir / 'gh'
    gh.write_text(f'''#!{sys.executable}\nimport json, sys\nif '/git/ref/' in sys.argv[2]:\n print(json.dumps({{"object": {{"sha": "{'a' * 40}"}}}}))\nelse:\n print(json.dumps([[{{"html_url": "https://github.com/acme/repo/pull/7", "state": "open", "draft": True, "head": {{"sha": "{'a' * 40}", "ref": "topic", "repo": {{"full_name": "acme/repo"}}}}, "base": {{"ref": "main"}}}}]]))\n''')
    gh.chmod(0o755)
    env = {**os.environ, 'HOME': str(home), 'HERMES_HOME': str(home), 'HERMES_KANBAN_HOME': str(home),
           'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']}
    before_files = {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')}
    code = ('import argparse,sys; from hermes_cli import kanban as k; '
            'p=argparse.ArgumentParser(); k.build_parser(p.add_subparsers(dest="top")); '
            'raise SystemExit(k.kanban_command(p.parse_args(sys.argv[1:])))')
    child = subprocess.run([sys.executable, '-B', '-c', code, *argv, '--reconcile'],
                           env=env, capture_output=True, text=True, timeout=20, check=False)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout)['original_run_id'] == task.current_run_id
    assert {p.relative_to(home): p.read_bytes() for p in home.rglob('*') if p.is_file() and not p.name.endswith('-shm')} == before_files
    with kbc.connect() as conn:
        assert kb.unblock_task(conn, tid)
        successor = kb.claim_task(conn, tid, claimer="successor:test")
        assert successor and successor.current_run_id != task.current_run_id
        before = [tuple(row) for row in conn.execute("SELECT id,kind,payload,run_id FROM task_events WHERE task_id=? ORDER BY id", (tid,))]
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 0
    with kbc.connect() as conn:
        assert [tuple(row) for row in conn.execute("SELECT id,kind,payload,run_id FROM task_events WHERE task_id=? ORDER BY id", (tid,))] == before
        assert kb.get_task(conn, tid).current_run_id == successor.current_run_id
        attempt = conn.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='wave2_publication_attempt'", (tid,)).fetchone()
        damaged = json.loads(attempt['payload'])
        damaged['head'] = 'b' * 40
        conn.execute("UPDATE task_events SET payload=? WHERE id=?", (json.dumps(damaged), attempt['id']))
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    with kbc.connect() as conn:
        conn.execute("UPDATE task_events SET payload=? WHERE id=?", (attempt['payload'], attempt['id']))
    state["ambiguous"] = True
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    state["ambiguous"] = False
    state["race"] = True
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    import hermes_yaml
    cached_config = {"plugins": {"enabled": ["ai-colleague-k1"], "entries": {"ai-colleague-k1": {"settings": {"grant": grant}}}}}
    with monkeypatch.context() as scoped:
        scoped.setattr(hermes_yaml, "safe_load", lambda _source: cached_config)
        state["grant_race"] = True
        assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    grant["decision_ref"] = "approved"
    state["created"] = False
    assert kc.kanban_command(parser.parse_args(argv + ["--reconcile"])) == 1
    assert "publication UNKNOWN" in capsys.readouterr().err
    assert kc.kanban_command(parser.parse_args(argv + ["--attempt"])) == 1


def test_wave2_stale_claim_token_rejected_by_cli_and_worker_tools(monkeypatch, tmp_path):
    import argparse
    from hermes_cli import kanban_pr_acceptance as acceptance
    from hermes_cli import kanban_pr_acceptance_store as store
    from hermes_cli import profiles
    from tools import kanban_tools as tools

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_PROFILE", "builder")
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    monkeypatch.setattr(profiles, "profile_exists", lambda name: True)
    monkeypatch.setattr(acceptance, "verify_publication", lambda *args, **kwargs: True)
    monkeypatch.setattr(store, "collect_acceptance", lambda *args, **kwargs: {
        "ok": True, "classification": "success", "head_sha": "a" * 40, "base_ref": "main", "recovery": ""})
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    with kbc.connect() as conn:
        tid = kb.create_task(conn, title="publish", body=json.dumps({"publication_protocol": "wave2_v1",
            "publication_target": {"repo": "acme/repo", "base": "main", "branch": "topic"}}),
            created_by="ai-colleague-stage3", assignee="builder", workspace_kind="worktree",
            branch_name="topic", completion_contract="acme/repo")
        implementer = kb.claim_task(conn, tid, claimer="old-builder")
        args = dict(run_id=implementer.current_run_id, claim_lock=implementer.claim_lock,
                    repo="acme/repo", base="main", branch="topic", head="a" * 40)
        assert store.record_publication_intent(conn, tid, **args, attempt=True)
        conn.execute("UPDATE tasks SET claim_lock='new-builder' WHERE id=?", (tid,))
        conn.execute("UPDATE task_runs SET claim_lock='new-builder' WHERE id=?", (implementer.current_run_id,))
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(implementer.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", implementer.claim_lock)
    parser = argparse.ArgumentParser()
    kc.build_parser(parser.add_subparsers(dest="top"))
    url = "https://github.com/acme/repo/pull/7"
    handoff = {"published_pr": url, "head_sha": "a" * 40}
    cli_review = ["kanban", "request-review", tid, "--reviewer", "reviewer", "--metadata", json.dumps(handoff)]
    assert kc.kanban_command(parser.parse_args(cli_review)) == 1
    assert json.loads(tools._handle_request_review({"summary": "ready", "reviewer": "reviewer", "metadata": handoff})).get("ok") is not True
    with kbc.connect() as conn:
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='wave2_handoff'", (tid,)).fetchone()[0] == 0
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", "new-builder")
    assert json.loads(tools._handle_request_review({"summary": "ready", "reviewer": "reviewer", "metadata": handoff}))["ok"] is True
    with kbc.connect() as conn:
        review = kb.claim_review_task(conn, tid, claimer="old-reviewer")
        request = 'kanban:' + json.dumps(["default", tid, review.current_run_id], separators=(',', ':'))
        kb._append_event(conn, tid, "owner_admitted", {"session_id": "session", "request_id": request,
            "db": "/owner/session.db", "pid": 123, "birth": 42.0}, run_id=review.current_run_id)
        kb._append_event(conn, tid, "owner_admission_bound", {"session_id": "session", "request_id": request,
            "admission_id": "admission"}, run_id=review.current_run_id)
        conn.execute("UPDATE tasks SET claim_lock='new-reviewer' WHERE id=?", (tid,))
        conn.execute("UPDATE task_runs SET claim_lock='new-reviewer' WHERE id=?", (review.current_run_id,))
    monkeypatch.setenv("HERMES_PROFILE", "reviewer")
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(review.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", review.claim_lock)
    verdict = {**handoff, "review_verdict": "approved"}
    cli_complete = ["kanban", "complete", tid, "--result", "done", "--metadata", json.dumps(verdict)]
    assert kc.kanban_command(parser.parse_args(cli_complete)) == 1
    assert json.loads(tools._handle_complete({"result": "done", "metadata": verdict})).get("ok") is not True
    with kbc.connect() as conn:
        assert kb.get_task(conn, tid).status == "running"
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0] == 0
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", "new-reviewer")
    assert json.loads(tools._handle_complete({"result": "done", "metadata": verdict}))["ok"] is True
