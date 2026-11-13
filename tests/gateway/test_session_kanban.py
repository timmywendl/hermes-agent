"""Task claims, not caller-supplied launch policy, authorize Kanban execution."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_claim_freezes_task_policy_and_rejects_forgery(tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'pyproject.toml').write_text('[project]\nname = "task"\n')  # a code worktree
    from contextlib import closing
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned acceptance', body='Goal criteria', assignee='default',
            workspace_kind='dir', workspace_path=str(workspace), skills=['owned-skill'], goal_mode=True,
            goal_max_turns=3, model_override='loop-model', provider_override='custom')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=SimpleNamespace(profile_id=str(tmp_path)), actor=actor, native_owner=True)
    params = dict(board='owned', task_id=task.id, run_id=task.current_run_id, claim_lock=task.claim_lock)
    from gateway.session_kanban import build_kanban_policy
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal', 'file']},
              'agent': {'coding_context': 'focus'}}  # the worktree must not collapse a worker into the coding posture
    policy, _secrets = build_kanban_policy(connection, params, config)
    context = json.loads(policy.kanban_json)
    assert policy.source == 'kanban' and policy.cwd == str(workspace)
    assert policy.model == task.model_override and policy.provider == task.provider_override
    assert {'kanban', 'terminal', 'file'} <= set(policy.toolsets)
    assert context['task_id'] == task.id and context['run_id'] == task.current_run_id
    assert context['board'] == 'owned' and context['claim_lock'] == task.claim_lock
    assert context['skills'] == ['owned-skill'] and context['goal_mode'] and context['goal_max_turns'] == 3
    assert context['accept_hooks'] is True and 'Goal criteria' in context['goal_text']
    for changed in ({'run_id': task.current_run_id + 1}, {'board': 'foreign'}, {'claim_lock': 'forged'}, {'cwd': '/tmp'}):
        with pytest.raises(RuntimeStoreError):
            build_kanban_policy(connection, params | changed, config)
    connection.native_owner = False
    with pytest.raises(RuntimeStoreError, match='permission_denied'):
        build_kanban_policy(connection, params, config)
    from gateway.session_policy import build_policy
    with pytest.raises(RuntimeStoreError, match='invalid_params'):
        build_policy({'source': 'kanban', 'cwd': str(workspace)}, config)


@pytest.mark.parametrize('mode', ['complete', 'timeout', 'rate_limit', 'billing', 'crash'])
def test_real_dispatcher_lifecycle(tmp_path, mode):
    import os
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[2]
    from tests.gateway.fixtures.local_recovery_probe import child_env
    env = child_env()
    env.update(HOME=str(tmp_path / 'home'), USERPROFILE=str(tmp_path / 'home'), HERMES_HOME=str(tmp_path / 'state'), PYTHONPATH=str(repo), KANBAN_PROBE_MODE=mode)
    result = subprocess.run([sys.executable, str(Path(__file__).parent / 'fixtures' / 'kanban_owner_probe.py')],
        env=env, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads((tmp_path / 'state' / 'receipt.json').read_text())
    print(json.dumps(receipt))
    if mode != 'complete':
        assert receipt['task_status'] == 'ready'
        return
    assert receipt['task_status'] == 'done' and receipt['source'] == 'kanban'
    assert receipt['tools'] and receipt['task_context'] and receipt['skill_context'] and receipt['hook_effect']
    assert receipt['admissions'] == 1 and receipt['retry_same_session']
    assert receipt['goal_continuation'] and receipt['stable_prefix']
    print(json.dumps(receipt))


def test_late_launcher_cannot_stamp_replacement_claim(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb, kanban_db_dispatch as dispatch
    from hermes_cli.kanban_db_connect import connect
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        tid = kb.create_task(conn, title='Owned race', assignee='default')
        old = kb.claim_task(conn, tid)
        kb.block_task(conn, tid, reason='replace claim', expected_run_id=old.current_run_id)
        kb.unblock_task(conn, tid)
        new = kb.claim_task(conn, tid)
        dispatch._set_worker_pid(conn, tid, 424242, run_id=old.current_run_id, claim_lock=old.claim_lock)
        assert kb.get_task(conn, tid).worker_pid is None
        assert conn.execute('SELECT worker_pid FROM task_runs WHERE id=?', (new.current_run_id,)).fetchone()[0] is None


def test_claim_reclaimed_before_admission_marker_is_refused(tmp_path, monkeypatch):
    """A claim that stops being current between policy/session creation and the marker
    transaction is refused: no owner_admitted row, no resume, no submit."""
    import asyncio
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned race', assignee='default', workspace_kind='dir', workspace_path=str(workspace))
        kb.recompute_ready(conn)
        old = kb.claim_task(conn, task_id)
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal']}}
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda: config)
    calls = []
    def create_local_session(authority, actor, params, *, trusted_policy=None, trusted_secrets=None):
        # Another process reclaims the task while the owner session is being created.
        with closing(connect(board='owned')) as conn:
            kb.block_task(conn, task_id, reason='replace claim', expected_run_id=old.current_run_id)
            kb.unblock_task(conn, task_id)
            kb.claim_task(conn, task_id)
        return SimpleNamespace(session_id='owner-session', profile_id=str(tmp_path))
    monkeypatch.setattr('gateway.session_local.create_local_session', create_local_session)
    async def submit(actor, submission):
        calls.append(('submit', submission))
    async def resume(ref, params):
        calls.append(('resume', ref))
    db = SimpleNamespace(get_session=lambda sid: None, db_path=str(tmp_path / 'state.db'))
    authority = SimpleNamespace(profile_id=str(tmp_path), db=db, submit=submit)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=authority, actor=actor, native_owner=True, resume=resume)
    params = dict(board='owned', task_id=task_id, run_id=old.current_run_id, claim_lock=old.claim_lock)
    from gateway.session_kanban import run_task
    with pytest.raises(RuntimeStoreError, match='stale_kanban_claim'):
        asyncio.run(run_task(connection, params))
    assert calls == []
    with closing(connect(board='owned')) as conn:
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0] == 0


@pytest.mark.parametrize('later_change', ['operator_backfill', 'new_developer_run'])
def test_delayed_reviewer_notification_cannot_use_later_task_result(tmp_path, monkeypatch, later_change):
    """A safe Review event must not acquire a later result at notification time."""
    import asyncio
    from contextlib import closing
    from unittest.mock import AsyncMock

    from gateway.kanban_watchers import GatewayKanbanWatchersMixin
    from gateway.platforms.base import BasePlatformAdapter
    from gateway import kanban_watchers_notifier as notifier
    from gateway.config import Platform
    from hermes_cli import kanban_db as kb, kanban_db_notify as kbn
    from hermes_cli.kanban_db_connect import connect

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    board = 'delayed-review'
    kb.create_board(board)
    later_file = tmp_path / 'later-developer.txt'
    later_file.write_text('synthetic disposable content')
    with closing(connect(board=board)) as conn:
        tid = kb.create_task(conn, title='Review one work item', assignee='default')
        kbn.add_notify_sub(conn, task_id=tid, platform='telegram', chat_id='disposable-chat')
        kb.recompute_ready(conn)
        developer = kb.claim_task(conn, tid)
        assert kb.request_review(conn, tid, summary='Ready for review',
                                 expected_run_id=developer.current_run_id)
        reviewer = kb.claim_review_task(conn, tid)
        # The proposed allowed tools can ensure exactly this safe completion.
        assert kb.complete_task(conn, tid, summary='Review passed', result=None,
                                expected_run_id=reviewer.current_run_id)
        event = conn.execute("SELECT id, run_id, payload FROM task_events WHERE task_id=? "
                             "AND kind='completed' ORDER BY id DESC LIMIT 1", (tid,)).fetchone()
        assert event['run_id'] == reviewer.current_run_id
        old_payload = json.loads(event['payload'])
        assert not old_payload.get('artifacts')
        assert kb.get_task(conn, tid).result is None
        if later_change == 'operator_backfill':
            assert kb.edit_task(conn, tid, result=str(later_file))
        else:
            from plugins.kanban.dashboard.plugin_api import _set_status_direct
            assert _set_status_direct(conn, tid, 'ready')
            next_run = kb.claim_task(conn, tid)
            assert next_run.current_run_id != reviewer.current_run_id
            assert kb.complete_task(conn, tid, result=str(later_file),
                                    expected_run_id=next_run.current_run_id)
        # Both supported independent mutations can outlive the old Review event.
        current_task = kb.get_task(conn, tid)
        assert current_task.result == str(later_file)

    adapter = SimpleNamespace(
        extract_local_files=BasePlatformAdapter.extract_local_files,
        send_document=AsyncMock(), send_multiple_images=AsyncMock(), send_video=AsyncMock(),
    )
    # Keep the real local-delivery filter; fixtures must meet its actual policy.
    assert str(later_file) in BasePlatformAdapter.filter_local_delivery_paths([str(later_file)])
    adapter.send = AsyncMock(return_value=SimpleNamespace(success=True))
    runner = SimpleNamespace(adapters={Platform.TELEGRAM: adapter}, _profile_adapters={},
                             _owns_kanban_dispatcher_lock=lambda: True)
    from types import MethodType
    runner._deliver_kanban_artifacts = MethodType(GatewayKanbanWatchersMixin._deliver_kanban_artifacts, runner)
    monkeypatch.setattr(notifier, '_adapter_for_subscription', lambda *a: adapter)
    collector = notifier._Collector(runner, kb, notifier_profile=None, gc_due=False, gc_retention_days=30)
    with closing(connect(board=board)) as conn:
        sub = kbn.list_notify_subs(conn)[0]
        delivery = collector._claim_for_sub(conn, board, sub)
    assert delivery['task'].result == current_task.result
    review_event = next(ev for ev in delivery['events'] if ev.id == event['id'])
    assert review_event.run_id == reviewer.current_run_id
    notification = notifier._KanbanNotification(runner, delivery, platform_cls=Platform, sub_fail_counts={})
    notification.adapter = adapter
    assert asyncio.run(notification._send_event(review_event, 'Review passed')) is True
    adapter.send.assert_awaited_once()
    # No network call is made: these are adapter spies around the real consumer.
    adapter.send_document.assert_not_awaited()
    adapter.send_multiple_images.assert_not_awaited()
    adapter.send_video.assert_not_awaited()
    assert later_file.read_text() == 'synthetic disposable content'


def test_developer_notification_keeps_legitimate_file_delivery(tmp_path):
    """A repair must preserve the existing Developer artifact delivery path."""
    import asyncio
    from unittest.mock import AsyncMock

    from gateway.kanban_watchers import GatewayKanbanWatchersMixin
    from gateway.platforms.base import BasePlatformAdapter

    deliverable = tmp_path / 'developer.txt'
    deliverable.write_text('disposable developer deliverable')
    adapter = SimpleNamespace(
        extract_local_files=BasePlatformAdapter.extract_local_files,
        send_document=AsyncMock(), send_multiple_images=AsyncMock(), send_video=AsyncMock(),
    )
    asyncio.run(GatewayKanbanWatchersMixin._deliver_kanban_artifacts(
        SimpleNamespace(), adapter=adapter, chat_id='disposable-chat', metadata={},
        event_payload={'summary': 'Developer output'}, task=SimpleNamespace(result=str(deliverable)),
    ))
    adapter.send_document.assert_awaited_once_with(
        chat_id='disposable-chat', file_path=str(deliverable), metadata={},
    )
    assert deliverable.read_text() == 'disposable developer deliverable'


from tests.tools.test_kanban_tools import reviewer_env as _reviewer_fixture
reviewer_env = _reviewer_fixture


def test_gateway_review_policy_keeps_only_current_task_context(reviewer_env):
    from contextlib import closing
    from gateway.session_contract import Principal
    from gateway.session_kanban import build_kanban_policy
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect

    with closing(connect(board='owned')) as conn:
        other = kb.create_task(conn, title='FOREIGN_ROLE_HISTORY_SECRET', assignee='default')
        assert kb.complete_task(conn, other, summary='FOREIGN_HANDOFF_SECRET')
        with kb.write_txn(conn):
            conn.execute('UPDATE tasks SET model_override=? WHERE id=?', ('synthetic-model', reviewer_env.task_id))
    actor = Principal('owner', reviewer_env.home, frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(native_owner=True, actor=actor,
                                 authority=SimpleNamespace(profile_id=reviewer_env.home))
    policy, _ = build_kanban_policy(connection, {
        'board': reviewer_env.board, 'task_id': reviewer_env.task_id,
        'run_id': reviewer_env.run_id, 'claim_lock': reviewer_env.claim_lock,
    }, {'model': {'default': 'synthetic', 'provider': 'custom'},
        'platform_toolsets': {'cli': ['terminal', 'file', 'web']}})
    context = json.loads(policy.kanban_json)
    assert context['reviewer'] is True and context['owner_home'] == reviewer_env.home
    assert 'abc123' in context['context']
    assert 'FOREIGN_ROLE_HISTORY_SECRET' not in context['context']
    assert 'FOREIGN_HANDOFF_SECRET' not in context['context']
    assert policy.toolsets == ('kanban',)


def test_reviewer_worker_rebuilds_current_context_instead_of_cached_policy(reviewer_env, monkeypatch):
    from gateway import session_kanban as worker

    context = dict(board=reviewer_env.board, task_id=reviewer_env.task_id, run_id=reviewer_env.run_id,
                   claim_lock=reviewer_env.claim_lock, db=reviewer_env.kanban_db,
                   profile=reviewer_env.profile, owner_home=reviewer_env.home,
                   context='LEGACY_CROSS_TASK_CONTEXT')
    agent = SimpleNamespace(session_id=reviewer_env.session_id)
    seen = []
    def run(agent, frame, history, current):
        seen.append(current['context'])
        return {'completed': True, 'final_response': 'offline review'}
    monkeypatch.setattr(worker, '_run_task_turns', run)
    monkeypatch.setattr(worker, '_record_worker_result', lambda *args: None)
    result = worker._run_worker_turns(agent, {'policy': {'kanban_json': json.dumps(context)}}, [])
    assert result['completed'] and agent._kanban_reviewer_binding == reviewer_env
    assert len(seen) == 1 and 'abc123' in seen[0]
    assert 'LEGACY_CROSS_TASK_CONTEXT' not in seen[0]


@pytest.mark.parametrize('missing', ['board', 'profile', 'owner_home'])
def test_reviewer_missing_locators_do_not_become_legacy_developer(reviewer_env, monkeypatch, missing):
    from unittest.mock import Mock
    from gateway import session_kanban as worker

    context = dict(board=reviewer_env.board, task_id=reviewer_env.task_id, run_id=reviewer_env.run_id,
                   claim_lock=reviewer_env.claim_lock, db=reviewer_env.kanban_db,
                   profile=reviewer_env.profile, owner_home=reviewer_env.home)
    del context[missing]
    # Empty paths must not acquire authority from a coincidentally matching cwd.
    monkeypatch.chdir(reviewer_env.home)
    model = Mock(side_effect=AssertionError('Reviewer must not fall back'))
    monkeypatch.setattr(worker, '_run_task_turns', model)
    monkeypatch.setattr(worker, '_record_worker_result', lambda *args: None)
    agent = SimpleNamespace(session_id=reviewer_env.session_id)
    with pytest.raises(ValueError):
        worker._run_worker_turns(agent, {'policy': {'kanban_json': json.dumps(context)}}, [])
    model.assert_not_called()


@pytest.mark.parametrize('mode', ['chat_completions', 'codex_responses', None])
def test_reviewer_cannot_use_unqualified_runtime(reviewer_env, monkeypatch, mode):
    from unittest.mock import Mock
    from gateway import session_kanban as worker

    monkeypatch.setattr('agent.skill_commands.build_preloaded_skills_prompt', lambda *a, **kw: ('', [], []))
    model = Mock(side_effect=AssertionError('no model may run'))
    agent = SimpleNamespace(session_id=reviewer_env.session_id, _kanban_reviewer_binding=reviewer_env,
                            api_mode=mode, run_conversation=model)
    with pytest.raises(ValueError, match='qualified Codex app-server'):
        worker._run_task_turns(agent, {'text': 'Review'}, [], {'skills': [], 'context': 'Current Task'})
    model.assert_not_called()


@pytest.mark.parametrize('origin', ['claimed_developer', 'operator_complete', 'operator_review_requested'])
def test_notifier_preserves_exact_developer_and_synthesized_operator_delivery(tmp_path, monkeypatch, origin):
    import asyncio
    from contextlib import closing
    from types import MethodType
    from unittest.mock import AsyncMock
    from gateway import kanban_watchers_notifier as notifier
    from gateway.config import Platform
    from gateway.kanban_watchers import GatewayKanbanWatchersMixin
    from gateway.platforms.base import BasePlatformAdapter
    from hermes_cli import kanban_db as kb, kanban_db_notify as kbn
    from hermes_cli.kanban_db_connect import connect

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    for key in ('HERMES_KANBAN_TASK', 'HERMES_KANBAN_RUN_ID', 'HERMES_KANBAN_DB', 'HERMES_DELEGATED_CHILD_CONTEXT'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    kb.create_board('operator-parity')
    document = tmp_path / 'permitted-developer.txt'
    document.write_text('permitted disposable output')
    with closing(connect(board='operator-parity')) as conn:
        tid = kb.create_task(conn, title='Deliver legitimate work', assignee='default')
        kbn.add_notify_sub(conn, task_id=tid, platform='telegram', chat_id='disposable-chat')
        kb.recompute_ready(conn)
        run_id = None
        if origin == 'claimed_developer':
            run_id = kb.claim_task(conn, tid).current_run_id
        if origin == 'operator_review_requested':
            assert kb.request_review(conn, tid, summary='Review this delivery', metadata={'artifacts': [str(document)]})
        else:
            assert kb.complete_task(conn, tid, result=str(document), expected_run_id=run_id)
    adapter = SimpleNamespace(extract_local_files=BasePlatformAdapter.extract_local_files,
        send_document=AsyncMock(), send_multiple_images=AsyncMock(), send_video=AsyncMock(),
        send=AsyncMock(return_value=SimpleNamespace(success=True)))
    runner = SimpleNamespace(adapters={Platform.TELEGRAM: adapter}, _profile_adapters={},
                             _owns_kanban_dispatcher_lock=lambda: True)
    runner._deliver_kanban_artifacts = MethodType(GatewayKanbanWatchersMixin._deliver_kanban_artifacts, runner)
    monkeypatch.setattr(notifier, '_adapter_for_subscription', lambda *a: adapter)
    collector = notifier._Collector(runner, kb, notifier_profile=None, gc_due=False, gc_retention_days=30)
    with closing(connect(board='operator-parity')) as conn:
        delivery = collector._claim_for_sub(conn, 'operator-parity', kbn.list_notify_subs(conn)[0])
    event = next(ev for ev in delivery['events'] if ev.kind in ('completed', 'review_requested'))
    assert event.run_id is not None
    notification = notifier._KanbanNotification(runner, delivery, platform_cls=Platform, sub_fail_counts={})
    notification.adapter = adapter
    assert asyncio.run(notification._send_event(event, 'Work delivered')) is True
    adapter.send_document.assert_awaited_once()
    assert Path(adapter.send_document.await_args.kwargs['file_path']).read_text() == 'permitted disposable output'


def _f7_historical_delivery(tmp_path, monkeypatch, *, kind, origin='developer', payload='artifacts',
                            mutation=None, later='manual'):
    from contextlib import closing
    from types import MethodType
    from unittest.mock import AsyncMock
    from gateway import kanban_watchers_notifier as notifier
    from gateway.config import Platform
    from gateway.kanban_watchers import GatewayKanbanWatchersMixin
    from gateway.platforms.base import BasePlatformAdapter
    from hermes_cli import kanban_db as kb, kanban_db_notify as kbn
    from hermes_cli.kanban_db_connect import connect

    for key in ('HERMES_KANBAN_TASK', 'HERMES_KANBAN_RUN_ID', 'HERMES_KANBAN_DB', 'HERMES_DELEGATED_CHILD_CONTEXT'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    original, future = tmp_path / 'original-event.txt', tmp_path / 'LATER_RESULT_SECRET.txt'
    original.write_text('ORIGINAL_FILE_CONTENT')
    future.write_text('LATER_FILE_CONTENT')
    assert BasePlatformAdapter.filter_local_delivery_paths([str(original), str(future)]) == [str(original), str(future)]
    kb.create_board('f7-history')
    with closing(connect(board='f7-history')) as conn:
        tid = kb.create_task(conn, title='Historical event', assignee='default', session_id='owner-session')
        kbn.add_notify_sub(conn, task_id=tid, platform='telegram', chat_id='disposable-chat', delivery_mode='notify+wake')
        kb.recompute_ready(conn)
        run_id = None if origin == 'operator' else kb.claim_task(conn, tid).current_run_id
        if origin == 'reviewer':
            assert kb.request_review(conn, tid, summary='Developer handoff', expected_run_id=run_id)
            run_id = kb.claim_review_task(conn, tid).current_run_id
        summary = 'ORIGINAL_EVENT_HANDOFF'
        if payload == 'summary':
            summary = 'Original output MEDIA: ' + str(original)
        metadata = {'artifacts': [str(original)]} if payload == 'artifacts' else None
        if kind == 'completed':
            assert kb.complete_task(conn, tid, summary=summary, metadata=metadata, expected_run_id=run_id)
        else:
            assert kb.request_review(conn, tid, summary=summary, metadata=metadata, expected_run_id=run_id)
        row = conn.execute('SELECT * FROM task_events WHERE task_id=? AND kind=? ORDER BY id DESC LIMIT 1', (tid, kind)).fetchone()
        event_id, old_run = row['id'], row['run_id']
        frozen_payload = json.loads(row['payload'])
        if payload == 'empty':
            # Represent a historical row whose payload predates summaries.
            summary = None
            frozen_payload['summary'] = None
            with kb.write_txn(conn):
                conn.execute('UPDATE task_events SET payload=? WHERE id=?', (json.dumps(frozen_payload), event_id))
        if later == 'new_run':
            from plugins.kanban.dashboard.plugin_api import _set_status_direct
            assert _set_status_direct(conn, tid, 'ready')
            successor = kb.claim_task(conn, tid)
            assert successor.current_run_id != old_run
            assert kb.complete_task(conn, tid, result=str(future), expected_run_id=successor.current_run_id)
        else:
            with kb.write_txn(conn):
                conn.execute('UPDATE tasks SET result=? WHERE id=?', (str(future), tid))
        with kb.write_txn(conn):
            if mutation == 'no_event_run':
                conn.execute('UPDATE task_events SET run_id=NULL WHERE id=?', (event_id,))
            elif mutation == 'missing_run':
                conn.execute('DELETE FROM task_runs WHERE id=?', (old_run,))
            elif mutation == 'wrong_task':
                other = kb.create_task(conn, title='Different task', assignee='default')
                conn.execute('UPDATE task_runs SET task_id=? WHERE id=?', (other, old_run))
            elif mutation == 'wrong_run':
                conn.execute('UPDATE task_events SET run_id=? WHERE id=?', (old_run + 10000, event_id))
            elif mutation in {'wrong_outcome', 'wrong_status', 'missing_end', 'invalid_run_time', 'operator_worker', 'operator_lock', 'operator_duration'}:
                columns = {'wrong_outcome': ('outcome', 'blocked'), 'wrong_status': ('status', 'running'),
                           'missing_end': ('ended_at', None), 'invalid_run_time': ('ended_at', 'unknown'),
                           'operator_worker': ('worker_pid', 424242),
                           'operator_lock': ('claim_lock', 'unproved'), 'operator_duration': ('started_at', 1)}
                column, value = columns[mutation]
                conn.execute(f'UPDATE task_runs SET {column}=? WHERE id=?', (value, old_run))
            elif mutation == 'foreign_operator_claim':
                other = kb.create_task(conn, title='Foreign claim', assignee='default')
                kb._append_event(conn, other, 'claimed', {'lock': 'foreign', 'expires': 9999999999,
                    'run_id': old_run}, run_id=old_run)
            elif mutation:
                claim = conn.execute("SELECT * FROM task_events WHERE task_id=? AND run_id=? AND kind='claimed'", (tid, old_run)).fetchone()
                source = json.loads(claim['payload'])
                if mutation == 'duplicate_claim':
                    kb._append_event(conn, tid, 'claimed', source, run_id=old_run)
                elif mutation == 'missing_claim':
                    conn.execute('DELETE FROM task_events WHERE id=?', (claim['id'],))
                elif mutation == 'invalid_claim_time':
                    conn.execute('UPDATE task_events SET created_at=? WHERE id=?', ('unknown', claim['id']))
                else:
                    values = {'review_claim': ('source_status', 'review'), 'unknown_claim': ('source_status', 'unknown'),
                              'null_source_status': ('source_status', None), 'wrong_claim_lock': ('lock', 'other'),
                              'wrong_claim_run': ('run_id', old_run + 1), 'invalid_expiry': ('expires', 0)}
                    if mutation not in {'malformed_claim', 'duplicate_keys', 'deep_claim'}:
                        key, value = values[mutation]
                        source[key] = value
                    raw = '{invalid' if mutation == 'malformed_claim' else json.dumps(source)
                    if mutation == 'duplicate_keys':
                        raw = raw.replace('"run_id":', '"run_id": 0, "run_id":')
                    if mutation == 'deep_claim':
                        raw = '[' * 1500 + '0' + ']' * 1500
                    conn.execute('UPDATE task_events SET payload=? WHERE id=?', (raw, claim['id']))
        assert kb.get_task(conn, tid).result == str(future)
        assert json.loads(conn.execute('SELECT payload FROM task_events WHERE id=?', (event_id,)).fetchone()[0]) == frozen_payload
    adapter = SimpleNamespace(extract_local_files=BasePlatformAdapter.extract_local_files,
        send_document=AsyncMock(), send_multiple_images=AsyncMock(), send_video=AsyncMock(),
        send=AsyncMock(return_value=SimpleNamespace(success=True)))
    runner = SimpleNamespace(adapters={Platform.TELEGRAM: adapter}, _profile_adapters={}, _owns_kanban_dispatcher_lock=lambda: True)
    runner._deliver_kanban_artifacts = MethodType(GatewayKanbanWatchersMixin._deliver_kanban_artifacts, runner)
    monkeypatch.setattr(notifier, '_adapter_for_subscription', lambda *a: adapter)
    collector = notifier._Collector(runner, kb, notifier_profile=None, gc_due=False, gc_retention_days=30)
    with closing(connect(board='f7-history')) as conn:
        delivery = collector._claim_for_sub(conn, 'f7-history', kbn.list_notify_subs(conn)[0])
    event = next(ev for ev in delivery['events'] if ev.id == event_id)
    assert delivery['cursor'] >= event_id and delivery['task'].result == str(future)
    # Deliver this historical event, not the successor's independently valid event.
    delivery['events'] = [event]
    notice = notifier._KanbanNotification(runner, delivery, platform_cls=Platform, sub_fail_counts={})
    notice.adapter = adapter
    paths = frozen_payload.get('artifacts', []) if payload == 'artifacts' else [str(original)] if payload == 'summary' else []
    return notice, adapter, event, paths, summary, future


def _assert_f7_event_delivery(notice, adapter, event, paths, summary, future):
    import asyncio
    from agent.i18n import t

    handoff = summary[:200] if summary else ''
    message = notice.format_event(event)
    expected = t('gateway.kanban.ping.' + event.kind, head=notice.head, title=notice.title,
                 handoff='\n' + handoff if handoff else '')
    assert message == expected
    notice.build_wake_text()
    wake = t('gateway.kanban.wake.message', task_id=notice.task_id,
             status=t('gateway.kanban.wake.' + event.kind), title=notice.title,
             assignee=notice.task.assignee, board=notice.board_slug)
    if handoff:
        wake += '\n' + t('gateway.kanban.wake.handoff', summary=handoff)
    assert notice.synth == wake + '\n\n' + t('gateway.kanban.wake.guidance')
    assert str(future) not in message + notice.synth
    assert asyncio.run(notice._send_event(event, message)) is True
    adapter.send.assert_awaited_once_with('disposable-chat', expected, metadata={})
    assert adapter.send_document.await_count == len(paths)
    assert [call.kwargs for call in adapter.send_document.await_args_list] == [
        {'chat_id': 'disposable-chat', 'file_path': path, 'metadata': {}} for path in paths]
    adapter.send_multiple_images.assert_not_awaited()
    adapter.send_video.assert_not_awaited()
    assert future.read_text() == 'LATER_FILE_CONTENT'


@pytest.mark.parametrize('kind', ['completed', 'review_requested'])
@pytest.mark.parametrize('later', ['manual', 'new_run'])
@pytest.mark.parametrize('missing_run', [False, True])
def test_f7_historical_event_never_borrows_later_task_result(tmp_path, monkeypatch, kind, later, missing_run):
    args = _f7_historical_delivery(tmp_path, monkeypatch, kind=kind, payload='empty', later=later,
                                  mutation='no_event_run' if missing_run else None)
    _assert_f7_event_delivery(*args)


@pytest.mark.parametrize('mutation', ['no_event_run', 'missing_run', 'wrong_task', 'wrong_run',
    'wrong_outcome', 'wrong_status', 'missing_end', 'duplicate_claim', 'malformed_claim', 'missing_claim',
    'review_claim', 'unknown_claim', 'null_source_status', 'wrong_claim_lock', 'wrong_claim_run', 'invalid_expiry',
    'duplicate_keys', 'deep_claim', 'invalid_claim_time', 'invalid_run_time'])
@pytest.mark.parametrize('kind', ['completed', 'review_requested'])
def test_f7_unproved_event_cannot_upload_even_immutable_artifacts(tmp_path, monkeypatch, mutation, kind):
    notice, adapter, event, _paths, summary, future = _f7_historical_delivery(tmp_path, monkeypatch, kind=kind, mutation=mutation)
    assert event.id not in notice.d['artifact_events']
    _assert_f7_event_delivery(notice, adapter, event, [], summary, future)


@pytest.mark.parametrize('origin', ['developer', 'operator'])
@pytest.mark.parametrize('kind', ['completed', 'review_requested'])
@pytest.mark.parametrize('payload', ['artifacts', 'summary'])
def test_f7_proven_event_uploads_only_its_immutable_payload(tmp_path, monkeypatch, origin, kind, payload):
    args = _f7_historical_delivery(tmp_path, monkeypatch, kind=kind, origin=origin, payload=payload)
    notice, _adapter, event, paths, _summary, _future = args
    assert event.id in notice.d['artifact_events'] and len(paths) == 1
    _assert_f7_event_delivery(*args)


@pytest.mark.parametrize('mutation', ['operator_worker', 'operator_lock', 'operator_duration', 'foreign_operator_claim'])
def test_f7_invalid_synthesized_operator_run_is_not_authority(tmp_path, monkeypatch, mutation):
    notice, adapter, event, _paths, summary, future = _f7_historical_delivery(
        tmp_path, monkeypatch, kind='completed', origin='operator', mutation=mutation)
    assert event.id not in notice.d['artifact_events']
    _assert_f7_event_delivery(notice, adapter, event, [], summary, future)


def test_f7_original_reviewer_run_cannot_upload_historical_payload(tmp_path, monkeypatch):
    notice, adapter, event, _paths, summary, future = _f7_historical_delivery(
        tmp_path, monkeypatch, kind='completed', origin='reviewer')
    assert event.id not in notice.d['artifact_events']
    _assert_f7_event_delivery(notice, adapter, event, [], summary, future)
