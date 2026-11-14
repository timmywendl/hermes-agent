"""Codex app-server session lifecycle on hard agent teardown (#65260).

The Codex runtime drops ``agent._codex_session`` on turn crash and on
retirement (agent/codex_runtime.py), but ``AIAgent.close()`` — the hard
teardown for /new, /reset, and session expiry — had no owner for it, so
the app-server child process survived until interpreter exit.
"""

import threading

from run_agent import AIAgent


class _FakeCodexSession:
    def __init__(self, raises: bool = False):
        self.close_calls = 0
        self._raises = raises

    def close(self):
        self.close_calls += 1
        if self._raises:
            raise RuntimeError("app-server already dead")


def _bare_agent(session_id: str) -> AIAgent:
    """Minimal agent shell exercising close() without a real build."""
    agent = AIAgent.__new__(AIAgent)
    agent.session_id = session_id
    agent.client = None
    agent._active_children_lock = threading.Lock()
    agent._active_children = set()
    agent._end_session_on_close = False
    agent._session_messages = ["retained"]
    return agent


def test_agent_close_releases_codex_app_server_session(monkeypatch):
    agent = _bare_agent("test-codex-lifecycle")
    codex_session = _FakeCodexSession()
    agent._codex_session = codex_session

    monkeypatch.setattr("run_agent.cleanup_vm", lambda _task_id: None)
    monkeypatch.setattr("run_agent.cleanup_browser", lambda _task_id: None)

    agent.close()
    agent.close()

    # Idempotent: the second close must not re-close a released session.
    assert codex_session.close_calls == 1
    assert agent._codex_session is None
    assert agent._session_messages == []


def test_close_clears_reference_even_when_session_close_raises(monkeypatch):
    """A wedged app-server must not strand a stale session reference.

    The attribute is cleared BEFORE close() precisely so a raising close
    can't leave a dead session attached to the agent.
    """
    agent = _bare_agent("test-codex-lifecycle-raises")
    codex_session = _FakeCodexSession(raises=True)
    agent._codex_session = codex_session

    monkeypatch.setattr("run_agent.cleanup_vm", lambda _task_id: None)
    monkeypatch.setattr("run_agent.cleanup_browser", lambda _task_id: None)

    agent.close()

    assert codex_session.close_calls == 1
    assert agent._codex_session is None


def test_close_without_codex_session_is_a_noop(monkeypatch):
    """Non-Codex sessions (the common case) must be unaffected."""
    agent = _bare_agent("test-no-codex")

    monkeypatch.setattr("run_agent.cleanup_vm", lambda _task_id: None)
    monkeypatch.setattr("run_agent.cleanup_browser", lambda _task_id: None)

    agent.close()

    assert getattr(agent, "_codex_session", None) is None


def test_release_clients_releases_codex_app_server_session():
    """Gateway cache eviction (#72548, #66671) pops the agent and soft-releases it via release_clients();
    a rebuilt agent spawns its own app-server child, so the evicted one must be closed here too — and
    repeated release/close must not re-close it."""
    agent = _bare_agent("test-codex-evict")
    codex_session = _FakeCodexSession(raises=True)
    agent._codex_session = codex_session
    agent._session_messages = []

    agent.release_clients()
    agent.release_clients()

    assert codex_session.close_calls == 1
    assert agent._codex_session is None


import pytest
from tests.tools.test_kanban_tools import reviewer_env as _reviewer_fixture
reviewer_env = _reviewer_fixture


def test_loaded_developer_session_cannot_become_reviewer(reviewer_env, monkeypatch):
    from types import SimpleNamespace
    from agent import codex_runtime as runtime
    old = SimpleNamespace(_reviewer_binding=None)
    agent = SimpleNamespace(_codex_session=old, _kanban_reviewer_binding=reviewer_env)
    monkeypatch.setattr(runtime, '_codex_developer_instructions', lambda a: 'fixed prompt')
    monkeypatch.setattr(runtime, '_codex_model_provider', lambda a: None)
    with pytest.raises(ValueError, match='different Reviewer authority'):
        runtime._ensure_codex_session(agent)
    assert agent._codex_session is old


def test_original_developer_session_reuse_is_unchanged(monkeypatch):
    from types import SimpleNamespace
    from agent import codex_runtime as runtime
    old = SimpleNamespace(_reviewer_binding=None)
    agent = SimpleNamespace(_codex_session=old)
    monkeypatch.setattr(runtime, '_codex_developer_instructions', lambda a: 'fixed prompt')
    monkeypatch.setattr(runtime, '_codex_model_provider', lambda a: None)
    runtime._ensure_codex_session(agent)
    assert agent._codex_session is old


def test_private_gateway_binding_reaches_original_session(reviewer_env, monkeypatch):
    from types import SimpleNamespace
    from agent import codex_runtime as runtime
    from agent.transports import codex_app_server_session as transport
    agent = SimpleNamespace(_codex_session=None, _kanban_reviewer_binding=reviewer_env,
                             session_cwd=reviewer_env.home)
    monkeypatch.setattr(runtime, '_codex_developer_instructions', lambda a: 'fixed prompt')
    monkeypatch.setattr(runtime, '_codex_model_provider', lambda a: None)
    monkeypatch.setattr(runtime, '_stored_codex_thread_id', lambda a: None)
    monkeypatch.setattr(runtime, '_codex_wire_model', lambda a, p: 'synthetic-model')
    monkeypatch.setattr(runtime, 'make_codex_app_server_event_bridge', lambda a: None)
    monkeypatch.setattr('hermes_cli.config.load_config', dict)
    monkeypatch.setattr('hermes_cli.codex_runtime_switch.get_configured_codex_binary', lambda c: 'codex')
    captured = {}
    def session(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(_reviewer_binding=kwargs['reviewer_binding'])
    monkeypatch.setattr(transport, 'CodexAppServerSession', session)
    runtime._ensure_codex_session(agent)
    assert captured['reviewer_binding'] is reviewer_env
    assert captured['model'] == 'synthetic-model'
    assert captured['history_seed'] is None


def test_reviewer_thread_lineage_is_persisted_and_required_on_cold_resume(reviewer_env, tmp_path):
    from dataclasses import replace
    from types import SimpleNamespace
    from agent import codex_runtime as runtime
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / 'owner-session.db')
    db.create_session(reviewer_env.session_id, source='cli', model='synthetic-model')
    agent = SimpleNamespace(_session_db=db, session_id=reviewer_env.session_id,
                            _kanban_reviewer_binding=reviewer_env)
    try:
        db.patch_session_model_config(agent.session_id, {runtime._CODEX_THREAD_ID_KEY: 'old-developer'})
        with pytest.raises(ValueError, match='lineage'):
            runtime._stored_codex_thread_id(agent)
        runtime._store_codex_thread_id(agent, 'qualified-review')
        assert runtime._stored_codex_thread_id(agent) == 'qualified-review'
        # A new Python object with the same original authority may resume.
        agent._kanban_reviewer_binding = replace(reviewer_env)
        assert runtime._stored_codex_thread_id(agent) == 'qualified-review'
        agent._kanban_reviewer_binding = replace(reviewer_env, run_id=reviewer_env.run_id + 1)
        with pytest.raises(ValueError, match='lineage'):
            runtime._stored_codex_thread_id(agent)
    finally:
        db.close()


def test_reviewer_failed_resume_has_no_fresh_thread_fallback(reviewer_env):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from agent import codex_runtime as runtime
    from agent.transports.codex_app_server_session import CodexThreadResumeError

    session = SimpleNamespace(ensure_started=Mock(side_effect=CodexThreadResumeError('old', 'unavailable')))
    agent = SimpleNamespace(_codex_session=session, _kanban_reviewer_binding=reviewer_env)
    with pytest.raises(CodexThreadResumeError):
        runtime._start_codex_thread(agent)
    assert session.ensure_started.call_count == 1


def test_reviewer_denied_turn_has_zero_usage_and_no_auxiliary_calls(reviewer_env, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from agent import codex_runtime as runtime
    from agent.transports.codex_app_server_session import TurnResult

    turn = TurnResult(error='Reviewer permission qualification failed', should_retire=True)
    session = SimpleNamespace(ensure_started=lambda: 'review-thread', run_turn=lambda **kw: turn, close=Mock())
    agent = SimpleNamespace(_codex_session=session, _kanban_reviewer_binding=reviewer_env,
                            session_api_calls=0, _session_db=SimpleNamespace(queue_token_counts=Mock()),
                            _sync_external_memory_for_turn=Mock(), _spawn_background_review=Mock())
    monkeypatch.setattr(runtime, '_ensure_codex_session', lambda *a: None)
    monkeypatch.setattr(runtime, '_codex_wire_model', lambda *a: 'synthetic-model')
    monkeypatch.setattr(runtime, '_codex_turn_effort', lambda *a: None)
    monkeypatch.setattr(runtime, '_codex_turn_service_tier', lambda *a: None)
    result = runtime.run_codex_app_server_turn(agent, user_message='review', original_user_message='review',
                                               messages=[], effective_task_id='review')
    assert result['api_calls'] == agent.session_api_calls == 0
    assert not result['completed'] and result['error']
    agent._session_db.queue_token_counts.assert_not_called()
    agent._sync_external_memory_for_turn.assert_not_called()
    agent._spawn_background_review.assert_not_called()
    session.close.assert_called_once()


def test_reviewer_error_cannot_activate_original_provider_fallback(reviewer_env, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from agent import codex_runtime as runtime
    from agent.turn_recovery import activate_codex_app_server_fallback

    agent = SimpleNamespace(_kanban_reviewer_binding=reviewer_env, _codex_session=None,
                            _fallback_chain=[{'provider': 'must-not-run', 'model': 'forbidden'}],
                            _fallback_index=0, _try_activate_fallback=Mock())
    agent._has_pending_fallback = lambda: AIAgent._has_pending_fallback(agent)
    def unavailable(*args):
        raise ValueError('429 rate_limit exceeded')
    monkeypatch.setattr(runtime, '_ensure_codex_session', unavailable)
    result = runtime.run_codex_app_server_turn(agent, user_message='review', original_user_message='review',
                                               messages=[], effective_task_id='review')
    assert result['error'] and result['api_calls'] == 0
    assert not activate_codex_app_server_fallback(agent, result)
    assert '/codex-runtime auto' not in result['final_response']
    agent._try_activate_fallback.assert_not_called()


# These fixtures retain the public facade, real Store and Session protocol path.
from tests.agent.transports.test_codex_app_server_session import reviewer_session as _session_fixture
reviewer_session = _session_fixture


def _review_store_snapshot(binding):
    import sqlite3
    from pathlib import Path

    with sqlite3.connect(Path(binding.kanban_db).as_uri() + '?mode=ro', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        return {table: [dict(row) for row in conn.execute('SELECT * FROM ' + table + ' ORDER BY id')]
                for table in ('tasks', 'task_runs', 'task_events')}


def _assert_only_current_review_liveness(before, after, binding):
    # Compare every field in every row, not just aggregate counts.
    for table, current in (('tasks', binding.task_id), ('task_runs', binding.run_id)):
        assert [row['id'] for row in before[table]] == [row['id'] for row in after[table]]
        for old, new in zip(before[table], after[table]):
            changed = {key for key in old if old[key] != new[key]}
            assert not changed or (old['id'] == current and
                                   changed <= {'claim_expires', 'last_heartbeat_at'})
    assert after['task_events'][:len(before['task_events'])] == before['task_events']
    for event in after['task_events'][len(before['task_events']):]:
        assert (event['kind'], event['task_id'], event['run_id'], event['payload']) == (
            'heartbeat', binding.task_id, binding.run_id, None)


@pytest.fixture
def public_reviewer_entry(reviewer_session, tmp_path, monkeypatch):
    import collections
    from types import SimpleNamespace

    import httpx
    import requests
    from agent import auxiliary_client
    from hermes_cli import plugins
    from hermes_state import SessionDB
    from tools import kanban_tools as kt

    session, client, wire = reviewer_session
    binding = session._reviewer_binding
    counts = collections.Counter()
    phase = {'value': 'constructor'}
    marker = tmp_path / 'unauthorized-callback.txt'

    def no_network(*args, **kwargs):
        counts['network_' + phase['value']] += 1
        raise AssertionError('offline test blocks physical HTTP sends')

    for target, method in ((httpx.Client, 'send'), (httpx.AsyncClient, 'send'),
                           (requests.sessions.Session, 'request')):
        monkeypatch.setattr(target, method, no_network)

    def auxiliary_stub(*args, **kwargs):
        counts['auxiliary_intents'] += 1
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='offline stub'))])

    def callback(name, result=None):
        def invoke(*args, **kwargs):
            counts[name] += 1
            marker.write_text(name)
            counts['marker_writes'] += 1
            auxiliary_client.call_llm(task=name, messages=[])
            return result
        return invoke

    monkeypatch.setattr(auxiliary_client, 'call_llm', auxiliary_stub)
    manager = plugins.PluginManager()
    manager._discovered = True
    monkeypatch.setattr(plugins, 'get_plugin_manager', lambda: manager)
    monkeypatch.setattr(plugins, 'render_system_prompt_sections', callback('plugin_renderer', ()))
    monkeypatch.setattr('agent.title_generator.maybe_auto_title', callback('title'))
    manager._hooks['pre_llm_call'] = [callback('pre_llm', {'context': 'bounded callback context'})]
    manager._hooks['on_session_start'] = [callback('session_start')]

    class Memory:
        providers = []
        on_turn_start = staticmethod(callback('memory_start'))
        prefetch_all = staticmethod(callback('memory_prefetch', ''))
        build_system_prompt = staticmethod(callback('memory_prompt', 'external memory callback'))

        def describe_recall(self):
            return None

    db = SessionDB(tmp_path / 'isolated-owner-session.db')
    agent = None
    try:
        agent = AIAgent(model='offline-entry-fence', provider='custom', api_mode='codex_app_server',
            api_key='offline-key', base_url='http://127.0.0.1:1/v1', quiet_mode=True,
            skip_context_files=True, skip_memory=True, skip_background_review=True,
            enabled_toolsets=['kanban', 'memory'], session_db=db, session_id=binding.session_id)
        agent._kanban_reviewer_binding = binding
        agent._codex_session = session
        agent._codex_session_prompt = None
        agent._cached_system_prompt = 'Current isolated Review Task context.'
        agent._memory_manager = Memory()
        agent._fallback_chain = [{'provider': 'forbidden', 'model': 'never'}]
        agent._fallback_index = 0
        monkeypatch.setattr(agent, '_try_activate_fallback', callback('fallback'))
        monkeypatch.setattr(agent, '_try_refresh_env_client_credentials', callback('credentials'))
        monkeypatch.setattr(agent, 'reaction_callback', callback('reaction'))
        original_restore = agent._restore_primary_runtime
        def restore_runtime():
            counts['runtime_restore'] += 1
            return original_restore()
        monkeypatch.setattr(agent, '_restore_primary_runtime', restore_runtime)
        # Configure a real late-MCP refresh opportunity, replacing only its external edge.
        from importlib import import_module
        import_module('tools.mcp_tool')
        monkeypatch.setattr('tools.mcp_tool_discovery.has_registered_mcp_tools', lambda: True)
        monkeypatch.setattr('tools.mcp_tool_agent.refresh_agent_mcp_tools', callback('mcp_refresh'))
        monkeypatch.setattr(kt, '_auto_heartbeat_last_attempt', 0.0)
        original_handler = client._request_handler
        gate = {'deny': 'extra'}

        def handler(method, params):
            response = original_handler(method, params)
            if method == 'mcpServerStatus/list' and not params.get('serverName'):
                if gate['deny'] == '429':
                    from agent.transports.codex_app_server import CodexAppServerError
                    raise CodexAppServerError(code=-32603, message='429 rate_limit exceeded')
                if gate['deny'] == 'extra':
                    response['data'].append({'name': 'unexpected-server'})
            return response

        client._request_handler = handler

        def call(*, reviewer=True, history=None, message='Review current task and report verified findings.'):
            phase['value'] = 'public_entry'
            with kt.reviewer_tool_scope(binding if reviewer else None):
                return agent.run_conversation(message,
                    system_message='Authorized current Task description and exact HEAD.',
                    conversation_history=history)

        yield SimpleNamespace(agent=agent, session=session, client=client, gate=gate,
            wire=wire, binding=binding, counts=counts, marker=marker, db=db, call=call,
            manager=manager, callback=callback, phase=phase)
    finally:
        if agent is not None:
            agent._memory_manager = None
            agent.close()
        db.close()


def _assert_no_reviewer_aux(entry):
    forbidden = ('pre_llm', 'session_start', 'memory_start', 'memory_prefetch', 'memory_prompt',
                 'plugin_renderer', 'title', 'compression', 'fallback', 'credentials', 'reaction',
                 'network_public_entry', 'auxiliary_intents', 'marker_writes',
                 'runtime_restore', 'mcp_refresh')
    assert all(entry.counts[name] == 0 for name in forbidden), dict(entry.counts)
    assert not entry.marker.exists()


@pytest.mark.parametrize('mode', ['warm', 'configured', 'fresh', 'slow_idle', '429'])
def test_reviewer_public_entry_fences_generic_side_effects(public_reviewer_entry, monkeypatch, mode):
    import json
    import time
    from agent import conversation_loop

    entry = public_reviewer_entry
    if mode == 'warm':
        entry.agent._memory_manager = None
        entry.manager._hooks.clear()
    if mode in {'fresh', 'slow_idle'}:
        entry.agent._cached_system_prompt = None
    if mode == '429':
        entry.gate['deny'] = '429'
    if mode == 'slow_idle':
        # Delay an actual OS setup boundary after lease.start. No predicate/clock rewrite.
        original_stdio = conversation_loop._install_safe_stdio
        def slow_stdio():
            original_stdio()
            threading.Event().wait(1.05)  # health: allow HX013 -- real idle expiry is under test; no clock/predicate override
        monkeypatch.setattr(conversation_loop, '_install_safe_stdio', slow_stdio)
        entry.agent.compression_enabled = True
        entry.agent.compression_idle_compact_after_seconds = 1
        entry.agent.context_compressor.threshold_tokens = 2
        entry.agent.context_compressor.summary_target_ratio = 0.5
        entry.agent.context_compressor.awaiting_real_usage_after_compression = False
        monkeypatch.setattr(entry.agent, '_compress_context', entry.callback('compression'))
    before = _review_store_snapshot(entry.binding)
    started = time.monotonic()
    result = entry.call()
    after = _review_store_snapshot(entry.binding)
    print('PUBLIC_ENTRY_RECEIPT=' + json.dumps({'mode': mode, 'counts': dict(entry.counts),
        'before': before, 'after': after, 'messages': entry.db.get_messages(entry.agent.session_id),
        'api_calls': result['api_calls'], 'completed': result['completed']}, default=str))
    assert result['error'] and result['api_calls'] == 0 and not result['completed']
    assert entry.agent._last_turn_usage is None
    assert not any(method == 'turn/start' for method, _ in entry.client.requests)
    _assert_no_reviewer_aux(entry)
    _assert_only_current_review_liveness(before, after, entry.binding)
    assert len(after['task_events']) == len(before['task_events']) + 1
    if mode == 'slow_idle':
        assert time.monotonic() - started >= 1.0


@pytest.mark.parametrize('mode', ['missing_owner', 'expired_claim', 'foreign_task'])
def test_reviewer_public_entry_rejects_untrusted_liveness(public_reviewer_entry, monkeypatch, mode):
    import json
    import sqlite3
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect

    entry = public_reviewer_entry
    with sqlite3.connect(entry.binding.kanban_db) as conn:
        if mode == 'missing_owner':
            conn.execute("DELETE FROM task_events WHERE kind='owner_admitted'")
        elif mode == 'expired_claim':
            conn.execute('UPDATE tasks SET claim_expires=1')
            conn.execute('UPDATE task_runs SET claim_expires=1 WHERE id=?', (entry.binding.run_id,))
    if mode == 'foreign_task':
        with closing(connect(board=entry.binding.board)) as conn:
            foreign = kb.create_task(conn, title='Foreign Developer task', assignee='default')
            kb.recompute_ready(conn)
            claim = kb.claim_task(conn, foreign, claimer='foreign-claim')
        for key, value in {'TASK': foreign, 'RUN_ID': str(claim.current_run_id),
                           'CLAIM_LOCK': claim.claim_lock}.items():
            monkeypatch.setenv('HERMES_KANBAN_' + key, value)
    before = _review_store_snapshot(entry.binding)
    try:
        result = entry.call()
        assert result['error'] and result['api_calls'] == 0 and not result['completed']
    except ValueError:
        pass  # Original binding validation is an explicit denial, not a Developer fallback.
    after = _review_store_snapshot(entry.binding)
    print('UNTRUSTED_LIVENESS_RECEIPT=' + json.dumps({'mode': mode, 'before': before,
        'after': after, 'counts': dict(entry.counts)}))
    _assert_no_reviewer_aux(entry)
    assert not any(method == 'turn/start' for method, _ in entry.client.requests)
    assert before == after, 'Untrusted Review provenance must not obtain liveness writes'


@pytest.mark.parametrize('field', ['missing', 'task_id', 'run_id', 'board', 'session_id',
                                  'owner_db', 'claimed_event_id', 'runtime'])
def test_public_entry_cannot_downgrade_review_identity(public_reviewer_entry, monkeypatch, field):
    from dataclasses import replace
    entry = public_reviewer_entry
    if field == 'missing':
        entry.agent._kanban_reviewer_binding = None
    elif field == 'runtime':
        entry.agent.api_mode = 'chat_completions'
    else:
        old = getattr(entry.binding, field)
        entry.agent._kanban_reviewer_binding = replace(entry.binding,
            **{field: old + 1 if type(old) is int else 'foreign-' + old})
    with pytest.raises(ValueError):
        entry.call()
    _assert_no_reviewer_aux(entry)
    assert entry.client.requests == []


def test_public_reviewer_rechecks_every_turn(public_reviewer_entry):
    entry = public_reviewer_entry
    entry.gate['deny'] = None
    first = entry.call()
    assert not first.get('error')
    assert [method for method, _ in entry.client.requests].count('turn/start') == 1
    entry.gate['deny'] = '429'
    second = entry.call(history=first['messages'])
    assert second['error'] and second['api_calls'] == 0 and not second['completed']
    assert [method for method, _ in entry.client.requests].count('turn/start') == 1
    _assert_no_reviewer_aux(entry)


def test_public_reviewer_reaction_cannot_invoke_a_callback(public_reviewer_entry):
    entry = public_reviewer_entry
    result = entry.call(message='Thank you! Review the current task and report verified findings.')
    assert result['error'] and result['api_calls'] == 0
    _assert_no_reviewer_aux(entry)


def test_developer_public_entry_keeps_normal_callbacks(public_reviewer_entry, monkeypatch):
    entry = public_reviewer_entry
    for name in ('TASK', 'RUN_ID', 'CLAIM_LOCK', 'DB', 'BOARD'):
        monkeypatch.delenv('HERMES_KANBAN_' + name, raising=False)
    entry.agent._kanban_reviewer_binding = None
    entry.session._reviewer_binding = None
    entry.agent._cached_system_prompt = None
    entry.gate['deny'] = None
    result = entry.call(reviewer=False, message='Thank you! Review current task and report verified findings.')
    assert not result.get('error')
    for name in ('pre_llm', 'session_start', 'memory_start', 'memory_prefetch',
                 'memory_prompt', 'plugin_renderer', 'title', 'credentials', 'runtime_restore',
                 'mcp_refresh', 'reaction'):
        assert entry.counts[name] == 1, (name, dict(entry.counts))
    assert entry.counts['auxiliary_intents'] >= 7
    assert entry.marker.exists()
    assert entry.counts['network_public_entry'] == 0
    assert [method for method, _ in entry.client.requests].count('turn/start') == 1


@pytest.mark.parametrize('with_run_id', [True, False])
def test_developer_native_liveness_keeps_local_and_worker_paths(public_reviewer_entry, monkeypatch, with_run_id):
    import json
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect

    entry = public_reviewer_entry
    with closing(connect(board=entry.binding.board)) as conn:
        tid = kb.create_task(conn, title='Original Developer claim', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, tid, claimer='original-developer')
    for key, value in {'TASK': tid, 'RUN_ID': str(task.current_run_id), 'CLAIM_LOCK': task.claim_lock}.items():
        monkeypatch.setenv('HERMES_KANBAN_' + key, value)
    if not with_run_id:
        monkeypatch.delenv('HERMES_KANBAN_RUN_ID')
    entry.agent._kanban_reviewer_binding = None
    entry.session._reviewer_binding = None
    entry.gate['deny'] = None
    before = _review_store_snapshot(entry.binding)
    result = entry.call(reviewer=False)
    assert not result.get('error')
    after = _review_store_snapshot(entry.binding)
    events = after['task_events'][len(before['task_events']):]
    assert len(events) == 1
    assert (events[0]['kind'], events[0]['task_id'], events[0]['run_id']) == ('heartbeat', tid, task.current_run_id)
    for table in ('tasks', 'task_runs'):
        original = [row for row in before[table] if row.get('task_id', row['id']) == entry.binding.task_id]
        retained = [row for row in after[table] if row.get('task_id', row['id']) == entry.binding.task_id]
        assert original == retained
    print('DEVELOPER_LIVENESS_RECEIPT=' + json.dumps({'with_run_id': with_run_id, 'before': before, 'after': after}))


def test_missing_original_reviewer_scope_cannot_become_developer(public_reviewer_entry):
    from tools.kanban_tools import reviewer_tool_scope
    entry = public_reviewer_entry
    before = _review_store_snapshot(entry.binding)
    with reviewer_tool_scope(None), pytest.raises(ValueError):
        entry.agent.run_conversation('Review current task')
    assert _review_store_snapshot(entry.binding) == before
    assert entry.client.requests == []
    _assert_no_reviewer_aux(entry)


@pytest.mark.parametrize('locator', ['BOARD', 'RUN_ID', 'CLAIM_LOCK', 'DB', 'HERMES_PROFILE',
                                   'HERMES_HOME', 'HERMES_SESSION_ID'])
def test_reviewer_auto_heartbeat_rejects_env_drift(public_reviewer_entry, monkeypatch, locator):
    from tools.kanban_tools import heartbeat_current_worker_from_env, reviewer_tool_scope
    entry = public_reviewer_entry
    key = locator if locator.startswith('HERMES_') else 'HERMES_KANBAN_' + locator
    monkeypatch.setenv(key, 'untrusted-locator')
    before = _review_store_snapshot(entry.binding)
    with reviewer_tool_scope(entry.binding):
        assert heartbeat_current_worker_from_env() is False
    assert _review_store_snapshot(entry.binding) == before
    _assert_no_reviewer_aux(entry)


def test_reviewer_auto_heartbeat_preserves_throttle(public_reviewer_entry):
    from tools.kanban_tools import heartbeat_current_worker_from_env, reviewer_tool_scope
    entry = public_reviewer_entry
    before = _review_store_snapshot(entry.binding)
    with reviewer_tool_scope(entry.binding):
        assert heartbeat_current_worker_from_env() is True
        renewed = _review_store_snapshot(entry.binding)
        assert heartbeat_current_worker_from_env() is False
    assert _review_store_snapshot(entry.binding) == renewed
    _assert_only_current_review_liveness(before, renewed, entry.binding)
    assert len(renewed['task_events']) == len(before['task_events']) + 1


def test_reviewer_auto_heartbeat_reports_partial_renewal(public_reviewer_entry, monkeypatch, caplog):
    import json
    import sqlite3
    import time
    from tools.kanban_tools import heartbeat_current_worker_from_env, reviewer_tool_scope

    entry = public_reviewer_entry
    # An original, still-live fixture claim with less time remaining than its original TTL.
    with sqlite3.connect(entry.binding.kanban_db) as conn:
        expiry = int(time.time()) + 60
        conn.execute('UPDATE tasks SET claim_expires=?', (expiry,))
        conn.execute('UPDATE task_runs SET claim_expires=? WHERE id=?', (expiry, entry.binding.run_id))
    monkeypatch.setattr('hermes_cli.kanban_db_dispatch.heartbeat_worker', lambda *args, **kwargs: False)
    before = _review_store_snapshot(entry.binding)
    with reviewer_tool_scope(entry.binding), caplog.at_level('WARNING', logger='tools.kanban_tools'):
        assert heartbeat_current_worker_from_env() is False
    after = _review_store_snapshot(entry.binding)
    assert after != before
    _assert_only_current_review_liveness(before, after, entry.binding)
    assert after['task_events'] == before['task_events']
    assert 'partial: claim renewed' in caplog.text
    print('PARTIAL_LIVENESS_RECEIPT=' + json.dumps({'before': before, 'after': after}))


def test_reviewer_missing_prompt_cannot_broaden_callbacks(public_reviewer_entry):
    entry = public_reviewer_entry
    entry.agent._cached_system_prompt = ''
    with pytest.raises(ValueError, match='prompt context unavailable'):
        entry.call()
    assert entry.client.requests == []
    _assert_no_reviewer_aux(entry)


@pytest.mark.parametrize(('reviewer', 'surface'), [(True, 'cli'), (False, 'cli'), (False, 'tui')])
def test_constructor_fence_preserves_developer_initialization(reviewer_env, tmp_path, monkeypatch, reviewer, surface):
    import collections
    import json
    import httpx
    import requests
    from agent import agent_init
    from hermes_state import SessionDB
    from tools.kanban_tools import reviewer_tool_scope

    counts = collections.Counter()
    marker = tmp_path / 'constructor-external-effect'
    def sink(name, result=None):
        def call(*args, **kwargs):
            counts[name] += 1
            marker.write_text(name)
            return result
        return call
    def no_http(*args, **kwargs):
        counts['http_attempt'] += 1
        raise AssertionError('no host HTTP in Reviewer constructor')
    monkeypatch.setattr(httpx.Client, 'send', no_http)
    monkeypatch.setattr(httpx.AsyncClient, 'send', no_http)
    monkeypatch.setattr(requests.sessions.Session, 'request', no_http)
    for path, name in (
        ('hermes_cli.left_core_migration.recover_at_startup', 'startup_migration'),
        ('hermes_cli.plugins.discover_plugins', 'plugin_discovery'),
        ('plugins.memory.load_memory_provider', 'memory_plugin'),
        ('hermes_cli.memory_provider_migration.recover_at_startup', 'memory_migration'),
        ('plugins.context_engine.load_context_engine', 'context_engine_plugin'),
        ('hermes_cli.plugins.get_plugin_context_engine', 'context_engine_callback'),
        ('tools.env_probe.warm_environment_probe_async', 'background_probe'),
    ):
        monkeypatch.setattr(path, sink(name))
    monkeypatch.setattr(AIAgent, '_ensure_lmstudio_runtime_loaded', sink('lmstudio_probe_load'))
    config = {'model': {'default': 'offline-unknown', 'provider': 'custom'},
              'memory': {'provider': 'external-negative'}, 'context': {'engine': 'external-negative'}}
    monkeypatch.setattr('hermes_cli.config.load_config_readonly', lambda: config)
    if not reviewer:
        for suffix in ('TASK', 'RUN_ID', 'CLAIM_LOCK', 'DB', 'BOARD'):
            monkeypatch.delenv('HERMES_KANBAN_' + suffix, raising=False)
    db = SessionDB(tmp_path / 'constructor-session.db')
    agent = None
    try:
        with reviewer_tool_scope(reviewer_env if reviewer else None):
            agent = AIAgent(model='offline-unknown', provider='custom', api_mode='codex_app_server',
                base_url='http://127.0.0.1:1/v1', api_key='offline-only', quiet_mode=True,
                session_id=reviewer_env.session_id, session_db=db, platform=surface,
                _reviewer_binding=reviewer_env if reviewer else None,
                enabled_toolsets=['kanban'], skip_context_files=True)
        if reviewer:
            assert agent._kanban_reviewer_binding == reviewer_env
            assert agent.api_mode == 'codex_app_server' and agent.client is None
            assert agent._reviewer_context_length_status == 'UNKNOWN'
            assert agent.context_compressor.name == 'compressor'
            assert agent.valid_tool_names == {'kanban_heartbeat', 'kanban_complete', 'kanban_request_changes', 'kanban_block'}
            assert not counts and not marker.exists(), dict(counts)
            print('EARLY_CONSTRUCTOR_RECEIPT=' + json.dumps({'counts': dict(counts), 'context_status': 'UNKNOWN'}))
        else:
            assert agent.client is not None
            for name in ('startup_migration', 'plugin_discovery', 'memory_plugin', 'context_engine_plugin',
                         'lmstudio_probe_load', 'background_probe'):
                assert counts[name] >= 1, (name, dict(counts))
            assert counts['http_attempt'] >= 1 and marker.exists()
            print('DEVELOPER_CONSTRUCTOR_RECEIPT=' + json.dumps({'surface': surface, 'counts': dict(counts)}))
    finally:
        if agent is not None:
            agent.close()
        db.close()
