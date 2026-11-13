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
