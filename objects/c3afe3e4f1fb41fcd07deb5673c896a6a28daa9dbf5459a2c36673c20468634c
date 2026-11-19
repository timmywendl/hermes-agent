"""Original Core evidence persists before use and fresh hooks only read selectors."""
import copy
import sqlite3
import time

import pytest

from agent.native_capabilities import (
    HookScope,
    commit_capability,
    hook_scope,
    intake_capability,
)
from agent.native_turn import current_invocation, digest
from tests.agent import test_native_isolated_capabilities as native_fixtures

native = native_fixtures.native
_Channel = native_fixtures._Channel


def original(native):
    _, host, state = native
    channel = _Channel(host)
    host._channels.append(channel)
    invocation = host.invocation('colleague_query')
    token = current_invocation.set(invocation)
    try:
        evidence = host.record_result(invocation, control_request_id='request', context_revision='c',
            mission_revision='m', query_result_digest='q', output='verified', result_ref='result',
            control_epoch='control1', channel_ref='channel1', project_id='cloud')
    finally:
        current_invocation.reset(token)
    state.closed = True
    receipt = {'output_commit_status': 'OUTPUT_COMMITTED', 'gate_decision': 'OUTPUT_GATE_PASSED',
               'final_output_digest': digest(evidence.output)}
    return channel, evidence, commit_capability(host, evidence, state, receipt)


def hook(native, channel):
    state = native[2]
    state.closed = False
    scope = HookScope('pre_llm_call', {'user_message': 'Check Cloud Test status'})
    return scope, hook_scope.set(scope)


def test_durable_commit_precedes_rpc_and_exact_cleanup(native):
    _, _, state = native
    channel, _, cap = original(native)
    def remote(invocation, frame, **kwargs):
        rows = state.recovery_store._read_all('SELECT * FROM native_response_use_hints')
        assert len(rows) == 1 and rows[0]['request_id'] == 'request'
        assert rows[0]['original_turn_id'] == state.ingress.turn
        return {'request_id': 'request', 'request_state': 'COMPLETED_READ_ONLY'}
    channel._call = remote
    assert cap.response_used()['request_state'] == 'COMPLETED_READ_ONLY'
    assert state.recovery_store._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 0
    with pytest.raises(PermissionError):
        cap.response_used()


@pytest.mark.parametrize('mode', ['missing', 'full', 'busy', 'readonly', 'unknown_commit'])
def test_failed_or_uncertain_hint_commit_never_calls_control(native, monkeypatch, mode):
    state = native[2]
    channel, _, cap = original(native)
    calls = []
    channel._call = lambda *a, **kw: calls.append(a)
    if mode == 'missing':
        state.recovery_store = None
    elif mode == 'readonly':
        monkeypatch.setattr(state.recovery_store, 'read_only', True)
    else:
        original_write = state.recovery_store._execute_write
        def fail(fn, **kw):
            if mode == 'unknown_commit':
                original_write(fn, **kw)
            raise sqlite3.OperationalError(mode)
        monkeypatch.setattr(state.recovery_store, '_execute_write', fail)
    assert cap.response_used() == {'state': 'UNKNOWN'}
    assert calls == []
    if mode == 'unknown_commit':
        assert state.recovery_store._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 1


@pytest.mark.parametrize('change', ['finished', 'generation', 'evidence', 'deadline', 'policy'])
def test_revalidate_after_persistence_before_control_call(native, monkeypatch, change):
    _, host, state = native
    channel, evidence, cap = original(native)
    calls = []
    channel._call = lambda *a, **kw: calls.append(a)
    original_write = state.recovery_store.native_response_use
    def changed(*args, **kw):
        result = original_write(*args, **kw)
        actions = {
            'finished': lambda: setattr(state, 'finished', True),
            'generation': lambda: setattr(host, 'generation', 'changed'),
            'evidence': lambda: state.evidence.update({host.plugin_id: copy.copy(evidence)}),
            'policy': lambda: monkeypatch.setattr(state, 'policy_valid', lambda: False),
            'deadline': lambda: object.__setattr__(cap, '_deadline', 0),
        }
        actions[change]()
        return result
    monkeypatch.setattr(state.recovery_store, 'native_response_use', changed)
    with pytest.raises(PermissionError):
        cap.response_used()
    assert calls == []
    assert state.recovery_store._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 1


@pytest.mark.parametrize('receipt', [
    {'request_id': 'wrong', 'request_state': 'COMPLETED_READ_ONLY'},
    {'request_id': 'request', 'request_state': 'RECEIVED'},
    {'request_id': 'request', 'request_state': 'PARTIAL'},
    {'request_id': 'request', 'request_state': 'UNKNOWN'},
    {'status': 'REJECTED', 'reason': 'UNKNOWN'}, TimeoutError(),
])
def test_uncertain_receipt_retained_and_current_hook_read_does_not_spend_rpc(native, receipt):
    _, host, _ = native
    channel, _, cap = original(native)
    def remote(*args, **kw):
        if isinstance(receipt, Exception):
            raise receipt
        return receipt
    channel._call = remote
    if isinstance(receipt, Exception):
        with pytest.raises(TimeoutError):
            cap.response_used()
    else:
        cap.response_used()
    scope, token = hook(native, channel)
    try:
        fresh = intake_capability(host, channel)
        result = fresh.recovery_hints('cloud')
        assert result == {'state': 'ONE', 'selector': {
            'request_id': 'request', 'result_ref': 'result', 'projection_digest': digest('verified')}}
        assert fresh.pending_lookup({'project_id': 'cloud', 'reconcile_use': result['selector']}) == {'state': 'RECEIVED'}
        assert len(channel.calls) == 1
        with pytest.raises(PermissionError):
            fresh.intake({})
    finally:
        scope.live = False
        hook_scope.reset(token)


def test_exact_pending_readback_clears_all_and_recovery_scope_is_enforced(native):
    _, host, state = native
    channel, _, cap = original(native)
    channel._call = lambda *args, **kw: {'state': 'UNKNOWN'}
    cap.response_used()
    scope, token = hook(native, channel)
    try:
        fresh = intake_capability(host, channel)
        with pytest.raises(PermissionError):
            fresh.recovery_hints('load')
        selector = fresh.recovery_hints('cloud')['selector']
        channel.call = lambda *args, **kw: {'status': 'OK', 'result': {
            'request_id': 'request', 'request_state': 'COMPLETED_READ_ONLY'}}
        fresh.pending_lookup({'project_id': 'cloud', 'reconcile_use': selector})
        assert state.recovery_store._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 0
        second = intake_capability(host, channel)
        scope.deadline = time.monotonic() - 1
        with pytest.raises(PermissionError):
            second.recovery_hints('cloud')
    finally:
        hook_scope.reset(token)
