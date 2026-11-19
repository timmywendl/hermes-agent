"""Isolated formal native APIs: original identity, scope and policy proof."""

import copy
import hashlib
import json
import os
import pickle
import socket
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from agent.native_bootstrap import (
    DeniedBootstrapProvider,
    PinnedBootstrapProvider,
    SupervisorApproval,
)
from agent.native_capabilities import (
    HookScope,
    commit_capability,
    hook_scope,
    intake_capability,
)
from agent.native_control_verifier import NativeControlVerifier
from agent.native_lifecycle import NativeLifecycleChannel
from agent.native_selector import (
    POLICY_UNAVAILABLE,
    CandidateSelectorBundle,
    install_selector,
    require_selector,
    select,
)
from agent.native_turn import (
    PluginHost,
    TurnSource,
    consume_ingress,
    current_turn,
    digest,
    issue_ingress,
)
from agent.native_wire import canonical, signed
from agent.response_gate import TurnGate, requirements
from hermes_constants import hermes_home_key
from hermes_platform.native_peer import process_snapshot

pytestmark = pytest.mark.platforms("macos")


def bundle(profile, *, expires=None):
    gates = [{"plugin_id": "fixture", "request_terms": ["Cloud Test", "Load Testing"]}]
    record = {
        "profile": profile,
        "revision": "policy1",
        "registry_revision": "registry1",
        "registry": {
            "cloud": {
                "aliases": ["Cloud Test", "cloud", "云测试"],
                "repository": "fake/cloud",
            },
            "load": {
                "aliases": ["Load Testing", "load", "压测"],
                "repository": "fake/load",
            },
        },
        "selector_revision": "selector1",
        "plugin_id": "fixture",
        "plugin_artifact_digest": "a" * 64,
        "release_digest": "b" * 64,
        "required_response_gates": gates,
        "expires_at": expires or time.time() + 60,
    }
    return CandidateSelectorBundle(
        record,
        hashlib.sha256(canonical(record)).hexdigest(),
        identity_check=lambda: {
            k: record[k] for k in ("plugin_artifact_digest", "release_digest")
        },
    )


@pytest.fixture
def native(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    profile = hermes_home_key()
    os.makedirs(profile, exist_ok=True)
    b = bundle(profile)
    install_selector(profile, b)
    from pathlib import Path

    Path(profile, "config.yaml").write_text(
        "plugins:\n  required_response_gates:\n"
        + "\n".join(
            f"    - plugin_id: {g['plugin_id']}\n      request_terms: {json.dumps(g['request_terms'])}"
            for g in b.record["required_response_gates"]
        )
        + "\n"
    )
    host = PluginHost("fixture", profile)
    ingress = issue_ingress(
        TurnSource.TOP_LEVEL_HUMAN, actor="test", conversation="conv", session="s"
    )
    state = TurnGate(
        consume_ingress(ingress, "s"),
        ("fixture",),
        selection=select(profile, "Check Cloud Test status"),
    )
    from agent.response_gate import register_gate
    from hermes_state import SessionDB
    recovery_store = SessionDB(Path(profile) / 'state.db')
    state.recovery_store = recovery_store

    cleanup = register_gate(host, lambda evidence: True)
    token = current_turn.set(state)
    yield profile, host, state
    cleanup()
    recovery_store.close()
    host.close()
    state.finished = True
    current_turn.reset(token)


def approval(host=None, manager=None, *, epoch="control1"):
    record = {
        "role": "manager" if manager else "business",
        "profile": manager.profile if manager else host.profile,
        "process": process_snapshot(os.getpid()),
        "approval_ref": "approval1",
        "supervisor_epoch": "supervisor1",
        "control_epoch": epoch,
        "public_key": manager.public_key
        if manager
        else host._key.public_key().public_bytes_raw().hex(),
        "artifact_digest": "c" * 64,
        "expires_at": time.time() + 60,
    }
    if manager:
        record.update(
            manager_instance=manager.manager_instance,
            manager_epoch=manager.manager_epoch,
        )
    else:
        record.update(
            plugin_id=host.plugin_id,
            host_instance=host.instance,
            host_generation=host.generation,
        )
    return PinnedBootstrapProvider(record).verify(record)


def test_bootstrap_capability_requires_independent_exact_pins(native):
    _, host, _ = native
    a = approval(host)
    with pytest.raises(PermissionError):
        SupervisorApproval({})
    with pytest.raises(PermissionError):
        DeniedBootstrapProvider().verify({})
    for copier in (copy.copy, copy.deepcopy, pickle.dumps, json.dumps):
        with pytest.raises(TypeError):
            copier(a)
    with pytest.raises(TypeError):
        a.profile = "wrong"
    changed = a.process
    changed["pid"] += 1
    assert a.process["pid"] == os.getpid()
    parent, child = socket.socketpair()
    try:
        with pytest.raises(PermissionError):
            NativeControlVerifier.staged(
                parent, approval=None, control_epoch="control1"
            )
        v = NativeControlVerifier.staged(parent, approval=a, control_epoch="control1")
        with pytest.raises(PermissionError):
            NativeControlVerifier.staged(parent, approval=a, control_epoch="old")
        record = {
            "contract": "hermes.native-registration/2",
            "profile": a.profile,
            "process": a.process,
            "plugin_id": a.plugin_id,
            "host_instance": a.host_instance,
            "host_generation": a.host_generation,
            "public_key": a.public_key,
            "approval_ref": a.approval_ref,
        }
        bad = dict(record, public_key="0" * 64)
        with pytest.raises(PermissionError):
            v.accept_registration(bad)
        challenge = v.accept_registration(record)
        assert v.accept_proof(signed(host._key, challenge)) == {
            "registered": v.channel,
            "control_epoch": "control1",
        }
        with pytest.raises(PermissionError):
            v.accept_proof(signed(host._key, challenge))
        with pytest.raises(PermissionError):
            v.reply({}, {"secret": "never"})
    finally:
        parent.close()
        child.close()


@pytest.mark.parametrize(
    "text",
    [
        "我引用“Cloud Test目前状态如何”",
        "他说“Load Testing进展”",
        "An example: Cloud Test status",
        'She asked "Load Testing status"',
        "Don't continue Cloud Test",
    ],
)
def test_embedded_quotes_reports_examples_never_intake(native, text):
    profile, _, _ = native
    s = select(profile, text)
    assert s.candidate and not s.intake_allowed and s.valid()
    assert requirements(text) == ("fixture",)


def test_core_policy_survives_missing_gate_config_and_denies_candidates(native):
    profile, _, state = native
    from pathlib import Path

    assert select(profile, "hello").required == ()
    assert state.policy_valid() and state.intake_allowed
    Path(profile, "config.yaml").write_text("plugins: {}\n")
    assert not state.policy_valid()
    assert requirements("Cloud Test status") == ("<policy-unavailable>",)
    assert requirements("hello") == ()
    assert state.final_output("fake") == POLICY_UNAVAILABLE
    require_selector(profile)
    assert requirements("hello") == ("<policy-unavailable>",)


class _Channel:
    def __init__(self, host):
        self.host = host
        self.control_epoch = "control1"
        self.calls = []
        self.channel = "channel1"

    def live(self):
        return self.host.live()

    def call(self, invocation, payload, **kw):
        self.calls.append((invocation, payload))
        return {"state": "RECEIVED"}

    def _call(self, invocation, payload, **kw):
        self.calls.append((invocation, payload))
        return {"request_state": "COMPLETED_READ_ONLY"}

    def close(self):
        pass

    lock = __import__("threading").RLock()


def test_hook_capability_single_use_scope_finished_and_nonhuman(native):
    _, host, state = native
    c = _Channel(host)
    with pytest.raises(PermissionError):
        intake_capability(host, c)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, c)
        assert cap.pending_lookup({"project_id": "cloud"}) == {"state": "RECEIVED"}
        assert c.calls[0][0].tool_name == "__native_intake__"
        with pytest.raises(PermissionError):
            cap.intake({})
        late = intake_capability(host, c)
        scope.live = False
        with pytest.raises(PermissionError):
            late.intake({})
        for copier in (copy.copy, copy.deepcopy, pickle.dumps, json.dumps):
            with pytest.raises(TypeError):
                copier(late)
    finally:
        hook_scope.reset(token)
    state.ingress = replace(state.ingress, source=TurnSource.SCHEDULED)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        with pytest.raises(PermissionError):
            intake_capability(host, c)
    finally:
        hook_scope.reset(token)


def test_original_commit_evidence_only_and_finished_unload_expiry(native):
    from agent.native_turn import current_invocation

    _, host, state = native
    c = _Channel(host)
    host._channels.append(c)
    inv = host.invocation("colleague_query")
    t = current_invocation.set(inv)
    try:
        e = host.record_result(
            inv,
            control_request_id="r",
            context_revision="context1",
            mission_revision="mission1",
            query_result_digest="d",
            output="verified",
            result_ref="result1",
            control_epoch="control1",
            channel_ref="channel1",
            project_id="cloud",
        )
    finally:
        current_invocation.reset(t)
    state.closed = True
    receipt = {
        "output_commit_status": "OUTPUT_COMMITTED",
        "gate_decision": "OUTPUT_GATE_PASSED",
        "final_output_digest": digest(e.output),
    }
    with pytest.raises(PermissionError):
        commit_capability(host, copy.copy(e), state, receipt)
    cap = commit_capability(host, e, state, receipt)
    assert cap.response_used()["request_state"] == "COMPLETED_READ_ONLY"
    assert c.calls[-1][1] == {
        "operation": "response_used",
        "payload": {
            "request_id": "r",
            "result_ref": "result1",
            "projection_digest": digest("verified"),
        },
    }
    with pytest.raises(PermissionError):
        cap.response_used()
    late = commit_capability(host, e, state, receipt)
    state.finished = True
    with pytest.raises(PermissionError):
        late.response_used()
    state.finished = False
    late = commit_capability(host, e, state, receipt)
    host.close()
    with pytest.raises(PermissionError):
        late.response_used()


def test_real_PluginManager_lifecycle_is_outside_plugin_ledger(native):
    from hermes_cli.plugins import PluginManager

    profile, _, _ = native
    m = PluginManager(profile)
    assert not m._discovered and isinstance(m.native_lifecycle, NativeLifecycleChannel)
    channel = m.native_lifecycle
    with pytest.raises(PermissionError):
        channel.connect_control("/not/used", {})
    a = approval(manager=channel)
    channel.bootstrap(a)
    m.unload()
    assert m.native_lifecycle is channel
    assert channel.public_key == a.public_key


@pytest.mark.parametrize(
    "policy",
    [None, [], [{"plugin_id": "wrong", "request_terms": ["Cloud Test"]}], "malformed"],
)
def test_frozen_selector_denies_missing_empty_mismatched_policy(native, policy):
    from pathlib import Path

    profile, _, state = native
    Path(profile, "config.yaml").write_text(
        "plugins:\n  required_response_gates: " + json.dumps(policy) + "\n",
        encoding="utf8",
    )
    assert not state.policy_valid()
    assert requirements("Check Cloud Test status") == ("<policy-unavailable>",)
    assert requirements("unrelated hello") == ()


def test_selector_requires_actual_identity_provider_and_expiry(native):
    profile, _, _ = native
    b = bundle(profile)
    r = b.record
    h = hashlib.sha256(canonical(r)).hexdigest()
    absent = CandidateSelectorBundle(r, h)
    install_selector(profile, absent)
    assert not select(profile, "Cloud Test status").valid()
    facts = {k: r[k] for k in ("plugin_artifact_digest", "release_digest")}
    checked = CandidateSelectorBundle(r, h, identity_check=lambda: dict(facts))
    install_selector(profile, checked)
    assert select(profile, "Cloud Test status").valid()
    facts["plugin_artifact_digest"] = "e" * 64
    assert not select(profile, "Cloud Test status").valid()
    r["expires_at"] = time.time() - 1
    expired = CandidateSelectorBundle(
        r,
        hashlib.sha256(canonical(r)).hexdigest(),
        identity_check=lambda: {k: r[k] for k in facts},
    )
    install_selector(profile, expired)
    assert not select(profile, "Cloud Test status").valid()


def test_hook_concurrency_expiry_cross_turn_and_immutable_capability(native):
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    _, host, state = native
    c = _Channel(host)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, c)
        with pytest.raises(TypeError):
            cap._used = True

        def attempt():
            try:
                return cap.intake({"message": "Check Cloud Test status"})
            except PermissionError:
                return "DENIED"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(contextvars.copy_context().run, attempt) for _ in range(2)
            ]
            outcomes = [f.result() for f in futures]
        assert outcomes.count("DENIED") == 1 and len(c.calls) == 1
        late = intake_capability(host, c)
        other = TurnGate(state.ingress, ())
        turn = current_turn.set(other)
        try:
            with pytest.raises(PermissionError):
                late.intake({})
        finally:
            current_turn.reset(turn)
        scope.deadline = 0
        with pytest.raises(PermissionError):
            late.intake({})
    finally:
        hook_scope.reset(token)


def test_commit_capability_wrong_projection_changed_evidence_and_deadline(
    native, monkeypatch
):
    import agent.native_capabilities as capabilities
    from agent.native_turn import current_invocation

    _, host, state = native
    c = _Channel(host)
    host._channels.append(c)
    inv = host.invocation("colleague_query")
    t = current_invocation.set(inv)
    try:
        e = host.record_result(
            inv,
            control_request_id="r",
            context_revision="c",
            mission_revision="m",
            query_result_digest="q",
            output="verified",
            result_ref="result",
            control_epoch="control1",
            channel_ref="channel1",
            project_id="cloud",
        )
    finally:
        current_invocation.reset(t)
    receipt = {
        "output_commit_status": "OUTPUT_COMMITTED",
        "gate_decision": "OUTPUT_GATE_PASSED",
        "final_output_digest": digest(e.output),
    }
    with pytest.raises(PermissionError):
        commit_capability(host, e, state, receipt)
    state.closed = True
    with pytest.raises(PermissionError):
        commit_capability(host, e, state, dict(receipt, final_output_digest="wrong"))
    cap = commit_capability(host, e, state, receipt)
    with pytest.raises(PermissionError):
        cap.response_used(
            {
                "request_id": "r",
                "result_ref": "wrong",
                "projection_digest": digest(e.output),
            }
        )
    state.evidence[host.plugin_id] = copy.copy(e)
    with pytest.raises(PermissionError):
        cap.response_used()
    state.evidence[host.plugin_id] = e
    monkeypatch.setattr(capabilities, "time", SimpleNamespace(monotonic=lambda: 10**12))
    with pytest.raises(PermissionError):
        cap.response_used()
    assert c.calls == []


def test_late_commit_observer_cannot_send_after_turn_finish(native):
    import threading

    from agent.native_turn import current_invocation
    from agent.response_gate import notify_committed, register_gate

    _, host, state = native
    c = _Channel(host)
    host._channels.append(c)
    inv = host.invocation("colleague_query")
    t = current_invocation.set(inv)
    try:
        e = host.record_result(
            inv,
            control_request_id="r",
            context_revision="c",
            mission_revision="m",
            query_result_digest="q",
            output="verified",
            result_ref="result",
            control_epoch="control1",
            channel_ref="channel1",
            project_id="cloud",
        )
    finally:
        current_invocation.reset(t)
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    outcomes = []

    def observer(receipt, *, commit_use):
        entered.set()
        release.wait(5)
        try:
            commit_use.response_used()
        except PermissionError:
            outcomes.append("DENIED")
        finally:
            done.set()
        return True

    cleanup = register_gate(host, lambda e: True, on_commit=observer)
    state.closed = True
    receipt = {
        "output_commit_status": "OUTPUT_COMMITTED",
        "gate_decision": "OUTPUT_GATE_PASSED",
        "final_output_digest": digest(e.output),
    }
    try:
        notify_committed(state, receipt)
        assert entered.is_set() and receipt["commit_observers"] == {
            "fixture": "UNKNOWN"
        }
        state.finished = True
        release.set()
        assert done.wait(3)
        assert outcomes == ["DENIED"] and c.calls == []
    finally:
        release.set()
        cleanup()


def test_hook_original_message_and_selected_project_cannot_be_substituted(native):
    _, host, _ = native
    c = _Channel(host)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, c)
        with pytest.raises(PermissionError, match="original native message/project"):
            cap.intake({"message": "Check Load Testing status"})
        wrong = intake_capability(host, c)
        with pytest.raises(PermissionError, match="original native message/project"):
            wrong.pending_lookup({"project_id": "load"})
        assert c.calls == []
    finally:
        hook_scope.reset(token)


def test_core_gate_missing_cannot_mint_intake_even_with_valid_policy(native):
    _, host, _ = native
    c = _Channel(host)
    # Use the public release owner callback to model failed registration/unload.
    from agent.response_gate import register_gate

    release = register_gate(host, lambda e: True)
    release()
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        with pytest.raises(PermissionError, match="trusted native hook"):
            intake_capability(host, c)
        assert c.calls == []
    finally:
        hook_scope.reset(token)


@pytest.mark.parametrize("mode", ["success", "denied", "error"])
def test_native_turn_end_occurs_after_commit_and_capability_invalidation(
    native, monkeypatch, mode
):
    from agent.native_turn import current_invocation
    from agent.response_gate import register_gate, run_guarded
    from hermes_cli.plugins import PluginContext, PluginManager
    from hermes_cli.plugins_manifest import PluginManifest

    profile, host, _ = native
    c = _Channel(host)
    host._channels.append(c)
    manager = PluginManager(profile)
    ctx = PluginContext(PluginManifest(name="cleanup-fixture"), manager)
    order = []
    states = []

    def finished(session_id, turn_id):
        assert session_id == "s" and turn_id == ingress.turn
        assert states[0].finished and current_turn.get() is not states[0]
        order.append("end")

    ctx.register_hook("on_native_turn_end", finished)
    monkeypatch.setattr("hermes_cli.lifecycle.invoke_hook", manager.invoke_hook)

    def committed(receipt, *, commit_use):
        assert not states[0].finished
        assert commit_use.response_used()["request_state"] == "COMPLETED_READ_ONLY"
        order.append("commit")
        return True

    release = register_gate(host, lambda e: True, on_commit=committed)
    ingress = issue_ingress(
        TurnSource.TOP_LEVEL_HUMAN, actor="fixture", conversation="c", session="s"
    )

    def run(state):
        states.append(state)
        if mode == "error":
            raise RuntimeError("synthetic selected-turn failure")
        if mode == "success":
            invocation = host.invocation("colleague_query")
            token = current_invocation.set(invocation)
            try:
                host.record_result(
                    invocation,
                    control_request_id="r",
                    context_revision="c",
                    mission_revision="m",
                    query_result_digest="q",
                    output="verified",
                    result_ref="result",
                    control_epoch="control1",
                    channel_ref="channel1",
            project_id="cloud",
                )
            finally:
                current_invocation.reset(token)
        return {"final_response": "unverified draft", "api_calls": 1}

    try:
        result = run_guarded(
            SimpleNamespace(session_id="s", _session_db=native[2].recovery_store), "Check Cloud Test status", ingress, run
        )
        assert order == (["commit", "end"] if mode == "success" else ["end"])
        assert result["native_response_receipt"]["gate_decision"] == (
            "OUTPUT_GATE_PASSED" if mode == "success" else "DENIED"
        )
    finally:
        release()
        manager.unload()


def test_native_turn_end_registration_is_known_and_dispatches_cleanup(native, caplog):
    import logging

    from hermes_cli.plugins import PluginContext, PluginManager
    from hermes_cli.plugins_manifest import PluginManifest

    profile, _, _ = native
    manager = PluginManager(profile)
    ctx = PluginContext(PluginManifest(name="turn-cleanup"), manager)
    seen = []
    caplog.set_level(logging.WARNING, logger="hermes_cli.plugins")
    ctx.register_hook(
        "on_native_turn_end",
        lambda session_id, turn_id: seen.append((session_id, turn_id)),
    )
    manager.invoke_hook("on_native_turn_end", session_id="session", turn_id="turn")
    assert seen == [("session", "turn")]
    assert not any(
        "registered unknown hook" in record.message for record in caplog.records
    )
    manager.unload()


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {
            "request_id": "request-1",
            "result_ref": "result-1",
            "projection_digest": "a" * 64,
        },
        {
            "request_id": "é" * 128,
            "result_ref": "r" * 256,
            "projection_digest": "0" * 64,
        },
    ],
)
def test_hook_pending_lookup_accepts_only_bound_project_and_exact_use_receipt(
    native, receipt
):
    _, host, state = native
    channel = _Channel(host)
    payload = {"project_id": "cloud"}
    if receipt is not None:
        payload["reconcile_use"] = receipt
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, channel)
        assert cap.pending_lookup(payload) == {"state": "RECEIVED"}
        invocation, sent = channel.calls[0]
        assert invocation.ingress is state.ingress
        assert invocation.tool_name == "__native_intake__"
        assert sent == {"operation": "pending_lookup", "payload": payload}
        with pytest.raises(PermissionError):
            cap.pending_lookup(payload)
        assert len(channel.calls) == 1
    finally:
        hook_scope.reset(token)


_USE_RECEIPT = {
    "request_id": "request-1",
    "result_ref": "result-1",
    "projection_digest": "a" * 64,
}
_INVALID_LOOKUPS = [
    {},
    None,
    [],
    {"project_id": None},
    {"project_id": True},
    {"project_id": "load"},
    {"project_id": "cloud", "operation": "response_used"},
    {"project_id": "cloud", "session_id": "old-session"},
    {"project_id": "cloud", "reconcile_use": None},
    {"project_id": "cloud", "reconcile_use": []},
    {"project_id": "cloud", "reconcile_use": {}},
    {
        "project_id": "cloud",
        "reconcile_use": dict(_USE_RECEIPT, authority="human-approved"),
    },
    {
        "project_id": "cloud",
        "reconcile_use": dict(_USE_RECEIPT, session_id="old-session"),
    },
]
_INVALID_LOOKUPS += [
    {
        "project_id": "cloud",
        "reconcile_use": {k: v for k, v in _USE_RECEIPT.items() if k != missing},
    }
    for missing in _USE_RECEIPT
]
_INVALID_LOOKUPS += [
    {"project_id": "cloud", "reconcile_use": dict(_USE_RECEIPT, **{key: value})}
    for key in ("request_id", "result_ref")
    for value in (None, True, 7, "", "  ", "x" * 257, "é" * 129, "\ud800")
]
_INVALID_LOOKUPS += [
    {
        "project_id": "cloud",
        "reconcile_use": dict(_USE_RECEIPT, projection_digest=value),
    }
    for value in (None, True, b"a" * 64, "", "a" * 63, "a" * 65, "g" * 64, "A" * 64)
]


@pytest.mark.parametrize("payload", _INVALID_LOOKUPS)
def test_hook_pending_lookup_rejects_extra_rpc_fields_and_invalid_receipt_before_send(
    native, payload
):
    _, host, _ = native
    channel = _Channel(host)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, channel)
        with pytest.raises(PermissionError):
            cap.pending_lookup(payload)
        assert channel.calls == []
        with pytest.raises(PermissionError):
            cap.pending_lookup({"project_id": "cloud"})
        assert channel.calls == []
    finally:
        hook_scope.reset(token)


def test_use_ack_selector_reconciliation_uses_fresh_human_session_capability(native):
    from agent.native_selector import select

    profile, host, old = native
    channel = _Channel(host)
    ingress = issue_ingress(
        TurnSource.TOP_LEVEL_HUMAN,
        actor="fixture",
        conversation="fresh-conversation",
        session="fresh-session",
    )
    fresh = TurnGate(
        consume_ingress(ingress, "fresh-session"),
        ("fixture",),
        selection=select(profile, "Check Cloud Test status"),
    )
    turn = current_turn.set(fresh)
    scope = HookScope("pre_llm_call", {"user_message": "Check Cloud Test status"})
    token = hook_scope.set(scope)
    try:
        cap = intake_capability(host, channel)
        cap.pending_lookup({"project_id": "cloud", "reconcile_use": dict(_USE_RECEIPT)})
        invocation, payload = channel.calls[0]
        assert (
            invocation.ingress is fresh.ingress
            and invocation.ingress is not old.ingress
        )
        assert invocation.ingress.session == "fresh-session"
        assert payload["payload"]["reconcile_use"] == _USE_RECEIPT
        assert "session_id" not in payload["payload"]["reconcile_use"]
    finally:
        hook_scope.reset(token)
        current_turn.reset(turn)
