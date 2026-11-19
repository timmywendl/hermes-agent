"""Capabilities cannot be copied from model data, another profile or a dead host."""
import copy
from queue import Queue
from types import SimpleNamespace

import pytest
from cli import HermesCLI

from agent.native_turn import (HumanText, PluginHost, TurnSource, consume_ingress,
                               current_invocation, current_turn, issue_ingress)
from agent.response_gate import TurnGate
from hermes_constants import (hermes_home_key, reset_hermes_home_override,
                              set_hermes_home_override)


def test_attestation_generation_peer_signature_and_finished_turn():
    native = issue_ingress(TurnSource.TOP_LEVEL_HUMAN, actor="fixture", conversation="c", session="s")
    host = PluginHost("fixture", hermes_home_key())
    state = TurnGate(consume_ingress(native, "s"), ())
    token = current_turn.set(state)
    try:
        invocation = host.invocation("query")
        bound = current_invocation.set(invocation)
        try:
            envelope = host.attest(invocation)
        finally:
            current_invocation.reset(bound)
        peer = dict(peer_pid=host.process.pid, peer_uid=host.process.uid)
        assert host.verify_attestation(envelope, **peer)["ingress"]["turn"] == native.turn
        for field in ("host_generation", "host_instance", "invocation_id"):
            altered = copy.deepcopy(envelope)
            altered["body"][field] = "forged"
            with pytest.raises(PermissionError):
                host.verify_attestation(altered, **peer)
        with pytest.raises(PermissionError):
            host.verify_attestation(envelope, peer_pid=host.process.pid + 1, peer_uid=host.process.uid)
        with pytest.raises(PermissionError):
            host.verify_attestation(envelope, peer_pid=host.process.pid, peer_uid=host.process.uid + 1)
        state.finished = True
        with pytest.raises(PermissionError):
            host.verify_attestation(envelope, **peer)
        host.close()
        replacement = PluginHost("fixture", hermes_home_key())
        with pytest.raises(PermissionError):
            replacement.verify_attestation(envelope, **peer)
        replacement.close()
    finally:
        host.close()
        current_turn.reset(token)


def test_real_profile_a_b_a_loader_and_capability_scope(tmp_path):
    from agent.response_gate import requirements
    for name, term in (("a", "Alpha"), ("b", "Beta")):
        home = tmp_path / name
        home.mkdir()
        (home / "config.yaml").write_text(
            f"plugins:\n  required_response_gates:\n    - plugin_id: {name}\n      request_terms: [{term}]\n")
    first = None
    for name in ("a", "b", "a"):
        token = set_hermes_home_override(tmp_path / name)
        try:
            assert requirements("Alpha") == (("a",) if name == "a" else ())
            assert requirements("Beta") == (("b",) if name == "b" else ())
            if first is None:
                first = HumanText("Alpha", session="s").native_ingress
            elif name == "b":
                assert consume_ingress(first, "s") is None
        finally:
            reset_hermes_home_override(token)


def test_keyboard_enter_is_the_issuer_and_queued_plain_text_is_untrusted():
    queued = Queue()
    buffer = SimpleNamespace(text="Cloud Test 当前状态", cursor_position=0,
                             reset=lambda **kw: None)
    event = SimpleNamespace(app=SimpleNamespace(current_buffer=buffer, invalidate=lambda: None))
    cli = SimpleNamespace(_tui_enter_overlay=lambda e: False, _tui_multiline_shortcuts=False,
        _attached_images=[], _tui_enter_inline_command=lambda *a: False, session_id="keyboard-session",
        _agent_running=False, _pending_input=queued, _inline_pastes=lambda b: None)
    HermesCLI._tui_handle_enter(cli, event)
    value = queued.get_nowait()
    assert isinstance(value, HumanText)
    native = consume_ingress(value.native_ingress, "keyboard-session")
    assert native.source is TurnSource.TOP_LEVEL_HUMAN
    assert native.actor == "local-keyboard"
    assert consume_ingress(value.native_ingress, "keyboard-session") is None
    assert not hasattr(str(value), "native_ingress")
