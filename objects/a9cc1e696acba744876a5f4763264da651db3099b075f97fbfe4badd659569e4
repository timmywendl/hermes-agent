"""Synthetic launch dependencies; the real Hermes main owns all startup operations."""

import hashlib
import json
import os
import sys
from pathlib import Path

from agent.native_selector import CandidateSelectorBundle
from agent.native_wire import canonical
from hermes_platform.native_peer import process_snapshot
from tests.hermes_cli.native_isolated_child import SyntheticParentPins, record
from tests.waiting import wait_until


def owner_loss_boundary(root, phase, **extra):
    import threading

    record(root, "owner_loss_boundary", phase=phase,
           process=process_snapshot(os.getpid()), supervisor=process_snapshot(os.getppid()), **extra)
    threading.Event().wait()  # Only test teardown or Core fail-stop may end this blocked operation.



def run():
    root = Path(sys.argv.pop(1))
    fault = sys.argv.pop(1)
    entry = sys.argv.pop(1)
    record(root, "start", role="core")
    inherited_fd = int(sys.argv[-1]) if "--native-bootstrap-fd" in sys.argv else None
    if entry == "gateway":
        import gateway.run as facade
    else:
        import hermes_cli.main as facade
    from hermes_cli.native_core_startup import CoreLaunchPins

    source = Path(facade.__file__)
    selector = json.loads((root / "selector.json").read_text())
    plugin = root / "plugins/fixture/__init__.py"

    def identity():
        return {
            "plugin_artifact_digest": hashlib.sha256(plugin.read_bytes()).hexdigest(),
            "release_digest": hashlib.sha256(source.read_bytes()).hexdigest(),
        }

    if fault in ("empty", "malformed"):
        bundle = selector
    elif fault == "missing_selector":
        bundle = None
    else:
        bundle = CandidateSelectorBundle(
            selector, hashlib.sha256(canonical(selector)).hexdigest(), identity_check=identity
        )
    parent = process_snapshot(os.getppid())
    expected = dict(parent)
    if fault == "supervisor":
        parent["pid"] += 1
    pins = CoreLaunchPins(
        str(root), parent, SyntheticParentPins(expected, str(root)),
        hashlib.sha256(source.read_bytes()).hexdigest(), bundle,
    )

    def downstream():
        record(root, "application_entered")
        # Reached from real main only AFTER its native startup completed. No
        # Endpoint/Manager/selector installation is performed by this fixture.
        from agent.native_selector import POLICY_UNAVAILABLE
        from agent.response_gate import UNAVAILABLE, requirements, run_guarded
        from agent.native_turn import TurnSource, current_invocation, issue_ingress
        from types import SimpleNamespace
        from hermes_cli.plugins import get_plugin_manager

        manager = get_plugin_manager()
        assert requirements("hello") == ()
        assert requirements("Cloud Test status") == ("fixture",)
        fd_index = sys.argv.index("--native-bootstrap-fd") if "--native-bootstrap-fd" in sys.argv else -1
        assert fd_index == -1
        from tests.hermes_cli.native_isolated_child import descriptor_probe
        assert inherited_fd is not None and not os.get_inheritable(inherited_fd)
        descriptor_probe(inherited_fd, str(root))
        record(root, "fd_consumed_noninheritable")
        channel = manager._plugins["fixture"].module.CHANNEL

        rejected_operations = []

        def business_cannot_manage(state):
            invocation = channel.host.invocation("colleague_query")
            token = current_invocation.set(invocation)
            try:
                for operation in ("approve", "state_sync", "revoke"):
                    try:
                        channel.call(invocation, {"operation": operation, "payload": {}})
                    except PermissionError as exc:
                        assert str(exc) == "native business operation not allowed"
                        rejected_operations.append(operation)
                    else:
                        raise AssertionError("Business acquired Manager authority")
            finally:
                current_invocation.reset(token)
            return {"final_response": "untrusted"}

        ingress = issue_ingress(TurnSource.TOP_LEVEL_HUMAN, actor="synthetic", conversation="c", session="s")
        run_guarded(SimpleNamespace(session_id="s"), "Cloud Test status", ingress, business_cannot_manage)
        assert rejected_operations == ["approve", "state_sync", "revoke"]
        record(root, "business_cannot_manage")
        output = run_guarded(
            SimpleNamespace(session_id="s"), "Cloud Test status", None,
            lambda state: {"final_response": "untrusted"}
        )
        assert output["final_response"] in (UNAVAILABLE, POLICY_UNAVAILABLE)
        if fault == "expiry_after_start":
            plugin.write_text(plugin.read_text() + "\n# changed after startup\n")
            assert requirements("hello") == ("<policy-unavailable>",)
        manager.unload("fixture")
        assert requirements("Cloud Test status") == (("<policy-unavailable>",) if fault == "expiry_after_start" else ("fixture",))
        denied = run_guarded(SimpleNamespace(session_id="s"), "Cloud Test status", None,
                             lambda state: {"final_response": "should never escape"})
        assert denied["final_response"] in (UNAVAILABLE, POLICY_UNAVAILABLE)
        assert manager.native_lifecycle.state_sync("test-manager-after-unload")["state"] == "ACTIVE"
        if fault == "expires_after_start":
            from unittest.mock import patch
            with patch("agent.native_selector.time.time", return_value=selector["expires_at"] + 1):
                assert requirements("hello") == ("<policy-unavailable>",)
                assert requirements("Cloud Test status") == ("<policy-unavailable>",)
        record(root, "downstream", manager_alive=True)
        if fault == "liveness_idle":
            from tests.hermes_cli.native_liveness_probe import measure_phase
            measure_phase(root, "idle")
        else:
            assert wait_until(lambda: (root / "finish").exists(), timeout=10)
        return True

    if entry == "gateway":
        def gateway_downstream():
            downstream()
            raise SystemExit(0)
        facade._guard_corrupt_user_config = gateway_downstream
    else:
        facade._try_termux_fast_tui_launch = downstream
        facade._recover_update_debts_on_startup = lambda: None
        facade._sweep_stale_bytecode_if_checkout_changed = lambda: None
        from hermes_cli import boot_bootstrap, venv_sync
        boot_bootstrap.maybe_run_boot_bootstrap = lambda *a: None
        venv_sync.check_runtime = lambda *a: None
    if fault.startswith("owner_loss_"):
        from agent.native_bootstrap import NativeBootstrapEndpoint
        from agent.native_lifecycle import NativeLifecycleChannel

        original_approve = NativeLifecycleChannel.approve
        original_acknowledge = NativeBootstrapEndpoint.acknowledge

        def observed_approve(manager, *args, **kwargs):
            if fault == "owner_loss_manager_approval":
                with manager._NativeLifecycleChannel__lock:
                    owner_loss_boundary(root, "manager_approval_with_lifecycle_lock")
            result = original_approve(manager, *args, **kwargs)
            record(root, "manager_approved", active=not manager.admission_closed,
                   manager_epoch=manager.manager_epoch)
            return result

        def observed_acknowledge(endpoint, result):
            if fault == "owner_loss_after_approval" and result == {"connected": True}:
                owner_loss_boundary(root, "after_approval_before_connect_ack")
            return original_acknowledge(endpoint, result)

        NativeLifecycleChannel.approve = observed_approve
        NativeBootstrapEndpoint.acknowledge = observed_acknowledge

    try:
        facade.main(**({} if fault == "untrusted" else {"native_bootstrap": pins}))
    finally:
        record(root, "exit", role="core")


def run_owner():
    from hermes_cli.stderr_timestamp import run_isolated_profile
    from tests.hermes_cli.native_isolated_owner import Provider

    spec = json.loads(Path(sys.argv[2]).read_text())

    class HandshakeOwner(Provider):
        def verify_child(self, role, record, actual):
            super().verify_child(role, record, actual)
            if role != "business":
                return
            fault = spec["startup_fault"]
            if fault == "handshake_policy":
                path = self.root / "config.yaml"
                config = json.loads(path.read_text())
                config["plugins"]["required_response_gates"] = []
                path.write_text(json.dumps(config))
            else:
                path = self.root / "plugins/fixture/__init__.py"
                path.write_text(path.read_text() + "\n# invalidated during handshake\n")
            (self.root / "handshake-invalidated").touch()

    try:
        result = run_isolated_profile(spec, provider=HandshakeOwner(spec))
    except (PermissionError, OSError, EOFError, ValueError):
        result = 127
    raise SystemExit(result)


if __name__ == "__main__":
    if sys.argv[1:2] == ["owner"]:
        run_owner()
    else:
        run()
