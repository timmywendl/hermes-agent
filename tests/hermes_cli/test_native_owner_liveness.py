"""Full approval once; hot owner checks must not rehash the executable."""

import hashlib
import os
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent.native_bootstrap import NativeBootstrapEndpoint
from hermes_cli.native_core_startup import NativeCoreStartup
from hermes_constants import hermes_home_key
from hermes_platform.native_peer import process_snapshot
from tests.hermes_cli.native_isolated_child import SyntheticParentPins

pytest_plugins = ["tests.hermes_cli.test_native_core_startup"]
pytestmark = pytest.mark.platforms("macos")


def test_frequent_owner_checks_keep_full_verification_out_of_hot_loop():
    profile, parent = hermes_home_key(), process_snapshot(os.getppid())
    peer, inherited = socket.socketpair()
    fd = inherited.detach()
    endpoint = None
    try:
        with patch("hashlib.file_digest", wraps=hashlib.file_digest) as digest:
            endpoint = NativeBootstrapEndpoint(
                fd, role="core", profile=profile, artifact_digest="a" * 64,
                approved_supervisor=parent, provider=SyntheticParentPins(parent, profile),
            )
            core = NativeCoreStartup(endpoint, SimpleNamespace(profile=profile))
            initial = digest.call_count
            for _ in range(50):
                core._check_owner()
            assert digest.call_count - initial == 0
            assert initial >= 1
    finally:
        if endpoint is not None:
            endpoint.close()
        else:
            os.close(fd)
        peer.close()


@pytest.mark.parametrize("field,value", [
    ("pid", -1), ("uid", -1), ("birth", -1), ("boot", "foreign-boot"),
    ("executable", "/different/executable"),
])
def test_changed_instance_is_denied_without_digest_fallback(field, value):
    from hermes_platform.native_peer import ProcessLivenessPin, _process_instance_snapshot

    parent = process_snapshot(os.getppid())
    pin = ProcessLivenessPin(parent["pid"], parent)
    changed = _process_instance_snapshot(parent["pid"])
    changed[field] = value
    with patch("hermes_platform.native_peer._process_instance_snapshot", return_value=changed), \
            patch("hashlib.file_digest", side_effect=AssertionError("hot digest fallback")):
        assert pin.is_alive() is False


def test_unavailable_or_replaced_executable_is_denied():
    from hermes_platform.native_peer import ProcessLivenessPin

    parent = process_snapshot(os.getppid())
    pin = ProcessLivenessPin(parent["pid"], parent)
    with patch("hermes_platform.native_peer._process_instance_snapshot", side_effect=PermissionError):
        assert pin.is_alive() is False
    with patch("hermes_platform.native_peer._executable_identity", return_value=("replaced",)):
        assert pin.is_alive() is False


def test_full_initial_digest_and_stable_file_identity_are_required():
    from hermes_platform.native_peer import ProcessLivenessPin

    parent = process_snapshot(os.getppid())
    with pytest.raises(PermissionError):
        ProcessLivenessPin(parent["pid"], dict(parent, executable_digest="0" * 64))
    with patch("hermes_platform.native_peer._executable_identity", side_effect=[("before",), ("after",)]):
        with pytest.raises(PermissionError):
            ProcessLivenessPin(parent["pid"], parent)


def test_atomic_executable_replacement_changes_metadata_identity(tmp_path):
    from hermes_platform.native_peer import _executable_identity

    executable = tmp_path / "executable"
    executable.write_bytes(b"old")
    before = _executable_identity(executable)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"new")
    replacement.replace(executable)
    assert _executable_identity(executable) != before


def test_core_still_fails_stop_on_instance_mismatch_or_reparenting():
    profile, parent = hermes_home_key(), process_snapshot(os.getppid())
    peer, inherited = socket.socketpair()
    endpoint = NativeBootstrapEndpoint(
        inherited.detach(), role="core", profile=profile, artifact_digest="a" * 64,
        approved_supervisor=parent, provider=SyntheticParentPins(parent, profile),
    )
    core = NativeCoreStartup(endpoint, SimpleNamespace(profile=profile))

    class Stopped(Exception):
        pass

    try:
        with patch.object(endpoint.owner_liveness, "is_alive", return_value=False), \
                patch("os._exit", side_effect=Stopped) as stop:
            with pytest.raises(Stopped):
                core._check_owner()
            stop.assert_called_once_with(78)
        with patch("os.getppid", return_value=parent["pid"] + 1), \
                patch("os._exit", side_effect=Stopped) as stop:
            with pytest.raises(Stopped):
                core._check_owner()
            stop.assert_called_once_with(78)
    finally:
        endpoint.close()
        peer.close()


def test_actual_idle_gateway_monitor_has_bounded_digest_io_and_cpu(launch):
    import json
    import signal
    import threading

    import psutil

    from tests.waiting import wait_until

    owner, root = launch("liveness_idle", entry="gateway")
    ready = root / "measure-ready-idle.json"
    wait_until(lambda: ready.exists() or owner.poll() is not None, timeout=10)
    assert owner.poll() is None, owner.communicate()
    core = json.loads(ready.read_text())
    assert psutil.Process(core["pid"]).ppid() == owner.pid
    # This is an explicit CPU/I/O sampling window, not a readiness delay.
    threading.Event().wait(3)  # health: allow HX013 -- an explicit CPU/I/O sampling interval is the behavior measured, after readiness was proven
    assert psutil.Process(core["pid"]).create_time() == core["birth"]
    os.kill(core["pid"], signal.SIGUSR1)
    result = root / "measure-result-idle.json"
    wait_until(lambda: result.exists() or owner.poll() is not None, timeout=5)
    assert result.exists()
    stats = json.loads(result.read_text())
    stdout, stderr = owner.communicate(timeout=12)
    assert owner.returncode == 0, (stdout, stderr)
    assert stats["wall_seconds"] >= 2
    assert stats["owner_checks"] >= 5
    assert stats["executable_digest_calls"] == 0
    assert stats["logical_executable_bytes_hashed"] == 0
    assert stats["one_core_cpu_percent"] <= 10
