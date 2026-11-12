"""Actual CLI/Gateway entrypoints, private supervisor FDs and real plugin discovery."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from tests.waiting import wait_until

pytestmark = pytest.mark.platforms("macos")
REPO = Path(__file__).resolve().parents[2]
PLUGIN = '''from tests.hermes_cli.native_isolated_child import record
from hermes_constants import get_hermes_home
from hermes_cli.plugins import get_plugin_manager
from agent.response_gate import requirements
record(get_hermes_home(), "discovery_entered")
manager = get_plugin_manager()
assert manager.native_lifecycle.manager_epoch
assert manager.native_lifecycle.closed is False
assert manager.native_lifecycle.admission_closed is True
assert requirements("hello") == ()
record(get_hermes_home(), "discovery", manager_epoch=manager.native_lifecycle.manager_epoch)
def register(ctx):
    raise AssertionError("native startup must defer stock registration")
def register_native(ctx, channel):
    global CHANNEL
    CHANNEL = channel
    assert channel.connection.fileno() >= 0
    ctx.register_response_gate(lambda evidence: False)
    record(get_hermes_home(), "business", channel=channel.channel)
'''


def rows(root):
    path = root / "children.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def launch(tmp_path):
    owners, roots = [], []

    def start(fault="none", entry="cli", supervised=True):
        root = tmp_path / str(len(roots))
        root.mkdir()
        roots.append(root)
        (root / ".hermes-isolated-profile").touch()
        plugin = root / "plugins/fixture"
        plugin.mkdir(parents=True)
        (plugin / "plugin.yaml").write_text("name: fixture\nversion: 1.0.0\ndescription: synthetic native startup\n")
        plugin_source = {
            "import": PLUGIN + "\nraise RuntimeError('import failure')\n",
            "no_native_registration": PLUGIN.replace("def register_native(", "def unavailable_native("),
            "no_gate": PLUGIN.replace("    ctx.register_response_gate(lambda evidence: False)\n", ""),
            "register_failure": PLUGIN.replace("    ctx.register_response_gate(lambda evidence: False)", "    raise RuntimeError('native registration failed')"),
        }.get(fault, PLUGIN)
        registration_changes = {
            "registration_policy": "    import json\n    path = get_hermes_home() / 'config.yaml'\n    config = json.loads(path.read_text())\n    config['plugins']['required_response_gates'] = []\n    path.write_text(json.dumps(config))\n",
            "registration_artifact": "    from pathlib import Path\n    path = Path(__file__)\n    path.write_text(path.read_text() + '\\n# invalidated during registration\\n')\n",
        }
        plugin_source += registration_changes.get(fault, "")
        if fault == "liveness_startup":
            plugin_source += "    from tests.hermes_cli.native_liveness_probe import measure_phase\n    measure_phase(get_hermes_home(), 'startup')\n"
        if fault == "owner_loss_registration":
            plugin_source += "    from tests.hermes_cli.native_core_startup_child import owner_loss_boundary\n    with ctx.native_host._lock:\n        owner_loss_boundary(get_hermes_home(), 'registration')\n"
        if fault == "owner_loss_discovery":
            plugin_source = plugin_source.replace('record(get_hermes_home(), "discovery_entered")',
                'record(get_hermes_home(), "discovery_entered")\nfrom tests.hermes_cli.native_core_startup_child import owner_loss_boundary\nowner_loss_boundary(get_hermes_home(), "discovery")')
        (plugin / "__init__.py").write_text(plugin_source)
        artifact = REPO / ("gateway/run.py" if entry == "gateway" else "hermes_cli/main.py")
        policy = [{"plugin_id": "fixture", "request_terms": ["Cloud Test"]}]
        selector = {
            "profile": str(root), "revision": "accepted1", "registry_revision": "r1",
            "registry": {"cloud": {"aliases": ["Cloud Test"], "repository": "fake/cloud"}},
            "selector_revision": "v1", "plugin_id": "fixture",
            "plugin_artifact_digest": hashlib.sha256((plugin / "__init__.py").read_bytes()).hexdigest(),
            "release_digest": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "required_response_gates": policy, "expires_at": time.time() + 120,
        }
        if fault == "stale":
            selector["expires_at"] = time.time() - 1
        if fault == "profile":
            selector["profile"] += "-wrong"
        if fault == "empty":
            selector["registry"] = {}
        (root / "selector.json").write_text(json.dumps(selector))
        if fault == "malformed":
            selector["registry"] = "invalid"
            (root / "selector.json").write_text(json.dumps(selector))
        config_policy = [] if fault in ("empty_policy", "missing_selector") else policy
        config = {"plugins": {"enabled": ["fixture"], "isolation": "in-process", "required_response_gates": config_policy}}
        # JSON is valid YAML and remains confined to this disposable profile.
        (root / "config.yaml").write_text(json.dumps(config))
        command = [sys.executable, "-B", "-m", "tests.hermes_cli.native_core_startup_child", str(root), fault, entry]
        if supervised:
            control = REPO / "tests/hermes_cli/native_isolated_child.py"
            spec = {
                "profile": str(root), "error_log": str(root / "stderr.log"), "startup_fault": fault,
                "core": {"command": command, "artifact": str(artifact), "artifact_digest": hashlib.sha256(artifact.read_bytes()).hexdigest()},
                "control": {"command": [sys.executable, "-B", "-m", "tests.hermes_cli.native_isolated_child", "control", str(root)],
                            "artifact": str(control), "artifact_digest": hashlib.sha256(control.read_bytes()).hexdigest()},
            }
            plan = root / "plan.json"
            plan.write_text(json.dumps(spec))
            command = [sys.executable, "-B", "-m", "tests.hermes_cli.native_isolated_owner", str(plan)]
            if fault.startswith("handshake_"):
                command = [sys.executable, "-B", "-m", "tests.hermes_cli.native_core_startup_child", "owner", str(plan)]
        env = {"HOME": str(tmp_path), "HERMES_HOME": str(root), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=REPO)
        owners.append(proc)
        return proc, root

    yield start
    for proc in owners:
        if proc.poll() is None:
            proc.terminate()
        proc.communicate(timeout=12)
    for root in roots:
        for row in rows(root):
            if row["kind"] == "start":
                assert wait_until(lambda: not psutil.pid_exists(row["pid"]), timeout=5)


@pytest.mark.parametrize("entry", ["cli", "gateway"])
def test_actual_entrypoint_consumes_private_fd_before_discovery_and_business(launch, entry):
    proc, root = launch(entry=entry)
    assert wait_until(lambda: any(r["kind"] == "downstream" for r in rows(root)) or proc.poll() is not None, timeout=12)
    assert proc.poll() is None, proc.communicate()
    events = [row["kind"] for row in rows(root)]
    assert events.index("discovery") < events.index("business") < events.index("downstream")
    (root / "finish").touch()
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode == 0, (stdout, stderr, (root / "stderr.log").read_text())


@pytest.mark.parametrize("fault", ["supervisor", "untrusted", "missing_selector", "stale", "profile", "empty", "malformed", "empty_policy"])
def test_unqualified_bootstrap_fails_before_discovery_without_legacy_fallback(launch, fault):
    proc, root = launch(fault)
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode != 0, (stdout, stderr)
    assert not {"discovery", "business", "downstream"} & {r["kind"] for r in rows(root)}


def test_missing_fd_is_denied_by_actual_entrypoint(launch):
    proc, root = launch(supervised=False)
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode != 0
    assert "PermissionError" in stderr and "bootstrap" in stderr, (stdout, stderr)
    assert not any(r["kind"] == "discovery" for r in rows(root))


def test_plugin_import_failure_never_activates_business_or_runtime(launch):
    proc, root = launch("import")
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode != 0, (stdout, stderr)
    assert any(r["kind"] == "discovery" for r in rows(root))
    assert not any(r["kind"] in ("business", "downstream") for r in rows(root))


def test_changed_selector_identity_cannot_authorize_unrelated_chat(launch):
    proc, root = launch("expiry_after_start")
    assert wait_until(lambda: any(r["kind"] == "downstream" for r in rows(root)) or proc.poll() is not None, timeout=12)
    assert proc.poll() is None, proc.communicate()
    (root / "finish").touch()
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode == 0, (stdout, stderr, (root / "stderr.log").read_text())


@pytest.mark.parametrize("entry", ["cli", "gateway"])
@pytest.mark.parametrize("fault", ["untrusted", "supervisor", "missing_selector"])
def test_rejected_actual_entrypoint_closes_owned_fd(tmp_path, monkeypatch, entry, fault):
    import importlib
    import socket

    from hermes_cli.native_core_startup import CoreLaunchPins
    from hermes_constants import hermes_home_key
    from hermes_platform.native_peer import process_snapshot
    from tests.hermes_cli.native_isolated_child import SyntheticParentPins

    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / ".hermes-isolated-profile").touch()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(profile))
    facade = importlib.import_module("gateway.run" if entry == "gateway" else "hermes_cli.main")
    parent, child = socket.socketpair()
    fd = child.detach()
    monkeypatch.setattr(sys, "argv", ["hermes", "--native-bootstrap-fd", str(fd)])
    expected = process_snapshot(os.getppid())
    actual = dict(expected)
    if fault == "supervisor":
        actual["pid"] += 1
    pins = CoreLaunchPins(
        hermes_home_key(), actual, SyntheticParentPins(expected, hermes_home_key()),
        hashlib.sha256(Path(facade.__file__).read_bytes()).hexdigest(), None,
    )
    try:
        with pytest.raises(PermissionError):
            facade.main(**({} if fault == "untrusted" else {"native_bootstrap": pins}))
        with pytest.raises(OSError):
            os.fstat(fd)
        parent.settimeout(2)
        assert parent.recv(1) == b""
        from agent.response_gate import requirements
        assert requirements("hello") == ("<policy-unavailable>",)
        assert requirements("Cloud Test status") == ("<policy-unavailable>",)
    finally:
        parent.close()


@pytest.mark.parametrize("fault", ["no_native_registration", "no_gate", "register_failure"])
def test_native_registration_failure_never_runs_application_body(launch, fault):
    proc, root = launch(fault)
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode != 0, (stdout, stderr)
    assert any(r["kind"] == "discovery" for r in rows(root))
    assert not any(r["kind"] == "downstream" for r in rows(root))


def test_expired_installed_selector_cannot_prove_unrelatedness(launch):
    proc, root = launch("expires_after_start")
    assert wait_until(lambda: any(r["kind"] == "downstream" for r in rows(root)) or proc.poll() is not None, timeout=12)
    assert proc.poll() is None, proc.communicate()
    (root / "finish").touch()
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode == 0, (stdout, stderr, (root / "stderr.log").read_text())


def test_owner_fail_stop_exits_actual_core_without_orphan(launch):
    import signal

    proc, root = launch()
    assert wait_until(lambda: any(r["kind"] == "downstream" for r in rows(root)) or proc.poll() is not None, timeout=12)
    assert proc.poll() is None, proc.communicate()
    assert wait_until(lambda: (root / "ready.json").exists(), timeout=5)
    children = json.loads((root / "ready.json").read_text())["children"]
    os.kill(proc.pid, signal.SIGKILL)
    proc.communicate(timeout=12)
    for pid in children.values():
        assert wait_until(lambda: not psutil.pid_exists(pid), timeout=5)


def test_owner_revoke_is_acknowledged_before_core_exit(launch):
    proc, root = launch()
    assert wait_until(lambda: any(r["kind"] == "downstream" for r in rows(root)) or proc.poll() is not None, timeout=12)
    assert proc.poll() is None, proc.communicate()
    (root / "stop").touch()
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode == 0, (stdout, stderr, (root / "stderr.log").read_text())


@pytest.mark.parametrize("fault", ["handshake_policy", "handshake_artifact"])
def test_selector_invalidated_during_handshake_fails_before_discovery(launch, fault):
    proc, root = launch(fault)
    stdout, stderr = proc.communicate(timeout=12)
    assert (root / "handshake-invalidated").exists()
    assert proc.returncode != 0, (stdout, stderr)
    assert not any(r["kind"] in ("discovery_entered", "discovery", "business", "application_entered") for r in rows(root))


@pytest.mark.parametrize("fault", ["registration_policy", "registration_artifact"])
def test_selector_invalidated_during_registration_never_becomes_ready(launch, fault):
    proc, root = launch(fault)
    stdout, stderr = proc.communicate(timeout=12)
    assert proc.returncode != 0, (stdout, stderr)
    assert any(r["kind"] == "business" for r in rows(root))
    assert not (root / "ready.json").exists()
    assert not any(r["kind"] == "application_entered" for r in rows(root))


@pytest.mark.parametrize("options", [
    ["--native-bootstrap-fd", "malformed", "--native-bootstrap-fd", "{fd}"],
    ["--native-bootstrap-fd", "--native-bootstrap-fd", "{fd}"],
    ["--native-bootstrap-fd", "{fd}", "--native-bootstrap-fd", "{fd}"],
    ["--native-bootstrap-fd", "{fd}", "--native-bootstrap-fd", "malformed"],
    ["--native-bootstrap-fd=malformed", "--native-bootstrap-fd={fd}"],
    ["--native-bootstrap-fd=2", "--native-bootstrap-fd={fd}"],
    ["--native-bootstrap-fd=" + "9" * 100, "--native-bootstrap-fd={fd}"],
])
def test_rejected_private_options_close_all_identifiable_inherited_fds(monkeypatch, options):
    import socket

    from hermes_cli.main import main

    parent, child = socket.socketpair()
    fd = child.detach()
    monkeypatch.setattr(sys, "argv", ["hermes", *(s.format(fd=fd) for s in options)])
    try:
        with pytest.raises(PermissionError):
            main()
        with pytest.raises(OSError):
            os.fstat(fd)
        parent.settimeout(2)
        assert parent.recv(1) == b""
        # The parser must never close stdout/stderr as part of malformed input cleanup.
        os.fstat(1)
        os.fstat(2)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        parent.close()
