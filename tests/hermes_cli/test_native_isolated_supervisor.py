"""Actual wrapper process + private FDs + native PluginManager lifecycle."""

import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import psutil
import pytest

from tests.waiting import wait_until

pytestmark = pytest.mark.platforms("macos")


@pytest.fixture
def owner(tmp_path):
    processes = []
    roots = []

    def start(first="none", second="none"):
        root = tmp_path / str(len(processes))
        root.mkdir()
        roots.append(root)
        (root / ".hermes-isolated-profile").write_text("disposable", encoding="utf8")
        source = Path(__file__).with_name("native_isolated_child.py")

        def child(role, fault):
            command = [
                sys.executable,
                "-B",
                "-m",
                "tests.hermes_cli.native_isolated_child",
                role,
                str(root),
            ]
            if fault == "exec_fail":
                command[0] = str(root / "missing-executable")
            elif fault != "none":
                command += ["--fault", fault]
            return {
                "command": command,
                "artifact": str(source),
                "artifact_digest": hashlib.sha256(source.read_bytes()).hexdigest(),
            }

        spec = {
            "profile": str(root),
            "error_log": str(root / "stderr.log"),
            "core": child("core", first),
            "control": child("control", second),
        }
        plan = root / "plan.json"
        plan.write_text(json.dumps(spec), encoding="utf8")
        env = {
            "HOME": str(tmp_path),
            "HERMES_HOME": str(root),
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
        }
        proc = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-m",
                "tests.hermes_cli.native_isolated_owner",
                str(plan),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        processes.append(proc)
        return proc, root

    yield start
    for p in processes:
        if p.poll() is None:
            p.terminate()
        p.communicate(timeout=10)
    for root in roots:
        rows = (
            [
                json.loads(x)
                for x in (root / "children.jsonl")
                .read_text(encoding="utf8")
                .splitlines()
            ]
            if (root / "children.jsonl").exists()
            else []
        )
        for row in rows:
            if row["kind"] == "start":
                assert wait_until(lambda: not psutil.pid_exists(row["pid"]), timeout=5)


def ready(p, root):
    assert wait_until(
        lambda: (root / "ready.json").exists() or p.poll() is not None, timeout=8
    )
    assert p.poll() is None, p.communicate()
    return json.loads((root / "ready.json").read_text(encoding="utf8"))


def test_two_direct_children_FD_lifecycle_unload_and_normal_reaping(owner):
    p, root = owner()
    info = ready(p, root)
    assert info["wrapper"]["pid"] == p.pid
    assert len(psutil.Process(p.pid).children()) == 2
    for pid in info["children"].values():
        assert psutil.Process(pid).ppid() == p.pid
    rows = [
        json.loads(x)
        for x in (root / "children.jsonl").read_text(encoding="utf8").splitlines()
    ]
    assert all(
        r["noninheritable"] and len(r["socket_fds"]) == 1
        for r in rows
        if r["kind"] == "start"
    )
    assert any(r["kind"] == "manager_survived_actual_plugin_unload" for r in rows)
    (root / "stop").touch()
    stdout, stderr = p.communicate(timeout=8)
    assert p.returncode == 0, (stdout, stderr)
    assert "core stdout" in stdout and "control stdout" in stdout
    log = (root / "stderr.log").read_text(encoding="utf8")
    assert "core stderr" in log and "control stderr" in log
    assert not any(psutil.pid_exists(pid) for pid in info["children"].values())


@pytest.mark.parametrize("role", ["first", "second"])
def test_child_exec_failure_reaps_any_started_child(owner, role):
    p, _ = owner(
        first="exec_fail" if role == "first" else "none",
        second="exec_fail" if role == "second" else "none",
    )
    p.communicate(timeout=8)
    assert p.returncode == 127


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_wrapper_signal_forwards_and_reaps(owner, sig):
    p, root = owner()
    info = ready(p, root)
    p.send_signal(sig)
    p.communicate(timeout=8)
    assert p.returncode == 128 + sig
    assert not any(psutil.pid_exists(pid) for pid in info["children"].values())


def test_wrapper_SIGKILL_private_FD_EOF_exits_and_OS_reaps(owner):
    p, root = owner()
    info = ready(p, root)
    p.kill()
    p.communicate(timeout=8)
    for pid in info["children"].values():
        assert wait_until(lambda: not psutil.pid_exists(pid), timeout=5)


@pytest.mark.parametrize("role", ["core", "control"])
def test_child_crash_closes_sibling_and_requires_fresh_approval(owner, role):
    p, root = owner()
    old = ready(p, root)
    os.kill(old["children"][role], signal.SIGKILL)
    p.communicate(timeout=8)
    assert p.returncode == 137
    q, newroot = owner()
    new = ready(q, newroot)
    assert new["supervisor_epoch"] != old["supervisor_epoch"]
    assert new["control_epoch"] != old["control_epoch"]
    assert set(new["approval_refs"]).isdisjoint(old["approval_refs"])
    (newroot / "stop").touch()
    q.communicate(timeout=8)
    assert q.returncode == 0


def test_unapproved_profile_cli_cannot_mint_bootstrap_authority(tmp_path):
    from hermes_cli.stderr_timestamp import run_isolated_profile

    with pytest.raises(PermissionError, match="trust root UNKNOWN"):
        run_isolated_profile({})


@pytest.mark.parametrize("fault", ["wrong_pid", "wrong_artifact"])
def test_wrong_bootstrap_identity_fails_closed(owner, fault):
    p, _ = owner(first=fault)
    p.communicate(timeout=8)
    assert p.returncode == 127


def test_startup_signal_reaps_partial_child(owner):
    p, root = owner(first="delay")
    assert wait_until(lambda: (root / "children.jsonl").exists(), timeout=5)
    p.terminate()
    p.communicate(timeout=8)
    assert p.returncode == 143


def test_duplicate_wrapper_cannot_create_second_control_owner(owner):
    p, root = owner()
    info = ready(p, root)
    env = {
        "HOME": str(root.parent),
        "HERMES_HOME": str(root),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    other = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "tests.hermes_cli.native_isolated_owner",
            str(root / "plan.json"),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=8,
        check=False,
    )
    assert other.returncode == 127
    assert len(psutil.Process(p.pid).children()) == 2
    assert all(psutil.pid_exists(pid) for pid in info["children"].values())
    (root / "stop").touch()
    p.communicate(timeout=8)
    assert p.returncode == 0
