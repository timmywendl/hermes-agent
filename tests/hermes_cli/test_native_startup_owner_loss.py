"""Real Supervisor loss at blocked Core startup boundaries; synthetic dependencies."""

import json
import os
import signal
from pathlib import Path

import psutil
import pytest

from tests.hermes_cli.test_native_core_startup import rows
from tests.waiting import wait_until

pytest_plugins = ["tests.hermes_cli.test_native_core_startup"]
pytestmark = pytest.mark.platforms("macos")


def _save_proof(request, entry, fault, proof):
    target = request.config.getoption("xmlpath", default=None)
    if target:
        path = Path(target).with_suffix("").with_name(Path(target).stem + "-traces")
        path.mkdir(parents=True, exist_ok=True)
        (path / f"{fault}-{entry}.json").write_text(json.dumps(proof, indent=2) + "\n")


def _kill_owned_remaining(identities):
    # Red tests must clean their own demonstrably orphaned disposable children.
    for identity in identities:
        try:
            child = psutil.Process(identity["pid"])
            if child.create_time() == identity["birth"]:
                child.kill()
        except psutil.NoSuchProcess:
            pass


def _owner_loss(launch, entry, fault, request):
    owner, root = launch(fault, entry=entry)
    assert wait_until(lambda: any(r["kind"] == "owner_loss_boundary" for r in rows(root))
                      or owner.poll() is not None, timeout=12)
    assert owner.poll() is None, owner.communicate()
    boundary = next(r for r in rows(root) if r["kind"] == "owner_loss_boundary")
    core, supervisor = boundary["process"], boundary["supervisor"]
    assert supervisor["pid"] == owner.pid
    assert psutil.Process(core["pid"]).ppid() == owner.pid
    identities = [core]
    for row in rows(root):
        if row["kind"] == "start" and row.get("role") == "control":
            child = psutil.Process(row["pid"])
            identities.append({"pid": child.pid, "birth": child.create_time()})
    proof = {"boundary": boundary, "entry": entry, "fault": fault}
    try:
        os.kill(owner.pid, signal.SIGKILL)
        assert owner.wait(timeout=3) == -signal.SIGKILL
        try:
            wait_until(lambda: not psutil.pid_exists(core["pid"]), timeout=3)
            proof["core_exited_without_test_cleanup"] = True
        except AssertionError:
            proof["core_exited_without_test_cleanup"] = False
        proof["events"] = rows(root)
        _save_proof(request, entry, fault, proof)
        assert proof["core_exited_without_test_cleanup"], proof
        owner.communicate(timeout=5)
        events = rows(root)
        assert not (root / "ready.json").exists()
        assert not any(r["kind"] in ("application_entered", "downstream") for r in events)
        approvals = [r for r in events if r["kind"] == "manager_approved"]
        if fault == "owner_loss_after_approval":
            assert len(approvals) == 1 and approvals[0]["active"]
            assert any(r["kind"] == "control_generation_closed" and r["role"] == "manager"
                       and r["was_active"] for r in events)
        else:
            assert not approvals
            assert not any(r["kind"] == "control_lifecycle" and r["operation"] == "approve" for r in events)
        assert any(r["kind"] == "control_shutdown" and r["active_generations"] == 0 for r in events)
        assert all(not r["generation_active"] and not r["verifier_active"]
                   for r in events if r["kind"] == "control_generation_closed")
        for identity in identities:
            wait_until(lambda: not psutil.pid_exists(identity["pid"]), timeout=5)
        proof.update(events=events, ready=False, application_entered=False,
                     control_active_generations=0, all_children_reaped=True)
        _save_proof(request, entry, fault, proof)
    finally:
        _kill_owned_remaining(identities)
        owner.communicate(timeout=5)


# Supervisor SIGKILL deliberately reparents our recorded children outside the
# pytest subtree; cleanup below verifies their exact birth before signalling.
@pytest.mark.live_system_guard_bypass
@pytest.mark.parametrize("entry", ["cli", "gateway"])
@pytest.mark.parametrize("fault", ["owner_loss_registration", "owner_loss_after_approval"])
def test_supervisor_death_during_native_startup_fails_closed_without_orphans(launch, entry, fault, request):
    _owner_loss(launch, entry, fault, request)


@pytest.mark.live_system_guard_bypass
def test_supervisor_death_during_plugin_discovery_fails_closed_without_orphans(launch, request):
    _owner_loss(launch, "cli", "owner_loss_discovery", request)


@pytest.mark.live_system_guard_bypass
def test_supervisor_death_during_locked_manager_approval_fails_stop(launch, request):
    _owner_loss(launch, "cli", "owner_loss_manager_approval", request)
