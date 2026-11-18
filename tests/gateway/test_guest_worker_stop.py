"""E1–E3/M10 future native shutdown proof; collection and default gate are inert.

A disposable parent dying is tested separately from VM death. An SSH exit or
fixture rescue cannot become a verified production Owner-recovery claim.
"""
from __future__ import annotations

import signal
import subprocess
from typing import Any

import psutil
import pytest

from tests.gateway.test_guest_worker_boundary import native_lab as native_lab


def _live_guest(lab: Any) -> dict[str, Any]:
    lab.start()
    value = lab.ssh_code("import json,os; print(json.dumps({'live':True,'pid':os.getpid()}))")
    assert value['live'] is True and value['pid'] > 0
    lab.assert_identity()
    state = lab.state()
    assert isinstance(state, dict)
    assert state['vm_running'] and state['tracked_processes'] and state['open_endpoints']
    return state


def _verified(receipt: dict[str, Any]) -> None:
    assert receipt['verified'] is True
    assert receipt['vm_stopped'] is True
    assert receipt['processes_gone'] is True
    assert receipt['endpoints_closed'] is True
    assert receipt['writers_quiescent'] is True
    assert not any(receipt['state'].values())


@pytest.mark.platforms('macos', arch='arm64')
def test_e1_revoke_stop_wait_closes_actual_vm_and_channels(native_lab: Any) -> None:
    lab = native_lab
    before = _live_guest(lab)
    # Long-lived real SSH stream; tracked and explicitly revoked before VM stop.
    code = "import sys; print('LIVE',flush=True); sys.stdin.read()"
    import shlex
    stream = lab.spawn_transport(lab.ssh_argv() + ['/usr/bin/python3 -u -c ' + shlex.quote(code)])
    assert stream.stdout is not None
    import selectors
    with selectors.DefaultSelector() as ready:
        ready.register(stream.stdout, selectors.EVENT_READ)
        assert ready.select(lab.gate['deadlines']['probe'])
        assert stream.stdout.readline() == 'LIVE\n'
    receipt = lab.stop()
    _verified(receipt)
    assert stream.poll() is not None
    assert stream.stdout.closed and stream.stdin.closed and stream.stderr.closed
    assert before['tracked_processes']
    assert lab.stop() == receipt, 'idempotent Stop must not mint another receipt'
    lab.assert_no_successor()


@pytest.mark.platforms('macos', arch='arm64')
def test_m10_ssh_exit_is_not_vm_stop(native_lab: Any) -> None:
    lab = native_lab
    _live_guest(lab)
    finished = lab.run(lab.ssh_argv() + ['true'])
    assert finished.returncode == 0
    assert lab.state()['vm_running'], 'positive VMM witness disappeared'
    assert not lab.verified_stop
    with pytest.raises(AssertionError, match='successor'):
        lab.assert_no_successor()
    _verified(lab.stop())


@pytest.mark.platforms('macos', arch='arm64')
def test_e2_stubborn_vmm_stop_deadline_cannot_be_silently_success(native_lab: Any) -> None:
    lab = native_lab
    _live_guest(lab)
    driver = psutil.Process(lab.driver_pid)
    birth = driver.create_time()
    assert birth == lab.process_identities[driver.pid]
    driver.send_signal(signal.SIGSTOP)  # Only this freshly owned disposable VMM.
    try:
        try:
            receipt = lab.stop()
        except (AssertionError, subprocess.TimeoutExpired):
            assert not lab.verified_stop
            lab.mark_uncertain('stop_deadline')
            with pytest.raises(AssertionError, match='successor'):
                lab.assert_no_successor()
        else:
            # A supported bounded force-stop may legitimately succeed even for
            # a suspended VMM. Verify reality instead of demanding a timeout.
            _verified(receipt)
    finally:
        if psutil.pid_exists(driver.pid):
            assert driver.create_time() == birth, 'PID replacement: do not signal'
            if driver.status() != psutil.STATUS_ZOMBIE:
                driver.send_signal(signal.SIGCONT)
        if not lab.verified_stop:
            # A separate, bounded fixture rescue, never a renewed first Stop.
            lab.record('rescue-required', {'qualification': 'UNKNOWN', 'first_stop_failed': True})
            lab._stop_at = None
            _verified(lab.stop())
            assert lab.uncertain == 'stop_deadline'



@pytest.mark.platforms('macos', arch='arm64')
def test_e3_actual_disposable_parent_death_never_authorizes_adoption(native_lab: Any) -> None:
    lab = native_lab
    _live_guest(lab)
    owner = lab.process
    assert owner is not None and owner.poll() is None
    parent_pid = owner.pid
    owner.kill()
    owner.wait(timeout=lab.gate['deadlines']['probe'])
    assert owner.returncode is not None
    lab.mark_uncertain('test_owner_died')
    observed = lab.state()
    lab.record('owner-death-observation', {'owner_pid': parent_pid, 'state': observed,
                                          'qualification': 'UNKNOWN_NO_SUCCESSOR'})
    with pytest.raises(AssertionError, match='successor'):
        lab.assert_no_successor()
    with pytest.raises(AssertionError):
        lab.start()
    # The outer test can clean only its recorded exact VM. This is no evidence
    # that the unimplemented production Owner restart path automatically reaps it.
    _verified(lab.stop())
    assert lab.uncertain == 'test_owner_died'
