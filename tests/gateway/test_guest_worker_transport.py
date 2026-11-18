"""Future native B1/B2/C1 qualification for AI Colleague Issue 139.

Collection is inert. Every test first enters the boundary module's complete,
explicit disposable authorization gate. This file never supplies approval,
selects an ambient SSH identity, or treats a skip as Q1 qualification. M7-M9
and M11 operate on actual future VM/SSH channels, not fabricated SSH results.
"""
from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
import json
from pathlib import Path
import selectors
import shlex
import socket
import struct
import subprocess
import threading
from typing import Any

import pytest

from tests.gateway.test_guest_worker_boundary import native_lab as native_lab


def _replace_option(argv: list[str], name: str, value: str) -> list[str]:
    """OpenSSH uses the first option value; never append a conflicting override."""
    result = list(argv)
    positions = [i for i, item in enumerate(result[:-1])
                 if item == '-o' and result[i + 1].startswith(name + '=')]
    assert len(positions) == 1, f'UNAVAILABLE: no unique protected {name} option'
    result[positions[0] + 1] = f'{name}={value}'
    return result


def _guest_command(code: str) -> str:
    return '/usr/bin/python3 -u -c ' + shlex.quote(code)


def _read_ready(process: subprocess.Popen[str], seconds: float) -> None:
    assert process.stdout is not None
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(seconds), 'UNAVAILABLE: SSH canary never became ready'
        assert process.stdout.readline() == 'Q1_FORWARD_READY\n', 'protocol stdout polluted'


@contextmanager
def _echo_socket(path: Path) -> Iterator[tuple[socket.socket, list[bytes]]]:
    """Synthetic Host UDS: no Docker/CDP, credentials or production service."""
    assert len(str(path).encode()) < 100, 'UNAVAILABLE: temporary UDS path is too long'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stop = threading.Event()
    received: list[bytes] = []
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(4)

    def serve() -> None:
        with selectors.DefaultSelector() as selector:
            selector.register(listener, selectors.EVENT_READ)
            while not stop.is_set():
                if selector.select(0.2):
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        body = connection.recv(256)
                        received.append(body)
                        connection.sendall(body)

    thread = threading.Thread(target=serve, name='q1-uds-canary', daemon=True)
    thread.start()
    try:
        yield listener, received
    finally:
        stop.set()
        thread.join(timeout=3)
        listener.close()
        assert not thread.is_alive(), 'UNKNOWN: UDS canary thread remains live'
        path.unlink()


@contextmanager
def _reverse_forward(lab: Any, path: Path) -> Iterator[subprocess.Popen[str]]:
    command = _guest_command("import sys; print('Q1_FORWARD_READY', flush=True); sys.stdin.read()")
    argv = lab.ssh_argv(extra=('-o', 'ExitOnForwardFailure=yes', '-R',
                               f'127.0.0.1:51837:{path}')) + [command]
    process = lab.spawn_transport(argv)
    try:
        _read_ready(process, float(lab.gate['deadlines']['command']))
        yield process
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=float(lab.gate['deadlines']['stop']))
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=float(lab.gate['deadlines']['stop']))
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()


@pytest.mark.platforms('macos', arch='arm64')
def test_vsock_byte_channel_and_joint_identity(native_lab: Any) -> None:
    """B1/C1 positive witness uses real Guest boot, framing and Host custody."""
    native_lab.start()
    snapshot = native_lab.identity_snapshot()
    native_lab.assert_identity(expected=snapshot)
    result = native_lab.ssh_code(
        "import json; from pathlib import Path; "
        "print(json.dumps({'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),"
        "'canary':'Q1_NATIVE_VSOCK','bytes':[0,10,127,255]}))")
    assert result == {'boot': native_lab.boot_id, 'canary': 'Q1_NATIVE_VSOCK',
                      'bytes': [0, 10, 127, 255]}
    assert snapshot['boot_id'] == result['boot']
    assert snapshot['listener_fd'] >= 0
    assert snapshot['listener_pid'] > 0
    assert snapshot['policy_digest']
    assert snapshot['instance'] == native_lab.instance


@pytest.mark.platforms('macos', arch='arm64')
def test_wrong_host_key_is_rejected_by_real_ssh(native_lab: Any) -> None:
    """M8: a reachable real Guest must still reject a different valid public key."""
    native_lab.start()
    assert native_lab.ssh_code("import json; print(json.dumps({'reachable':True}))") == {'reachable': True}
    key_type = b'ssh-ed25519'
    public = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    wire = struct.pack('>I', len(key_type)) + key_type + struct.pack('>I', 32) + public
    wrong_hosts = native_lab.root / 'wrong_known_hosts'
    wrong_hosts.write_text(f"[127.0.0.1]:{native_lab.gate['ssh_port']} ssh-ed25519 "
                           + base64.b64encode(wire).decode() + '\n')
    wrong_hosts.chmod(0o600)
    argv = _replace_option(native_lab.ssh_argv(), 'UserKnownHostsFile', str(wrong_hosts))
    result = native_lab.run(argv + [_guest_command("print('MUST_NOT_RUN')")])
    assert result.returncode != 0
    assert 'MUST_NOT_RUN' not in result.stdout
    assert ('Host key verification failed' in result.stderr
            or 'REMOTE HOST IDENTIFICATION HAS CHANGED' in result.stderr), result.stderr


@pytest.mark.platforms('macos', arch='arm64')
def test_tcp_fallback_is_not_an_admitted_vsock_channel(native_lab: Any) -> None:
    """M7: first prove native vsock, then reject a fresh forced NIC-SSH attempt."""
    native_lab.start()
    assert native_lab.ssh_code("import json; print(json.dumps({'vsock':True}))") == {'vsock': True}
    assert native_lab.stop()['verified'] is True
    with pytest.raises(AssertionError, match='vsock'):
        native_lab.start(over_vsock=False)


@pytest.mark.platforms('macos', arch='arm64')
def test_only_declared_reverse_forward_reaches_host_uds(native_lab: Any) -> None:
    """B2/M9: real UDS receipt and extra-listen denial under the same sshd policy."""
    native_lab.start()
    path = native_lab.root / 'echo.sock'
    with _echo_socket(path) as (_, received):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.settimeout(2)
            control.connect(str(path))
            control.sendall(b'Q1_HOST_CONTROL')
            assert control.recv(256) == b'Q1_HOST_CONTROL'
        with _reverse_forward(native_lab, path):
            result = native_lab.ssh_code(
                "import json,socket; s=socket.create_connection(('127.0.0.1',51837),timeout=2); "
                "s.sendall(b'Q1_GUEST_FORWARD'); value=s.recv(256); s.close(); "
                "print(json.dumps({'echo':value.decode()}))")
            assert result == {'echo': 'Q1_GUEST_FORWARD'}
            assert b'Q1_GUEST_FORWARD' in received
            extra = native_lab.ssh_argv(extra=('-o', 'ExitOnForwardFailure=yes', '-R',
                                                f'127.0.0.1:51838:{path}'))
            refused = native_lab.run(extra + [_guest_command("print('MUST_NOT_RUN')")])
            assert refused.returncode != 0
            assert 'MUST_NOT_RUN' not in refused.stdout
            assert 'remote port forwarding failed' in refused.stderr.lower(), refused.stderr


@pytest.mark.platforms('macos', arch='arm64')
@pytest.mark.parametrize('pin', ['boot_id', 'policy_digest', 'instance',
                                 'listener_pid', 'listener_fd'])
def test_joint_identity_rejects_a_substituted_pin(native_lab: Any, pin: str) -> None:
    """C1/M8/M11: actual live custody is checked, not a model-supplied hello."""
    native_lab.start()
    snapshot = native_lab.identity_snapshot()
    native_lab.assert_identity(expected=snapshot)
    substituted = dict(snapshot)
    value = substituted[pin]
    substituted[pin] = value + 100_000 if isinstance(value, int) else str(value) + '-stale'
    with pytest.raises(AssertionError):
        native_lab.assert_identity(expected=substituted)
    native_lab.assert_identity(expected=snapshot)


@pytest.mark.platforms('macos', arch='arm64')
def test_previous_vm_identity_cannot_resume_after_verified_restart(native_lab: Any) -> None:
    """M11 uses two actual VM boots, with full stop before the successor."""
    native_lab.start()
    previous = native_lab.identity_snapshot()
    assert native_lab.stop()['verified'] is True
    native_lab.start()
    current = native_lab.identity_snapshot()
    assert current['boot_id'] != previous['boot_id']
    assert current['instance'] != previous['instance']
    native_lab.assert_identity(expected=current)
    with pytest.raises(AssertionError):
        native_lab.assert_identity(expected=previous)


@pytest.mark.platforms('macos', arch='arm64')
def test_protocol_stdout_pollution_cannot_be_accepted_as_a_result(native_lab: Any) -> None:
    """Real SSH is successful; a banner before JSON must break the closed parser."""
    native_lab.start()
    assert native_lab.ssh_code("import json; print(json.dumps({'clean':True}))") == {'clean': True}
    with pytest.raises((AssertionError, json.JSONDecodeError)):
        native_lab.ssh_code("import json; print('UNTRUSTED_BANNER'); print(json.dumps({'clean':False}))")
