"""Real independent OS Control and macOS kernel UDS authentication, no injected verifier."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.native_turn import (HumanText, PluginHost, consume_ingress, current_invocation,
                               current_turn)
from agent.native_wire import canonical, receive, send, signed
from agent.response_gate import TurnGate
from hermes_constants import hermes_home_key
from hermes_platform.native_peer import process_snapshot

pytestmark = pytest.mark.platforms('macos')


@pytest.fixture
def control_peer(tmp_path, monkeypatch):
    # External runners are not sufficient: bind both HOME and HERMES_HOME here.
    home = tmp_path / 'user'
    home.mkdir()
    (home / '.native-test-fixture').write_text('disposable')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(home / 'hermes'))
    assert (Path(os.environ['HOME']) / '.native-test-fixture').is_file()
    processes = []
    with tempfile.TemporaryDirectory(prefix='h-native-', dir='/tmp') as sockets:
        def start(approved=None):
            path = str(Path(sockets) / f'c{len(processes)}.sock')
            process = subprocess.Popen([sys.executable, '-u', '-m', 'tests.agent.native_control_peer',
                path, json.dumps(approved or process_snapshot(os.getpid())), hermes_home_key()],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=dict(os.environ))
            processes.append(process)
            identity = json.loads(process.stdout.readline())
            assert identity['pid'] != os.getpid()
            return path, identity, process
        yield start
    for process in processes:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=10)


@pytest.fixture
def native_host():
    host = PluginHost('fixture', hermes_home_key())
    ingress = HumanText('project facts', session='s').native_ingress
    state = TurnGate(consume_ingress(ingress, 's'), ())
    turn_token = current_turn.set(state)
    invocation = host.invocation('query')
    call_token = current_invocation.set(invocation)
    yield host, state, invocation
    host.close()
    current_invocation.reset(call_token)
    current_turn.reset(turn_token)


def raw_register(path, host, **changes):
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(3)
    connection.connect(path)
    registration = {'contract': 'hermes.native-registration/2', 'plugin_id': host.plugin_id,
                    'profile': host.profile, 'host_instance': host.instance,
                    'host_generation': host.generation, 'process': process_snapshot(os.getpid()),
                    'public_key': host._key.public_key().public_bytes_raw().hex()}
    registration.update(changes)
    send(connection, registration)
    return connection


def proof(connection, host, challenge=None):
    actual = receive(connection)
    send(connection, signed(host._key, actual if challenge is None else challenge))
    assert receive(connection) == {'registered': actual['channel']}
    return actual


def frame(host, invocation, channel, **changes):
    payload = {'operation': 'query'}
    body = {'contract': 'hermes.native-call/2', 'channel': channel,
            'invocation': asdict(invocation), 'nonce': 'test-nonce',
            'expires_at': time.time() + 30,
            'payload_digest': hashlib.sha256(canonical(payload)).hexdigest()}
    body.update(changes)
    return {'attestation': signed(host._key, body), 'payload': payload}


def test_live_registration_restart_reload_result_and_expired_turn(control_peer, native_host):
    host, state, invocation = native_host
    path, identity, process = control_peer()
    channel = host.connect_control(path, identity)
    result = channel.call(invocation, {'operation': 'query'})
    assert result['pid'] == process.pid and result['turn'] == invocation.ingress.turn
    with pytest.raises(PermissionError, match='result binding'):
        channel.call(invocation, {'operation': 'bad-result'})
    state.closed = True
    with pytest.raises(PermissionError, match='expired'):
        channel.call(invocation, {})
    state.closed = False
    evidence = host.record_result(invocation, control_request_id='r', context_revision='c',
        mission_revision='m', query_result_digest='d', output='verified')
    state.closed = True
    assert channel.call_evidence(evidence, {})['turn'] == invocation.ingress.turn
    with pytest.raises(PermissionError):
        channel.call_evidence(copy.copy(evidence), {})
    state.finished = True
    with pytest.raises(PermissionError):
        channel.call_evidence(evidence, {})
    state.finished = False
    state.closed = False
    process.terminate()
    process.wait(10)
    with pytest.raises((OSError, PermissionError)):
        channel.call(invocation, {})
    new_path, new_identity, _ = control_peer()
    resumed = host.connect_control(new_path, new_identity)
    assert resumed.call(invocation, {})['turn'] == invocation.ingress.turn
    host.close()
    with pytest.raises(PermissionError):
        resumed.call(invocation, {})
    replacement = PluginHost('fixture', hermes_home_key())
    assert replacement.generation != host.generation
    try:
        reloaded = replacement.connect_control(new_path, new_identity)
        with pytest.raises(PermissionError):
            reloaded.call(invocation, {})
        next_invocation = replacement.invocation('query')
        token = current_invocation.set(next_invocation)
        try:
            assert reloaded.call(next_invocation, {})['turn'] == invocation.ingress.turn
        finally:
            current_invocation.reset(token)
    finally:
        replacement.close()


@pytest.mark.parametrize('field', ['pid', 'uid', 'birth', 'boot', 'executable', 'executable_digest'])
def test_wrong_supervisor_pin_rejects_native_peer(control_peer, native_host, field):
    host, _, _ = native_host
    approved = process_snapshot(os.getpid())
    approved[field] = approved[field] + 1 if isinstance(approved[field], (int, float)) else 'wrong'
    path, identity, _ = control_peer(approved)
    with pytest.raises((OSError, EOFError, PermissionError)):
        host.connect_control(path, identity)


@pytest.mark.parametrize('field,value', [('profile', '/wrong/profile'), ('plugin_id', 'stranger')])
def test_registration_policy_rejects_wrong_profile_plugin(control_peer, native_host, field, value):
    host, _, _ = native_host
    path, _, _ = control_peer()
    with raw_register(path, host, **{field: value}) as connection:
        with pytest.raises((OSError, EOFError)):
            receive(connection)


def test_same_uid_unregistered_process(control_peer, native_host):
    path, _, _ = control_peer()
    script = "import socket,sys; from agent.native_wire import receive; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]);\ntry: receive(s)\nexcept (OSError,EOFError): print('REJECTED')"
    result = subprocess.run([sys.executable, '-c', script, path], capture_output=True, text=True,
                            timeout=10, env=dict(os.environ), check=False)
    assert result.returncode == 0 and result.stdout.strip() == 'REJECTED'


def test_wrong_key_and_challenge_replay(control_peer, native_host):
    host, _, _ = native_host
    path, _, _ = control_peer()
    with raw_register(path, host) as connection:
        challenge = receive(connection)
        send(connection, signed(Ed25519PrivateKey.generate(), challenge))
        with pytest.raises((OSError, EOFError)):
            receive(connection)
    with raw_register(path, host) as connection:
        fresh = receive(connection)
        assert fresh['channel'] != challenge['channel']
        send(connection, signed(host._key, challenge))
        with pytest.raises((OSError, EOFError)):
            receive(connection)


@pytest.mark.parametrize('mutation', ['replay', 'expired', 'generation', 'old-channel', 'payload', 'invocation', 'key'])
def test_signed_call_binding_and_replay(control_peer, native_host, mutation):
    host, _, invocation = native_host
    path, _, _ = control_peer()
    with raw_register(path, host) as connection:
        challenge = proof(connection, host)
        valid = frame(host, invocation, challenge['channel'])
        send(connection, valid)
        assert receive(connection)['result']['turn'] == invocation.ingress.turn
        altered = copy.deepcopy(valid)
        body = altered['attestation']['body']
        if mutation != 'replay':
            body['nonce'] = 'fresh-nonce'
        if mutation == 'expired': body['expires_at'] = time.time() - 1
        if mutation == 'generation': body['invocation']['host_generation'] = 'old'
        if mutation == 'old-channel': body['channel'] = 'previous-control-registration'
        if mutation == 'payload': altered['payload']['operation'] = 'tampered'
        if mutation == 'invocation': body['invocation']['ingress']['profile'] = 'wrong'
        key = Ed25519PrivateKey.generate() if mutation == 'key' else host._key
        altered['attestation'] = signed(key, body)
        send(connection, altered)
        with pytest.raises((OSError, EOFError)):
            receive(connection)


@pytest.mark.parametrize('field', ['pid', 'uid', 'birth', 'boot', 'executable', 'executable_digest'])
def test_registration_claim_cannot_override_kernel_identity(control_peer, native_host, field):
    host, _, _ = native_host
    path, _, _ = control_peer()
    claimed = process_snapshot(os.getpid())
    claimed[field] = claimed[field] + 1 if isinstance(claimed[field], (int, float)) else 'forged'
    with raw_register(path, host, process=claimed) as connection:
        with pytest.raises((OSError, EOFError)):
            receive(connection)


def test_registered_public_key_must_match_proof(control_peer, native_host):
    host, _, _ = native_host
    path, _, _ = control_peer()
    other_public = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    with raw_register(path, host, public_key=other_public) as connection:
        challenge = receive(connection)
        send(connection, signed(host._key, challenge))
        with pytest.raises((OSError, EOFError)):
            receive(connection)


def test_expired_registration_challenge(control_peer, native_host):
    import threading
    host, _, _ = native_host
    path, _, _ = control_peer()
    with raw_register(path, host) as connection:
        challenge = receive(connection)
        # Server's finite receive deadline expires even before the proof TTL.
        threading.Event().wait(2.2)  # health: allow HX013 -- challenge deadline itself is the behavior under test
        try:
            send(connection, signed(host._key, challenge))
        except OSError:
            return
        with pytest.raises((OSError, EOFError)):
            receive(connection)


def test_client_checks_control_process_pin(control_peer, native_host):
    host, _, _ = native_host
    path, identity, _ = control_peer()
    identity['birth'] += 1
    with pytest.raises(PermissionError, match='process mismatch'):
        host.connect_control(path, identity)
