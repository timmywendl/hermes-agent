"""Client registration; the generation private key never leaves the native Host."""
from __future__ import annotations

import hashlib
import socket
import threading
import time
import uuid
from dataclasses import asdict

from agent.native_wire import canonical, receive, send, signed
from agent.native_turn import current_turn
from hermes_platform.native_peer import process_snapshot, verify_peer


class NativeControlChannel:
    def __init__(self, host, path, approved_control):
        self.host = host
        self.lock = threading.RLock()
        self.connection = socket.socket(socket.AF_UNIX)
        self.connection.set_inheritable(False)
        self.connection.settimeout(2)
        self.approved_control = approved_control
        try:
            self.connection.connect(str(path))
            verify_peer(self.connection, approved_control)
            registration = {'contract': 'hermes.native-registration/2',
                            'plugin_id': host.plugin_id, 'profile': host.profile,
                            'host_instance': host.instance, 'host_generation': host.generation,
                            'process': process_snapshot(host.process.pid),
                            'public_key': host._key.public_key().public_bytes_raw().hex()}
            send(self.connection, registration)
            challenge = receive(self.connection)
            if (challenge.get('contract') != 'hermes.native-challenge/2'
                    or challenge['registration_digest'] != hashlib.sha256(canonical(registration)).hexdigest()
                    or not time.time() < challenge['expires_at'] <= time.time() + 10):
                raise PermissionError('native registration challenge mismatch')
            send(self.connection, signed(host._key, challenge))
            receipt = receive(self.connection)
            if receipt != {'registered': challenge['channel']}:
                raise PermissionError('native registration not confirmed')
            self.channel = challenge['channel']
        except BaseException:
            self.connection.close()
            raise

    def call(self, invocation, payload):
        with self.lock:
            if not self.host.matches(invocation):
                raise PermissionError('native invocation expired')
            return self._call(invocation, payload)

    def call_evidence(self, evidence, payload):
        """Revalidate/ack only this turn's native-owned evidence during commit."""
        with self.lock:
            state = current_turn.get()
            if (not self.host.live() or state is None or state.finished
                    or state.evidence.get(self.host.plugin_id) is not evidence
                    or evidence.expires_at <= time.monotonic()
                    or evidence.invocation.ingress is not state.ingress
                    or evidence.invocation.host_generation != self.host.generation):
                raise PermissionError('native evidence expired')
            return self._call(evidence.invocation, payload)

    def _call(self, invocation, payload):
        verify_peer(self.connection, self.approved_control)
        body = {'contract': 'hermes.native-call/2', 'channel': self.channel,
                'invocation': asdict(invocation), 'nonce': uuid.uuid4().hex,
                'expires_at': time.time() + 30,
                'payload_digest': hashlib.sha256(canonical(payload)).hexdigest()}
        send(self.connection, {'attestation': signed(self.host._key, body), 'payload': payload})
        response = receive(self.connection)
        if (response.get('call_nonce') != body['nonce']
                or response.get('payload_digest') != body['payload_digest']
                or response.get('result_digest') != hashlib.sha256(canonical(response.get('result'))).hexdigest()):
            raise PermissionError('native Control result binding mismatch')
        return response['result']

    def close(self):
        with self.lock:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # An already closed Control channel has no surviving registration.
            self.connection.close()
