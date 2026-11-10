"""Independent-process verifier for one authenticated, generation-scoped UDS.

The supervisor supplies the approved process/profile/plugin. Never construct
that policy from registration JSON or model arguments. No product Store here.
"""
from __future__ import annotations

import hashlib
import time
import uuid

from agent.native_wire import canonical, receive, send, verified
from hermes_platform.native_peer import verify_peer


class NativeControlVerifier:
    def __init__(self, connection, *, approved_process, plugin_id, profile):
        self.connection = connection
        self.approved_process = dict(approved_process)
        self.plugin_id, self.profile = plugin_id, profile
        self.active = False
        self.seen = set()
        peer = verify_peer(connection, approved_process)
        registration = receive(connection)
        if (registration.get('contract') != 'hermes.native-registration/2'
                or registration.get('process') != peer
                or registration.get('plugin_id') != plugin_id
                or registration.get('profile') != profile
                or not registration.get('host_instance') or not registration.get('host_generation')):
            raise PermissionError('native registration policy mismatch')
        self.registration = registration
        self.channel = uuid.uuid4().hex
        challenge = {'contract': 'hermes.native-challenge/2', 'channel': self.channel,
                     'registration_digest': hashlib.sha256(canonical(registration)).hexdigest(),
                     'expires_at': time.time() + 5}
        send(connection, challenge)
        proof = verified(registration['public_key'], receive(connection))
        if proof != challenge or time.time() >= challenge['expires_at']:
            raise PermissionError('native challenge expired or mismatched')
        verify_peer(connection, approved_process)
        self.active = True
        send(connection, {'registered': self.channel})

    def receive_call(self):
        try:
            frame = receive(self.connection)
            return self._verify_call(frame), frame['payload']
        except (OSError, EOFError, ValueError, KeyError, TypeError, PermissionError):
            self.close()
            raise

    def _verify_call(self, frame):
        if not self.active:
            raise PermissionError('native registration revoked')
        verify_peer(self.connection, self.approved_process)
        body = verified(self.registration['public_key'], frame['attestation'])
        invocation = body['invocation']
        ingress = invocation['ingress']
        expected = self.registration
        process = invocation['process']
        if (body.get('contract') != 'hermes.native-call/2' or body.get('channel') != self.channel
                or not time.time() < body['expires_at'] <= time.time() + 60
                or body['nonce'] in self.seen or len(self.seen) >= 4096
                or body['payload_digest'] != hashlib.sha256(canonical(frame['payload'])).hexdigest()
                or any(invocation.get(k) != expected[k] for k in ('plugin_id', 'host_instance', 'host_generation'))
                or any(process.get(k) != self.approved_process[k] for k in ('pid', 'uid', 'birth', 'executable'))
                or ingress.get('profile') != self.profile or ingress.get('source') != 'TOP_LEVEL_HUMAN'
                or not all(ingress.get(k) for k in ('turn', 'session', 'actor', 'conversation'))
                or not invocation.get('invocation_id') or not invocation.get('tool_name')):
            raise PermissionError('native attestation binding mismatch')
        self.seen.add(body['nonce'])
        return body

    def reply(self, attestation, result):
        if not self.active or attestation['channel'] != self.channel:
            raise PermissionError('native registration revoked')
        verify_peer(self.connection, self.approved_process)
        send(self.connection, {'call_nonce': attestation['nonce'],
                              'payload_digest': attestation['payload_digest'], 'result': result,
                              'result_digest': hashlib.sha256(canonical(result)).hexdigest()})

    def close(self):
        self.active = False
        self.connection.close()
