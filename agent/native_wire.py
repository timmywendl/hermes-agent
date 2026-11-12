"""Bounded canonical frames and asymmetric native envelopes, wire contract v2."""
from __future__ import annotations

import json
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LIMIT = 131072


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf8')


def signed(key, body):
    return {'body': body, 'signature': key.sign(canonical(body)).hex()}


def verified(public_key, envelope):
    try:
        body = envelope['body']
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(envelope['signature']), canonical(body))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        raise PermissionError('native signature mismatch') from None
    return body


def send(connection, value):
    raw = canonical(value)
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('native frame too large')
    connection.sendall(struct.pack('!I', len(raw)) + raw)


def _read(connection, size, deadline):
    result = bytearray()
    while len(result) < size:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        if time.monotonic() >= deadline:
            raise TimeoutError('native frame expired')
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError('native channel closed')
        result.extend(chunk)
    return bytes(result)


def receive(connection, timeout=2, *, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + timeout
    size = struct.unpack('!I', _read(connection, 4, deadline))[0]
    if not 0 < size <= LIMIT:
        raise ValueError('native frame too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate native field')
            result[key] = value
        return result
    value = json.loads(_read(connection, size, deadline), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite value')))
    if not isinstance(value, dict):
        raise ValueError('invalid native frame')
    return value
