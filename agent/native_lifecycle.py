"""Core-owned lifecycle identity, outside PluginHost and plugin unload ledgers."""

from __future__ import annotations

import hashlib
import socket
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.native_bootstrap import require_approval
from agent.native_wire import canonical, receive, send, signed
from hermes_platform.native_peer import process_snapshot, verify_peer


class NativeLifecycleChannel:
    def __init__(self, profile):
        self.profile = profile
        self.manager_instance, self.manager_epoch = uuid.uuid4().hex, uuid.uuid4().hex
        self.__key = Ed25519PrivateKey.generate()
        self.__approval = None
        self.__connection = None
        self.__lock = threading.RLock()
        self.closed = True
        self.admission_closed = True
        self.__hosts = []

    def track_host(self, host):
        import weakref

        self.__hosts.append(weakref.ref(host))

    def bootstrap_proof(self, nonce, control_epoch, public):
        """Only the fixed bootstrap nonce/public-pin proof; no generic signing API."""
        if not isinstance(nonce, str) or len(nonce) != 32 or not control_epoch:
            raise PermissionError("invalid bootstrap challenge")
        return signed(
            self.__key,
            {"nonce": nonce, "control_epoch": control_epoch, "public": public},
        )

    @property
    def public_key(self):
        return self.__key.public_key().public_bytes_raw().hex()

    def bootstrap(self, approval):
        a = require_approval(approval, role="manager")
        if (
            a.profile != self.profile
            or a.process != process_snapshot(__import__("os").getpid())
            or a.manager_instance != self.manager_instance
            or a.manager_epoch != self.manager_epoch
            or a.public_key != self.public_key
        ):
            raise PermissionError("Manager bootstrap mismatch")
        with self.__lock:
            self.close()
            self.__approval = a

    def connect_control(self, path, approved_control):
        with self.__lock:
            a = require_approval(self.__approval, role="manager")
            self.close()
            c = socket.socket(socket.AF_UNIX)
            c.set_inheritable(False)
            c.settimeout(2)
            try:
                c.connect(str(path))
                verify_peer(c, approved_control)
                registration = {
                    "contract": "hermes.native-lifecycle-registration/2",
                    "profile": a.profile,
                    "process": a.process,
                    "public_key": self.public_key,
                    "manager_instance": self.manager_instance,
                    "manager_epoch": self.manager_epoch,
                    "approval_ref": a.approval_ref,
                }
                send(c, registration)
                challenge = receive(c)
                if (
                    challenge.get("contract") != "hermes.native-challenge/2"
                    or challenge.get("registration_digest")
                    != hashlib.sha256(canonical(registration)).hexdigest()
                    or challenge.get("approval_ref") != a.approval_ref
                    or challenge.get("control_epoch") != a.control_epoch
                    or not time.time() < challenge["expires_at"] <= time.time() + 10
                ):
                    raise PermissionError("Manager challenge mismatch")
                send(c, signed(self.__key, challenge))
                if receive(c) != {
                    "registered": challenge["channel"],
                    "control_epoch": a.control_epoch,
                }:
                    raise PermissionError("Manager registration mismatch")
                self.__connection, self.__control = c, dict(approved_control)
                self.channel, self.control_epoch = challenge["channel"], a.control_epoch
                self.closed = False
            except BaseException:
                c.close()
                raise
        return self

    def _call(self, operation, operation_id, params):
        with self.__lock:
            a = require_approval(self.__approval, role="manager")
            if (
                self.closed
                or not operation_id
                or operation not in ("approve", "state_sync", "revoke")
            ):
                raise PermissionError("Manager lifecycle unavailable")
            verify_peer(self.__connection, self.__control)
            payload = {
                "operation": operation,
                "operation_id": operation_id,
                "params": params or {},
            }
            body = {
                "contract": "hermes.native-lifecycle/2",
                "channel": self.channel,
                "manager_instance": self.manager_instance,
                "manager_epoch": self.manager_epoch,
                "control_epoch": a.control_epoch,
                "approval_ref": a.approval_ref,
                "nonce": uuid.uuid4().hex,
                "expires_at": time.time() + 10,
                **payload,
                "payload_digest": hashlib.sha256(canonical(payload)).hexdigest(),
            }
            send(
                self.__connection,
                {"attestation": signed(self.__key, body), "payload": payload},
            )
            result = receive(self.__connection, 10)
            if (
                result.get("control_epoch") != a.control_epoch
                or result.get("call_nonce") != body["nonce"]
                or result.get("payload_digest") != body["payload_digest"]
                or result.get("result_digest")
                != hashlib.sha256(canonical(result.get("result"))).hexdigest()
            ):
                raise PermissionError("Manager response binding mismatch")
            return result["result"]

    def approve(self, operation_id, params=None):
        self.admission_closed = True
        result = self._call("approve", operation_id, params)
        if not isinstance(result, dict) or result.get("state") != "ACTIVE":
            raise PermissionError("Manager approval not confirmed")
        self.admission_closed = False
        return result

    def state_sync(self, operation_id, params=None):
        return self._call("state_sync", operation_id, params)

    def revoke(self, operation_id, params=None):
        self.admission_closed = True
        for ref in self.__hosts:
            host = ref()
            if host is not None:
                host.invalidate()
        return self._call("revoke", operation_id, params)

    def close(self):
        with self.__lock:
            self.closed = True
            if self.__connection is not None:
                try:
                    self.__connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.__connection.close()
                self.__connection = None
