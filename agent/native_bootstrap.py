"""Explicit supervisor approval capabilities; no ambient production trust root.

The provider is supplied by the launch owner, never by registration JSON, config,
model arguments or an environment switch. Python plugins remain trusted code.
"""

from __future__ import annotations

import copy
import time
from abc import ABC, abstractmethod

from hermes_platform.native_peer import process_snapshot

_TOKEN = object()
_COMMON = {
    "role",
    "process",
    "profile",
    "approval_ref",
    "supervisor_epoch",
    "control_epoch",
    "public_key",
    "artifact_digest",
    "expires_at",
}


class SupervisorApproval:
    __slots__ = ("__record",)

    def __init__(self, record, *, _token=None):
        if _token is not _TOKEN:
            raise PermissionError("supervisor provider required")
        object.__setattr__(self, "_SupervisorApproval__record", copy.deepcopy(record))

    def __setattr__(self, name, value):
        raise TypeError("immutable supervisor approval")

    def __getattr__(self, name):
        try:
            return copy.deepcopy(self.__record[name])
        except KeyError:
            raise AttributeError(name) from None

    def get(self, name, default=None):
        return copy.deepcopy(self.__record.get(name, default))

    def valid(self, *, control_epoch=None):
        return (
            time.time() < self.expires_at
            and (control_epoch is None or self.control_epoch == control_epoch)
            and self.process == process_snapshot(self.process["pid"])
        )

    def __reduce__(self):
        raise TypeError("opaque supervisor approval")

    def __copy__(self):
        raise TypeError("opaque supervisor approval")

    def __deepcopy__(self, memo):
        raise TypeError("opaque supervisor approval")


class BootstrapProvider(ABC):
    @abstractmethod
    def verify(self, record) -> SupervisorApproval:
        """Verify independently corroborated launch/process/artifact/key pins."""
        raise NotImplementedError


class DeniedBootstrapProvider(BootstrapProvider):
    def verify(self, record):
        raise PermissionError("supervisor bootstrap UNKNOWN")


class PinnedBootstrapProvider(BootstrapProvider):
    """Explicit launch-owner dependency, including synthetic isolated test owners.

    Expected pins must be built by the caller from its owned process handles and
    approved artifacts. This class does not discover/approve a production owner.
    """

    def __init__(self, expected):
        self.__expected = copy.deepcopy(expected)

    def verify(self, record):
        if not isinstance(record, dict) or record != self.__expected:
            raise PermissionError("supervisor approval pin mismatch")
        role = record.get("role")
        fields = (
            {"plugin_id", "host_instance", "host_generation"}
            if role == "business"
            else {"manager_instance", "manager_epoch"}
            if role == "manager"
            else set()
        )
        if (
            not fields
            or not _COMMON | fields <= set(record)
            or not all(record.get(k) for k in _COMMON | fields)
            or type(record["expires_at"]) not in (int, float)
            or not time.time() < record["expires_at"] <= time.time() + 3600
            or record["process"] != process_snapshot(record["process"]["pid"])
            or len(record["public_key"]) != 64
            or len(record["artifact_digest"]) != 64
        ):
            raise PermissionError("invalid supervisor approval")
        return SupervisorApproval(record, _token=_TOKEN)


def require_approval(approval, *, role=None, control_epoch=None):
    if (
        type(approval) is not SupervisorApproval
        or (role is not None and approval.role != role)
        or not approval.valid(control_epoch=control_epoch)
    ):
        raise PermissionError("supervisor approval required or expired")
    return approval


class NativeBootstrapEndpoint:
    """Private inherited FD endpoint with an independently approved launch owner.

    No implicit owner lookup: callers without a verified parent pin fail closed.
    Endpoint dictionaries are a launch protocol, never a model/plugin RPC.
    """

    def __init__(
        self, fd, *, role, profile, artifact_digest, approved_supervisor, provider=None
    ):
        import os
        import socket

        if (
            provider is None
            or not provider.verify_supervisor(approved_supervisor, profile)
            or not isinstance(approved_supervisor, dict)
            or approved_supervisor != process_snapshot(os.getppid())
        ):
            raise PermissionError("approved supervisor process required")
        self.socket = socket.socket(fileno=fd)
        self.socket.set_inheritable(False)
        self.role, self.profile = role, profile
        self.parent = copy.deepcopy(approved_supervisor)
        self.artifact_digest = artifact_digest
        self.sequence = 0
        self.channel = None
        if role == "core":
            from agent.native_selector import require_selector

            require_selector(profile)

    def announce(self, data):
        import os

        from agent.native_wire import send

        send(
            self.socket,
            {
                "contract": "hermes.private-bootstrap/1",
                "role": self.role,
                "profile": self.profile,
                "process": process_snapshot(os.getpid()),
                "artifact_digest": self.artifact_digest,
                "data": data,
            },
        )

    def receive(self):
        from agent.native_wire import receive

        packet = receive(self.socket, 5)
        if (
            packet.get("contract") != "hermes.private-bootstrap/1"
            or packet.get("supervisor") != self.parent
            or packet.get("role") != self.role
            or packet.get("profile") != self.profile
            or packet.get("seq") != self.sequence + 1
            or not packet.get("channel")
            or self.channel is not None
            and self.channel != packet["channel"]
        ):
            raise PermissionError("bootstrap binding mismatch")
        self.sequence = packet["seq"]
        self.channel = packet["channel"]
        return packet

    def acknowledge(self, result):
        from agent.native_wire import send

        send(
            self.socket,
            {"channel": self.channel, "seq": self.sequence, "result": result},
        )

    def approval(self, packet):
        if packet.get("operation") != "approval":
            raise PermissionError("bootstrap approval operation required")
        # Only called on the privately inherited, launch-owner-bound endpoint.
        record = packet["data"]
        return PinnedBootstrapProvider(record).verify(record)

    def close(self):
        self.socket.close()
