"""Staged independently approved wire-v2 verifier; never owns product sends."""

from __future__ import annotations

import hashlib
import socket
import time
import uuid
from typing import Any

from agent.native_bootstrap import SupervisorApproval, require_approval
from agent.native_wire import canonical, receive, send, verified
from hermes_platform.native_peer import verify_peer


class NativeControlVerifier:
    connection: socket.socket
    approval: SupervisorApproval
    control_epoch: str
    role: str
    approved_process: dict[str, Any]
    profile: str
    plugin_id: str | None
    active: bool
    seen: set[str]
    registration: dict[str, Any] | None
    challenge: dict[str, Any] | None
    channel: str

    @classmethod
    def staged(cls, connection, *, approval, control_epoch):
        approval = require_approval(approval, control_epoch=control_epoch)
        self = object.__new__(cls)
        self.connection, self.approval = connection, approval
        self.control_epoch, self.role = control_epoch, approval.role
        self.approved_process = approval.process
        self.profile = approval.profile
        self.plugin_id = approval.get("plugin_id")
        self.active = False
        self.seen = set()
        self.registration = None
        self.channel = uuid.uuid4().hex
        self.challenge = None
        return self

    def __init__(
        self,
        connection,
        *,
        approved_process=None,
        plugin_id=None,
        profile=None,
        approval=None,
        control_epoch=None,
    ):
        epoch = control_epoch or (
            approval.control_epoch if approval is not None else None
        )
        staged = self.staged(connection, approval=approval, control_epoch=epoch)
        self.__dict__.update(staged.__dict__)
        if (
            (approved_process is not None and approved_process != self.approved_process)
            or (plugin_id is not None and plugin_id != self.plugin_id)
            or (profile is not None and profile != self.profile)
        ):
            raise PermissionError("independent supervisor policy mismatch")
        send(connection, self.accept_registration(receive(connection)))
        send(connection, self.accept_proof(receive(connection)))

    def accept_registration(self, registration):
        if self.registration is not None:
            raise PermissionError("registration replay")
        a = require_approval(self.approval, control_epoch=self.control_epoch)
        peer = verify_peer(self.connection, a.process)
        fields = (
            ("plugin_id", "host_instance", "host_generation")
            if self.role == "business"
            else ("manager_instance", "manager_epoch")
        )
        contract = (
            "hermes.native-registration/2"
            if self.role == "business"
            else "hermes.native-lifecycle-registration/2"
        )
        if (
            not isinstance(registration, dict)
            or registration.get("contract") != contract
            or registration.get("process") != peer
            or registration.get("profile") != a.profile
            or registration.get("public_key") != a.public_key
            or registration.get("approval_ref") != a.approval_ref
            or any(registration.get(k) != a.get(k) for k in fields)
        ):
            raise PermissionError("native registration policy mismatch")
        self.registration = dict(registration)
        self.challenge = {
            "contract": "hermes.native-challenge/2",
            "channel": self.channel,
            "registration_digest": hashlib.sha256(canonical(registration)).hexdigest(),
            "expires_at": time.time() + 5,
            "control_epoch": self.control_epoch,
            "approval_ref": a.approval_ref,
        }
        return dict(self.challenge)

    def accept_proof(self, envelope):
        require_approval(self.approval, control_epoch=self.control_epoch)
        if (
            self.active
            or self.challenge is None
            or self.registration is None
            or time.time() >= self.challenge["expires_at"]
            or verified(self.approval.public_key, envelope) != self.challenge
        ):
            raise PermissionError("native challenge expired or mismatched")
        verify_peer(self.connection, self.approved_process)
        self.active = True
        return {"registered": self.channel, "control_epoch": self.control_epoch}

    def receive_call(self):
        try:
            return self.verify_call(receive(self.connection))
        except (OSError, EOFError, ValueError, KeyError, TypeError, PermissionError):
            self.close()
            raise

    def verify_call(self, frame):
        if not self.active:
            raise PermissionError("native registration revoked")
        a = require_approval(self.approval, control_epoch=self.control_epoch)
        verify_peer(self.connection, self.approved_process)
        body = verified(a.public_key, frame["attestation"])
        payload = frame["payload"]
        if (
            body.get("channel") != self.channel
            or body.get("control_epoch") != self.control_epoch
            or body.get("approval_ref") != a.approval_ref
            or not time.time() < body["expires_at"] <= time.time() + 60
            or not isinstance(body.get("nonce"), str)
            or not body["nonce"]
            or body["nonce"] in self.seen
            or len(self.seen) >= 4096
            or body["payload_digest"] != hashlib.sha256(canonical(payload)).hexdigest()
        ):
            raise PermissionError("native call binding mismatch")
        if self.role == "manager":
            if (
                body.get("contract") != "hermes.native-lifecycle/2"
                or body.get("manager_instance") != a.manager_instance
                or body.get("manager_epoch") != a.manager_epoch
                or body.get("operation") not in ("approve", "state_sync", "revoke")
                or not isinstance(body.get("operation_id"), str)
                or not body["operation_id"]
                or payload
                != {k: body[k] for k in ("operation", "operation_id", "params")}
                or "invocation" in body
            ):
                raise PermissionError("native lifecycle domain mismatch")
        else:
            invocation = body["invocation"]
            ingress, process = invocation["ingress"], invocation["process"]
            if (
                body.get("contract") != "hermes.native-call/2"
                or any(
                    invocation.get(k) != a.get(k)
                    for k in ("plugin_id", "host_instance", "host_generation")
                )
                or any(
                    process.get(k) != a.process[k]
                    for k in ("pid", "uid", "birth", "executable")
                )
                or ingress.get("profile") != a.profile
                or ingress.get("source") != "TOP_LEVEL_HUMAN"
                or not all(
                    ingress.get(k) for k in ("turn", "session", "actor", "conversation")
                )
                or not invocation.get("invocation_id")
                or not invocation.get("tool_name")
            ):
                raise PermissionError("native attestation binding mismatch")
        self.seen.add(body["nonce"])
        return body, payload

    # Existing standalone verifier peers must not bypass product-owned permits.
    def reply(self, attestation, result):
        raise PermissionError("Control-owned ResponseReleasePermit required")

    def close(self):
        self.active = False
        self.connection.close()
