"""Approved persistent native business channel; keys stay with the Host."""

from __future__ import annotations

import hashlib
import socket
import threading
import time
import uuid
from dataclasses import asdict

from agent.native_bootstrap import require_approval
from agent.native_turn import current_turn
from agent.native_wire import canonical, receive, send, signed
from hermes_platform.native_peer import process_snapshot, verify_peer


class NativeControlChannel:
    def __init__(self, host, path, approved_control, *, supervisor_approval=None):
        self.host = host
        self.lock = threading.RLock()
        self.approval = require_approval(supervisor_approval, role="business")
        a = self.approval
        if (
            a.process != process_snapshot(host.process.pid)
            or a.profile != host.profile
            or a.plugin_id != host.plugin_id
            or a.host_instance != host.instance
            or a.host_generation != host.generation
            or a.public_key != host._key.public_key().public_bytes_raw().hex()
        ):
            raise PermissionError("native Host approval mismatch")
        self.control_epoch = a.control_epoch
        self.connection = socket.socket(socket.AF_UNIX)
        self.connection.set_inheritable(False)
        self.connection.settimeout(2)
        self.approved_control = approved_control
        try:
            self.connection.connect(str(path))
            verify_peer(self.connection, approved_control)
            registration = {
                "contract": "hermes.native-registration/2",
                "plugin_id": host.plugin_id,
                "profile": host.profile,
                "host_instance": host.instance,
                "host_generation": host.generation,
                "process": a.process,
                "public_key": a.public_key,
                "approval_ref": a.approval_ref,
            }
            send(self.connection, registration)
            challenge = receive(self.connection)
            if (
                challenge.get("contract") != "hermes.native-challenge/2"
                or challenge.get("registration_digest")
                != hashlib.sha256(canonical(registration)).hexdigest()
                or challenge.get("control_epoch") != a.control_epoch
                or challenge.get("approval_ref") != a.approval_ref
                or not time.time() < challenge["expires_at"] <= time.time() + 10
            ):
                raise PermissionError("native registration challenge mismatch")
            send(self.connection, signed(host._key, challenge))
            if receive(self.connection) != {
                "registered": challenge["channel"],
                "control_epoch": a.control_epoch,
            }:
                raise PermissionError("native registration not confirmed")
            self.channel = challenge["channel"]
        except BaseException:
            self.connection.close()
            raise

    def live(self):
        return (
            self.host.live()
            and self.connection.fileno() >= 0
            and self.approval.valid(control_epoch=self.control_epoch)
        )

    def call(self, invocation, payload, *, deadline=None):
        deadline = time.monotonic() + 10 if deadline is None else deadline
        if not self.lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("native call lock expired")
        try:
            if not self.live() or not self.host.matches(invocation):
                raise PermissionError("native invocation expired")
            if (
                not isinstance(payload, dict)
                or set(payload) != {"operation", "payload"}
                or not isinstance(payload["payload"], dict)
            ):
                raise PermissionError("native business operation shape required")
            operation = payload.get("operation")
            if operation not in ("intake", "pending_lookup", "query"):
                raise PermissionError("native business operation not allowed")
            if operation == "response_used" or (
                operation in ("intake", "pending_lookup")
                and invocation.tool_name != "__native_intake__"
            ):
                raise PermissionError("native operation capability required")
            return self._call(invocation, payload, deadline=deadline)

        finally:
            self.lock.release()

    def call_evidence(self, evidence, payload):
        """Only validate a current original result; use requires CommitUseCapability."""
        if (
            not isinstance(payload, dict)
            or set(payload) != {"operation", "payload"}
            or payload.get("operation") != "query"
            or not isinstance(payload["payload"], dict)
        ):
            raise PermissionError(
                "original commit-use capability required; validation query only"
            )
        with self.lock:
            state = current_turn.get()
            if (
                not self.live()
                or state is None
                or state.finished
                or state.evidence.get(self.host.plugin_id) is not evidence
                or evidence.expires_at <= time.monotonic()
                or evidence.invocation.ingress is not state.ingress
                or evidence.invocation.host_generation != self.host.generation
            ):
                raise PermissionError("native evidence expired")
            return self._call(evidence.invocation, payload)

    def _call(self, invocation, payload, *, deadline=None):
        deadline = time.monotonic() + 10 if deadline is None else deadline

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError("native call expired")
            return value

        if not self.live():
            raise PermissionError("native channel revoked")
        # Core/Profile proof is rechecked at invocation, not only at intake.
        state = current_turn.get()
        if (
            state is not None
            and callable(getattr(state, "policy_valid", None))
            and not state.policy_valid()
        ):
            raise PermissionError("native policy unavailable")
        if (
            state is not None
            and getattr(state, "selection", None) is not None
            and state.selection.candidate
        ):
            from agent.response_gate import gate_available

            if not gate_available(self.host):
                raise PermissionError("required gate unavailable")
        verify_peer(self.connection, self.approved_control)
        body = {
            "contract": "hermes.native-call/2",
            "channel": self.channel,
            "invocation": asdict(invocation),
            "nonce": uuid.uuid4().hex,
            "expires_at": time.time() + remaining(),
            "control_epoch": self.control_epoch,
            "approval_ref": self.approval.approval_ref,
            "payload_digest": hashlib.sha256(canonical(payload)).hexdigest(),
        }
        self.connection.settimeout(remaining())
        send(
            self.connection,
            {"attestation": signed(self.host._key, body), "payload": payload},
        )
        response = receive(self.connection, deadline=deadline)
        if (
            response.get("control_epoch") != self.control_epoch
            or response.get("call_nonce") != body["nonce"]
            or response.get("payload_digest") != body["payload_digest"]
            or response.get("result_digest")
            != hashlib.sha256(canonical(response.get("result"))).hexdigest()
        ):
            raise PermissionError("native Control result binding mismatch")
        return response["result"]

    def close(self):
        with self.lock:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
