"""Original hook/evidence capabilities. Nothing here grants model authority."""

from __future__ import annotations

import threading
import time
from contextvars import ContextVar
from typing import Any

from agent.native_turn import TurnSource, current_invocation, current_turn, digest

hook_scope = ContextVar("native_hook_scope", default=None)
_SECRET = object()


class HookScope:
    def __init__(self, name, payload=None):
        self.name, self.state = name, current_turn.get()
        message = (payload or {}).get("user_message")
        self.message_digest = digest(message) if isinstance(message, str) else None
        self.deadline = time.monotonic() + 2
        self.live = True
        self.count = 0
        self.lock = threading.Lock()


class _Opaque:
    def __setattr__(self, name, value):
        if hasattr(self, name):
            raise TypeError("immutable native capability")
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("opaque native capability")

    def __copy__(self):
        raise TypeError("opaque native capability")

    def __deepcopy__(self, memo):
        raise TypeError("opaque native capability")


def _bounded_lookup_id(value):
    if type(value) is not str or not value.strip():
        return False
    try:
        return 0 < len(value.encode("utf8")) <= 256
    except UnicodeError:
        return False


def _pending_lookup_payload(payload, projects):
    # A receipt is an untrusted selector for exact durable readback, not an
    # invocation, authorization, arbitrary operation or old Session capability.
    if (
        type(payload) is not dict
        or set(payload) not in ({"project_id"}, {"project_id", "reconcile_use"})
        or not _bounded_lookup_id(payload.get("project_id"))
        or payload["project_id"] not in projects
    ):
        return False
    if "reconcile_use" not in payload:
        return True
    receipt = payload["reconcile_use"]
    if (
        type(receipt) is not dict
        or set(receipt) != {"request_id", "result_ref", "projection_digest"}
        or not _bounded_lookup_id(receipt["request_id"])
        or not _bounded_lookup_id(receipt["result_ref"])
    ):
        return False
    value = receipt["projection_digest"]
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


class NativeIntakeCapability(_Opaque):
    _scope: HookScope
    _state: Any
    _host: Any
    _channel: Any
    _generation: str
    _policy: Any
    _used: bool
    _lock: threading.Lock
    _invocation: Any

    def __init__(self, host, channel, *, _secret=None):
        from agent.response_gate import gate_available

        scope, state = hook_scope.get(), current_turn.get()
        if (
            _secret is not _SECRET
            or scope is None
            or scope.name != "pre_llm_call"
            or scope.message_digest is None
            or not scope.live
            or scope.state is not state
            or state is None
            or state.closed
            or state.ingress is None
            or state.ingress.source is not TurnSource.TOP_LEVEL_HUMAN
            or not channel.live()
            or channel.host is not host
            or not getattr(state, "intake_allowed", False)
            or not gate_available(host)
        ):
            raise PermissionError("trusted native hook required")
        with scope.lock:
            if scope.count >= 2:
                raise PermissionError("native hook capacity")
            scope.count += 1
        self._scope, self._state, self._host, self._channel = (
            scope,
            state,
            host,
            channel,
        )
        self._generation, self._policy = (
            host.generation,
            getattr(state, "policy_digest", None),
        )
        self._used = False
        self._lock = threading.Lock()
        self._invocation = host.invocation("__native_intake__")

    def _call(self, operation, payload):
        with self._lock:
            scope, state = self._scope, self._state
            if (
                self._used
                or not scope.live
                or time.monotonic() >= scope.deadline
                or current_turn.get() is not state
                or state.closed
                or state.finished
                or self._host.generation != self._generation
                or not self._channel.live()
                or self._policy != getattr(state, "policy_digest", None)
                or callable(getattr(state, "policy_valid", None))
                and not state.policy_valid()
            ):
                raise PermissionError("native intake capability expired")
            object.__setattr__(self, "_used", True)
            if (
                not isinstance(payload, dict)
                or operation == "intake"
                and (
                    not isinstance(payload.get("message"), str)
                    or digest(payload["message"]) != scope.message_digest
                )
                or operation == "pending_lookup"
                and not _pending_lookup_payload(payload, state.selection.projects)
            ):
                raise PermissionError("original native message/project required")
            token = current_invocation.set(self._invocation)
            try:
                return self._channel.call(
                    self._invocation,
                    {"operation": operation, "payload": payload},
                    deadline=scope.deadline,
                )
            finally:
                current_invocation.reset(token)

    def intake(self, payload):
        return self._call("intake", payload)

    def pending_lookup(self, payload):
        return self._call("pending_lookup", payload)


def intake_capability(host, channel):
    return NativeIntakeCapability(host, channel, _secret=_SECRET)


class CommitUseCapability(_Opaque):
    _host: Any
    _evidence: Any
    _state: Any
    _generation: str
    _receipt: dict[str, Any]
    _deadline: float
    _used: bool
    _lock: threading.Lock

    def __init__(self, host, evidence, state, receipt, *, _secret=None):
        from agent.response_gate import gate_available

        if (
            _secret is not _SECRET
            or not state.closed
            or state.finished
            or state.evidence.get(host.plugin_id) is not evidence
            or receipt.get("output_commit_status") != "OUTPUT_COMMITTED"
            or receipt.get("gate_decision") != "OUTPUT_GATE_PASSED"
            or receipt.get("final_output_digest") != digest(evidence.output)
            or not evidence.result_ref
            or not evidence.control_epoch
            or not evidence.channel_ref
            or evidence.projection_digest != digest(evidence.output)
            or not state.policy_valid()
            or not gate_available(host)
        ):
            raise PermissionError("original committed evidence required")
        self._host, self._evidence, self._state = host, evidence, state
        self._generation, self._receipt = host.generation, dict(receipt)
        self._deadline = min(evidence.expires_at, time.monotonic() + 2)
        self._used = False
        self._lock = threading.Lock()

    def response_used(self, payload=None):
        with self._lock:
            e, state, host = self._evidence, self._state, self._host
            if (
                self._used
                or time.monotonic() >= self._deadline
                or state.finished
                or current_turn.get() is not state
                or not host.live()
                or state.evidence.get(host.plugin_id) is not e
                or e.invocation.ingress is not state.ingress
                or host.generation != self._generation
                or digest(e.output) != self._receipt["final_output_digest"]
                or callable(getattr(state, "policy_valid", None))
                and not state.policy_valid()
            ):
                raise PermissionError("native commit-use capability expired")
            expected = {
                "request_id": e.control_request_id,
                "result_ref": e.result_ref,
                "projection_digest": e.projection_digest,
            }
            if payload is not None and payload != expected:
                raise PermissionError("native response-use binding mismatch")
            channels = [
                c
                for c in host._channels
                if c.control_epoch == e.control_epoch
                and c.channel == e.channel_ref
                and c.live()
            ]
            if len(channels) != 1:
                raise PermissionError("native evidence channel ambiguous")
            object.__setattr__(self, "_used", True)
            # Only this original capability can invoke response_used after output commit.
            if not channels[0].lock.acquire(
                timeout=max(0, self._deadline - time.monotonic())
            ):
                raise TimeoutError("native commit lock expired")
            try:
                return channels[0]._call(
                    e.invocation,
                    {"operation": "response_used", "payload": expected},
                    deadline=self._deadline,
                )
            finally:
                channels[0].lock.release()


def commit_capability(host, evidence, state, receipt):
    return CommitUseCapability(host, evidence, state, receipt, _secret=_SECRET)
