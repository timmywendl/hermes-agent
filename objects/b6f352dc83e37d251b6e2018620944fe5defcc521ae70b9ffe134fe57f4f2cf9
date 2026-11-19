"""Native turn and plugin invocation capabilities (wire contract v2).

These objects stay outside model arguments. Python plugins are trusted code in the
Hermes process, not a sandbox; a hostile Python plugin can compromise its host.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from enum import Enum

import psutil
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_constants import hermes_home_key


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf8")).hexdigest()


class TurnSource(str, Enum):
    TOP_LEVEL_HUMAN = "TOP_LEVEL_HUMAN"
    SCHEDULED = "SCHEDULED"
    WEBHOOK = "WEBHOOK"
    AGENT_CONTINUATION = "AGENT_CONTINUATION"
    SUBAGENT = "SUBAGENT"
    TOOL_GENERATED = "TOOL_GENERATED"


@dataclass(frozen=True)
class NativeIngress:
    source: TurnSource
    actor: str
    conversation: str
    session: str
    turn: str
    profile: str


# A serialized/copied dataclass is not an ingress capability. Issuance belongs to
# native surface code. No model tool or environment variable can mint one.
_issued: dict[int, NativeIngress] = {}
_lock = threading.RLock()


def issue_ingress(source: TurnSource, *, actor: str, conversation: str, session: str) -> NativeIngress:
    if not isinstance(source, TurnSource) or not actor or not session or not conversation:
        raise ValueError("invalid native ingress")
    ingress = NativeIngress(source, actor, conversation, session, uuid.uuid4().hex, hermes_home_key())
    with _lock:
        # Bound abandoned surface requests as well as successful ones.
        while len(_issued) >= 1024:
            _issued.pop(next(iter(_issued)))
        _issued[id(ingress)] = ingress
    return ingress


def consume_ingress(ingress, session: str) -> NativeIngress | None:
    with _lock:
        valid = _issued.pop(id(ingress), None)
    return valid if (valid is not None and valid is ingress and valid.session == session
                     and valid.profile == hermes_home_key()) else None


class HumanText(str):
    """Keyboard submit envelope; plain queued continuations carry no capability."""
    def __new__(cls, text, *, session):
        value = super().__new__(cls, text)
        value.native_ingress = issue_ingress(TurnSource.TOP_LEVEL_HUMAN, actor="local-keyboard",
                                             conversation=session, session=session)
        return value


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    birth: float
    executable: str


def process_identity() -> ProcessIdentity:
    process = psutil.Process()
    return ProcessIdentity(process.pid, process.uids().real if hasattr(process, "uids") else -1,
                           process.create_time(), process.exe())


@dataclass(frozen=True)
class Invocation:
    plugin_id: str
    host_instance: str
    host_generation: str
    process: ProcessIdentity
    ingress: NativeIngress
    invocation_id: str
    tool_name: str


current_turn: ContextVar = ContextVar("native_turn", default=None)
current_invocation: ContextVar = ContextVar("native_invocation", default=None)


@dataclass(frozen=True)
class ControlEvidence:
    invocation: Invocation
    control_request_id: str
    context_revision: str
    mission_revision: str
    query_result_digest: str
    output: str
    expires_at: float
    result_ref: str = ""
    projection_digest: str = ""
    control_epoch: str = ""
    channel_ref: str = ""
    project_id: str = ""


class PluginHost:
    """One in-process plugin activation; unload/reload invalidates all its leases.

    Remote Control uses connect_control: kernel-authenticated registration plus
    challenge proof pins a generation key to one live connection.
    """
    def __init__(self, plugin_id: str, profile: str):
        self.plugin_id, self.profile = plugin_id, profile
        self.instance, self.generation = uuid.uuid4().hex, uuid.uuid4().hex
        self.process = process_identity()
        self._key = Ed25519PrivateKey.generate()
        self._channels = []
        self._active = True
        self._leases = {}
        self._lock = threading.RLock()

    def live(self) -> bool:
        return (self._active and self.profile == hermes_home_key()
                and self.process == process_identity())

    def invalidate(self):
        self._active = False
        with self._lock:
            self._leases.clear()

    def close(self):
        self._active = False
        with self._lock:
            self._leases.clear()
            for channel in self._channels:
                channel.close()
            self._channels.clear()

    def connect_control(self, path, approved_control, *, supervisor_approval=None):
        """Trusted plugin startup calls this with the supervisor-approved Control identity."""
        from agent.native_control_channel import NativeControlChannel
        with self._lock:
            if not self.live():
                raise PermissionError("native host inactive")
            channel = NativeControlChannel(self, path, approved_control, supervisor_approval=supervisor_approval)
            self._channels.append(channel)
            return channel

    def invocation(self, tool_name: str) -> Invocation | None:
        state = current_turn.get()
        if not self.live() or state is None or state.ingress is None or state.closed:
            return None
        return Invocation(self.plugin_id, self.instance, self.generation, self.process,
                          state.ingress, uuid.uuid4().hex, tool_name)

    def matches(self, invocation: Invocation) -> bool:
        state = current_turn.get()
        return (self.live() and isinstance(invocation, Invocation)
                and invocation is current_invocation.get() and state is not None
                and not state.closed and invocation.ingress is state.ingress
                and invocation.host_instance == self.instance
                and invocation.host_generation == self.generation
                and invocation.plugin_id == self.plugin_id and invocation.process == self.process)

    def attest(self, invocation: Invocation) -> dict:
        if not self.matches(invocation):
            raise PermissionError("native invocation expired")
        body = {"contract": "hermes.native-turn/2", **asdict(invocation)}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._leases = {k: v for k, v in self._leases.items()
                            if not v[0].finished and v[1] > time.monotonic()}
            if len(self._leases) >= 256:
                raise PermissionError("native attestation capacity")
            self._leases[invocation.invocation_id] = (current_turn.get(), time.monotonic() + 60, digest(raw))
        return {"body": body, "signature": self._key.sign(raw.encode()).hex()}

    def verify_attestation(self, envelope: dict, *, peer_pid: int, peer_uid: int) -> dict:
        # Called by a trusted verifier under the owning profile. A socket's PID/
        # UID must come from kernel peer credentials, never from this envelope.
        if not self.live() or peer_pid != self.process.pid or peer_uid != self.process.uid:
            raise PermissionError("native peer mismatch")
        body = envelope["body"]
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
        from agent.native_wire import verified
        verified(self._key.public_key().public_bytes_raw().hex(), envelope)
        with self._lock:
            lease = self._leases.get(body.get("invocation_id"))
        if (body.get("contract") != "hermes.native-turn/2" or body["host_generation"] != self.generation
                or body["host_instance"] != self.instance or lease is None
                or lease[0].finished or lease[1] <= time.monotonic() or lease[2] != digest(raw)):
            raise PermissionError("native host mismatch")
        return body

    def record_result(self, invocation: Invocation, *, control_request_id: str,
                      context_revision: str, mission_revision: str, query_result_digest: str,
                      output: str, ttl: float = 30, result_ref: str = "",
                      projection_digest: str = "", control_epoch: str = "", channel_ref: str = "",
                      project_id: str = "") -> ControlEvidence:
        if not self.matches(invocation) or invocation.ingress.source is not TurnSource.TOP_LEVEL_HUMAN:
            raise PermissionError("trusted Human invocation required")
        if (not all(isinstance(v, str) and v for v in (control_request_id, context_revision,
                mission_revision, query_result_digest, output)) or not 0 < ttl <= 60
                or len(output.encode("utf8")) > 65536):
            raise ValueError("invalid Control evidence")
        state = current_turn.get()
        if project_id and (state.selection is None or project_id not in state.selection.projects):
            raise PermissionError("Control project not selected")
        evidence = ControlEvidence(invocation, control_request_id, context_revision, mission_revision,
                                   query_result_digest, output, time.monotonic() + ttl, result_ref,
                                   projection_digest or digest(output), control_epoch, channel_ref, project_id)
        state = current_turn.get()
        with state.lock:
            state.evidence[self.plugin_id] = evidence
        return evidence
