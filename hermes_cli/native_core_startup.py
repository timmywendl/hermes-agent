"""Private-FD startup for explicitly approved, disposable native Core launches.

Launch dependencies are supplied in process by the independently approved owner.
Neither a CLI argument nor a profile file supplies a production trust root.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import select
import socket
import sys
import threading
import uuid
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

from agent.native_bootstrap import NativeBootstrapEndpoint
from agent.native_selector import CandidateSelectorBundle, require_selector
from agent.native_turn import PluginHost
from hermes_constants import hermes_home_key


@dataclass(frozen=True)
class CoreLaunchPins:
    """Explicit owner dependency; this object does not discover or approve an owner."""

    profile: str
    supervisor: dict
    provider: object
    artifact_digest: str
    selector: CandidateSelectorBundle


def _validate_selector(bundle, profile):
    from hermes_cli.config_effective import load_user_config_effective

    if type(bundle) is not CandidateSelectorBundle or bundle.record["profile"] != profile:
        raise PermissionError("qualified selector required before discovery")
    policy = load_user_config_effective(fail_closed=True).get("plugins", {}).get(
        "required_response_gates"
    )
    if not bundle.valid(policy):
        raise PermissionError("qualified selector required before discovery")


def _take_bootstrap_fd():
    """Consume only the private option, leaving ordinary Hermes parsing unchanged."""
    descriptors, remaining = [], []
    args = iter(sys.argv[1:])
    try:
        for arg in args:
            if arg == "--native-bootstrap-fd":
                descriptors.append(int(next(args)))
            elif arg.startswith("--native-bootstrap-fd="):
                descriptors.append(int(arg.split("=", 1)[1]))
            else:
                remaining.append(arg)
        if len(descriptors) > 1 or any(fd < 3 for fd in descriptors):
            raise ValueError("invalid bootstrap descriptor")
    except (ValueError, StopIteration):
        for fd in set(descriptors):
            if fd >= 3:
                os.close(fd)
        raise PermissionError("one private bootstrap descriptor required") from None
    sys.argv[1:] = remaining
    return descriptors[0] if descriptors else None


class NativeCoreStartup:
    """Own the existing endpoint/Manager/Business channels for one entrypoint call."""

    def __init__(self, endpoint, pins):
        from hermes_cli.plugins import get_plugin_manager

        self.endpoint, self.pins = endpoint, pins
        self.manager = get_plugin_manager()
        self.host = None
        self.approvals = {}
        self.stopped = threading.Event()
        self.worker = None

    def prepare(self):
        bundle, manager = self.pins.selector, self.manager
        _validate_selector(bundle, self.pins.profile)
        if manager._discovered or manager._plugins:
            raise PermissionError("native Manager must precede discovery")
        manager.configure_native_selector(bundle)
        self.host = PluginHost(bundle.record["plugin_id"], self.pins.profile)
        manager.native_lifecycle.track_host(self.host)
        manager._native_bootstrap_hosts = {self.host.plugin_id: self.host}
        lifecycle = manager.native_lifecycle
        self.public = {
            "manager": {
                "manager_instance": lifecycle.manager_instance,
                "manager_epoch": lifecycle.manager_epoch,
                "public_key": lifecycle.public_key,
            },
            "business": {
                "plugin_id": self.host.plugin_id,
                "host_instance": self.host.instance,
                "host_generation": self.host.generation,
                "public_key": self.host._key.public_key().public_bytes_raw().hex(),
            },
            "selector_digest": bundle.digest,
        }
        self.endpoint.announce(self.public)
        self._expect("prove", self._prove)
        self._expect("approval", self._approve)
        self._expect("approval", self._approve)
        self._expect("connect", self._connect)
        self.worker = threading.Thread(
            target=contextvars.copy_context().run, args=(self._watch,),
            name="native-bootstrap", daemon=True,
        )
        self.worker.start()

    def _expect(self, operation, action):
        packet = self.endpoint.receive()
        if packet.get("operation") != operation:
            raise PermissionError("bootstrap startup order mismatch")
        self.endpoint.acknowledge(action(packet))

    def _prove(self, packet):
        data = packet["data"]
        return self.manager.native_lifecycle.bootstrap_proof(
            data["nonce"], data["control_epoch"], self.public
        )

    def _approve(self, packet):
        approval = self.endpoint.approval(packet)
        if approval.role in self.approvals:
            raise PermissionError("duplicate bootstrap role")
        self.approvals[approval.role] = approval
        if approval.role == "manager":
            self.manager.native_lifecycle.bootstrap(approval)
        return {"approved": approval.role}

    def _connect(self, packet):
        from agent.response_gate import gate_available
        from hermes_cli.plugins import PluginContext, discover_plugins

        data, manager, host = packet["data"], self.manager, self.host
        if set(self.approvals) != {"manager", "business"}:
            raise PermissionError("both bootstrap roles required")
        manager.native_lifecycle.connect_control(data["path"], data["control"])
        # Normal discovery imports the pinned module, but defers its registration
        # until Core can supply the separately approved Business channel.
        discover_plugins()
        loaded = manager._plugins.get(host.plugin_id)
        if loaded is None or not loaded.enabled or loaded.error or loaded.module is None:
            raise PermissionError("native plugin discovery failed")
        _validate_selector(self.pins.selector, self.pins.profile)
        channel = host.connect_control(
            data["path"], data["control"], supervisor_approval=self.approvals["business"]
        )
        ctx = PluginContext(loaded.manifest, manager)
        start = len(manager._registration_order)
        loaded.module.register_native(ctx, channel)
        manager._attribute_registrations(loaded, host.plugin_id, start)
        if not gate_available(host):
            raise PermissionError("native response gate unavailable")
        manager.native_lifecycle.approve(uuid.uuid4().hex, {"host_generation": host.generation})
        return {"connected": True}

    def _watch(self):
        exit_code = 78
        try:
            while not self.stopped.is_set():
                readable, _, _ = select.select([self.endpoint.socket], [], [], .1)
                if not readable:
                    continue
                packet = self.endpoint.receive()
                if packet.get("operation") != "revoke":
                    raise PermissionError("unexpected running bootstrap operation")
                require_selector(self.pins.profile)
                result = self.manager.native_lifecycle.revoke(packet["data"]["operation_id"])
                self.endpoint.acknowledge(result)
                exit_code = 0
                return
        except (EOFError, OSError, ValueError, PermissionError):
            # Parent loss cannot remove the pinned denial or revive an old host.
            pass
        finally:
            require_selector(self.pins.profile)
            if self.host is not None:
                self.host.invalidate()
            if not self.stopped.is_set():
                # The approved isolated owner is gone or has revoked us. A real
                # application body cannot outlive it as an orphaned native Core.
                # Kernel exit closes every inherited/control descriptor, including
                # those whose user-space locks could be held by an in-flight call.
                os._exit(exit_code)

    def close(self):
        self.stopped.set()
        require_selector(self.pins.profile)
        try:
            self.endpoint.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self.worker is not None:
            self.worker.join(3)
        if self.host is not None:
            self.manager.unload(self.host.plugin_id)
            self.host.close()
        self.manager.native_lifecycle.close()
        self.manager._native_bootstrap_hosts = {}
        self.endpoint.close()


def run_core_entrypoint(entrypoint, pins=None):
    """Called by the supported CLI and Gateway entrypoints before their startup work."""
    profile = hermes_home_key()
    requested = pins is not None or any(
        arg == "--native-bootstrap-fd" or arg.startswith("--native-bootstrap-fd=")
        for arg in sys.argv[1:]
    )
    if not requested:
        return entrypoint()
    require_selector(profile)
    fd = _take_bootstrap_fd()
    endpoint, startup = None, None
    try:
        if (
            fd is None or type(pins) is not CoreLaunchPins or pins.profile != profile
            or not (Path(profile) / ".hermes-isolated-profile").is_file()
            or hashlib.sha256(Path(entrypoint.__code__.co_filename).read_bytes()).hexdigest()
            != pins.artifact_digest
        ):
            raise PermissionError("approved disposable Core bootstrap required")
        endpoint = NativeBootstrapEndpoint(
            fd, role="core", profile=profile, artifact_digest=pins.artifact_digest,
            approved_supervisor=pins.supervisor, provider=pins.provider,
        )
        startup = NativeCoreStartup(endpoint, pins)
        startup.prepare()
        return entrypoint()
    finally:
        require_selector(profile)
        if startup is not None:
            startup.close()
        elif endpoint is not None:
            endpoint.close()
        elif fd is not None:
            os.close(fd)


def native_core_entrypoint(entrypoint):
    """Keep startup ownership around the complete supported entrypoint lifetime."""
    @wraps(entrypoint)
    def run(*, native_bootstrap=None):
        return run_core_entrypoint(entrypoint, native_bootstrap)
    return run
