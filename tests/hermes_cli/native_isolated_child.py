"""Actual Core lifecycle/verifier on synthetic disposable child data only."""

import argparse
import hashlib
import json
import os
import selectors
import socket
import stat
import struct
import subprocess
import sys
import uuid
from pathlib import Path

from agent.native_bootstrap import NativeBootstrapEndpoint
from agent.native_control_verifier import NativeControlVerifier
from agent.native_wire import canonical, send
from hermes_platform.native_peer import process_snapshot
from tests.waiting import wait_until


def record(root, kind, **kw):
    with (Path(root) / "children.jsonl").open("a", encoding="utf8") as f:
        f.write(json.dumps({"pid": os.getpid(), "kind": kind, **kw}) + "\n")


class SyntheticParentPins:
    def __init__(self, expected, profile):
        self.expected, self.profile = expected, profile

    def verify_supervisor(self, actual, profile):
        return actual == self.expected and profile == self.profile


def descriptor_probe(fd, profile):
    sockets = []
    for entry in os.listdir("/dev/fd"):
        try:
            if stat.S_ISSOCK(os.fstat(int(entry)).st_mode):
                sockets.append(int(entry))
        except (OSError, ValueError):
            pass
    script = "import os,sys;\ntry:os.fstat(int(sys.argv[1]));print('LEAK')\nexcept OSError:print('CLOSED')"
    probe = subprocess.run(
        [sys.executable, "-B", "-c", script, str(fd)],
        close_fds=False,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
        env={"PATH": "/usr/bin:/bin", "HOME": profile, "HERMES_HOME": profile},
    )
    assert probe.returncode == 0 and probe.stdout.strip() == "CLOSED"
    return sockets


def delayed_start(endpoint):
    # The owning test releases readiness; startup interruption closes the child.
    assert wait_until(
        lambda: (Path(endpoint.profile) / "startup-release").exists(), timeout=10
    )
    return True


def wrong_hello(endpoint, mutate_pid=False):
    actual = process_snapshot(os.getpid())
    if mutate_pid:
        actual["pid"] += 1
    send(
        endpoint.socket,
        {
            "contract": "hermes.private-bootstrap/1",
            "role": endpoint.role,
            "profile": endpoint.profile,
            "process": actual,
            "artifact_digest": endpoint.artifact_digest if mutate_pid else "0" * 64,
            "data": {},
        },
    )
    return False


def apply_fault(endpoint, fault):
    actions = {
        "none": lambda: True,
        "delay": lambda: delayed_start(endpoint),
        "crash": lambda: os._exit(7),
        "wrong_pid": lambda: wrong_hello(endpoint, mutate_pid=True),
        "wrong_artifact": lambda: wrong_hello(endpoint),
    }
    return actions[fault]()


class CoreFixture:
    def __init__(self, endpoint):
        from hermes_cli.plugins import PluginContext, PluginManager
        from hermes_cli.plugins_manifest import PluginManifest

        self.endpoint = endpoint
        self.manager = PluginManager(endpoint.profile)
        ctx = PluginContext(PluginManifest(name="fixture"), self.manager)
        self.host = ctx.native_host
        lifecycle = self.manager.native_lifecycle
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
        }
        endpoint.announce(self.public)
        self.approvals = {}
        self.operations = {
            "prove": self.prove,
            "approval": self.approval,
            "connect": self.connect,
            "revoke": self.revoke,
        }

    def prove(self, packet):
        data = packet["data"]
        return self.manager.native_lifecycle.bootstrap_proof(
            data["nonce"], data["control_epoch"], self.public
        )

    def approval(self, packet):
        approval = self.endpoint.approval(packet)
        self.approvals[approval.role] = approval
        if approval.role == "manager":
            self.manager.native_lifecycle.bootstrap(approval)
        return {"approved": approval.role}

    def connect(self, packet):
        data, manager, host = packet["data"], self.manager, self.host
        manager.native_lifecycle.connect_control(data["path"], data["control"])
        host.connect_control(
            data["path"],
            data["control"],
            supervisor_approval=self.approvals["business"],
        )
        manager.native_lifecycle.approve(
            uuid.uuid4().hex, {"host_generation": host.generation}
        )
        manager.unload("fixture")
        assert not host.live()
        assert (
            manager.native_lifecycle.state_sync(uuid.uuid4().hex)["state"] == "ACTIVE"
        )
        record(
            self.endpoint.profile,
            "manager_survived_actual_plugin_unload",
            channel=manager.native_lifecycle.channel,
        )
        return {"connected": True}

    def revoke(self, packet):
        return self.manager.native_lifecycle.revoke(packet["data"]["operation_id"])

    def run(self):
        try:
            while True:
                packet = self.endpoint.receive()
                action = self.operations.get(packet["operation"])
                if action is None:
                    raise PermissionError("fixture bootstrap operation")
                self.endpoint.acknowledge(action(packet))
        except EOFError:
            pass
        finally:
            self.manager.native_lifecycle.close()
            self.host.close()
            record(self.endpoint.profile, "exit", role="core")


class ControlFixture:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.path = Path("/tmp") / ("h-wrap-" + uuid.uuid4().hex[:12] + ".sock")
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.epoch = uuid.uuid4().hex
        endpoint.announce({"path": str(self.path), "control_epoch": self.epoch})
        self.approvals = []
        for _ in range(2):
            packet = endpoint.receive()
            self.approvals.append(endpoint.approval(packet))
            endpoint.acknowledge({"approved": True})
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.listener, selectors.EVENT_READ, "accept")
        self.selector.register(endpoint.socket, selectors.EVENT_READ, "boot")
        self.clients = {}
        self.running = True
        self.events = {
            "boot": self.bootstrap,
            "accept": self.accept,
            "client": self.client,
        }
        self.phases = (self.register, self.proof, self.call)

    def bootstrap(self, _connection):
        if self.endpoint.socket.recv(1, socket.MSG_PEEK):
            raise PermissionError("unexpected bootstrap operation")
        self.running = False

    def accept(self, _connection):
        connection, _ = self.listener.accept()
        connection.setblocking(False)
        self.clients[connection] = {"buffer": bytearray(), "phase": 0}
        self.selector.register(connection, selectors.EVENT_READ, "client")

    def client(self, connection):
        state = self.clients[connection]
        data = connection.recv(131072)
        if not data:
            self.selector.unregister(connection)
            connection.close()
            self.clients.pop(connection)
            return
        state["buffer"].extend(data)
        if len(state["buffer"]) < 4:
            return
        length = struct.unpack("!I", state["buffer"][:4])[0]
        if len(state["buffer"]) < length + 4:
            return
        value = json.loads(state["buffer"][4 : length + 4])
        del state["buffer"][: length + 4]
        connection.settimeout(2)
        self.phases[state["phase"]](connection, state, value)
        connection.setblocking(False)

    def register(self, connection, state, value):
        role = (
            "manager"
            if value.get("contract") == "hermes.native-lifecycle-registration/2"
            else "business"
        )
        approval = next(a for a in self.approvals if a.role == role)
        verifier = NativeControlVerifier.staged(
            connection, approval=approval, control_epoch=self.epoch
        )
        state["verifier"] = verifier
        send(connection, verifier.accept_registration(value))
        state["phase"] = 1

    def proof(self, connection, state, value):
        send(connection, state["verifier"].accept_proof(value))
        state["phase"] = 2

    def call(self, connection, state, value):
        body, payload = state["verifier"].verify_call(value)
        assert state["verifier"].role == "manager"
        result = (
            {"state": "ACTIVE"}
            if payload["operation"] == "state_sync"
            else {
                "accepted": payload["operation"],
                "state": "ACTIVE" if payload["operation"] == "approve" else "CLOSED",
            }
        )
        send(
            connection,
            {
                "call_nonce": body["nonce"],
                "payload_digest": body["payload_digest"],
                "control_epoch": self.epoch,
                "result": result,
                "result_digest": hashlib.sha256(canonical(result)).hexdigest(),
            },
        )

    def run(self):
        try:
            while self.running:
                for key, _ in self.selector.select(2):
                    self.events[key.data](key.fileobj)
        finally:
            for connection in self.clients:
                connection.close()
            self.selector.close()
            self.listener.close()
            self.path.unlink(missing_ok=True)
            record(self.endpoint.profile, "exit", role="control")


def run(role, root, fd, fault):
    profile = str(Path(root).resolve())
    snapshot = process_snapshot(os.getppid())
    endpoint = NativeBootstrapEndpoint(
        fd,
        role=role,
        profile=profile,
        artifact_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        approved_supervisor=snapshot,
        provider=SyntheticParentPins(snapshot, profile),
    )
    sockets = descriptor_probe(fd, profile)
    record(
        profile,
        "start",
        role=role,
        parent=os.getppid(),
        noninheritable=not endpoint.socket.get_inheritable(),
        socket_fds=sockets,
        unrelated_exec_inherited=False,
    )
    print(role + " stdout", flush=True)
    print(role + " stderr", file=sys.stderr, flush=True)
    if apply_fault(endpoint, fault):
        {"core": CoreFixture, "control": ControlFixture}[role](endpoint).run()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("role")
    p.add_argument("root")
    p.add_argument("--fault", default="none")
    p.add_argument("--native-bootstrap-fd", type=int, required=True)
    a = p.parse_args()
    run(a.role, a.root, a.native_bootstrap_fd, a.fault)
