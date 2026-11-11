"""Actual Core lifecycle/verifier on synthetic disposable child data only."""

import argparse
import hashlib
import json
import os
import selectors
import socket
import uuid
from pathlib import Path

from agent.native_bootstrap import NativeBootstrapEndpoint
from agent.native_control_verifier import NativeControlVerifier
from agent.native_wire import canonical, send
from hermes_platform.native_peer import process_snapshot


def record(root, kind, **kw):
    with (Path(root) / "children.jsonl").open("a", encoding="utf8") as f:
        f.write(json.dumps({"pid": os.getpid(), "kind": kind, **kw}) + "\n")


class SyntheticParentPins:
    def __init__(self, expected, profile):
        self.expected, self.profile = expected, profile

    def verify_supervisor(self, actual, profile):
        return actual == self.expected and profile == self.profile


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
    import stat

    sockets = []
    for entry in os.listdir("/dev/fd"):
        try:
            if stat.S_ISSOCK(os.fstat(int(entry)).st_mode):
                sockets.append(int(entry))
        except (OSError, ValueError):
            pass
    import subprocess
    import sys

    script = "import os,sys;\ntry:os.fstat(int(sys.argv[1]));print('LEAK')\nexcept OSError:print('CLOSED')"
    probe = subprocess.run(
        [sys.executable, "-B", "-c", script, str(fd)],
        close_fds=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": profile, "HERMES_HOME": profile},
        timeout=3,
        check=False,
    )
    assert probe.returncode == 0 and probe.stdout.strip() == "CLOSED"
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
    print(role + " stderr", file=__import__("sys").stderr, flush=True)
    if fault == "delay":
        __import__("threading").Event().wait(3)
    if fault == "crash":
        os._exit(7)
    if fault in ("wrong_pid", "wrong_artifact"):
        actual = process_snapshot(os.getpid())
        if fault == "wrong_pid":
            actual["pid"] += 1
        send(
            endpoint.socket,
            {
                "contract": "hermes.private-bootstrap/1",
                "role": role,
                "profile": profile,
                "process": actual,
                "artifact_digest": "0" * 64,
                "data": {},
            },
        )
        return
    if role == "core":
        from hermes_cli.plugins import PluginContext, PluginManager
        from hermes_cli.plugins_manifest import PluginManifest

        manager = PluginManager(profile)
        ctx = PluginContext(PluginManifest(name="fixture"), manager)
        host = ctx.native_host
        public = {
            "manager": {
                "manager_instance": manager.native_lifecycle.manager_instance,
                "manager_epoch": manager.native_lifecycle.manager_epoch,
                "public_key": manager.native_lifecycle.public_key,
            },
            "business": {
                "plugin_id": host.plugin_id,
                "host_instance": host.instance,
                "host_generation": host.generation,
                "public_key": host._key.public_key().public_bytes_raw().hex(),
            },
        }
        endpoint.announce(public)
        approvals = {}
        try:
            while True:
                packet = endpoint.receive()
                op = packet["operation"]
                data = packet["data"]
                if op == "prove":
                    result = manager.native_lifecycle.bootstrap_proof(
                        data["nonce"], data["control_epoch"], public
                    )
                elif op == "approval":
                    a = endpoint.approval(packet)
                    approvals[a.role] = a
                    if a.role == "manager":
                        manager.native_lifecycle.bootstrap(a)
                    result = {"approved": a.role}
                elif op == "connect":
                    manager.native_lifecycle.connect_control(
                        data["path"], data["control"]
                    )
                    host.connect_control(
                        data["path"],
                        data["control"],
                        supervisor_approval=approvals["business"],
                    )
                    manager.native_lifecycle.approve(
                        uuid.uuid4().hex, {"host_generation": host.generation}
                    )
                    manager.unload("fixture")
                    assert not host.live()
                    assert (
                        manager.native_lifecycle.state_sync(uuid.uuid4().hex)["state"]
                        == "ACTIVE"
                    )
                    record(
                        profile,
                        "manager_survived_actual_plugin_unload",
                        channel=manager.native_lifecycle.channel,
                    )
                    result = {"connected": True}
                elif op == "revoke":
                    result = manager.native_lifecycle.revoke(data["operation_id"])
                else:
                    raise PermissionError("fixture bootstrap operation")
                endpoint.acknowledge(result)
        except EOFError:
            pass
        finally:
            manager.native_lifecycle.close()
            host.close()
            record(profile, "exit", role=role)
    else:
        path = str(Path("/tmp") / ("h-wrap-" + uuid.uuid4().hex[:12] + ".sock"))
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen(8)
        listener.setblocking(False)
        epoch = uuid.uuid4().hex
        endpoint.announce({"path": path, "control_epoch": epoch})
        approvals = []
        # Receive the two private Supervisor approvals before admitting UDS sessions.
        for _ in range(2):
            packet = endpoint.receive()
            approvals.append(endpoint.approval(packet))
            endpoint.acknowledge({"approved": True})
        sel = selectors.DefaultSelector()
        sel.register(listener, selectors.EVENT_READ, "accept")
        sel.register(endpoint.socket, selectors.EVENT_READ, "boot")
        clients = {}
        try:
            while True:
                for key, _ in sel.select(2):
                    if key.data == "boot":
                        if not endpoint.socket.recv(1, socket.MSG_PEEK):
                            return
                        raise PermissionError("unexpected bootstrap operation")
                    if key.data == "accept":
                        c, _ = listener.accept()
                        c.setblocking(False)
                        clients[c] = {"buffer": bytearray(), "phase": 0}
                        sel.register(c, selectors.EVENT_READ, "client")
                        continue
                    c = key.fileobj
                    state = clients[c]
                    data = c.recv(131072)
                    if not data:
                        sel.unregister(c)
                        c.close()
                        clients.pop(c)
                        continue
                    state["buffer"].extend(data)
                    import struct

                    if len(state["buffer"]) < 4:
                        continue
                    n = struct.unpack("!I", state["buffer"][:4])[0]
                    if len(state["buffer"]) < n + 4:
                        continue
                    value = json.loads(state["buffer"][4 : n + 4])
                    del state["buffer"][: n + 4]
                    c.settimeout(2)
                    if state["phase"] == 0:
                        role = (
                            "manager"
                            if value.get("contract")
                            == "hermes.native-lifecycle-registration/2"
                            else "business"
                        )
                        a = next(a for a in approvals if a.role == role)
                        verifier = NativeControlVerifier.staged(
                            c, approval=a, control_epoch=epoch
                        )
                        state["verifier"] = verifier
                        send(c, verifier.accept_registration(value))
                        state["phase"] = 1
                    elif state["phase"] == 1:
                        send(c, state["verifier"].accept_proof(value))
                        state["phase"] = 2
                    else:
                        body, payload = state["verifier"].verify_call(value)
                        assert state["verifier"].role == "manager"
                        result = (
                            {"state": "ACTIVE"}
                            if payload["operation"] == "state_sync"
                            else {
                                "accepted": payload["operation"],
                                "state": "ACTIVE"
                                if payload["operation"] == "approve"
                                else "CLOSED",
                            }
                        )
                        send(
                            c,
                            {
                                "call_nonce": body["nonce"],
                                "payload_digest": body["payload_digest"],
                                "control_epoch": epoch,
                                "result": result,
                                "result_digest": hashlib.sha256(
                                    canonical(result)
                                ).hexdigest(),
                            },
                        )
                    c.setblocking(False)
        finally:
            for c in clients:
                c.close()
            sel.close()
            listener.close()
            Path(path).unlink(missing_ok=True)
            record(profile, "exit", role=role)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("role")
    p.add_argument("root")
    p.add_argument("--fault", default="none")
    p.add_argument("--native-bootstrap-fd", type=int, required=True)
    a = p.parse_args()
    run(a.role, a.root, a.native_bootstrap_fd, a.fault)
