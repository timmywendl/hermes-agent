"""Q1-C1 pure wire contracts against compiled Swift; no VZ, Owner or VM execution.

Build only the conditional contract_check harness, never sign/apply entitlements.
The descriptor is fixture data, not an approved native artifact or identity proof.
"""

from __future__ import annotations

import copy
import hashlib
import json
import plistlib
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.platforms("macos")
ROOT = Path(__file__).resolve().parents[2]
JSON = dict[str, Any]
Check = Callable[..., JSON]


def descriptor() -> JSON:
    return {
        "version": "Q1C_ADAPTER_V1",
        "binding": {
            "VM_ID": "test:vm", "TASK_ID": "test:task", "RUN_ID": "test:run",
            "OWNER_EPOCH": 1, "BOOT_ID": "test:boot", "ADAPTER_PID": 123,
            "ADAPTER_BIRTH": "test:birth", "VZ_INSTANCE_ID": "test:instance",
            "IMAGE_DIGEST": "a" * 64, "POLICY_DIGEST": "b" * 64,
            "SOCKET_ENDPOINT": "test:private-pair", "CONNECTION_GENERATION": 1,
        },
        "artifacts": {
            "kernel": {"path": "/fixture/kernel", "sha256": "c" * 64},
            "initramfs": {"path": "/fixture/initramfs", "sha256": "d" * 64},
            "disk": {"path": "/fixture/disk", "sha256": "a" * 64},
            "policy": {"path": "/fixture/policy", "sha256": "b" * 64},
        },
        "resources": {"vcpus": 2, "memory_bytes": 2_147_483_648, "disk_bytes": 8_589_934_592,
                      "startup_seconds": 60, "stop_seconds": 30, "total_seconds": 300},
        "task_directory": {"path": "/fixture/task", "tag": "task", "read_only": True},
        "devices": {"network_devices": [], "socket_devices": 1, "console_devices": 1, "entropy_devices": 1},
    }


def frame(operation: str = "contract_check", sequence: int = 1, **changes: Any) -> JSON:
    value = {"version": "Q1C_ADAPTER_V1", "request_id": f"test:req:{sequence}", "sequence": sequence,
             "operation": operation, "binding": descriptor()["binding"], "payload": {}}
    value.update(changes)
    return value


@pytest.fixture(scope="module")
def check(tmp_path_factory: pytest.TempPathFactory) -> Check:
    compiler = shutil.which("swiftc")
    assert compiler, "Swift compiler required for actual implementation tests"
    binary = tmp_path_factory.mktemp("q1c-pure") / "contract_check"
    build = subprocess.run(
        [compiler, "-parse-as-library", "-warnings-as-errors", "-D", "Q1C_CONTRACT_CLI",
         str(ROOT / "native/vz_adapter/main.swift"), "-o", str(binary)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert build.returncode == 0, build.stderr

    def run(frames: list[JSON | str] | None = None, *, desc: JSON | str | None = None,
            end: str | None = None, raw_input: bytes | None = None) -> JSON:
        source = descriptor() if desc is None else desc
        body = {"descriptor": source if isinstance(source, str) else json.dumps(source),
                "frames": [f if isinstance(f, str) else json.dumps(f) for f in (frames or [])],
                "transport_end": end}
        result = subprocess.run([str(binary)], input=raw_input if raw_input is not None else json.dumps(body).encode(),
                                capture_output=True, timeout=5, check=False)
        assert result.returncode == 0, result.stderr
        value: JSON = json.loads(result.stdout)
        return value

    return run


def code(check: Check, item: JSON | str) -> str:
    result: str = check([item])["results"][0]["code"]
    return result


def test_planned_inventory_is_not_native_evidence(check: Check) -> None:
    result = check([frame("enumerate_devices")])
    assert result["state"] == "NEW"
    assert result["authority"] == "NOT_VERIFIED" and result["native"] == "NOT_RUN"
    inventory = result["inventory"]
    assert inventory["network_devices"] == [] and inventory["socket_devices"] == 1
    assert inventory["task_share"] == descriptor()["task_directory"]
    assert inventory["storage"] == [descriptor()["artifacts"]["disk"]]
    assert inventory["boot"] == "DIRECT_LINUX"
    assert inventory["console_devices"] == inventory["entropy_devices"] == 1
    receipt = result["results"][0]
    assert receipt["code"] == receipt["inventory_kind"] == "PLANNED_ONLY"
    assert receipt["native_observation"] == "NOT_RUN" and receipt["stop_verified"] is False
    # Paths remain nonexistent fixture strings: contract_check does not open artifacts.
    assert len(result["manifest_sha256"]) == 64
    assert result["manifest_sha256"] == check()["manifest_sha256"]


@pytest.mark.parametrize("operation", ["create_vm", "validate_configuration", "start_vm", "stop_exact_vm"])
def test_every_native_operation_is_closed(check: Check, operation: str) -> None:
    result = check([frame(operation)])
    assert result["results"][0]["code"] == "NATIVE_NOT_AUTHORIZED"
    assert result["state"] == "NEW" and result["capabilities_revoked"] is False


@pytest.mark.parametrize("key", list(frame()))
def test_missing_envelope_field(check: Check, key: str) -> None:
    value = frame()
    del value[key]
    assert code(check, value) == "INVALID_FRAME"


@pytest.mark.parametrize("key", list(frame()))
def test_null_envelope_field(check: Check, key: str) -> None:
    value = frame()
    value[key] = None
    assert code(check, value) == "INVALID_FRAME"


@pytest.mark.parametrize("value", [0, -1, True, 1.0, 1e100, 2**63, "1", None])
def test_sequence_type_and_range(check: Check, value: Any) -> None:
    assert code(check, frame(sequence=value)) == "INVALID_FRAME"


@pytest.mark.parametrize("value", ["Q1C_ADAPTER_V2", "", 1, True])
def test_strict_protocol_version(check: Check, value: Any) -> None:
    assert code(check, frame(version=value)) == "INVALID_FRAME"


@pytest.mark.parametrize("raw", [
    '{"version":"Q1C_ADAPTER_V1","version":"Q1C_ADAPTER_V1"}',
    '{"x":{"a":1,"a":2}}', '{"x":[{"a":1,"\\u0061":2}]}',
    '{"x":NaN}', '{"x":Infinity}', '{"x":1.5}', '{"x":1e0}', '{"x":01}',
    '{"x":9223372036854775808}', '{"x":"\\ud800"}', '{"x":"\\udfff"}',
    '{"x":"\\q"}', '{"x":1,}', '{}{}', '[]', 'null',
    '{"x":' + '[' * 9 + '0' + ']' * 9 + '}',
])
def test_wire_rejects_invalid_json_and_shape(check: Check, raw: str) -> None:
    assert code(check, raw) == "INVALID_FRAME"


def test_duplicate_valid_binding_key_is_not_erased(check: Check) -> None:
    raw = json.dumps(frame()).replace('"VM_ID": "test:vm"', '"VM_ID": "test:vm", "VM_ID": "test:vm"')
    assert code(check, raw) == "INVALID_FRAME"


def test_frame_byte_boundary_and_trailing_bytes(check: Check) -> None:
    raw = json.dumps(frame())
    exact = raw + " " * (65_536 - len(raw.encode()))
    assert code(check, exact) == "SHAPE_VALID_AUTHORITY_NOT_VERIFIED"
    assert code(check, exact + " ") == "INVALID_FRAME"
    assert code(check, raw + "x") == "INVALID_FRAME"


@pytest.mark.parametrize("value", ["", "a" * 129, "test request", "é", "test:\x00"])
def test_request_token_bounds(check: Check, value: str) -> None:
    assert code(check, frame(request_id=value)) == "INVALID_FRAME"


@pytest.mark.parametrize("key", list(descriptor()["binding"]))
def test_each_identity_pin_is_bound(check: Check, key: str) -> None:
    value = frame()
    old = value["binding"][key]
    value["binding"][key] = old + 1 if isinstance(old, int) else ("e" * 64 if key.endswith("DIGEST") else "test:other")
    assert code(check, value) == ("STALE_EPOCH" if key == "OWNER_EPOCH" else "IDENTITY_MISMATCH")


@pytest.mark.parametrize("key", list(descriptor()["binding"]))
def test_missing_identity_pin(check: Check, key: str) -> None:
    value = frame()
    del value["binding"][key]
    assert code(check, value) == "INVALID_FRAME"


def test_unknown_fields_and_injected_native_grant_denied(check: Check) -> None:
    for value in [frame(extra=True), frame(payload={"native_grant": True}), frame(operation="restore_vm")]:
        assert code(check, value) == "INVALID_FRAME"
    d = descriptor()
    d["native_grant"] = True
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


def test_replay_and_sequence_do_not_rerun(check: Check) -> None:
    a = frame("enumerate_devices")
    results = check([a, a, frame("contract_check", sequence=2)])["results"]
    assert results[0] == results[1]
    raw = json.dumps(a).encode()
    assert results[0]["observation_ref"] == "q1c-pure:1:" + hashlib.sha256(raw).hexdigest()
    assert results[2]["code"] == "SHAPE_VALID_AUTHORITY_NOT_VERIFIED"
    for bad in [frame(sequence=3), frame(sequence=1, request_id="test:new")]:
        assert check([a, bad])["results"][1]["code"] == "REPLAY_DETECTED"
    changed = copy.deepcopy(a)
    changed["operation"] = "create_vm"
    assert check([a, changed])["results"][1]["code"] == "REPLAY_DETECTED"
    # Replay identity is exact wire bytes, not normalization or reserialization.
    assert check([a, json.dumps(a) + " "])["results"][1]["code"] == "REPLAY_DETECTED"


def test_rejected_frames_do_not_consume_sequence(check: Check) -> None:
    wrong = frame()
    wrong["binding"]["RUN_ID"] = "test:other"
    results = check([wrong, frame(), frame(sequence=2)])["results"]
    assert [x["code"] for x in results] == ["IDENTITY_MISMATCH", "SHAPE_VALID_AUTHORITY_NOT_VERIFIED", "SHAPE_VALID_AUTHORITY_NOT_VERIFIED"]


def test_batch_bound(check: Check) -> None:
    assert len(check([frame(sequence=i) for i in range(1, 17)])["results"]) == 16
    assert check([frame(sequence=i) for i in range(1, 18)])["error"] == "CAPACITY_EXCEEDED"


@pytest.mark.parametrize("end", ["EOF", "ERROR", "TIMEOUT"])
def test_transport_fault_preserves_stop_uncertainty(check: Check, end: str) -> None:
    result = check([frame("revoke")], end=end)
    assert result["state"] == "STOP_UNCERTAIN" and result["capabilities_revoked"] is True


def test_revoke_is_sticky_and_not_verified_stop(check: Check) -> None:
    value = frame("revoke")
    results = check([value, value, frame("enumerate_devices", sequence=2), frame("lifecycle_receipt", sequence=2)])["results"]
    assert results[0] == results[1]
    assert results[0]["state"] == "REVOKING" and results[0]["stop_verified"] is False
    assert results[2]["code"] == "CAPABILITY_REVOKED"
    assert results[3]["code"] == "NATIVE_NOT_OBSERVED"


@pytest.mark.parametrize("name,port,direction,capability,expected", [
    ("owner_control", 4000, "OWNER_TO_GUEST", "INERT_DIAGNOSTIC_ONLY", "NATIVE_NOT_AUTHORIZED"),
    ("worker_rpc", 4001, "GUEST_TO_HOST", "DISABLED", "CHANNEL_DENIED"),
    ("inference", 4002, "GUEST_TO_HOST", "DISABLED", "CHANNEL_DENIED"),
    ("lifecycle", 4003, "GUEST_TO_HOST", "UNTRUSTED_DIAGNOSTIC_ONLY", "NATIVE_NOT_AUTHORIZED"),
    ("stop_revoke", 4004, "OWNER_TO_GUEST", "STOP_NOTICE_ONLY", "NATIVE_NOT_AUTHORIZED"),
    ("owner_control", 4001, "OWNER_TO_GUEST", "INERT_DIAGNOSTIC_ONLY", "CHANNEL_DENIED"),
    ("owner_control", 4000, "GUEST_TO_HOST", "INERT_DIAGNOSTIC_ONLY", "CHANNEL_DENIED"),
    ("lifecycle", 4003, "GUEST_TO_HOST", "STOP_VERIFIED", "CHANNEL_DENIED"),
    ("forward", 22, "GUEST_TO_HOST", "SHELL", "CHANNEL_DENIED"),
])
def test_five_channel_capabilities(check: Check, name: str, port: int, direction: str, capability: str, expected: str) -> None:
    payload = {"channel": name, "port": port, "direction": direction, "capability": capability}
    assert code(check, frame("accept_scoped_socket", payload=payload)) == expected


@pytest.mark.parametrize("key", list(descriptor()))
def test_missing_descriptor_fields(check: Check, key: str) -> None:
    d = descriptor()
    del d[key]
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


@pytest.mark.parametrize("key", list(descriptor()["resources"]))
@pytest.mark.parametrize("bad", [0, -1, True, 1.5, 2**63 - 1])
def test_resource_bounds(check: Check, key: str, bad: Any) -> None:
    d = descriptor()
    d["resources"][key] = bad
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


@pytest.mark.parametrize("path", ["relative/task", "/fixture/../task", "/fixture/./task", "/fixture//task", "/", "/fixture/task/", "/fixture/\x00task", "/" + "a" * 1024])
def test_task_path_bounds(check: Check, path: str) -> None:
    d = descriptor()
    d["task_directory"]["path"] = path
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


def test_attach_exact_share_no_live_mutation(check: Check) -> None:
    share = descriptor()["task_directory"]
    assert code(check, frame("attach_task_directory", payload=share)) == "SHAPE_VALID_AUTHORITY_NOT_VERIFIED"
    for key, value in [("path", "/fixture/other"), ("tag", "other"), ("read_only", False)]:
        changed = dict(share, **{key: value})
        assert code(check, frame("attach_task_directory", payload=changed)) == "INVALID_DESCRIPTOR"
    results = check([frame("revoke"), frame("attach_task_directory", sequence=2, payload=share)])["results"]
    assert results[1]["code"] == "CAPABILITY_REVOKED"
    d = descriptor()
    d["task_directory"]["path"] = "/fixture/é"
    share = dict(d["task_directory"], path="/fixture/e\u0301")
    assert check([frame("attach_task_directory", payload=share)], desc=d)["results"][0]["code"] == "INVALID_DESCRIPTOR"


@pytest.mark.parametrize("key,bad", [("network_devices", ["NAT"]), ("socket_devices", 2), ("console_devices", 0), ("entropy_devices", True), ("ssh", True)])
def test_forbidden_device_inventory(check: Check, key: str, bad: Any) -> None:
    d = descriptor()
    d["devices"][key] = bad
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


def test_bad_artifact_pins_and_aliases(check: Check) -> None:
    for key, bad in [("sha256", "a" * 63), ("sha256", "A" * 64), ("path", "relative"), ("extra", True)]:
        d = descriptor()
        d["artifacts"]["kernel"][key] = bad
        assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"
    for kind in ["disk", "policy"]:
        d = descriptor()
        d["artifacts"][kind]["sha256"] = "f" * 64
        assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"
    d = descriptor()
    d["artifacts"]["kernel"]["path"] = d["artifacts"]["disk"]["path"]
    assert check(desc=d)["error"] == "INVALID_DESCRIPTOR"


def test_invalid_utf8_and_harness_bounds(check: Check) -> None:
    assert check(raw_input=b"\xff")["error"] == "INVALID_FRAME"
    assert check(raw_input=b" " * 2_200_001)["error"] == "INVALID_FRAME"
    assert check(end="SUCCESS")["error"] == "INVALID_FRAME"


def test_pure_swift_lifecycle_and_illegal_transitions(tmp_path: Path) -> None:
    """Run the actual exhaustive state/event assertions, including sticky uncertainty."""
    compiler = shutil.which("swiftc")
    assert compiler
    binary = tmp_path / "pure_states"
    build = subprocess.run(
        [compiler, "-parse-as-library", "-warnings-as-errors", str(ROOT / "native/vz_adapter/main.swift"),
         str(ROOT / "tests/native/test_vz_no_nic.swift"), "-o", str(binary)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert build.returncode == 0, build.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    words = result.stdout.split()
    assert words[0] == "PASS" and int(words[1]) > 0
    assert "VZ_API_OPERATIONS=NOT_RUN" in result.stdout


def test_entitlement_is_minimal_declaration() -> None:
    with (ROOT / "native/vz_adapter/owner.entitlements").open("rb") as stream:
        assert plistlib.load(stream) == {"com.apple.security.virtualization": True}
