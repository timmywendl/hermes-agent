"""Idle measurement inside the real disposable Core; no provider/model/transport."""

import hashlib
import json
import os
import resource
import signal
import threading
import time
from pathlib import Path

from hermes_cli.native_core_startup import NativeCoreStartup
from hermes_platform.native_peer import process_snapshot


def measure_phase(root, phase):
    root = Path(root)
    identity = process_snapshot(os.getpid())
    stop = threading.Event()
    counts = {"owner_checks": 0, "executable_digest_calls": 0, "logical_executable_bytes_hashed": 0}
    original_check, original_digest = NativeCoreStartup._check_owner, hashlib.file_digest
    previous = signal.signal(signal.SIGUSR1, lambda *_: stop.set())

    def checked(core):
        if threading.current_thread().name == "native-bootstrap":
            counts["owner_checks"] += 1
        return original_check(core)

    def digested(source, *args, **kwargs):
        if threading.current_thread().name == "native-bootstrap":
            counts["executable_digest_calls"] += 1
            counts["logical_executable_bytes_hashed"] += os.fstat(source.fileno()).st_size
        return original_digest(source, *args, **kwargs)

    NativeCoreStartup._check_owner, hashlib.file_digest = checked, digested
    started_wall, started_cpu = time.monotonic(), time.process_time()
    started_io = resource.getrusage(resource.RUSAGE_SELF)
    try:
        (root / f"measure-ready-{phase}.json").write_text(json.dumps(identity))
        if not stop.wait(45):
            raise AssertionError("measurement coordinator did not release Core")
        ended_wall, ended_cpu = time.monotonic(), time.process_time()
        ended_io = resource.getrusage(resource.RUSAGE_SELF)
    finally:
        NativeCoreStartup._check_owner, hashlib.file_digest = original_check, original_digest
        signal.signal(signal.SIGUSR1, previous)
    wall, cpu = ended_wall - started_wall, ended_cpu - started_cpu
    result = {"phase": phase, "process": identity, "wall_seconds": wall, "cpu_seconds": cpu,
              "one_core_cpu_percent": 100 * cpu / wall, **counts,
              "os_input_blocks": ended_io.ru_inblock - started_io.ru_inblock,
              "os_output_blocks": ended_io.ru_oublock - started_io.ru_oublock,
              "scope": "Core process CPU including fixture/signal overhead; logical digest bytes plus OS block counters"}
    (root / f"measure-result-{phase}.json").write_text(json.dumps(result, indent=2))
