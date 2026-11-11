"""Synthetic launch provider explicitly injected into the actual wrapper API."""

import hashlib
import json
import os
import signal
import sys
from pathlib import Path

from hermes_cli.stderr_timestamp import run_isolated_profile


class Provider:
    def __init__(self, spec):
        self.expected = json.loads(json.dumps(spec))
        self.root = Path(spec["profile"])

    def verify_launch(self, spec, digest):
        assert spec == self.expected
        from hermes_cli import stderr_timestamp

        assert (
            digest
            == hashlib.sha256(Path(stderr_timestamp.__file__).read_bytes()).hexdigest()
        )

    def verify_child(self, role, record, actual):
        assert record["process"] == actual and record["profile"] == str(self.root)
        assert record["artifact_digest"] == self.expected["core"]["artifact_digest"]

    def ready(self, info):
        (self.root / "ready.json").write_text(json.dumps(info), encoding="utf8")
        print("READY " + json.dumps(info), flush=True)
        if (self.root / "kill-core").exists():
            os.kill(info["children"]["core"], signal.SIGKILL)

    def should_stop(self):
        return (self.root / "stop").exists()


if __name__ == "__main__":
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf8"))
    try:
        result = run_isolated_profile(spec, provider=Provider(spec))
    except (PermissionError, OSError, EOFError, ValueError):
        result = 127
    sys.exit(result)
