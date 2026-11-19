"""A vanished native peer denies identity without crashing its verifier caller."""
import subprocess
import sys

import pytest

from hermes_platform.native_peer import process_snapshot


@pytest.mark.platforms('macos')
def test_killed_peer_snapshot_is_a_permission_denial():
    child = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdin.read()'], stdin=subprocess.PIPE)
    try:
        assert process_snapshot(child.pid)['pid'] == child.pid
        child.kill()
        child.wait(timeout=5)
        with pytest.raises(PermissionError, match='native peer identity unavailable'):
            process_snapshot(child.pid)
    finally:
        child.stdin.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
