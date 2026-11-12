"""Kill a real Core at the SQLite commit boundary, then reopen in a new process."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('boundary,expected', [('before_commit', 'NONE'), ('after_commit', 'ONE')])
def test_killed_core_has_only_durably_committed_selectors(tmp_path, boundary, expected):
    profile = tmp_path / 'profile'
    profile.mkdir()
    (profile / 'config.yaml').write_text('plugins:\n  required_response_gates:\n'
        '    - plugin_id: fixture\n      request_terms: [Cloud Test, Load Testing]\n')
    env = dict(os.environ, HOME=str(tmp_path), HERMES_HOME=str(profile))
    child = subprocess.Popen([sys.executable, '-m', 'tests.agent.native_recovery_child', str(profile), boundary],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        identity = json.loads(child.stdout.readline())
        assert identity['pid'] == child.pid
        assert json.loads(child.stdout.readline()) == {'boundary': boundary}
        child.kill()
        output, error = child.communicate(timeout=5)
        assert child.returncode < 0 and 'unexpected_rpc' not in output and not error
        restarted = subprocess.run([sys.executable, '-m', 'tests.agent.native_recovery_child', str(profile), 'read'],
            env=env, capture_output=True, text=True, timeout=10, check=True)
        result = json.loads(restarted.stdout)
        assert result['state'] == expected
        if expected == 'ONE':
            assert result['selector']['request_id'] == 'request'
        # No sidecar JSON journal: only config and existing SessionDB files.
        assert not list(Path(profile).glob('*.json'))
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
