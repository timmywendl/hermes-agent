"""OS counterexample for PR14's mandatory independent-rights witness gate."""
import json
from pathlib import Path
import subprocess

import pytest

pytestmark = pytest.mark.platforms('macos')
ROOT = Path(__file__).resolve().parents[2]


def test_live_mach_right_is_not_a_file_snapshot_retirement_witness(tmp_path):
    """All resources belong to this inert canary; no ES subscription or VM."""
    binary = tmp_path / 'rights-visibility'
    subprocess.run([
        'xcrun', 'clang', '-std=c17', '-fblocks', '-Wall', '-Wextra', '-Werror',
        str(ROOT / 'native/vz_observer/rights_visibility_probe.c'), '-o', str(binary),
    ], capture_output=True, text=True, check=True, timeout=30)
    result = subprocess.run([str(binary)], capture_output=True, text=True,
                            check=True, timeout=10)
    observed = json.loads(result.stdout)
    assert observed['self_only']
    assert observed['same_fd_snapshot'] and observed['same_fileport_snapshot']
    assert observed['live_mach_send_refs'] > 0
    assert observed['restored_snapshots']
    assert observed['pipe_positive_control']
    assert observed['own_right_released']
    assert observed['per_vm_vz_release'] == 'UNKNOWN'
    assert observed['native'] == 'NOT_RUN'
    assert observed['es_client'] == 'NOT_CREATED'
