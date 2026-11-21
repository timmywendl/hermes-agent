"""Private Q2 Linux Guest entry into the original managed runtime.

An approved image starts this as a non-root user, with a raw private tty descriptor
and a read-only assignment file. It does not open a listener or a canonical DB.
No Host entry in this package starts this program during Source Ready testing.
"""
import json
import os
from pathlib import Path
import termios
import tty


def validate_mount(work, mountinfo):
    """Require a distinct block-backed /task mount; reviewer must be kernel RO."""
    entries = [line.split() for line in mountinfo.splitlines() if ' - ' in line]
    task = [parts for parts in entries if len(parts) > 6 and parts[4] == '/task']
    if len(task) != 1:
        raise ValueError('guest_task_mount_required')
    parts = task[0]
    split = parts.index('-')
    if parts[split + 1] != 'ext4' or not parts[split + 2].startswith('/dev/vd'):
        raise ValueError('guest_private_block_device_required')
    options = set(parts[5].split(','))
    if work['role'] == 'reviewer' and 'ro' not in options:
        raise ValueError('guest_reviewer_readonly_required')


def run(fd, work, outbox):
    if os.geteuid() == 0:
        raise ValueError('guest_unprivileged_user_required')
    from agent.runtime_session_guest import execute_guest, validate_guest_work
    work = validate_guest_work(work)
    validate_mount(work, Path('/proc/self/mountinfo').read_text())
    import subprocess
    actual = subprocess.check_output(['git', '-C', '/task', 'rev-parse', 'HEAD'], text=True, timeout=5).strip()
    if actual != work['base_commit']:
        raise ValueError('guest_workspace_head_mismatch')
    from agent.guest_serial import GuestSerialClient, SerialWire
    prior = termios.tcgetattr(fd)
    tty.setraw(fd)
    channel = GuestSerialClient(SerialWire(fd, work['assignment']))
    try:
        # Re-read assignment through the bound original Owner before adoption.
        if channel.call('context', {'operation': 'assignment'}) != work:
            raise ValueError('guest_assignment_changed')
        execute_guest(work, channel, persistence_exchange=channel,
                      control_stream=channel.controls, outbox_dir=outbox)
    finally:
        channel.close()
        termios.tcsetattr(fd, termios.TCSANOW, prior)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial-fd', type=int, required=True)
    parser.add_argument('--assignment', type=Path, required=True)
    parser.add_argument('--outbox', type=Path, required=True)
    args = parser.parse_args()
    work = json.loads(args.assignment.read_text())
    run(args.serial_fd, work, args.outbox)


if __name__ == '__main__':
    main()
