"""Actual ext4/FD contracts for Q2 qualification; no VM or Worker is started."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from native.qemu_guest.artifact_fs import ext4
from native.qemu_guest.artifact_inventory import file_record
from native.qemu_guest.build_artifacts import MKE2FS_CONFIG
from native.qemu_guest.build_inputs import canonical
from native.qemu_guest.image_contract import GuestImage
from native.qemu_guest.qualification_artifacts import (
    freeze_candidate, load_candidate, prepare_slot_devices, slot_image, verify_slot_devices,
)


def git(root, *args):
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_AUTHOR_NAME': 'Qualification fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
           'GIT_COMMITTER_NAME': 'Qualification fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
    return subprocess.check_output(['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null',
                                    '-c', 'commit.gpgsign=false', *args],
                                   env=env, text=True, timeout=10).strip()


@pytest.fixture(autouse=True)
def private_readonly_test_cleanup(tmp_path):
    yield
    for path in sorted(tmp_path.rglob('*'), key=lambda p: len(p.parts)):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    git(root, 'init', '-q', '--template=')
    (root / 'base.txt').write_text('accepted base\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'base')
    return root, git(root, 'rev-parse', 'HEAD')


@pytest.fixture
def ext4_tools(tmp_path):
    pytest.importorskip('dissect.extfs')
    from hermes_platform.resolver import locate_command
    command = locate_command('mke2fs').command
    if not command:
        pytest.skip('pinned external ext4 tool not installed')
    config = tmp_path / 'mke2fs.conf'
    config.write_text(MKE2FS_CONFIG)
    return Path(command[0]), config


def image_tree(tree, path, tools, label):
    tool, config = tools
    ext4(tree, path, label=label, mib=64, tool=tool, config=config, owner=1000)
    return path


def candidate_disk(repository, tmp_path, ext4_tools, *, commit=True):
    root, base = repository
    (root / 'qualification').mkdir()
    (root / 'qualification/result.txt').write_bytes(b'actual Guest candidate\n')
    if commit:
        git(root, 'add', '.')
        git(root, 'commit', '-qm', 'actual candidate')
    head = git(root, 'rev-parse', 'HEAD')
    disk = image_tree(root, tmp_path / 'actual-task.raw', ext4_tools, 'Q2ACTUAL')
    return disk, base, head


def work(head, role='developer', slot=1):
    scope = {'session_id': f'qualification-{slot}', 'generation': 1, 'epoch': slot,
             'execution_id': f'admission-worker:qualification-{slot}', 'task_id': f'task-{slot}',
             'run_id': slot, 'vm_id': f'vm-{slot}', 'connection_generation': 1,
             'image_digest': 'a' * 64, 'policy_digest': 'b' * 64}
    return {'version': 'HERMES_GUEST_WORK_V1', 'assignment': scope, 'title': 'Disposable qualification',
            'body': 'Public fixture only', 'repo': 'offline/qualification', 'base_commit': head,
            'branch': 'task/guest', 'workspace': '/task', 'role': role, 'model': 'fixed-fake',
            'completion_contract': 'qualification only'}


def inert_image(tmp_path, role='developer'):
    files = {}
    for name in ('kernel', 'initramfs', 'root', 'task', 'assignment'):
        path = tmp_path / (name + '.raw')
        path.write_bytes(('inert-' + name).encode())
        files[name] = path
    manifests = {name: {'path': str(path), 'sha256': file_record(path)['sha256'],
                       'st_dev': path.stat().st_dev, 'st_ino': path.stat().st_ino,
                       'readonly': name != 'task' or role == 'reviewer'}
                 for name, path in files.items() if name in ('root', 'task', 'assignment')}
    manifest = {'role': role, 'workspace': {'kind': 'directory_snapshot', 'mount': '/task',
                'head': 'a' * 40, 'role': role, 'readonly': role == 'reviewer', 'host_share': False},
                'devices': manifests}
    return GuestImage(**files, role=role, sha256={str(p): file_record(p)['sha256'] for p in files.values()},
                      manifest_json=canonical(manifest).rstrip('\n'))


@pytest.mark.platforms('posix')
def test_preopened_devices_use_fdsets_and_exact_access_modes(tmp_path):
    import fcntl
    image = inert_image(tmp_path)
    serial, peer = socket.socketpair()
    with image.open_devices() as devices, serial, peer:
        descriptors = devices.descriptors()
        assert set(descriptors) == {'root', 'task', 'assignment'}
        for name, fd in devices.fds.items():
            assert (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) == (os.O_RDWR if name == 'task' else os.O_RDONLY)
        os.lseek(devices.fds['task'], 3, os.SEEK_SET)
        args = devices.device_args(serial.fileno())
        assert os.lseek(devices.fds['task'], 0, os.SEEK_CUR) == 3
        assert args.count('-add-fd') == 3
        assert 'file=/dev/fdset/2,format=raw,if=none,id=task,readonly=off' in args
        assert str(image.task) not in args
        assert 'file=/dev/fdset/1,format=raw,if=none,id=root,readonly=on' in args
        assert 'file=/dev/fdset/3,format=raw,if=none,id=assignment,readonly=on' in args
        assert args[args.index('-nic') + 1] == 'none'
        before = devices.pass_fds
    assert devices.closed
    for fd in before:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.platforms('posix')
def test_reviewer_task_capability_is_kernel_readonly(tmp_path):
    image = inert_image(tmp_path, 'reviewer')
    with image.open_devices() as devices:
        with pytest.raises(OSError):
            os.pwrite(devices.fds['task'], b'bad', 0)
        assert devices.descriptors()['task']['readonly'] is True
        devices.verify()
        serial, peer = socket.socketpair()
        with serial, peer:
            args = devices.device_args(serial.fileno())
        assert 'file=/dev/fdset/2,format=raw,if=none,id=task,readonly=on' in args


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('damage', ['content', 'rename', 'hardlink', 'symlink'])
def test_open_capability_refuses_replaced_or_changed_device(tmp_path, damage):
    image = inert_image(tmp_path)
    with image.open_devices() as devices:
        task = image.task
        if damage == 'content':
            os.pwrite(devices.fds['task'], b'changed', 0)
        elif damage == 'hardlink':
            os.link(task, tmp_path / 'alias')
        else:
            task.rename(tmp_path / 'previous')
            if damage == 'rename':
                task.write_bytes(b'new')
            else:
                task.symlink_to(tmp_path / 'previous')
        with pytest.raises(ValueError):
            devices.verify()


@pytest.mark.platforms('posix')
def test_fd_argv_refuses_device_as_serial(tmp_path):
    image = inert_image(tmp_path)
    with image.open_devices() as devices:
        with pytest.raises(ValueError, match='serial'):
            devices.device_args(devices.fds['task'])


@pytest.mark.platforms('posix')
def test_actual_candidate_preserves_commit_and_reviewer_uses_actual_output(repository, tmp_path, ext4_tools):
    disk, base, head = candidate_disk(repository, tmp_path, ext4_tools)
    prior = file_record(disk)
    candidate = freeze_candidate(disk, tmp_path / 'frozen', expected_base=base,
                                 expected_head=head, required_files={'qualification/result.txt': b'actual Guest candidate\n'})
    assert candidate['candidate_head'] == head and head != base
    assert file_record(disk) == prior
    assert load_candidate(candidate['manifest_path']) == candidate
    result = prepare_slot_devices(work(head, 'reviewer', 2), candidate['snapshot_path'], tmp_path / 'reviewer',
                                  mke2fs=ext4_tools[0], parent_candidate=candidate['manifest_path'])
    assert result['head'] == head
    assert result['parent_candidate_sha256'] == candidate['manifest_sha256']
    assert result['workspace']['readonly'] is True
    assert result['task']['st_ino'] != prior['st_ino']
    from dissect.extfs import ExtFS
    with Path(result['task']['path']).open('rb') as stream:
        fs = ExtFS(stream)
        assert fs.get('/qualification/result.txt').open().read() == b'actual Guest candidate\n'
    assert git(Path(result['task']['path']).parent / 'task-tree', 'rev-parse', 'HEAD') == head
    assert git(Path(result['task']['path']).parent / 'task-tree', 'rev-parse', '--path-format=absolute', '--git-common-dir') != str(Path(candidate['snapshot_path']) / '.git')


@pytest.mark.platforms('posix')
def test_candidate_refuses_unchanged_base_and_uncommitted_disk(repository, tmp_path, ext4_tools):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools, commit=False)
    with pytest.raises(ValueError, match='actual_candidate'):
        freeze_candidate(disk, tmp_path / 'unchanged', expected_base=base)


@pytest.mark.platforms('posix')
def test_candidate_refuses_dirty_contents_even_with_real_candidate_commit(repository, tmp_path, ext4_tools):
    root, base = repository
    (root / 'result.txt').write_text('committed\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'candidate')
    (root / 'result.txt').write_text('dirty post-commit\n')
    disk = image_tree(root, tmp_path / 'dirty.raw', ext4_tools, 'Q2DIRTY')
    with pytest.raises(ValueError, match='worktree_not_committed'):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_candidate_refuses_image_alias_before_read(repository, tmp_path, ext4_tools, kind):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools)
    alias = tmp_path / 'alias.raw'
    if kind == 'symlink':
        alias.symlink_to(disk)
    else:
        os.link(disk, alias)
    with pytest.raises(ValueError, match='single_link'):
        freeze_candidate(alias, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
def test_candidate_refuses_untrusted_git_config_change_after_freeze(repository, tmp_path, ext4_tools):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools)
    record = freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)
    config = Path(record['snapshot_path']) / '.git/config'
    config.chmod(0o600)
    config.write_text('[core]\nfsmonitor = not-an-executable-test-fixture\n')
    with pytest.raises(ValueError, match='snapshot_changed'):
        load_candidate(record['manifest_path'])


@pytest.mark.platforms('posix')
def test_developer_devices_are_fresh_and_scope_bound(repository, tmp_path, ext4_tools):
    root, base = repository
    one = prepare_slot_devices(work(base), root, tmp_path / 'slot-one', mke2fs=ext4_tools[0])
    two = prepare_slot_devices(work(base, slot=3), root, tmp_path / 'slot-three', mke2fs=ext4_tools[0])
    assert one['task_fs']['uuid'] != two['task_fs']['uuid']
    assert one['task']['st_ino'] != two['task']['st_ino']
    assert one['assignment']['sha256'] != two['assignment']['sha256']
    assert verify_slot_devices(one['manifest_path']) == one
    assert one['workspace']['readonly'] is False


@pytest.mark.platforms('posix')
def test_reviewer_rejects_base_fixture_substitution(repository, tmp_path, ext4_tools):
    disk, base, head = candidate_disk(repository, tmp_path, ext4_tools)
    candidate = freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)
    with pytest.raises(ValueError, match='candidate_mismatch'):
        prepare_slot_devices(work(head, 'reviewer', 2), repository[0], tmp_path / 'wrong',
                             mke2fs=ext4_tools[0], parent_candidate=candidate['manifest_path'])
    assert not (tmp_path / 'wrong').exists()


@pytest.mark.platforms('posix')
def test_slot_image_binds_real_assignment_and_missing_corruption_refuses(repository, tmp_path, ext4_tools):
    root, base = repository
    record = prepare_slot_devices(work(base), root, tmp_path / 'slot', mke2fs=ext4_tools[0])
    boot = []
    for name in ('kernel', 'initramfs', 'root'):
        path = tmp_path / name
        path.write_bytes(name.encode())
        boot.append(path)
    image = slot_image(record, kernel=boot[0], initramfs=boot[1], root=boot[2])
    image.verify()
    Path(record['assignment']['path']).write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='device_changed'):
        verify_slot_devices(record['manifest_path'])
    with pytest.raises(ValueError):
        image.open_devices()


@pytest.mark.platforms('posix')
def test_slot_build_rejects_tool_and_nested_source_before_export(repository, tmp_path, ext4_tools):
    root, base = repository
    with pytest.raises(ValueError, match='private_output'):
        prepare_slot_devices(work(base), root, root / 'nested', mke2fs=ext4_tools[0])
    assert not (root / 'nested').exists()
    fake = tmp_path / 'not-pinned'
    fake.write_text('#!/bin/sh\n: > "$0.called"\nexit 0\n')
    fake.chmod(0o700)
    with pytest.raises(ValueError, match='tool_changed'):
        prepare_slot_devices(work(base), root, tmp_path / 'wrong-tool', mke2fs=fake)
    assert not fake.with_name(fake.name + '.called').exists()


@pytest.mark.platforms('posix')
def test_close_never_closes_a_reused_descriptor(tmp_path):
    image = inert_image(tmp_path)
    devices = image.open_devices()
    number = devices.fds['task']
    replacement = tmp_path / 'foreign-owned'
    replacement.write_bytes(b'foreign')
    foreign = os.open(replacement, os.O_RDONLY)
    try:
        os.dup2(foreign, number)
        with pytest.raises(ValueError, match='capability_close_incomplete'):
            devices.close()
        assert os.pread(number, 7, 0) == b'foreign'
        assert not devices.closed
    finally:
        os.close(foreign)
        os.close(number)
        devices.fds.clear()


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'untracked'])
def test_stopped_disk_refuses_non_private_or_uncommitted_entries(repository, tmp_path, ext4_tools, kind):
    root, base = repository
    (root / 'candidate.txt').write_text('candidate\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'candidate')
    if kind == 'symlink':
        (root / 'unsafe').symlink_to('/outside')
    elif kind == 'hardlink':
        os.link(root / 'candidate.txt', root / 'unsafe')
    else:
        (root / 'untracked').write_text('not committed\n')
    image = image_tree(root, tmp_path / 'bad.raw', ext4_tools, 'Q2UNSAFE')
    with pytest.raises(ValueError, match='candidate_file_invalid|worktree_not_committed'):
        freeze_candidate(image, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
def test_candidate_parent_raw_digest_is_immutable(repository, tmp_path, ext4_tools):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools)
    record = freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)
    with disk.open('r+b') as stream:
        stream.write(b'modified')
    with pytest.raises(ValueError, match='disk_changed'):
        load_candidate(record['manifest_path'])


@pytest.mark.platforms('posix')
def test_candidate_secret_inventory_refuses_tracked_host_config(repository, tmp_path, ext4_tools):
    root, base = repository
    (root / '.env').write_text('PUBLIC_NEGATIVE_TEST_MARKER=not-a-secret\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'bad config')
    disk = image_tree(root, tmp_path / 'bad-config.raw', ext4_tools, 'Q2CONFIG')
    with pytest.raises(ValueError, match='host_configuration'):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
def test_slot_device_manifest_rejects_duplicate_key_and_wrong_role(repository, tmp_path, ext4_tools):
    root, base = repository
    record = prepare_slot_devices(work(base), root, tmp_path / 'slot', mke2fs=ext4_tools[0])
    path = Path(record['manifest_path'])
    original = path.read_text()
    path.chmod(0o600)
    path.write_text(original.rstrip()[:-1] + ',"role":"developer"}\n')
    with pytest.raises(ValueError, match='manifest_unavailable'):
        verify_slot_devices(path)
    data = json.loads(original)
    data['role'] = 'reviewer'
    path.write_text(canonical(data))
    with pytest.raises(ValueError, match='workspace_changed'):
        verify_slot_devices(path)


@pytest.mark.platforms('posix')
def test_data_only_cli_freezes_actual_disk_and_emits_canonical_manifest(repository, tmp_path, ext4_tools):
    import sys
    disk, base, head = candidate_disk(repository, tmp_path, ext4_tools)
    raw = subprocess.check_output([sys.executable, '-m', 'native.qemu_guest.qualification_artifacts',
                                   'freeze', '--task-disk', str(disk), '--output', str(tmp_path / 'frozen'),
                                   '--expected-base', base, '--expected-head', head],
                                  timeout=20, text=True)
    record = json.loads(raw)
    assert canonical(record) == raw
    assert record['candidate_head'] == head
    assert load_candidate(record['manifest_path']) == record
    verified = subprocess.check_output([sys.executable, '-m', 'native.qemu_guest.qualification_artifacts',
                                       'verify', '--kind', 'candidate', '--manifest', record['manifest_path']],
                                      timeout=20, text=True)
    assert json.loads(verified) == record


@pytest.mark.platforms('posix')
def test_data_only_cli_builds_canonical_owner_work_devices(repository, tmp_path, ext4_tools):
    import sys
    root, base = repository
    assignment = tmp_path / 'owner-work.json'
    assignment.write_text(canonical(work(base)))
    raw = subprocess.check_output([sys.executable, '-m', 'native.qemu_guest.qualification_artifacts',
                                   'prepare', '--work', str(assignment), '--source', str(root),
                                   '--output', str(tmp_path / 'slot'), '--mke2fs', str(ext4_tools[0])],
                                  timeout=20, text=True)
    record = json.loads(raw)
    assert canonical(record) == raw
    assert verify_slot_devices(record['manifest_path']) == record
    assert record['work_sha256'] == hashlib.sha256(assignment.read_bytes()).hexdigest()


@pytest.mark.platforms('posix')
def test_slot_manifest_size_bound_rejects_valid_oversized_json(repository, tmp_path, ext4_tools):
    root, base = repository
    record = prepare_slot_devices(work(base), root, tmp_path / 'slot', mke2fs=ext4_tools[0])
    path = Path(record['manifest_path'])
    data = json.loads(path.read_text())
    data['untrusted_padding'] = 'x' * 1024**2
    path.chmod(0o600)
    path.write_text(canonical(data))
    with pytest.raises(ValueError, match='manifest_bounds'):
        verify_slot_devices(path)


@pytest.mark.platforms('posix')
def test_candidate_rejects_oversized_valid_ext4_device(repository, tmp_path, ext4_tools):
    root, base = repository
    (root / 'candidate.txt').write_text('actual candidate\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'candidate')
    disk = tmp_path / 'too-large.raw'
    ext4(root, disk, label='Q2OVERBUDGET', mib=128,
         tool=ext4_tools[0], config=ext4_tools[1], owner=1000)
    with pytest.raises(ValueError, match='candidate_bounds'):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
def test_clean_base_is_never_substituted_for_actual_developer_candidate(repository, tmp_path, ext4_tools):
    root, base = repository
    disk = image_tree(root, tmp_path / 'base-only.raw', ext4_tools, 'Q2BASEONLY')
    with pytest.raises(ValueError, match='actual_candidate'):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)


@pytest.mark.platforms('posix')
def test_reviewer_requires_actual_candidate_head_not_original_base(repository, tmp_path, ext4_tools):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools)
    candidate = freeze_candidate(disk, tmp_path / 'frozen', expected_base=base)
    with pytest.raises(ValueError, match='candidate_mismatch'):
        prepare_slot_devices(work(base, 'reviewer', 2), candidate['snapshot_path'], tmp_path / 'wrong-head',
                             mke2fs=ext4_tools[0], parent_candidate=candidate['manifest_path'])
    assert not (tmp_path / 'wrong-head').exists()


@pytest.mark.platforms('posix')
def test_actual_candidate_must_descend_from_owner_expected_base(repository, tmp_path, ext4_tools):
    root, base = repository
    git(root, 'checkout', '--orphan', 'unrelated')
    (root / 'other.txt').write_text('unrelated history\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'unrelated')
    unrelated = git(root, 'rev-parse', 'HEAD')
    git(root, 'checkout', '--detach', base)
    (root / 'candidate.txt').write_text('candidate\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'candidate')
    disk = image_tree(root, tmp_path / 'actual.raw', ext4_tools, 'Q2ANCESTRY')
    with pytest.raises(subprocess.CalledProcessError):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=unrelated)


@pytest.mark.platforms('posix')
def test_candidate_does_not_replace_wrong_actual_contents_with_expected_fixture(repository, tmp_path, ext4_tools):
    disk, base, _head = candidate_disk(repository, tmp_path, ext4_tools)
    with pytest.raises(ValueError, match='required_content_missing'):
        freeze_candidate(disk, tmp_path / 'frozen', expected_base=base,
                         required_files={'qualification/result.txt': b'different required actual result\n'})
