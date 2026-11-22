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
        assert set(devices.fds) == {'root', 'task', 'assignment', 'task_ro'}
        assert descriptors['task']['ro_fd'] == devices.fds['task_ro']
        for name, fd in devices.fds.items():
            assert (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) == (os.O_RDWR if name == 'task' else os.O_RDONLY)
        os.lseek(devices.fds['task'], 3, os.SEEK_SET)
        args = devices.device_args(serial.fileno())
        assert os.lseek(devices.fds['task'], 0, os.SEEK_CUR) == 3
        assert args.count('-add-fd') == 4
        assert 'file=/dev/fdset/2,format=raw,if=none,id=task,readonly=off' in args
        assert str(image.task) not in args
        assert 'file=/dev/fdset/1,format=raw,if=none,id=root,readonly=on' in args
        assert 'file=/dev/fdset/3,format=raw,if=none,id=assignment,readonly=on' in args
        assert args[args.index('-nic') + 1] == 'none'
        from native.qemu_guest.qualification_package import qemu_argv
        projected = qemu_argv(image.kernel.parent, descriptors, serial.fileno(), image.role)
        assert args[args.index('-add-fd'):] == projected[projected.index('-add-fd'):]
        assert f'fd={devices.fds["task_ro"]},set=2' in args
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
        assert set(devices.fds) == {'root', 'task', 'assignment'}
        assert 'ro_fd' not in devices.descriptors()['task']
        devices.verify()
        serial, peer = socket.socketpair()
        with serial, peer:
            args = devices.device_args(serial.fileno())
        assert 'file=/dev/fdset/2,format=raw,if=none,id=task,readonly=on' in args
        assert args.count('-add-fd') == 3


@pytest.mark.platforms('posix')
def test_developer_task_two_independent_handles_have_real_kernel_permissions(tmp_path):
    import errno
    import fcntl
    image = inert_image(tmp_path)
    with image.open_devices() as devices:
        assert 'task_ro' in devices.fds
        rw, ro = devices.fds['task'], devices.fds['task_ro']
        assert rw != ro
        assert (os.fstat(rw).st_dev, os.fstat(rw).st_ino, os.fstat(rw).st_size) == (
            os.fstat(ro).st_dev, os.fstat(ro).st_ino, os.fstat(ro).st_size)
        assert fcntl.fcntl(ro, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert not os.get_inheritable(ro) and not os.get_inheritable(rw)
        os.lseek(rw, 3, os.SEEK_SET)
        assert os.lseek(ro, 0, os.SEEK_CUR) == 0
        devices.verify()
        assert os.lseek(rw, 0, os.SEEK_CUR) == 3
        with pytest.raises(OSError) as refused:
            os.pwrite(ro, b'x', 0)
        assert refused.value.errno == errno.EBADF
        assert os.pwrite(rw, os.pread(rw, 1, 0), 0) == 1
        inherited = devices.pass_fds
        assert len(inherited) == 4 and ro in inherited and rw in inherited
    for fd in inherited:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('damage', ['missing', 'alias', 'writable', 'inode', 'size'])
def test_developer_readonly_handle_rejects_changed_capability(tmp_path, damage):
    image = inert_image(tmp_path)
    with image.open_devices() as devices:
        original = devices.fds['task_ro']
        saved_identity = devices.identities['task_ro']
        foreign = tmp_path / 'foreign'
        foreign.write_bytes(image.task.read_bytes())
        replacement = os.open(image.task if damage == 'writable' else foreign,
                              os.O_RDWR if damage == 'writable' else os.O_RDONLY)
        try:
            identity = list(saved_identity)
            identity[2] += 1
            operations = {
                'missing': lambda: devices.fds.pop('task_ro'),
                'alias': lambda: devices.fds.update(task_ro=devices.fds['task']),
                'size': lambda: devices.identities.update(task_ro=tuple(identity)),
                'writable': lambda: devices.fds.update(task_ro=replacement),
                'inode': lambda: devices.fds.update(task_ro=replacement),
            }
            operations[damage]()
            with pytest.raises(ValueError):
                devices.verify()
        finally:
            devices.fds['task_ro'] = original
            devices.identities['task_ro'] = saved_identity
            os.close(replacement)


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


def qemu_unit_function(source, signature):
    """Compile the pinned upstream function unchanged, not a rewritten matcher."""
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


@pytest.fixture
def pinned_qemu_fdset_unit(tmp_path):
    import tarfile
    from native.qemu_guest.qualification_package import QEMU_SHA256
    archive = Path('/Users/timmywen/Documents/AI_Colleague/evidence/'
                   'pr15-qemu-hvf-feasibility-20261121/downloads/qemu-11.1.3.tar.xz')
    if not archive.is_file():
        pytest.skip('Fixed upstream QEMU source archive unavailable for inert FD-set unit')
    with archive.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == QEMU_SHA256
    with tarfile.open(archive) as bundle:
        sources = {name: bundle.extractfile('qemu-11.1.3/' + name).read().decode()
                   for name in ('monitor/fds.c', 'util/osdep.c', 'include/qemu/queue.h')}
    monitor, queue = sources['monitor/fds.c'], sources['include/qemu/queue.h']
    license_text = monitor[:monitor.index('#include')]
    lists = queue[queue.index('#define QLIST_HEAD('):queue.index('/*\n * Singly-linked List definitions.')]
    types = monitor[monitor.index('/* file descriptor associated'):monitor.index('static bool monitor_add_fd(')]
    shims = '''
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
typedef int QemuMutex;
typedef void Error;
typedef struct {int64_t fdset_id; int fd;} AddfdInfo;
#define QEMU_LOCK_GUARD(pointer) ((void)(pointer))
#define QERR_INVALID_PARAMETER_VALUE "%s %s"
#define g_malloc0(size) calloc(1,size)
#define qemu_dup(fd) dup(fd)
static char *g_strdup(const char *value){return value?strdup(value):NULL;}
static void error_setg(Error **error,const char *format,...){(void)error;(void)format;}
'''
    functions = '\n'.join([
        qemu_unit_function(sources['util/osdep.c'], 'int qemu_dup_flags('),
        qemu_unit_function(monitor, 'AddfdInfo *monitor_fdset_add_fd('),
        qemu_unit_function(monitor, 'int monitor_fdset_dup_fd_add(')])
    driver = r'''
int main(int argc,char **argv) {
    if(argc!=4)return 71;
    int first=atoi(argv[1]), second=atoi(argv[2]);
    const char *mode=argv[3]; Error *error=NULL;
    int set=strcmp(mode,"wrong-set")==0?3:2;
    if(strcmp(mode,"dual-reverse")==0) {
        if(!monitor_fdset_add_fd(second,true,set,NULL,&error))return 72;
        if(!monitor_fdset_add_fd(first,true,set,NULL,&error))return 73;
    } else {
        if(!monitor_fdset_add_fd(first,true,set,NULL,&error))return 74;
        if(strcmp(mode,"dual")==0 && !monitor_fdset_add_fd(second,true,set,NULL,&error))return 75;
    }
    errno=0; int ro=monitor_fdset_dup_fd_add(2,O_RDONLY,&error);int ro_error=errno;
    errno=0; int rw=monitor_fdset_dup_fd_add(2,O_RDWR,&error);int rw_error=errno;
    struct stat left={0},right={0};
    bool same=ro>=0 && rw>=0 && !fstat(ro,&left) && !fstat(rw,&right) &&
        left.st_dev==right.st_dev && left.st_ino==right.st_ino && left.st_size==right.st_size;
    char byte=0; bool denied=false,writable=false;
    if(ro>=0){pread(ro,&byte,1,0);errno=0;denied=pwrite(ro,&byte,1,0)==-1 && errno==EBADF;}
    if(rw>=0){pread(rw,&byte,1,0);writable=pwrite(rw,&byte,1,0)==1;}
    printf("{\"ro\":%d,\"rw\":%d,\"ro_errno\":%d,\"rw_errno\":%d,"
           "\"ro_mode\":%d,\"rw_mode\":%d,\"same_inode_size\":%d,"
           "\"ro_write_rejected\":%d,\"rw_write_accepted\":%d}\n",
           ro,rw,ro_error,rw_error,ro>=0?(fcntl(ro,F_GETFL)&O_ACCMODE):-1,
           rw>=0?(fcntl(rw,F_GETFL)&O_ACCMODE):-1,same,denied,writable);
    if(ro>=0)close(ro);if(rw>=0)close(rw);
    return 0;
}
'''
    source = tmp_path / 'pinned-fdset-unit.c'
    source.write_text(license_text + shims + lists + types + functions + driver)
    binary = tmp_path / 'pinned-fdset-unit'
    subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', source, '-o', binary],
                   check=True, capture_output=True, timeout=30)
    return binary


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('mode', ['dual', 'dual-reverse', 'single-rw', 'readonly', 'wrong-set'])
def test_pinned_qemu_fdset_production_matcher_uses_real_modes(tmp_path, pinned_qemu_fdset_unit, mode):
    import errno
    image = inert_image(tmp_path, 'reviewer' if mode == 'readonly' else 'developer')
    with image.open_devices() as devices:
        primary, ro = devices.fds['task'], devices.fds.get('task_ro', -1)
        fds = (primary, ro) if ro >= 0 else (primary,)
        result = subprocess.run([pinned_qemu_fdset_unit, str(primary), str(ro), mode],
                                pass_fds=fds, capture_output=True, text=True, check=True, timeout=5)
        report = json.loads(result.stdout)
    if mode.startswith('dual'):
        assert report['ro'] >= 0 and report['rw'] >= 0
        assert report['ro_mode'] == os.O_RDONLY and report['rw_mode'] == os.O_RDWR
        assert report['same_inode_size'] == report['ro_write_rejected'] == report['rw_write_accepted'] == 1
    elif mode == 'single-rw':
        assert report['ro'] == -1 and report['ro_errno'] == errno.EACCES
        assert report['rw'] >= 0 and report['rw_mode'] == os.O_RDWR
    elif mode == 'readonly':
        assert report['ro'] >= 0 and report['ro_mode'] == os.O_RDONLY and report['ro_write_rejected'] == 1
        assert report['rw'] == -1 and report['rw_errno'] == errno.EACCES
    else:
        assert report['ro'] == report['rw'] == -1
        assert report['ro_errno'] == report['rw_errno'] == errno.ENOENT
