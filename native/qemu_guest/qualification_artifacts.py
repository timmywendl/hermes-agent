"""Finite Q2 fixture devices and actual stopped-disk candidate snapshots.

No Guest, mount, QEMU or Agent is executed. Ext4 is parsed read-only using the
accepted build verifier; the original seven artifacts are never mutated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from agent.runtime_session_guest import validate_guest_work
from gateway.session_guest_workspace import prepare_workspace
from native.qemu_guest.artifact_fs import ext4
from native.qemu_guest.artifact_inventory import file_record, verify_tree
from native.qemu_guest.build_artifacts import (
    MKE2FS_CONFIG, STARTUP_DIRECTORY, STARTUP_STAGES, private_git_snapshot,
)
from native.qemu_guest.build_inputs import canonical
from native.qemu_guest.image_contract import GuestImage
from native.qemu_guest.verify_images import git_head

MKE2FS_SHA256 = 'e1cb9ae14ce0cee376e9237e9134387adea7e8c5f13d957752bbe18039d830b8'
MAX_FILES = 4096
MAX_FILE_BYTES = 16 * 1024**2
MAX_TREE_BYTES = 64 * 1024**2
MAX_MANIFEST_BYTES = 1024**2


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _git(root, *args, binary=False):
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_OPTIONAL_LOCKS': '0'}
    value = subprocess.check_output(['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null',
                                     '-c', 'core.fsmonitor=false', '-c', 'core.attributesFile=/dev/null',
                                     *args], env=env, timeout=30, stderr=subprocess.PIPE)
    return value if binary else value.decode().strip()


def _new_output(source, output):
    source = Path(source).resolve(strict=True)
    output = Path(output).resolve(strict=False)
    common = Path(_git(source, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
    root = Path(_git(source, 'rev-parse', '--show-toplevel'))
    protected = (root, common, common.parent if common.name == '.git' else common)
    if any(output.is_relative_to(path) for path in protected) or output.exists():
        raise ValueError('q2_new_private_output_required')
    output.mkdir(parents=True, mode=0o700)
    return output


def _tool_config(output, tool, config):
    tool = Path(tool).resolve(strict=True)
    if file_record(tool)['sha256'] != MKE2FS_SHA256:
        raise ValueError('q2_build_tool_changed')
    if config is not None and Path(config).read_text() != MKE2FS_CONFIG:
        raise ValueError('q2_build_config_changed')
    fixed = output / 'mke2fs.conf'
    fixed.write_text(MKE2FS_CONFIG)
    return tool, fixed


def _write_manifest(output, name, record):
    path = output / name
    encoded = canonical(record)
    if len(encoded.encode()) > MAX_MANIFEST_BYTES:
        raise ValueError('q2_manifest_bounds')
    with path.open('x') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)
    return record | {'manifest_path': str(path), 'manifest_sha256': _digest(encoded.encode())}


def _read_manifest(path, schema):
    info = file_record(path)
    if info['size'] > MAX_MANIFEST_BYTES:
        raise ValueError('q2_manifest_bounds')
    raw = Path(path).read_text()
    record = json.loads(raw)
    if not isinstance(record, dict) or canonical(record) != raw or record.get('schema') != schema:
        raise ValueError('q2_manifest_unavailable')
    return record | {'manifest_path': str(Path(path).resolve()), 'manifest_sha256': info['sha256']}


def startup_receipt(raw):
    """Untrusted Guest numbers, never Worker completion or retirement evidence."""
    if not isinstance(raw, bytes) or not 0 < len(raw) < 160:
        raise ValueError('q2_startup_receipt_bounds')
    record = json.loads(raw)
    fields = {'errno', 'exception', 'exit_code', 'signal', 'stage', 'version'}
    if (not isinstance(record, dict) or set(record) != fields or
            any(type(value) is not int for value in record.values()) or
            canonical(record).encode() != raw or record['version'] != 1 or
            record['stage'] not in STARTUP_STAGES.values() or
            not 0 <= record['errno'] <= 4095 or not 0 <= record['exception'] <= 8 or
            not -1 <= record['exit_code'] <= 255 or not 0 <= record['signal'] <= 64 or
            (record['exit_code'] == -1) != (record['signal'] > 0)):
        raise ValueError('q2_startup_receipt_invalid')
    return record


def _startup_node(node, *, directory=False):
    expected = stat.S_IFDIR if directory else stat.S_IFREG
    if (node.filetype != expected or node.inode.i_uid != 1000 or node.inode.i_gid != 1000 or
            stat.S_IMODE(node.inode.i_mode) != (0o700 if directory else 0o600) or
            (not directory and (node.inode.i_links_count != 1 or not 0 < node.size < 160))):
        raise ValueError('q2_startup_node_invalid')


def inspect_startup(manifest, *, expected_manifest_sha256):
    """Data-only post-stop inspection; caller must establish exact wait first."""
    from dissect.extfs import ExtFS
    record = _read_manifest(manifest, 'HERMES_Q2_SLOT_DEVICES_V1')
    if (record['manifest_sha256'] != expected_manifest_sha256 or
            record['role'] not in ('developer', 'reviewer')):
        raise ValueError('q2_startup_manifest_changed')
    disk = record['task']
    before = file_record(disk['path'])
    if any(before[key] != disk[key] for key in ('st_dev', 'st_ino', 'size')):
        raise ValueError('q2_startup_device_changed')
    result = {'authority': 'UNTRUSTED_GUEST_DIAGNOSTIC_ONLY', 'retirement_proof': False,
              'status': 'UNKNOWN', 'reason': 'NO_DURABLE_RECEIPT', 'task': before,
              'scope': record['scope']}
    with os.fdopen(os.open(disk['path'], os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        fs = ExtFS(stream)
        names = {entry.filename for entry in fs.get('/').iterdir()}
        if STARTUP_DIRECTORY in names:
            if record['role'] != 'developer':
                raise ValueError('q2_reviewer_diagnostic_forbidden')
            directory = fs.get('/' + STARTUP_DIRECTORY)
            _startup_node(directory, directory=True)
            if {entry.filename for entry in directory.iterdir() if entry.filename not in ('.', '..')} != {'receipt.json'}:
                raise ValueError('q2_startup_incomplete_or_extra_files')
            node = fs.get('/' + STARTUP_DIRECTORY + '/receipt.json')
            _startup_node(node)
            with node.open() as source:
                receipt = startup_receipt(source.read(160))
            result.update(status='OBSERVED_UNTRUSTED', reason=None, receipt=receipt)
    if file_record(disk['path']) != before:
        raise ValueError('q2_startup_device_changed')
    return result


def prepare_slot_devices(work, source, output, *, mke2fs, config=None, parent_candidate=None):
    """Build private ext4 task and assignment devices from original Owner work.

    Reviewer inputs must be the validated actual prior candidate. The caller
    remains responsible for proving that its original VM has physically stopped.
    """
    work = validate_guest_work(work)
    parent = None
    if work['role'] == 'reviewer':
        if parent_candidate is None:
            raise ValueError('q2_actual_candidate_required')
        parent = load_candidate(parent_candidate)
        if (Path(source).resolve() != Path(parent['snapshot_path'])
                or work['base_commit'] != parent['candidate_head']):
            raise ValueError('q2_reviewer_candidate_mismatch')
    elif parent_candidate is not None:
        raise ValueError('q2_developer_candidate_forbidden')
    output = _new_output(source, output)
    tool, fixed = _tool_config(output, mke2fs, config)
    workspace = prepare_workspace(source, output / 'task-tree',
                                  head=work['base_commit'], role=work['role'])
    if (workspace.root / STARTUP_DIRECTORY).exists() or any(
            name == STARTUP_DIRECTORY or name.startswith(STARTUP_DIRECTORY + '/')
            for name in _tree_files(workspace.root, workspace.head)):
        raise ValueError('q2_reserved_startup_path')
    private_git_snapshot(workspace.root)
    if work['role'] == 'developer':
        exclude = workspace.root / '.git/info/exclude'
        exclude.parent.mkdir(exist_ok=True)
        with exclude.open('a') as stream:
            stream.write('\n/' + STARTUP_DIRECTORY + '/\n')
    verify_tree(workspace.root)
    assignment = output / 'assignment-tree'
    assignment.mkdir()
    encoded = canonical(work)
    (assignment / 'work.json').write_text(encoded)
    (assignment / 'policy').write_text(work['role'] + '\n')
    tag = _digest(canonical(work['assignment']).encode())[:10].upper()
    role = 'D' if work['role'] == 'developer' else 'R'
    task, assign = output / 'task.raw', output / 'assignment.raw'
    task_facts = ext4(workspace.root, task, label='Q2' + role + tag, mib=64,
                       tool=tool, config=fixed, owner=1000)
    assignment_facts = ext4(assignment, assign, label='Q2A' + tag, mib=16,
                             tool=tool, config=fixed, owner=1000)
    record = {'schema': 'HERMES_Q2_SLOT_DEVICES_V1', 'scope': work['assignment'],
              'role': work['role'], 'head': workspace.head, 'task': file_record(task),
              'assignment': file_record(assign), 'work_sha256': _digest(encoded.encode()),
              'workspace': workspace.device_contract(), 'task_fs': task_facts,
              'assignment_fs': assignment_facts,
              'parent_candidate_sha256': parent['manifest_sha256'] if parent else None}
    return _write_manifest(output, 'slot-devices.json', record)


def verify_slot_devices(path):
    record = _read_manifest(path, 'HERMES_Q2_SLOT_DEVICES_V1')
    identities = set()
    for name in ('task', 'assignment'):
        stored = record[name]
        observed = file_record(stored['path'])
        if observed != stored:
            raise ValueError('q2_slot_device_changed')
        identities.add((observed['st_dev'], observed['st_ino']))
    if len(identities) != 2:
        raise ValueError('q2_slot_device_alias')
    if record['role'] not in ('developer', 'reviewer') or record['workspace'] != {
            'kind': 'directory_snapshot', 'mount': '/task', 'head': record['head'],
            'role': record['role'], 'readonly': record['role'] == 'reviewer', 'host_share': False}:
        raise ValueError('q2_slot_workspace_changed')
    return record


def slot_image(record, *, kernel, initramfs, root):
    path = record['manifest_path'] if isinstance(record, dict) else record
    record = verify_slot_devices(path)
    paths = {name: Path(value).absolute() for name, value in {
        'kernel': kernel, 'initramfs': initramfs, 'root': root,
        'task': record['task']['path'], 'assignment': record['assignment']['path']}.items()}
    inventory = {name: file_record(path) for name, path in paths.items()}
    devices = {name: {'path': row['path'], 'sha256': row['sha256'],
                      'st_dev': row['st_dev'], 'st_ino': row['st_ino'],
                      'readonly': name != 'task' or record['role'] == 'reviewer'}
               for name, row in inventory.items() if name in ('root', 'task', 'assignment')}
    manifest = {'role': record['role'], 'workspace': record['workspace'], 'devices': devices}
    return GuestImage(**paths, sha256={str(paths[name]): row['sha256'] for name, row in inventory.items()},
                      role=record['role'], manifest_json=canonical(manifest).rstrip('\n'))


def _safe_name(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or not path.parts or len(path.parts) > 32 or len(name.encode()) > 1024 or any(part in ('.', '..') for part in path.parts)
            or any(c in name for c in '\0\n\r') or str(path) != name):
        raise ValueError('q2_candidate_path_invalid')
    return path


def _disk_files(task_disk):
    """Read bounded regular files; no symlink, hardlink, mount or special device."""
    from dissect.extfs import ExtFS
    from native.qemu_guest.verify_images import walk
    if Path(task_disk).lstat().st_size > MAX_TREE_BYTES:
        raise ValueError('q2_candidate_bounds')
    before = file_record(task_disk)
    records, contents = {}, {}
    with os.fdopen(os.open(task_disk, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        fs = ExtFS(stream)
        root = fs.get('/')
        if root.inode.i_uid != 1000 or root.inode.i_gid != 1000:
            raise ValueError('q2_candidate_owner_invalid')
        head = git_head(fs)
        total, nodes = 0, 0
        diagnostic_present = diagnostic_recorded = False
        for name, node in walk(fs.get('/')):
            nodes += 1
            if nodes > MAX_FILES:
                raise ValueError('q2_candidate_bounds')
            name = name.lstrip('/')
            _safe_name(name)
            if name == STARTUP_DIRECTORY:
                _startup_node(node, directory=True)
                diagnostic_present = True
                continue
            if name.startswith(STARTUP_DIRECTORY + '/'):
                if name != STARTUP_DIRECTORY + '/receipt.json':
                    raise ValueError('q2_startup_incomplete_or_extra_files')
                _startup_node(node)
                with node.open() as source:
                    startup_receipt(source.read(160))
                diagnostic_recorded = True
                continue
            if node.inode.i_uid != 1000 or node.inode.i_gid != 1000 or node.inode.i_mode & 0o6000:
                raise ValueError('q2_candidate_owner_invalid')
            if node.filetype == stat.S_IFDIR:
                continue
            if (node.filetype != stat.S_IFREG or node.inode.i_links_count != 1
                    or node.inode.i_mode & 0o6000 or node.size > MAX_FILE_BYTES):
                raise ValueError('q2_candidate_file_invalid')
            total += node.size
            if len(records) >= MAX_FILES or total > MAX_TREE_BYTES:
                raise ValueError('q2_candidate_bounds')
            with node.open() as source:
                data = source.read(MAX_FILE_BYTES + 1)
            if len(data) != node.size:
                raise ValueError('q2_candidate_file_truncated')
            records[name] = {'sha256': _digest(data), 'size': len(data),
                             'mode': '100755' if node.inode.i_mode & 0o111 else '100644'}
            contents[name] = data
    if diagnostic_present != diagnostic_recorded:
        raise ValueError('q2_startup_incomplete_or_extra_files')
    if file_record(task_disk) != before:
        raise ValueError('q2_candidate_disk_changed')
    return before, head, records, contents


def _objects(snapshot, contents):
    _git(snapshot, 'init', '-q', '--template=')
    for name, data in contents.items():
        if re.fullmatch(r'\.git/objects/(?:[0-9a-f]{2}/[0-9a-f]{38}|pack/pack-[0-9a-f]{40}\.(?:pack|idx))', name):
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    shallow = contents.get('.git/shallow')
    if shallow is not None:
        if not re.fullmatch(rb'(?:[0-9a-f]{40}\n)+', shallow):
            raise ValueError('q2_candidate_shallow_invalid')
        (snapshot / '.git/shallow').write_bytes(shallow)
    if any(name in contents for name in ('.git/objects/info/alternates', '.git/commondir')):
        raise ValueError('q2_candidate_shared_objects')


def _tree_files(snapshot, head):
    records = {}
    for entry in _git(snapshot, 'ls-tree', '-rz', '--full-tree', head, binary=True).split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, identity = header.decode().split()
        name = name.decode()
        _safe_name(name)
        if name == STARTUP_DIRECTORY or name.startswith(STARTUP_DIRECTORY + '/'):
            raise ValueError('q2_reserved_startup_path')
        if mode not in ('100644', '100755') or kind != 'blob':
            raise ValueError('q2_candidate_git_file_invalid')
        data = _git(snapshot, 'cat-file', 'blob', identity, binary=True)
        records[name] = {'sha256': _digest(data), 'size': len(data), 'mode': mode}
    return records


def _content_digest(records):
    return _digest(canonical(records).encode())


def _snapshot_record(snapshot, head):
    records = _tree_files(snapshot, head)
    actual = {}
    for path in snapshot.rglob('*'):
        if '.git' in path.relative_to(snapshot).parts or path.is_dir():
            continue
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise ValueError('q2_candidate_snapshot_alias')
        name = path.relative_to(snapshot).as_posix()
        actual[name] = {'sha256': file_record(path)['sha256'], 'size': path.stat().st_size,
                        'mode': '100755' if path.stat().st_mode & 0o111 else '100644'}
    if actual != records:
        raise ValueError('q2_candidate_snapshot_changed')
    return records



def _snapshot_inventory(snapshot):
    result = {}
    for path in sorted(snapshot.rglob('*')):
        if path.is_symlink():
            raise ValueError('q2_candidate_snapshot_alias')
        if path.is_dir():
            continue
        name = path.relative_to(snapshot).as_posix()
        if path.stat().st_size > MAX_FILE_BYTES or len(result) >= MAX_FILES:
            raise ValueError('q2_candidate_bounds')
        row = file_record(path)
        result[name] = {'sha256': row['sha256'], 'size': row['size'],
                        'mode': stat.S_IMODE(path.stat().st_mode)}
    return result


def freeze_candidate(task_disk, output, *, expected_base, expected_head=None, required_files=None):
    """Freeze the real stopped Developer disk; preserve its exact Git commit."""
    if not re.fullmatch(r'[0-9a-f]{40}', expected_base):
        raise ValueError('q2_candidate_base_required')
    disk, head, records, contents = _disk_files(Path(task_disk).absolute())
    if head == expected_base or (expected_head is not None and expected_head != head):
        raise ValueError('q2_actual_candidate_required')
    output = Path(output).resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    snapshot = output / 'snapshot'
    snapshot.mkdir(mode=0o700)
    _objects(snapshot, contents)
    _git(snapshot, 'fsck', '--strict', '--no-reflogs', head)
    _git(snapshot, 'merge-base', '--is-ancestor', expected_base, head)
    tree_records = _tree_files(snapshot, head)
    actual = {name: row for name, row in records.items() if not name.startswith('.git/')}
    if actual != tree_records:
        raise ValueError('q2_candidate_worktree_not_committed')
    for name, data in (required_files or {}).items():
        if contents.get(name) != data:
            raise ValueError('q2_candidate_required_content_missing')
    _git(snapshot, 'checkout', '--detach', head)
    if _git(snapshot, 'rev-parse', 'HEAD') != head:
        raise ValueError('q2_candidate_commit_changed')
    _snapshot_record(snapshot, head)
    verify_tree(snapshot)
    common = Path(_git(snapshot, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
    if common.resolve() != snapshot / '.git':
        raise ValueError('q2_candidate_shared_objects')
    for path in sorted(snapshot.rglob('*'), reverse=True):
        path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
    snapshot.chmod(0o555)
    record = {'schema': 'HERMES_Q2_CANDIDATE_V1', 'snapshot_path': str(snapshot),
              'expected_base': expected_base, 'candidate_head': head,
              'candidate_tree': _git(snapshot, 'rev-parse', head + '^{tree}'),
              'source_disk': disk, 'content': tree_records,
              'snapshot_inventory': _snapshot_inventory(snapshot),
              'content_manifest_sha256': _content_digest(tree_records)}
    return _write_manifest(output, 'candidate.json', record)


def load_candidate(path):
    record = _read_manifest(path, 'HERMES_Q2_CANDIDATE_V1')
    if file_record(record['source_disk']['path']) != record['source_disk']:
        raise ValueError('q2_candidate_disk_changed')
    snapshot = Path(record['snapshot_path'])
    if snapshot.resolve(strict=True) != snapshot or snapshot.is_symlink():
        raise ValueError('q2_candidate_snapshot_alias')
    if _snapshot_inventory(snapshot) != record['snapshot_inventory']:
        raise ValueError('q2_candidate_snapshot_changed')
    common = Path(_git(snapshot, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
    if (common.resolve() != snapshot / '.git' or _git(snapshot, 'rev-parse', 'HEAD') != record['candidate_head']
            or _git(snapshot, 'rev-parse', 'HEAD^{tree}') != record['candidate_tree']):
        raise ValueError('q2_candidate_snapshot_changed')
    records = _snapshot_record(snapshot, record['candidate_head'])
    if records != record['content'] or _content_digest(records) != record['content_manifest_sha256']:
        raise ValueError('q2_candidate_snapshot_changed')
    return record


def _prepare_command(args):
    if file_record(args.work)['size'] > MAX_MANIFEST_BYTES:
        raise ValueError('q2_manifest_bounds')
    raw = args.work.read_text()
    work = json.loads(raw)
    if raw not in (canonical(work), canonical(work).rstrip('\\n')):
        raise ValueError('q2_work_not_canonical')
    return prepare_slot_devices(work, args.source, args.output, mke2fs=args.mke2fs,
                                parent_candidate=args.parent_candidate)


def main():
    """Data-only build boundary: no Owner, admission, process or VM authority."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    freeze = commands.add_parser('freeze')
    freeze.add_argument('--task-disk', type=Path, required=True)
    freeze.add_argument('--output', type=Path, required=True)
    freeze.add_argument('--expected-base', required=True)
    freeze.add_argument('--expected-head')
    prepare = commands.add_parser('prepare')
    for field in ('work', 'source', 'output', 'mke2fs'):
        prepare.add_argument('--' + field, type=Path, required=True)
    prepare.add_argument('--parent-candidate', type=Path)
    verify = commands.add_parser('verify')
    verify.add_argument('--manifest', type=Path, required=True)
    verify.add_argument('--kind', choices=('candidate', 'slot'), required=True)
    startup = commands.add_parser('inspect-startup')
    startup.add_argument('--manifest', type=Path, required=True)
    startup.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args()
    operations = {
        'inspect-startup': lambda: inspect_startup(args.manifest,
            expected_manifest_sha256=args.expected_manifest_sha256),
        'freeze': lambda: freeze_candidate(args.task_disk, args.output,
                                           expected_base=args.expected_base,
                                           expected_head=args.expected_head),
        'prepare': lambda: _prepare_command(args),
        'verify': lambda: {'candidate': load_candidate, 'slot': verify_slot_devices}[args.kind](args.manifest),
    }
    encoded = canonical(operations[args.command]())
    if len(encoded.encode()) > 2 * MAX_MANIFEST_BYTES:
        raise ValueError('q2_manifest_bounds')
    print(encoded, end='')


if __name__ == '__main__':
    main()
