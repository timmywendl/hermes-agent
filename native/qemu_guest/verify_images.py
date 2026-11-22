"""Read-only ext4 inspection using a pinned external build tool, never a mount.

dissect.extfs is an external AGPL build-verification tool. It is not included in
the Guest or added to the Hermes runtime dependency set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import stat
import struct
import uuid

from native.qemu_guest.artifact_inventory import ARTIFACTS, file_record, role_image
from native.qemu_guest.artifact_fs import POLICY
from native.qemu_guest.build_inputs import SOURCE_HEAD, canonical, digest


def stream_digest(stream):
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return result.hexdigest()


def walk(node, prefix=''):
    for child in node.iterdir():
        if child.filename in ('.', '..', 'lost+found'):
            continue
        path = prefix + '/' + child.filename
        yield path, child
        if child.filetype == stat.S_IFDIR:
            yield from walk(child, path)


def disk_inventory(path, *, owner):
    from dissect.extfs import ExtFS
    records = {}
    with Path(path).open('rb') as image:
        fs = ExtFS(image)
        root = fs.get('/')
        if root.inode.i_uid != owner or root.inode.i_gid != owner:
            raise ValueError('disk_root_owner_mismatch')
        for name, node in walk(root):
            if node.inode.i_uid != owner or node.inode.i_gid != owner:
                raise ValueError('disk_owner_mismatch:' + name)
            if node.inode.i_mode & 0o6000:
                raise ValueError('disk_privileged_file:' + name)
            key = name.lstrip('/')
            if node.filetype == stat.S_IFREG:
                with node.open() as stream:
                    records[key] = {'sha256': stream_digest(stream), 'size': node.size,
                                    'mode': oct(stat.S_IMODE(node.inode.i_mode))}
            elif node.filetype == stat.S_IFLNK:
                records[key] = {'link': node.link}
            elif node.filetype != stat.S_IFDIR:
                raise ValueError('disk_special_file:' + name)
    return records


def compare_tree(records, expected):
    expected = {row['path']: {key: value for key, value in row.items() if key != 'path'}
                for row in expected}
    if records != expected:
        mismatched = sorted(key for key in set(records) | set(expected) if records.get(key) != expected.get(key))
        raise ValueError('disk_tree_mismatch:' + ','.join(mismatched[:10]))


def filesystem_metadata(path):
    with Path(path).open('rb') as image:
        image.seek(1024)
        data = image.read(1024)
    if len(data) != 1024 or struct.unpack_from('<H', data, 56)[0] != 0xef53:
        raise ValueError('ext4_superblock_required')
    return {'uuid': str(uuid.UUID(bytes=data[104:120])),
            'label': data[120:136].split(b'\0', 1)[0].decode(),
            'block_size': 1024 << struct.unpack_from('<I', data, 24)[0],
            'bytes': Path(path).stat().st_size}


def git_head(fs):
    head = fs.get('/.git/HEAD').open().read(256).decode().strip()
    if head.startswith('ref: '):
        reference = head[5:]
        if not re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+', reference) or '..' in Path(reference).parts:
            raise ValueError('private_git_reference_required')
        head = fs.get('/.git/' + reference).open().read(256).decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('exact_git_head_required')
    return head


def verify_manifest(directory):
    directory = Path(directory).resolve()
    for name in ('manifest.json', 'SHA256SUMS', 'build-facts.json', 'root-content-inventory.json',
                 'artifact-inputs.lock.json', 'sbom.spdx.json', 'provenance.json',
                 'developer.manifest.json', 'reviewer.manifest.json'):
        file_record(directory / name)
    manifest = json.loads((directory / 'manifest.json').read_text())
    if (directory / 'manifest.json').read_text() != canonical(manifest):
        raise ValueError('noncanonical_package_manifest')
    if canonical(manifest['policy']) != canonical(POLICY):
        raise ValueError('image_policy_changed')
    if (manifest['runtime_source_head'] != SOURCE_HEAD or manifest['boot'] != 'NOT_RUN'
            or manifest['worker_execution'] != 'NOT_RUN'):
        raise ValueError('source_or_qualification_mismatch')
    for name, expected in manifest['metadata_sha256'].items():
        if name not in ('build-facts.json', 'root-content-inventory.json', 'artifact-inputs.lock.json',
                        'sbom.spdx.json', 'provenance.json') or digest(directory / name) != expected:
            raise ValueError('package_metadata_changed')
    if len(manifest['metadata_sha256']) != 5 or len(manifest['artifacts']) != len(ARTIFACTS):
        raise ValueError('exact_package_metadata_required')
    inventory = {row['name']: row for row in manifest['artifacts']}
    if set(inventory) != set(ARTIFACTS):
        raise ValueError('exact_artifact_inventory_required')
    identities = set()
    for name, expected in inventory.items():
        observed = dict(file_record(directory / name), name=name)
        if observed != expected:
            raise ValueError('artifact_binding_changed:' + name)
        identities.add((observed['st_dev'], observed['st_ino']))
    if len(identities) != len(inventory):
        raise ValueError('artifact_alias')
    expected_sums = ''.join(inventory[name]['sha256'] + '  ' + name + '\n' for name in ARTIFACTS)
    if (directory / 'SHA256SUMS').read_text() != expected_sums:
        raise ValueError('checksum_inventory_mismatch')
    facts = json.loads((directory / 'build-facts.json').read_text())
    for role in ('developer', 'reviewer'):
        image = role_image(directory, role, facts['task_fixture_head'])
        stored = directory / (role + '.manifest.json')
        if (stored.read_text() != image.manifest_json
                or digest(stored) != manifest['roles'][role]['sha256']
                or image.device_args(3) != manifest['roles'][role]['qemu_argv_data_only']):
            raise ValueError('role_manifest_changed:' + role)
    return manifest


def verify_startup_directory(fs, role):
    """Offline build contract, not proof that PID1 reached this directory."""
    name = '.hermes-q2-startup-v1'
    entries = {node.filename for node in fs.get('/').iterdir()}
    if role == 'reviewer':
        if name in entries:
            raise ValueError('reviewer_startup_directory_forbidden')
        return 'ABSENT'
    if name not in entries:
        raise ValueError('developer_startup_directory_required')
    node = fs.get('/' + name)
    if (node.filetype != stat.S_IFDIR or node.inode.i_uid != 1000 or node.inode.i_gid != 1000 or
            stat.S_IMODE(node.inode.i_mode) != 0o700 or
            any(child.filename not in ('.', '..') for child in node.iterdir())):
        raise ValueError('developer_startup_directory_invalid')
    return 'PREPROVISIONED_EMPTY_1000_1000_0700'


def verify_content(directory):
    from dissect.extfs import ExtFS
    directory = Path(directory).resolve()
    expected = json.loads((directory / 'root-content-inventory.json').read_text())
    compare_tree(disk_inventory(directory / 'root.raw', owner=0), expected['files'])
    facts = json.loads((directory / 'build-facts.json').read_text())
    devices = {'root': ('root.raw', 'Q2ROOT'),
               'developer_task': ('developer-task.raw', 'Q2DEV'),
               'reviewer_task': ('reviewer-task.raw', 'Q2REVIEW'),
               'developer_assignment': ('developer-assignment.raw', 'Q2DEVASSIGN'),
               'reviewer_assignment': ('reviewer-assignment.raw', 'Q2REVASSIGN')}
    for name, (filename, label) in devices.items():
        observed = filesystem_metadata(directory / filename)
        if observed != {'uuid': facts['images'][name]['uuid'], 'label': label,
                        'block_size': 4096, 'bytes': facts['images'][name]['bytes']}:
            raise ValueError('filesystem_metadata_mismatch:' + name)
    reports = {}
    for role in ('developer', 'reviewer'):
        task = disk_inventory(directory / (role + '-task.raw'), owner=1000)
        assignment = disk_inventory(directory / (role + '-assignment.raw'), owner=0)
        if set(assignment) != {'policy', 'work.json'}:
            raise ValueError('exact_assignment_files_required')
        if ('.git/HEAD' not in task or 'sha256' not in task['.git/HEAD']
                or any(name in task for name in ('.git', '.git/commondir', '.git/gitdir', '.git/objects/info/alternates'))):
            raise ValueError('independent_git_metadata_required')
        with (directory / (role + '-task.raw')).open('rb') as stream:
            task_fs = ExtFS(stream)
            if facts.get('startup_directory', {}).get('developer_preprovisioned'):
                verify_startup_directory(task_fs, role)
            if git_head(task_fs) != facts['task_fixture_head']:
                raise ValueError('task_device_head_mismatch')
        with (directory / (role + '-assignment.raw')).open('rb') as stream:
            fs = ExtFS(stream)
            policy = fs.get('/policy').open().read()
            work = json.loads(fs.get('/work.json').open().read())
        if policy != (role + '\n').encode() or work['role'] != role or work['base_commit'] != facts['task_fixture_head']:
            raise ValueError('assignment_role_or_head_mismatch')
        if work['assignment']['session_id'] != 'OFFLINE_BUILD_ONLY':
            raise ValueError('offline_assignment_required')
        reports[role] = {'task_files': len(task), 'assignment_role': role, 'owner': 1000}
    return {'root_files': len(expected['files']), 'roles': reports,
            'inspection': 'READ_ONLY_EXT4_PARSER; no target code or filesystem mount',
            'boot': 'NOT_RUN', 'worker_execution': 'NOT_RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    verify_manifest(args.directory)
    print(canonical(verify_content(args.directory)))


if __name__ == '__main__':
    main()
