"""Unprivileged archive assembly and deterministic ext4/newc image construction."""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import copy
import posixpath
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import uuid
import zipfile

EPOCH = 1795268786
POLICY = {
    'uid': 1000, 'gid': 1000, 'network_devices': [], 'host_mounts': [],
    'root_readonly': True, 'assignment_readonly': True, 'reviewer_task_readonly': True,
    'tmpfs_mib': {'run': 128, 'tmp': 64, 'home': 64, 'outbox': 32, 'log': 16},
    'core_dump_bytes': 0, 'max_open_files': 128, 'max_processes': 64,
    'max_file_bytes': 16 * 1024 * 1024, 'no_new_privs': True,
}


def policy_header():
    lines = [f'#define Q2_UID {POLICY["uid"]}', f'#define Q2_GID {POLICY["gid"]}']
    for name, size in POLICY['tmpfs_mib'].items():
        mode = '0755' if name == 'run' else ('1777' if name == 'tmp' else '0700')
        user = '' if name in ('run', 'tmp') else f',uid={POLICY["uid"]},gid={POLICY["gid"]}'
        lines.append(f'#define Q2_{name.upper()}_OPTIONS "size={size}m{user},mode={mode}"')
    for name, field in (('CORE', 'core_dump_bytes'), ('FDS', 'max_open_files'),
                        ('PROCESSES', 'max_processes'), ('FILE', 'max_file_bytes')):
        lines.append(f'#define Q2_{name}_LIMIT {POLICY[field]}')
    return '\n'.join(lines) + '\n'


def inside(root, name):
    """Resolve existing parents before any write, including archive symlinks."""
    root = Path(root).resolve()
    part = PurePosixPath(name)
    if part.is_absolute() or '..' in part.parts:
        raise ValueError('archive_path_escape')
    target = root.joinpath(*part.parts)
    if not target.resolve().is_relative_to(root):
        raise ValueError('archive_symlink_escape')
    return target


def write_member(root, member, data):
    target = inside(root, member.name)
    target.parent.mkdir(parents=True, exist_ok=True)
    if member.isdir():
        target.mkdir(exist_ok=True)
        target.chmod(member.mode & 0o777)
    elif member.issym():
        # Linux absolute links refer to Guest /, never to Host /.
        link = member.linkname
        referent_name = link.lstrip('/') if link.startswith('/') else str(
            PurePosixPath(member.name).parent / link)
        referent = inside(root, posixpath.normpath(referent_name))
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            raise ValueError('archive_link_collision')
        target.symlink_to(os.path.relpath(referent, target.parent))
    elif member.isreg():
        if target.is_symlink():
            raise ValueError('archive_file_over_symlink:' + member.name)
        target.write_bytes(data)
        target.chmod(member.mode & 0o777)
    else:
        raise ValueError('archive_special_file_rejected')


def extract_tar(archive, root, *, strip_prefix=''):
    """Never invoke target maintainer scripts; materialize hardlinks as copies."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:*') as stream:
        members = stream.getmembers()
        for original_member in members:
            member = copy.copy(original_member)
            name = member.name.removeprefix('./')
            if name in ('', '.'):
                continue
            if strip_prefix:
                if not name.startswith(strip_prefix):
                    raise ValueError('unexpected_archive_prefix')
                name = name[len(strip_prefix):]
                if not name:
                    continue
            member.name = name
            if member.islnk():
                original = stream.getmember(member.linkname)
                if not original.isreg():
                    raise ValueError('archive_hardlink_target')
                member.type = tarfile.REGTYPE
                member.size = original.size
                data = stream.extractfile(original).read()
            else:
                data = stream.extractfile(member).read() if member.isreg() else b''
            write_member(root, member, data)


def deb_data(archive):
    raw = Path(archive).read_bytes()
    if raw[:8] != b'!<arch>\n':
        raise ValueError('invalid_deb_archive')
    offset = 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if header[58:60] != b'`\n':
            raise ValueError('invalid_ar_member')
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip('/')
        offset += 60
        data = raw[offset:offset + size]
        if name.startswith('data.tar.'):
            return data
        offset += size + size % 2
    raise ValueError('missing_deb_data')


def extract_wheel(path, site):
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            if name.endswith('/'):
                continue
            if name.endswith('.pth'):
                raise ValueError('wheel_startup_injection_not_allowed')
            if '.data/' in name:
                _, category, name = name.split('/', 2)
                if category not in ('purelib', 'platlib'):
                    raise ValueError('unsupported_wheel_data')
            target = inside(site, name)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('wheel_symlink_not_allowed')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
            target.chmod(((info.external_attr >> 16) & 0o777) or 0o644)


def normalize_tree(root):
    root = Path(root)
    for path in [*sorted(root.rglob('*')), root]:
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)


def newc(root):
    """Stable metadata; only explicitly supplied files are placed in initramfs."""
    root = Path(root)
    result = bytearray()
    for inode, path in enumerate([root, *sorted(root.rglob('*')), None], 1):
        if path is None:
            name, mode, data = 'TRAILER!!!', 0, b''
        else:
            name = '.' if path == root else path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            data = os.readlink(path).encode() if path.is_symlink() else (
                path.read_bytes() if path.is_file() else b'')
        encoded = name.encode() + b'\0'
        fields = (inode, mode, 0, 0, 1, EPOCH, len(data), 0, 0, 0, 0, len(encoded), 0)
        result.extend(b'070701' + ''.join(f'{value:08x}' for value in fields).encode() + encoded)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as stream:
        stream.write(result)
    return output.getvalue()


def normalize_inodes(path, *, owner):
    """No mount/chown: normalize copied ownership/timestamps without checksums.

    This follows the already reproduced Q1 filesystem contract. Metadata checksum
    is deliberately absent; SHA256 authenticates the complete raw artifact.
    """
    with Path(path).open('r+b') as image:
        image.seek(1024)
        superblock = image.read(1024)
        if int.from_bytes(superblock[100:104], 'little') & 0x400:
            raise ValueError('unsupported_metadata_checksum')
        size = int.from_bytes(superblock[88:90], 'little')
        per_group = int.from_bytes(superblock[40:44], 'little')
        count = int.from_bytes(superblock[:4], 'little')
        descriptor_size = int.from_bytes(superblock[254:256], 'little')
        for inode_number in range(count):
            image.seek(4096 + inode_number // per_group * descriptor_size)
            descriptor = image.read(descriptor_size)
            table = int.from_bytes(descriptor[8:12], 'little') | (
                int.from_bytes(descriptor[40:44], 'little') << 32)
            offset = table * 4096 + inode_number % per_group * size
            image.seek(offset)
            inode = bytearray(image.read(size))
            if not any(inode[:2]):
                continue
            for index in (2, 24):
                inode[index:index + 2] = owner.to_bytes(2, 'little')
            for index in (120, 122):
                inode[index:index + 2] = b'\0\0'
            for index in (8, 12, 16, 144):
                inode[index:index + 4] = EPOCH.to_bytes(4, 'little')
            for index in (132, 136, 140, 148):
                inode[index:index + 4] = b'\0\0\0\0'
            image.seek(offset)
            image.write(inode)


def ext4(tree, output, *, label, mib, tool, config, owner=0):
    if Path(output).exists():
        raise ValueError('new_image_required')
    normalize_tree(tree)
    identity = str(uuid.uuid5(uuid.NAMESPACE_URL, 'hermes:q2:' + label))
    with Path(output).open('xb') as image:
        image.truncate(mib * 1024**2)
    env = {'PATH': '/usr/bin:/bin', 'MKE2FS_CONFIG': str(config),
           'E2FSPROGS_FAKE_TIME': str(EPOCH), 'SOURCE_DATE_EPOCH': str(EPOCH),
           'TZ': 'UTC', 'LC_ALL': 'C'}
    command = [str(tool), '-t', 'ext4', '-F', '-b', '4096', '-m', '0',
               '-U', identity, '-L', label, '-O', '^has_journal',
               '-E', 'lazy_itable_init=0,hash_seed=' + identity + ',root_owner=0:0',
               '-d', str(tree), str(output), str(mib * 256)]
    subprocess.run(command, env=env, check=True, timeout=300, capture_output=True)
    normalize_inodes(output, owner=owner)
    return {'argv': command, 'tool_sha256': hashlib.sha256(Path(tool).read_bytes()).hexdigest(),
            'uuid': identity, 'bytes': Path(output).stat().st_size}
