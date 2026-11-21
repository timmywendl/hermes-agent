"""Q2-only image/device plan. Produces argv data; never executes QEMU.

The accepted Q1 inert initramfs and disk are not Worker images. Native APPLY must
freeze/sign a separate Q2 package with this serial/device plan and its SBOM.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import stat
from pathlib import Path
import re
from types import MappingProxyType


@dataclass(frozen=True)
class GuestImage:
    kernel: Path
    initramfs: Path
    root: Path
    task: Path
    assignment: Path
    sha256: dict
    role: str
    manifest_json: str

    def __post_init__(self):
        object.__setattr__(self, 'sha256', MappingProxyType(dict(self.sha256)))

    def verify(self):
        files = (self.kernel, self.initramfs, self.root, self.task, self.assignment)
        if self.role not in ('developer', 'reviewer') or len({p.resolve() for p in files}) != 5:
            raise ValueError('q2_distinct_artifacts_required')
        if set(self.sha256) != {str(p) for p in files}:
            raise ValueError('q2_exact_inventory_required')
        identities = set()
        for path in files:
            expected = self.sha256[str(path)]
            if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or not re.fullmatch(r'[0-9a-f]{64}', expected)
                    or path.stat().st_size > 8 * 1024**3
                    or any(c in str(path) for c in ',\n\r\x00')):
                raise ValueError('q2_artifact_invalid')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                observed = os.fstat(stream.fileno())
                identity = (observed.st_dev, observed.st_ino)
                if observed.st_nlink != 1 or identity in identities or not stat.S_ISREG(observed.st_mode):
                    raise ValueError('q2_artifact_inode_alias')
                identities.add(identity)
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
                if (any(getattr(observed, key) != getattr(after, key) for key in fields)
                        or identity != (path.stat().st_dev, path.stat().st_ino)):
                    raise ValueError('q2_artifact_identity_changed')
            if digest.hexdigest() != expected:
                raise ValueError('q2_artifact_changed')
        self._verify_manifest()

    def _verify_manifest(self):
        manifest = json.loads(self.manifest_json)
        if (not isinstance(manifest, dict) or set(manifest) != {'role', 'workspace', 'devices'}
                or json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False) != self.manifest_json
                or manifest['role'] != self.role):
            raise ValueError('q2_manifest_role_mismatch')
        workspace = manifest['workspace']
        if not isinstance(workspace, dict):
            raise ValueError('q2_manifest_workspace_mismatch')
        expected_workspace = {'kind': 'directory_snapshot', 'mount': '/task', 'head': workspace.get('head'),
                              'role': self.role, 'readonly': self.role == 'reviewer', 'host_share': False}
        if (json.dumps(workspace, sort_keys=True) != json.dumps(expected_workspace, sort_keys=True) or not isinstance(workspace.get('head'), str)
                or not re.fullmatch(r'[0-9a-f]{40}', workspace['head'])):
            raise ValueError('q2_manifest_workspace_mismatch')
        expected = {}
        for name, path in (('root', self.root), ('task', self.task), ('assignment', self.assignment)):
            info = path.stat()
            expected[name] = {'path': str(path), 'sha256': self.sha256[str(path)],
                              'readonly': name != 'task' or self.role == 'reviewer',
                              'st_dev': info.st_dev, 'st_ino': info.st_ino}
        if json.dumps(manifest['devices'], sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError('q2_manifest_device_mismatch')

    def device_args(self, serial_fd):
        self.verify()
        if type(serial_fd) is not int or serial_fd < 3:
            raise ValueError('q2_inherited_serial_required')
        result = self._base_args(serial_fd)
        for name, path, readonly in [('root', self.root, True), ('task', self.task, self.role == 'reviewer'),
                                     ('assignment', self.assignment, True)]:
            result.extend(['-drive', f'file={path},format=raw,if=none,id={name},readonly={"on" if readonly else "off"}',
                           '-device', f'virtio-blk-pci,drive={name}'])
        return result

    def open_devices(self):
        return OwnedDevices(self)

    def _base_args(self, serial_fd):
        return ['-nodefaults', '-display', 'none', '-monitor', 'none', '-qmp', 'stdio',
                  '-chardev', f'socket,id=worker,fd={serial_fd}', '-serial', 'chardev:worker',
                  '-nic', 'none', '-accel', 'hvf', '-machine', 'virt', '-cpu', 'host',
                  '-smp', '2', '-m', '2048', '-no-reboot',
                  '-kernel', str(self.kernel), '-initrd', str(self.initramfs),
                  # UART is exclusively binary Worker RPC. Kernel/init output must
                  # never interleave with frames (unlike Q1's diagnostic console).
                  '-append', 'console=tty0 root=/dev/vda ro rdinit=/init panic=-1']


class OwnedDevices:
    """Original Owner's exact preopened device capabilities, never path authority.

    Verification uses pread, preserving file offsets shared with QEMU fdsets. The
    Owner must verify immediately before Popen and again before release; after a
    Developer starts writing, a new post-stop inventory is a different receipt.
    """

    def __init__(self, image):
        image.verify()
        self.image = image
        self.fds = {}
        self.identities = {}
        self.closed = False
        try:
            for name in ('root', 'task', 'assignment'):
                path = getattr(image, name)
                mode = os.O_RDWR if name == 'task' and image.role == 'developer' else os.O_RDONLY
                fd = os.open(path, mode | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.fds[name] = fd
                self.identities[name] = self._identity(os.fstat(fd))
            self.verify()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, info.st_nlink)

    @property
    def pass_fds(self):
        return tuple(self.fds.values())

    def verify(self):
        import fcntl
        if self.closed or set(self.fds) != {'root', 'task', 'assignment'}:
            raise ValueError('q2_device_capability_closed')
        self.image.verify()
        identities = set()
        for name, fd in self.fds.items():
            info = os.fstat(fd)
            path = getattr(self.image, name)
            expected_mode = os.O_RDWR if name == 'task' and self.image.role == 'developer' else os.O_RDONLY
            mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
            identity = self._identity(info)
            if (mode != expected_mode or identity != self.identities[name]
                    or identity != self._identity(path.lstat()) or info.st_nlink != 1
                    or not stat.S_ISREG(info.st_mode) or identity[:2] in identities):
                raise ValueError('q2_device_capability_changed')
            identities.add(identity[:2])
            digest = hashlib.sha256()
            offset = 0
            while chunk := os.pread(fd, 1024 * 1024, offset):
                digest.update(chunk)
                offset += len(chunk)
            if (digest.hexdigest() != self.image.sha256[str(path)]
                    or self._identity(os.fstat(fd)) != identity):
                raise ValueError('q2_device_capability_changed')
        return self.descriptors()

    def descriptors(self):
        return {name: {'fd': fd, 'st_dev': self.identities[name][0],
                       'st_ino': self.identities[name][1], 'size': self.identities[name][2],
                       'readonly': name != 'task' or self.image.role == 'reviewer',
                       'sha256': self.image.sha256[str(getattr(self.image, name))]}
                for name, fd in self.fds.items()}

    def device_args(self, serial_fd):
        self.verify()
        if (type(serial_fd) is not int or serial_fd < 3 or serial_fd in self.fds.values()
                or not stat.S_ISSOCK(os.fstat(serial_fd).st_mode)):
            raise ValueError('q2_inherited_serial_required')
        result = self.image._base_args(serial_fd)
        for number, name in enumerate(('root', 'task', 'assignment'), 1):
            readonly = name != 'task' or self.image.role == 'reviewer'
            result.extend(['-add-fd', f'fd={self.fds[name]},set={number}',
                           '-drive', f'file=/dev/fdset/{number},format=raw,if=none,id={name},readonly={"on" if readonly else "off"}',
                           '-device', f'virtio-blk-pci,drive={name}'])
        return result

    def close(self):
        errors = []
        for name, fd in list(self.fds.items()):
            try:
                observed = os.fstat(fd)
                if (observed.st_dev, observed.st_ino) != self.identities[name][:2]:
                    raise ValueError('q2_device_capability_reused')
                os.close(fd)
            except (OSError, ValueError) as error:
                errors.append(error)
            else:
                del self.fds[name]
        self.closed = not self.fds
        if errors:
            raise ValueError('q2_device_capability_close_incomplete') from errors[0]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
