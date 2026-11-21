"""Q2-only image/device plan. Produces argv data; never executes QEMU.

The accepted Q1 inert initramfs and disk are not Worker images. Native APPLY must
freeze/sign a separate Q2 package with this serial/device plan and its SBOM.
"""
from dataclasses import dataclass
import hashlib
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

    def __post_init__(self):
        object.__setattr__(self, 'sha256', MappingProxyType(dict(self.sha256)))

    def verify(self):
        files = (self.kernel, self.initramfs, self.root, self.task, self.assignment)
        if self.role not in ('developer', 'reviewer') or len({p.resolve() for p in files}) != 5:
            raise ValueError('q2_distinct_artifacts_required')
        if set(self.sha256) != {str(p) for p in files}:
            raise ValueError('q2_exact_inventory_required')
        for path in files:
            expected = self.sha256[str(path)]
            if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or not re.fullmatch(r'[0-9a-f]{64}', expected)
                    or path.stat().st_size > 8 * 1024**3
                    or any(c in str(path) for c in ',\n\r\x00')):
                raise ValueError('q2_artifact_invalid')
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError('q2_artifact_changed')

    def device_args(self, serial_fd):
        self.verify()
        if type(serial_fd) is not int or serial_fd < 3:
            raise ValueError('q2_inherited_serial_required')
        result = ['-nodefaults', '-display', 'none', '-monitor', 'none', '-qmp', 'stdio',
                  '-chardev', f'socket,id=worker,fd={serial_fd}', '-serial', 'chardev:worker',
                  '-nic', 'none', '-accel', 'hvf', '-machine', 'virt', '-cpu', 'host',
                  '-smp', '2', '-m', '2048', '-no-reboot',
                  '-kernel', str(self.kernel), '-initrd', str(self.initramfs),
                  # UART is exclusively binary Worker RPC. Kernel/init output must
                  # never interleave with frames (unlike Q1's diagnostic console).
                  '-append', 'console=tty0 root=/dev/vda ro rdinit=/init panic=-1']
        for name, path, readonly in [('root', self.root, True), ('task', self.task, self.role == 'reviewer'),
                                     ('assignment', self.assignment, True)]:
            result.extend(['-drive', f'file={path},format=raw,if=none,id={name},readonly={"on" if readonly else "off"}',
                           '-device', f'virtio-blk-pci,drive={name}'])
        return result
