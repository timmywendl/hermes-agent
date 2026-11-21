"""Offline-only build recipe; explicit preverified sources, no QEMU execution."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent
QEMU_SHA256 = '5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22'


def run(argv, *, cwd=None):
    subprocess.run([str(p) for p in argv], cwd=cwd, check=True, timeout=1800)


def initramfs(binary):
    if (binary[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', binary, 18)[0] != 183
            or struct.unpack_from('<H', binary, 16)[0] != 2):
        raise ValueError('static_aarch64_executable_required')
    result = bytearray()
    entries = [('dev', 0o40755, b''), ('proc', 0o40755, b''), ('sys', 0o40755, b''),
               ('init', 0o100755, binary), ('TRAILER!!!', 0, b'')]
    for inode, (name, mode, data) in enumerate(entries, 1):
        encoded = name.encode() + b'\0'
        fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
        result.extend(b'070701' + ''.join(f'{n:08x}' for n in fields).encode() + encoded)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as stream:
        stream.write(result)
    return output.getvalue()


def build(args):
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != QEMU_SHA256:
        raise ValueError('qemu_archive_digest_mismatch')
    if (args.source / 'VERSION').read_text().strip() != '11.1.3':
        raise ValueError('qemu_version_mismatch')
    args.output.mkdir(parents=True, exist_ok=False)
    # Apply to a fresh source tree extracted from the signature-verified archive.
    run(['patch', '-p1', '-i', HERE / 'qemu-candidate.patch'], cwd=args.source)
    objects = []
    for name, source in [('admission', 'admission_gate.c'), ('sandbox', 'sandbox_canary.m'),
                         ('keychain', 'legacy_keychain_canary.m')]:
        obj = args.output / (name + '.o')
        flags = ['-fobjc-arc'] if source.endswith('.m') else []
        run(['xcrun', 'clang', *flags, '-Wall', '-Wextra', '-Werror', '-DHERMES_HVF_EMBEDDED',
             '-c', HERE / source, '-o', obj])
        objects.append(obj)
    guest = args.output / 'serial-init'
    run([args.zig, 'cc', '-target', 'aarch64-linux-musl', '-ffreestanding', '-fno-stack-protector',
         '-fno-builtin', '-nostdlib', '-static', '-O2', '-Wl,-e,_start', HERE / 'guest_init.c', '-o', guest])
    (args.output / 'serial-initramfs.cpio.gz').write_bytes(initramfs(guest.read_bytes()))
    link = ' '.join(str(p) for p in objects) + ' -framework Foundation -framework Security -framework LocalAuthentication'
    run([args.source / 'configure', '--target-list=aarch64-softmmu', '--enable-hvf', '--disable-tcg',
         '--without-default-features', '--enable-fdt=internal', '--disable-tools', '--disable-docs',
         '--disable-user', '--disable-install-blobs', '--disable-download',
         '--python=' + str(args.python), '--ninja=' + str(args.ninja), '--extra-ldflags=' + link], cwd=args.output)
    run([args.ninja, 'qemu-system-aarch64'], cwd=args.output)
    receipt = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [*objects, guest, args.output / 'serial-initramfs.cpio.gz', args.output / 'qemu-system-aarch64']}
    (args.output / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'source', 'output', 'python', 'ninja', 'zig'):
        parser.add_argument('--' + name, type=Path, required=True)
    build(parser.parse_args())


if __name__ == '__main__':
    main()
