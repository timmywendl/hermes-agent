"""Static Q2 artifact verification and local manifest/SBOM/provenance emission."""
from __future__ import annotations

import json
import hashlib
import posixpath
import os
import argparse
import subprocess
from pathlib import Path
import re
import stat
import struct

from native.qemu_guest.artifact_fs import EPOCH, POLICY
from native.qemu_guest.build_inputs import SOURCE_HEAD, canonical, digest
from native.qemu_guest.image_contract import GuestImage

ARTIFACTS = ('kernel.Image', 'initramfs.cpio.gz', 'root.raw', 'developer-task.raw',
             'reviewer-task.raw', 'developer-assignment.raw', 'reviewer-assignment.raw')
PRIVATE_KEY = re.compile(rb'-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----\r?\n'
                         rb'([A-Za-z0-9+/=\r\n]+)-----END \1-----')


def public_vectors(name, data):
    matches = list(PRIVATE_KEY.finditer(data))
    if not matches:
        return []
    public = json.loads((Path(__file__).parent / 'public-selftest-vectors.json').read_text())
    allowed = {row['sha256'] for row in public['keys']}
    if (name != 'usr/lib/aarch64-linux-gnu/libgnutls.so.30.40.3'
            or hashlib.sha256(data).hexdigest() != public['vendor_library_sha256']
            or any(hashlib.sha256(match[0]).hexdigest() not in allowed for match in matches)):
        raise ValueError('private_key_in_guest:' + name)
    return [hashlib.sha256(match[0]).hexdigest() for match in matches]


def file_record(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('artifact_regular_single_link_required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    if (any(getattr(info, key) != getattr(before, key) or getattr(before, key) != getattr(after, key)
            or getattr(after, key) != getattr(path.lstat(), key) for key in fields)):
        raise ValueError('artifact_identity_changed')
    return {'path': str(path.resolve()), 'sha256': value, 'size': info.st_size,
            'st_dev': info.st_dev, 'st_ino': info.st_ino}


def elf_needed(data):
    if data[:4] != b'\x7fELF':
        return None
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('unsupported_elf')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    if header[2] != 183:
        raise ValueError('non_arm64_elf')
    offset, size, count = header[6], header[11], header[12]
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + index * size)
                for index in range(count)]
    needed = []
    for section in sections:
        if section[1] != 6:  # SHT_DYNAMIC
            continue
        strings = sections[section[6]]
        table = data[strings[4]:strings[4] + strings[5]]
        for index in range(section[4], section[4] + section[5], 16):
            tag, value = struct.unpack_from('<qQ', data, index)
            if tag == 1:
                needed.append(table[value:].split(b'\0', 1)[0].decode())
    return needed


def verify_tree(root):
    root = Path(root).resolve()
    records, elf, vectors = [], {}, {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if not path.resolve().is_relative_to(root):
            raise ValueError('guest_tree_link_escape:' + name)
        if path.is_symlink():
            records.append({'path': name, 'link': str(path.readlink())})
            continue
        if not path.is_file():
            continue
        info = path.stat()
        if info.st_mode & 0o6000:
            raise ValueError('privileged_guest_file:' + name)
        if any(part in ('.ssh', '.aws', '.hermes', '.netrc', '.env') for part in path.relative_to(root).parts):
            raise ValueError('host_configuration_in_guest:' + name)
        data = path.read_bytes()
        if data.startswith(b'SQLite format 3\0'):
            raise ValueError('canonical_database_in_guest:' + name)
        keys = public_vectors(name, data)
        if keys:
            vectors[name] = keys
        needed = elf_needed(data)
        if needed is not None:
            elf[name] = needed
        records.append({'path': name, 'sha256': digest(path), 'size': info.st_size,
                        'mode': oct(stat.S_IMODE(info.st_mode))})
    present = {row['path'] for row in records}
    basenames = {Path(name).name for name in present}
    missing = []
    for binary, needed in elf.items():
        for library in needed:
            if '/' in library:
                path = library.replace('$ORIGIN', str(Path(binary).parent))
                found = posixpath.normpath(path).lstrip('/') in present
            else:
                found = library in basenames
            if not found:
                missing.append(binary + ':' + library)
    if missing:
        raise ValueError('missing_elf_dependencies:' + ','.join(missing))
    for forbidden in ('root/.ssh', 'etc/ssh', 'etc/systemd/system', 'var/lib/hermes', 'root/.hermes'):
        if (root / forbidden).exists():
            raise ValueError('unexpected_guest_service_or_state:' + forbidden)
    return {'files': records, 'arm64_elf': elf, 'public_vendor_selftest_vectors': vectors,
            'credential_inventory': 'NO_UNKNOWN_PRIVATE_KEYS_SSH_KEYS_OR_HOST_CONFIG_FOUND',
            'limitations': 'Static content/ELF inventory only; not an import/boot/OS isolation qualification'}


def role_image(directory, role, head):
    directory = Path(directory).resolve()
    names = ('kernel.Image', 'initramfs.cpio.gz', 'root.raw', role + '-task.raw', role + '-assignment.raw')
    files = [directory / name for name in names]
    hashes = {str(path): digest(path) for path in files}
    devices = {}
    for name, path in zip(('root', 'task', 'assignment'), files[2:]):
        info = path.stat()
        devices[name] = {'path': str(path), 'sha256': hashes[str(path)],
                         'readonly': name != 'task' or role == 'reviewer',
                         'st_dev': info.st_dev, 'st_ino': info.st_ino}
    manifest = {'role': role, 'workspace': {'kind': 'directory_snapshot', 'mount': '/task',
                'head': head, 'role': role, 'readonly': role == 'reviewer', 'host_share': False},
                'devices': devices}
    encoded = canonical(manifest).rstrip('\n')
    image = GuestImage(*files, hashes, role, encoded)
    image.verify()
    return image


def spdx(lock, artifacts):
    packages = []
    for row in lock['inputs']:
        packages.append({
            'SPDXID': 'SPDXRef-' + row['kind'] + '-' + re.sub(r'[^A-Za-z0-9.-]', '-', row['name']),
            'name': row['name'], 'versionInfo': row['version'],
            'downloadLocation': row['url'], 'filesAnalyzed': False,
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': row['sha256']}],
            'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
            'copyrightText': 'NOASSERTION',
        })
    packages.append({'SPDXID': 'SPDXRef-hermes', 'name': 'hermes-agent',
                     'versionInfo': SOURCE_HEAD, 'downloadLocation': 'NOASSERTION',
                     'filesAnalyzed': False, 'licenseConcluded': 'MIT', 'licenseDeclared': 'MIT',
                     'copyrightText': 'NOASSERTION'})
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'Hermes-Q2-offline-candidate',
            'documentNamespace': 'https://hermes.invalid/spdx/q2/' + hashlib.sha256(
                canonical([{key: row[key] for key in ('name', 'sha256', 'size')} for row in artifacts]).encode()).hexdigest(),
            'creationInfo': {'created': '2026-11-21T13:46:26Z', 'creators': ['Tool: hermes-q2-offline-packager-v1']},
            'packages': packages,
            'files': [{'SPDXID': 'SPDXRef-artifact-' + str(index), 'fileName': row['name'],
                       'checksums': [{'algorithm': 'SHA256', 'checksumValue': row['sha256']}],
                       'licenseConcluded': 'NOASSERTION', 'licenseInfoInFiles': ['NOASSERTION'],
                       'copyrightText': 'NOASSERTION'}
                      for index, row in enumerate(artifacts)],
            'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                               'relatedSpdxElement': 'SPDXRef-hermes'}]}


def emit(directory, lock, *, builder_head):
    directory = Path(directory).resolve()
    facts = json.loads((directory / 'build-facts.json').read_text())
    inventory = [dict(file_record(directory / name), name=name) for name in ARTIFACTS]
    identities = {(row['st_dev'], row['st_ino']) for row in inventory}
    if len(identities) != len(inventory):
        raise ValueError('artifact_alias')
    manifests = {}
    for role in ('developer', 'reviewer'):
        image = role_image(directory, role, facts['task_fixture_head'])
        (directory / (role + '.manifest.json')).write_text(image.manifest_json)
        manifests[role] = {'sha256': digest(directory / (role + '.manifest.json')),
                           'qemu_argv_data_only': image.device_args(3)}
    manifest = {'schema': 'HERMES_Q2_ARTIFACT_PACKAGE_V1', 'runtime_source_head': SOURCE_HEAD,
                'builder_source_head': builder_head, 'source_date_epoch': EPOCH,
                'input_lock_sha256': facts['input_lock_sha256'], 'artifacts': inventory,
                'roles': manifests, 'policy': POLICY, 'boot': 'NOT_RUN', 'worker_execution': 'NOT_RUN',
                'assignment': 'OFFLINE_BUILD_ONLY; no real Owner admission or execution grant'}
    (directory / 'SHA256SUMS').write_text(''.join(row['sha256'] + '  ' + row['name'] + '\n' for row in inventory))
    (directory / 'sbom.spdx.json').write_text(canonical(spdx(lock, inventory)))
    provenance = {'_type': 'https://in-toto.io/Statement/v1',
        'subject': [{'name': row['name'], 'digest': {'sha256': row['sha256']}} for row in inventory],
        'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {'buildDefinition': {'buildType': 'https://hermes.invalid/build/q2-offline-v1',
            'externalParameters': {'builder_source_head': builder_head, 'runtime_source_head': SOURCE_HEAD},
            'internalParameters': facts, 'resolvedDependencies': [
                {'uri': row['url'], 'digest': {'sha256': row['sha256']}} for row in lock['inputs']]},
            'runDetails': {'builder': {'id': 'hermes-local-unprivileged-offline-packager-v1'},
                           'metadata': {'invocationId': lock['uv_lock_sha256']}}}}
    (directory / 'provenance.json').write_text(canonical(provenance))
    (directory / 'artifact-inputs.lock.json').write_text(canonical(lock))
    metadata = ('build-facts.json', 'root-content-inventory.json', 'artifact-inputs.lock.json',
                'sbom.spdx.json', 'provenance.json')
    manifest['metadata_sha256'] = {name: digest(directory / name) for name in metadata}
    (directory / 'manifest.json').write_text(canonical(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--root-tree', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], env=env, timeout=30):
        raise ValueError('clean_builder_head_required')
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], env=env, text=True, timeout=30).strip()
    lock = json.loads((source / 'native/qemu_guest/artifact-inputs.lock.json').read_text())
    report = verify_tree(args.root_tree)
    (args.directory / 'root-content-inventory.json').write_text(canonical(report))
    emit(args.directory, lock, builder_head=head)
    print(canonical({'builder_source_head': head, 'manifest_sha256': digest(args.directory / 'manifest.json'),
                     'boot': 'NOT_RUN', 'worker_execution': 'NOT_RUN'}))


if __name__ == '__main__':
    main()
