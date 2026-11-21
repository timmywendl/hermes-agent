"""Resolve a finite Linux ARM64 input inventory from existing frozen locks.

This module only reads metadata and downloads bytes. It never installs packages,
executes target code, runs maintainer scripts, mounts images or starts a VM.
"""
from __future__ import annotations

import hashlib
import json
import lzma
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote, urlparse
from urllib.request import urlopen

from packaging.markers import Marker
from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

SOURCE_HEAD = '9a270a78b421565a64901182062b18a0d3b2e673'
HOST_TOOLS = {
    'zig': {'version': '0.15.2', 'sha256': 'c65cd34917923f575448cc0603dd7c2326da0af0e5c323043d090662dcdf351c'},
    'mke2fs': {'version': '1.47.2-android-platform-15.0.0_r5-314-ga1f793f6b',
               'sha256': 'e1cb9ae14ce0cee376e9237e9134387adea7e8c5f13d957752bbe18039d830b8'},
}
Q1_SIGNATURE_PROOF_SHA256 = '664d0ddf6e06d99e21ac0c6645886751fcce8aa472910d69e422cd9d027cf477'
Q1_AUTHENTICATED_INDEX_SHA256 = 'be16b37b2f740f066ea93d35d56f04f94d63693e5a3eb421b052bf86fae75bcd'
DEBIAN_ROOTS = ('git', 'busybox-static', 'libc6', 'libstdc++6', 'bash', 'coreutils',
                'findutils', 'grep', 'sed', 'diffutils', 'tar', 'gzip')
TARGET = {
    'implementation_name': 'cpython', 'implementation_version': '3.14.7',
    'os_name': 'posix', 'platform_machine': 'aarch64',
    'platform_release': '', 'platform_system': 'Linux', 'platform_version': '',
    'python_full_version': '3.14.7', 'platform_python_implementation': 'CPython',
    'python_version': '3.14', 'sys_platform': 'linux', 'extra': '',
}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'


def enabled(marker, extras=()):
    return not marker or any(Marker(marker).evaluate({**TARGET, 'extra': extra})
                             for extra in ('', *extras))


def wheel_tags():
    # Debian13 ARM64 glibc2.41; never select musl, x86 or free-threaded wheels.
    platforms = [f'manylinux_2_{minor}_aarch64' for minor in range(41, 16, -1)]
    platforms += ['manylinux2014_aarch64', 'linux_aarch64']
    return {tag: index for index, tag in enumerate([
        *cpython_tags((3, 14), abis=['cp314'], platforms=platforms),
        *compatible_tags((3, 14), interpreter='cp314', platforms=platforms),
    ])}


def choose_wheel(package):
    supported = wheel_tags()
    candidates = []
    for wheel in package.get('wheels', []):
        name = unquote(urlparse(wheel['url']).path.rsplit('/', 1)[-1])
        tags = parse_wheel_filename(name)[3]
        scores = [supported[tag] for tag in tags if tag in supported]
        if scores:
            candidates.append((min(scores), name, wheel))
    if not candidates:
        raise ValueError('missing_locked_arm64_wheel:' + package['name'])
    _, name, wheel = min(candidates)
    return {'kind': 'wheel', 'name': package['name'], 'version': package['version'],
            'filename': name, 'url': wheel['url'], 'size': wheel['size'],
            'sha256': wheel['hash'].removeprefix('sha256:')}


def python_closure(source):
    lock = tomllib.loads((Path(source) / 'uv.lock').read_text())
    packages = {}
    for package in lock['package']:
        packages.setdefault(canonicalize_name(package['name']), []).append(package)
    pending = [{'name': 'hermes-agent'}]
    selected, visited = {}, set()
    while pending:
        edge = pending.pop()
        if not enabled(edge.get('marker')):
            continue
        name = canonicalize_name(edge['name'])
        matches = [p for p in packages[name]
                   if ('version' not in edge or p['version'] == edge['version'])
                   and ('source' not in edge or p['source'] == edge['source'])]
        if len(matches) != 1:
            raise ValueError('ambiguous_locked_package:' + name)
        package = matches[0]
        key = (name, tuple(sorted(edge.get('extra', []))))
        if key in visited:
            continue
        visited.add(key)
        if name != 'hermes-agent':
            selected[name] = choose_wheel(package)
        pending.extend(package.get('dependencies', []))
        for extra in edge.get('extra', []):
            pending.extend(package.get('optional-dependencies', {}).get(extra, []))
    return [selected[name] for name in sorted(selected)]


def debian_records(packages_xz):
    result = {}
    text = lzma.decompress(Path(packages_xz).read_bytes()).decode()
    for paragraph in text.split('\n\n'):
        record = dict(line.split(': ', 1) for line in paragraph.splitlines()
                      if ': ' in line and not line.startswith(' '))
        if record.get('Architecture') in ('arm64', 'all') and 'Filename' in record:
            result[record['Package']] = record
    return result


def debian_closure(packages_xz):
    records = debian_records(packages_xz)
    providers = {}
    for name, record in sorted(records.items()):
        for provided in filter(None, record.get('Provides', '').split(',')):
            virtual = re.split(r'[\s:(]', provided.strip())[0]
            providers.setdefault(virtual, name)
    pending = list(DEBIAN_ROOTS)
    selected = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        record = records[name]
        selected[name] = {
            'kind': 'deb', 'name': name, 'version': record['Version'],
            'architecture': record['Architecture'], 'filename': Path(record['Filename']).name,
            'url': 'https://deb.debian.org/debian/' + record['Filename'],
            'size': int(record['Size']), 'sha256': record['SHA256'],
            'depends': record.get('Depends', ''), 'pre_depends': record.get('Pre-Depends', ''),
        }
        for field in ('Pre-Depends', 'Depends'):
            for group in filter(None, record.get(field, '').split(',')):
                alternatives = [re.split(r'[\s:(]', item.strip())[0] for item in group.split('|')]
                available = next((item if item in records else providers[item]
                                  for item in alternatives if item in records or item in providers), None)
                if available is None:
                    raise ValueError('unresolved_debian_dependency:' + group)
                pending.append(available)
    return [selected[name] for name in sorted(selected)]


def resolve(source, packages_xz):
    source = Path(source)
    python = json.loads((source / 'pm/lock.json').read_text())['packages']['python']
    runtime = python['artifacts']['linux-arm64']
    q1 = Path(packages_xz).parent.parent
    if (digest(q1 / 'supply-chain-verification.json') != Q1_SIGNATURE_PROOF_SHA256
            or digest(packages_xz) != Q1_AUTHENTICATED_INDEX_SHA256):
        raise ValueError('q1_authenticated_input_envelope_changed')
    record = dict(line.split(': ', 1) for line in (q1 / 'downloads/kernel-package-record.txt').read_text().splitlines()
                  if ': ' in line and not line.startswith(' '))
    signed = debian_records(packages_xz)[record['Package']]
    if any(signed[key] != record[key] for key in ('Version', 'SHA256', 'Filename')):
        raise ValueError('kernel_record_not_in_signed_index')
    kernel = {'kind': 'kernel', 'name': signed['Package'], 'version': signed['Version'],
              'filename': Path(signed['Filename']).name, 'sha256': signed['SHA256'],
              'url': 'https://deb.debian.org/debian/' + signed['Filename'], 'size': int(signed['Size'])}
    modules = json.loads((q1 / 'modules-closure.json').read_text())
    selected = [row for row in modules if row['name'] in ('virtio_blk', 'crc16', 'mbcache', 'jbd2', 'ext4')]
    if len(selected) != 5:
        raise ValueError('exact_kernel_module_closure_required')
    return {
        'schema': 'HERMES_Q2_BUILD_INPUTS_V1', 'source_head': SOURCE_HEAD,
        'target': TARGET, 'uv_lock_sha256': digest(source / 'uv.lock'),
        'host_tools': HOST_TOOLS, 'q1_signature_proof_sha256': Q1_SIGNATURE_PROOF_SHA256,
        'pm_lock_sha256': digest(source / 'pm/lock.json'),
        'debian_packages_sha256': digest(packages_xz),
        'debian_release_sha256': digest(Path(packages_xz).parent / 'Release'),
        'debian_release_signature_sha256': digest(Path(packages_xz).parent / 'Release.gpg'),
        'kernel_payload': {'image': 'boot/vmlinuz-6.12.107+deb13-arm64',
                           'sha256': digest(q1 / 'artifacts/kernel.Image'), 'modules': selected},
        'inputs': [
            {'kind': 'python', 'name': 'cpython', 'version': python['version'],
             'filename': unquote(urlparse(runtime['url']).path.rsplit('/', 1)[-1]), **runtime},
            kernel, *debian_closure(packages_xz), *python_closure(source),
        ],
    }


def fetch(item, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = item['filename']
    if Path(name).name != name or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
        raise ValueError('invalid_locked_download')
    target = directory / name
    if target.exists():
        if target.is_symlink() or digest(target) != item['sha256']:
            raise ValueError('cached_input_changed:' + name)
        return target
    if urlparse(item['url']).scheme != 'https':
        raise ValueError('https_input_required')
    pending = target.with_suffix(target.suffix + '.partial')
    with urlopen(item['url'], timeout=60) as response, pending.open('xb') as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    if digest(pending) != item['sha256'] or (
            'size' in item and pending.stat().st_size != item['size']):
        raise ValueError('download_digest_mismatch:' + name)
    pending.rename(target)
    return target
