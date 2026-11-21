"""Offline Q2 construction/integrity contracts; no ARM64 code or VM is executed."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import struct
import tarfile
import zipfile

import pytest

from native.qemu_guest.artifact_fs import POLICY, extract_tar, extract_wheel, ext4, newc, policy_header
from native.qemu_guest.artifact_inventory import (
    ARTIFACTS, elf_needed, emit, public_vectors, role_image, spdx, verify_tree,
)
from native.qemu_guest.build_artifacts import MKE2FS_CONFIG, private_git_snapshot, require_case_sensitive, verify_tools
from native.qemu_guest.build_inputs import (
    DEBIAN_ROOTS, SOURCE_HEAD, canonical, choose_wheel, debian_closure, digest, fetch, python_closure,
)
from native.qemu_guest.verify_images import compare_tree, disk_inventory, filesystem_metadata, git_head, verify_manifest


def tar_bytes(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if kind == 'dir' else 0o644
            if kind in ('symlink', 'hardlink'):
                info.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                info.linkname = payload
                archive.addfile(info)
            elif kind == 'dir':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


@pytest.mark.parametrize('name', ['../outside', '/outside', 'nested/../inside'])
def test_archive_refuses_path_escape(tmp_path, name):
    with pytest.raises(ValueError, match='archive_path_escape'):
        extract_tar(tar_bytes([(name, 'file', b'bad')]), tmp_path / 'root')
    assert not (tmp_path / 'outside').exists()


def test_archive_copies_hardlinks_and_keeps_safe_internal_symlinks(tmp_path):
    tree = tmp_path / 'root'
    data = tar_bytes([('lib/original', 'file', b'locked'), ('copy', 'hardlink', 'lib/original'),
                      ('lib/link', 'symlink', '../copy'), ('absolute', 'symlink', '/copy')])
    extract_tar(data, tree)
    assert (tree / 'lib/link').read_bytes() == b'locked'
    assert (tree / 'absolute').read_bytes() == b'locked'
    assert (tree / 'copy').stat().st_ino != (tree / 'lib/original').stat().st_ino
    assert (tree / 'copy').stat().st_nlink == 1


@pytest.mark.parametrize('members', [
    [('bad', 'symlink', '../../outside')],
    [('bad', 'symlink', '/safe'), ('bad', 'file', b'overwrite')],
])
def test_archive_refuses_external_link_or_link_overwrite(tmp_path, members):
    with pytest.raises(ValueError, match='archive_'):
        extract_tar(tar_bytes(members), tmp_path / 'root')


def test_archive_refuses_existing_foreign_parent_link(tmp_path):
    tree, foreign = tmp_path / 'root', tmp_path / 'foreign'
    tree.mkdir()
    foreign.mkdir()
    (tree / 'alias').symlink_to(foreign)
    with pytest.raises(ValueError, match='archive_symlink_escape'):
        extract_tar(tar_bytes([('alias/file', 'file', b'inert')]), tree)
    assert not (foreign / 'file').exists()


@pytest.mark.parametrize('name', ['../escape.py', 'injected.pth'])
def test_wheel_refuses_traversal_and_startup_injection(tmp_path, name):
    wheel = tmp_path / 'bad.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        archive.writestr(name, 'import unreviewed_code')
    with pytest.raises(ValueError):
        extract_wheel(wheel, tmp_path / 'site')
    assert not (tmp_path / 'escape.py').exists()


def test_wheel_retains_reviewed_binary_execute_permission(tmp_path):
    path = tmp_path / 'tool.whl'
    info = zipfile.ZipInfo('package/tool')
    info.external_attr = 0o100755 << 16
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(info, b'inert fixture; not executed')
    extract_wheel(path, tmp_path / 'site')
    assert (tmp_path / 'site/package/tool').stat().st_mode & 0o777 == 0o755


def test_newc_is_byte_reproducible_despite_source_mtime(tmp_path):
    root = tmp_path / 'init'
    root.mkdir()
    (root / 'init').write_bytes(b'inert-image-fixture')
    first = newc(root)
    os.utime(root / 'init', (1, 2))
    assert newc(root) == first


def test_linux_wheel_resolution_refuses_host_and_free_threaded_artifacts():
    def wheel(tag):
        return {'url': 'https://files.pythonhosted.org/q2-1.0-' + tag + '.whl',
                'hash': 'sha256:' + 'a' * 64, 'size': 3}
    data = {'name': 'q2', 'version': '1.0', 'wheels': [
        wheel('cp314-cp314-macosx_11_0_arm64'), wheel('cp314-cp314t-manylinux_2_17_aarch64')]}
    with pytest.raises(ValueError, match='missing_locked_arm64_wheel'):
        choose_wheel(data)
    data['wheels'].append(wheel('cp314-cp314-manylinux_2_17_aarch64'))
    assert 'manylinux_2_17_aarch64' in choose_wheel(data)['filename']


def test_python_lock_closure_honors_target_markers_and_transitive_extras(tmp_path):
    data = """
[[package]]
name = "hermes-agent"
version = "0"
dependencies = [{name="alpha", extra=["rpc"]}, {name="host",marker="sys_platform == 'darwin'"}]
[[package]]
name = "alpha"
version = "1"
wheels = [{url="https://files.pythonhosted.org/alpha-1-py3-none-any.whl",hash="sha256:aaa",size=1}]
[package.optional-dependencies]
rpc = [{name="transport"}]
[[package]]
name = "transport"
version = "1"
wheels = [{url="https://files.pythonhosted.org/transport-1-py3-none-any.whl",hash="sha256:bbb",size=1}]
"""
    (tmp_path / 'uv.lock').write_text(data)
    assert {row['name'] for row in python_closure(tmp_path)} == {'alpha', 'transport'}


def test_debian_input_closure_is_deterministic_and_resolves_virtual_dependency(tmp_path):
    rows = []
    for name in DEBIAN_ROOTS:
        fields = [f'Package: {name}', 'Architecture: arm64', 'Version: 1',
                  f'Filename: pool/{name}.deb', 'Size: 2', 'SHA256: ' + 'a' * 64]
        if name == 'git':
            fields.append('Depends: awk, libc6')
        rows.append('\n'.join(fields))
    rows.append('Package: awk-provider\nArchitecture: arm64\nVersion: 2\nProvides: awk\n'
                'Filename: pool/awk.deb\nSize: 3\nSHA256: ' + 'b' * 64)
    path = tmp_path / 'Packages.xz'
    path.write_bytes(lzma.compress(('\n\n'.join(rows) + '\n').encode()))
    first = debian_closure(path)
    assert any(row['name'] == 'awk-provider' and row['version'] == '2' for row in first)
    assert canonical(first) == canonical(debian_closure(path))


def test_download_uses_locked_digest_and_refuses_cache_symlink(tmp_path, monkeypatch):
    from native.qemu_guest import build_inputs
    row = {'filename': 'input.bin', 'sha256': hashlib.sha256(b'locked').hexdigest(),
           'url': 'https://example.invalid/input', 'size': 6}
    monkeypatch.setattr(build_inputs, 'urlopen', lambda *args, **kwargs: io.BytesIO(b'changed'))
    with pytest.raises(ValueError, match='digest_mismatch'):
        fetch(row, tmp_path / 'download')
    assert not (tmp_path / 'download/input.bin').exists()
    cache = tmp_path / 'cache'
    cache.mkdir()
    (tmp_path / 'original').write_bytes(b'locked')
    (cache / 'input.bin').symlink_to(tmp_path / 'original')
    with pytest.raises(ValueError, match='cached_input_changed'):
        fetch(row, cache)


@pytest.fixture
def package(tmp_path):
    for name in ARTIFACTS:
        (tmp_path / name).write_bytes(('inert-' + name).encode())
    facts = {'task_fixture_head': 'a' * 40, 'input_lock_sha256': 'b' * 64}
    (tmp_path / 'build-facts.json').write_text(canonical(facts))
    (tmp_path / 'root-content-inventory.json').write_text(canonical({'files': []}))
    lock = {'inputs': [], 'uv_lock_sha256': 'c' * 64}
    emit(tmp_path, lock, builder_head='d' * 40)
    return tmp_path


def test_package_binds_all_files_roles_and_policy(package):
    manifest = verify_manifest(package)
    assert manifest['runtime_source_head'] == SOURCE_HEAD
    assert manifest['policy']['host_mounts'] == manifest['policy']['network_devices'] == []
    assert manifest['policy']['uid'] > 0 and manifest['policy']['core_dump_bytes'] == 0
    for role, readonly in [('developer', False), ('reviewer', True)]:
        image = role_image(package, role, 'a' * 40)
        args = image.device_args(3)
        task = next(value for value in args if 'id=task,' in value)
        assert ('readonly=on' in task) == readonly
        assert args[args.index('-nic') + 1] == 'none'
    dev = (package / 'developer-task.raw').stat()
    review = (package / 'reviewer-task.raw').stat()
    assert (dev.st_dev, dev.st_ino) != (review.st_dev, review.st_ino)


@pytest.mark.parametrize('damage', ['corrupt', 'missing', 'hardlink', 'symlink'])
def test_package_rejects_changed_or_aliased_artifact(package, damage):
    target = package / 'developer-task.raw'
    if damage == 'corrupt':
        target.write_bytes(b'corrupted')
    else:
        target.unlink()
        actions = {'hardlink': lambda: os.link(package / 'root.raw', target),
                   'symlink': lambda: target.symlink_to(package / 'root.raw'),
                   'missing': lambda: None}
        actions[damage]()
    with pytest.raises((ValueError, FileNotFoundError)):
        verify_manifest(package)


@pytest.mark.parametrize('name', ['root-content-inventory.json', 'sbom.spdx.json', 'provenance.json'])
def test_package_rejects_changed_metadata(package, name):
    (package / name).write_text('{}\n')
    with pytest.raises(ValueError, match='package_metadata_changed'):
        verify_manifest(package)


@pytest.mark.parametrize('name', ['manifest.json', 'provenance.json', 'reviewer.manifest.json'])
@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_package_rejects_metadata_alias_before_reading(package, name, kind):
    path = package / name
    content = path.read_bytes()
    path.unlink()
    other = package / 'foreign-data'
    other.write_bytes(content)
    if kind == 'symlink':
        path.symlink_to(other)
    else:
        os.link(other, path)
    with pytest.raises((ValueError, OSError)):
        verify_manifest(package)


@pytest.mark.parametrize('name', ['kernel.Image', 'initramfs.cpio.gz'])
def test_package_rejects_changed_boot_artifact(package, name):
    (package / name).write_bytes(b'changed')
    with pytest.raises(ValueError):
        verify_manifest(package)


def test_package_rejects_changed_role_manifest(package):
    path = package / 'reviewer.manifest.json'
    role = json.loads(path.read_text())
    role['devices']['task']['readonly'] = False
    path.write_text(canonical(role).rstrip('\n'))
    with pytest.raises(ValueError, match='role_manifest_changed'):
        verify_manifest(package)


def test_package_rejects_relaxed_network_or_identity_policy(package):
    path = package / 'manifest.json'
    data = json.loads(path.read_text())
    data['policy']['network_devices'] = ['unapproved']
    path.write_text(canonical(data))
    with pytest.raises(ValueError, match='image_policy_changed'):
        verify_manifest(package)


def test_unknown_private_key_and_host_configuration_are_rejected(tmp_path):
    synthetic = b'-----BEGIN OPENSSH PRIVATE KEY-----\n' + b'YWJj' * 50 + b'\n-----END OPENSSH PRIVATE KEY-----'
    with pytest.raises(ValueError, match='private_key'):
        public_vectors('usr/lib/unknown.so', synthetic)
    (tmp_path / '.env').write_text('NOT_A_REAL_TOKEN=fixture\n')
    with pytest.raises(ValueError, match='host_configuration'):
        verify_tree(tmp_path)


def test_guest_content_rejects_copied_session_or_board_database(tmp_path):
    (tmp_path / 'state.db').write_bytes(b'SQLite format 3\0' + b'\0' * 100)
    with pytest.raises(ValueError, match='canonical_database_in_guest'):
        verify_tree(tmp_path)


def test_static_elf_verification_rejects_wrong_architecture(tmp_path):
    raw = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01' + b'\0' * 10,
                      2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
    with pytest.raises(ValueError, match='non_arm64'):
        elf_needed(raw)
    arm = bytearray(raw)
    struct.pack_into('<H', arm, 18, 183)
    assert elf_needed(bytes(arm)) == []


def test_generated_boot_policy_has_bounded_storage_and_no_privileged_uid():
    header = policy_header()
    assert f'#define Q2_UID {POLICY["uid"]}' in header and POLICY['uid'] != 0
    assert all(size > 0 for size in POLICY['tmpfs_mib'].values())
    assert 'Q2_OUTBOX_OPTIONS "size=32m,uid=1000,gid=1000,mode=0700"' in header


def test_case_sensitive_staging_is_enforced_on_actual_filesystem(tmp_path):
    first = tmp_path / 'a'
    first.write_bytes(b'a')
    insensitive = (tmp_path / 'A').exists()
    if insensitive:
        with pytest.raises(ValueError, match='case_sensitive_build_volume'):
            require_case_sensitive(tmp_path)
    else:
        require_case_sensitive(tmp_path)


def test_build_refuses_changed_host_tool(tmp_path):
    from types import SimpleNamespace
    tool = tmp_path / 'inert-build-tool'
    tool.write_bytes(b'pinned; not executed')
    args = SimpleNamespace(zig=tool, mke2fs=tool)
    lock = {'host_tools': {name: {'sha256': digest(tool)} for name in ('zig', 'mke2fs')}}
    verify_tools(args, lock)
    tool.write_bytes(b'changed')
    with pytest.raises(ValueError, match='build_tool_changed'):
        verify_tools(args, lock)


@pytest.fixture
def source_repository(tmp_path):
    import subprocess
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'agent').mkdir()
    (root / 'agent/accepted.py').write_bytes(b'# accepted runtime fixture, never executed\n')
    (root / '.env').write_text('PUBLIC_TEST_SENTINEL=not-a-secret\n')
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_AUTHOR_NAME': 'Offline Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
           'GIT_COMMITTER_NAME': 'Offline Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], env=env, text=True).strip()
    git('init', '-q')
    git('add', '.')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'accepted')
    return root, git, git('rev-parse', 'HEAD')


def test_application_snapshot_uses_pinned_commit_not_current_tree(source_repository, tmp_path, monkeypatch):
    from native.qemu_guest import build_artifacts
    root, git, pinned = source_repository
    (root / 'agent/accepted.py').write_bytes(b'# unaccepted future revision\n')
    git('add', '.')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'later')
    monkeypatch.setattr(build_artifacts, 'SOURCE_HEAD', pinned)
    output = tmp_path / 'assembled'
    build_artifacts.accepted_source(root, output)
    assert (output / 'opt/hermes/agent/accepted.py').read_bytes() == b'# accepted runtime fixture, never executed\n'
    assert not (output / 'opt/hermes/.env').exists()
    assert not (output / 'opt/hermes/.git').exists()


def test_private_git_snapshots_omit_reflogs_and_host_stat_cache(source_repository, tmp_path):
    from gateway.session_guest_workspace import prepare_workspace
    root, _git, head = source_repository
    copies = [prepare_workspace(root, tmp_path / name, head=head, role='developer').root for name in ('one', 'two')]
    for path in copies:
        private_git_snapshot(path)
        assert not (path / '.git/logs').exists()
        assert (path / '.git').is_dir()
    assert (copies[0] / '.git/index').read_bytes() == (copies[1] / '.git/index').read_bytes()


def test_filesystem_metadata_rejects_non_ext4(tmp_path):
    path = tmp_path / 'not-ext4.raw'
    path.write_bytes(b'\0' * 4096)
    with pytest.raises(ValueError, match='ext4_superblock_required'):
        filesystem_metadata(path)


@pytest.mark.platforms('posix')
def test_actual_ext4_reproduces_and_preserves_unprivileged_ownership(tmp_path):
    pytest.importorskip('dissect.extfs', reason='pinned external artifact verification tool unavailable')
    from hermes_platform.resolver import locate_command
    command = locate_command('mke2fs').command
    if not command:
        pytest.skip('external ext4 build tool unavailable')
    tree = tmp_path / 'tree'
    tree.mkdir()
    (tree / 'fixture.txt').write_bytes(b'inert ext4 fixture; never executed\n')
    config = tmp_path / 'mke2fs.conf'
    config.write_text(MKE2FS_CONFIG)
    first, second = tmp_path / 'one.raw', tmp_path / 'two.raw'
    for path in (first, second):
        facts = ext4(tree, path, label='Q2TEST', mib=16, tool=command[0], config=config, owner=1000)
    assert digest(first) == digest(second)
    assert filesystem_metadata(first) == {'uuid': facts['uuid'], 'label': 'Q2TEST',
                                           'block_size': 4096, 'bytes': 16 * 1024**2}
    inventory = disk_inventory(first, owner=1000)
    compare_tree(inventory, [{'path': 'fixture.txt', 'sha256': digest(tree / 'fixture.txt'),
                             'size': (tree / 'fixture.txt').stat().st_size, 'mode': '0o644'}])
    with pytest.raises(ValueError, match='disk_root_owner_mismatch'):
        disk_inventory(first, owner=0)


def test_sbom_includes_exact_dependency_versions_and_hashes():
    lock = {'uv_lock_sha256': 'a' * 64, 'inputs': [{'kind': 'wheel', 'name': 'transport',
            'version': '1.2.3', 'url': 'https://example.invalid/pinned.whl', 'sha256': 'b' * 64}]}
    report = spdx(lock, [])
    dependency = next(row for row in report['packages'] if row['name'] == 'transport')
    assert dependency['versionInfo'] == '1.2.3'
    assert dependency['checksums'] == [{'algorithm': 'SHA256', 'checksumValue': 'b' * 64}]


@pytest.mark.platforms('posix')
@pytest.mark.parametrize('head', ['ref: refs/heads/main\n', 'b' * 40 + '\n', 'ref: refs/heads/../foreign\n', 'malformed\n'])
def test_actual_task_device_git_head_is_exact(tmp_path, head):
    extfs = pytest.importorskip('dissect.extfs')
    from hermes_platform.resolver import locate_command
    command = locate_command('mke2fs').command
    if not command:
        pytest.skip('external ext4 build tool unavailable')
    tree = tmp_path / 'tree'
    refs = tree / '.git/refs/heads'
    refs.mkdir(parents=True)
    (tree / '.git/HEAD').write_text(head)
    (refs / 'main').write_text('a' * 40 + '\n')
    config = tmp_path / 'mke2fs.conf'
    config.write_text(MKE2FS_CONFIG)
    image = tmp_path / 'task.raw'
    ext4(tree, image, label='Q2TASK', mib=16, tool=command[0], config=config, owner=1000)
    with image.open('rb') as stream:
        fs = extfs.ExtFS(stream)
        if '..' in head or head == 'malformed\n':
            with pytest.raises(ValueError, match='private_git_reference_required|exact_git_head_required'):
                git_head(fs)
        else:
            assert git_head(fs) == ('a' if head.startswith('ref: ') else 'b') * 40
