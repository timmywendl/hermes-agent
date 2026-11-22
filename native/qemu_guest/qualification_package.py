"""Q2 fixed-source Helper and exact-identity no-VM Sandbox diagnostics.

The actual Helper executes only its early diagnostic return. Normal QEMU
initialization, Hypervisor operations and Guest execution are not authorized.
"""
from __future__ import annotations

from contextlib import ExitStack
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import shlex
import socket
import subprocess
import sys
import tarfile
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
Q1 = HERE.parent / 'qemu_hvf'
QEMU_SHA256 = '5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22'
FIXTURE_SHA256 = '87a34479ff2f4f9fd8c6c982a9e461f637a7bd9b88e82b03f3e765a58bf77582'
ENTITLEMENTS = {'com.apple.security.app-sandbox': True, 'com.apple.security.hypervisor': True}
PREFIX = 'HERMES_Q2_SANDBOX_RESULT_V1 '
PREFLIGHT_FLAG = '--hermes-q2-sandbox-preflight'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv, *, cwd=None, env=None, timeout=30):
    return subprocess.run([str(p) for p in argv], cwd=cwd, env=env, timeout=timeout,
                          check=True, capture_output=True, text=True)


def build_objects(output):
    """Compile one shared preflight object; no guest, QEMU or VM execution."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    objects = {}
    for name, source in [('admission', Q1 / 'admission_gate.c'),
                         ('keychain', Q1 / 'legacy_keychain_canary.m'),
                         ('gate', HERE / 'qualification_gate.c'),
                         ('preflight', HERE / 'qualification_canary.m')]:
        obj = output / (name + '.o')
        flags = ['-fobjc-arc'] if source.suffix == '.m' else []
        run(['xcrun', 'clang', *flags, '-Wall', '-Wextra', '-Werror',
             '-DHERMES_HVF_EMBEDDED', '-c', source, '-o', obj])
        objects[name] = str(obj)
    entry = output / 'canary-main.c'
    entry.write_text('extern int hermes_q2_canary(const char*,int,char**);\n'
                     'int main(int argc,char**argv){return argc>=2?hermes_q2_canary(argv[1],argc-2,argv+2):2;}\n')
    canary = output / 'sandbox-canary'
    run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', entry, *objects.values(),
         '-framework', 'Foundation', '-framework', 'Security', '-framework', 'LocalAuthentication', '-o', canary])
    return {'objects': objects, 'object_sha256': {name: digest(path) for name, path in objects.items()},
            'canary': str(canary), 'canary_sha256': digest(canary)}


def extract_source(archive, source, dtc_source):
    archive, source, dtc_source = Path(archive), Path(source), Path(dtc_source)
    if digest(archive) != QEMU_SHA256:
        raise ValueError('q2_fixed_qemu_archive_required')
    if run(['git', '-C', dtc_source, 'rev-parse', 'HEAD']).stdout.strip() != 'b6910bec11614980a21e46fbccc35934b671bd81':
        raise ValueError('q2_fixed_dtc_required')
    run(['git', '-C', dtc_source, 'diff', '--quiet', 'HEAD'])
    source.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as stream:
        members = [row for row in stream.getmembers() if
                   row.name != 'qemu-11.1.3/roms/edk2/EmulatorPkg/Unix/Host/X11IncludeHack']
        stream.extractall(source, members=members, filter='data')
    tree = source / 'qemu-11.1.3'
    target = tree / 'subprojects/dtc'
    if target.exists():
        target.rmdir()  # The fixed release contains an empty subproject placeholder.
    shutil.copytree(dtc_source, target, symlinks=False, ignore=shutil.ignore_patterns('.git'))
    return tree



def build_wheels(tree, archive):
    from native.qemu_guest.build_inputs import fetch
    lock = tomllib.loads((HERE.parents[1] / 'uv.lock').read_text())
    inputs = []
    for name, version in (('pip', '26.2.1'), ('setuptools', '83.0.0')):
        package = next(row for row in lock['package'] if row['name'] == name and row['version'] == version)
        wheel = package['wheels'][0]
        item = {'filename': wheel['url'].rsplit('/', 1)[1], 'url': wheel['url'],
                'sha256': wheel['hash'].removeprefix('sha256:'), 'size': wheel['size']}
        fetch(item, tree / 'python/wheels')
        inputs.append(item)
    wheel = Path(archive).parent / 'wheel-0.45.1-py3-none-any.whl'
    if digest(wheel) != '708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248':
        raise ValueError('q2_fixed_wheel_required')
    shutil.copyfile(wheel, tree / 'python/wheels' / wheel.name)
    return inputs + [{'filename': wheel.name, 'sha256': digest(wheel)}]


def build_helper(*, archive, dtc_source, output, python, ninja, pkgconf, pkgconfig_dirs=()):
    """Fresh ARM64 HVF-only build, preserving Q1 sources, binaries and outputs."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    tree = extract_source(archive, output / 'source', dtc_source)
    run(['patch', '-p1', '-i', Q1 / 'qemu-candidate.patch'], cwd=tree)
    run(['patch', '-p1', '-i', HERE / 'qualification-main.patch'], cwd=tree)
    wheels = build_wheels(tree, archive)
    objects = build_objects(output / 'objects')
    build = output / 'build'
    build.mkdir()
    link = ' '.join(objects['objects'].values()) + ' -framework Foundation -framework Security -framework LocalAuthentication'
    if any(not Path(path).is_absolute() or not Path(path).is_dir() for path in pkgconfig_dirs):
        raise ValueError('q2_absolute_pkgconfig_directories_required')
    env = dict(os.environ, PKG_CONFIG=str(pkgconf), PKG_CONFIG_PATH=os.pathsep.join(map(str, pkgconfig_dirs)))
    command = [tree / 'configure', '--target-list=aarch64-softmmu', '--enable-hvf', '--disable-tcg',
               '--without-default-features', '--enable-fdt=internal', '--disable-tools', '--disable-docs',
               '--disable-user', '--disable-install-blobs', '--disable-download',
               '--python=' + str(python), '--ninja=' + str(ninja), '--extra-ldflags=' + link]
    for name, args in [('configure', command), ('compile', [ninja, '-j8', 'qemu-system-aarch64'])]:
        with (output / (name + '.log')).open('w') as log:
            result = subprocess.run([str(p) for p in args], cwd=build, env=env, timeout=1800,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise RuntimeError('q2_' + name + '_failed')
    binary = build / 'qemu-system-aarch64'
    result = {'binary': str(binary), 'sha256': digest(binary), 'objects': objects,
              'source_archive_sha256': QEMU_SHA256, 'build_wheels': wheels, 'configure_argv': [str(p) for p in command],
              'pkgconfig_directories': list(map(str, pkgconfig_dirs)),
              'q1_patch_sha256': digest(Q1 / 'qemu-candidate.patch'),
              'q2_patch_sha256': digest(HERE / 'qualification-main.patch'), 'qemu_executions': 0}
    (output / 'build-receipt.json').write_text(canonical(result))
    return result



def relink_helper(previous, output):
    """Reuse immutable compiled fixed-QEMU objects, link changed Q2 preflight only."""
    if (previous.get('q2_patch_sha256') != digest(HERE / 'qualification-main.patch')
            or previous.get('q1_patch_sha256') != digest(Q1 / 'qemu-candidate.patch')):
        raise ValueError('q2_changed_main_requires_fresh_build')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    objects = build_objects(output / 'objects')
    build = Path(previous['binary']).parent
    ninja = next(value.split('=', 1)[1] for value in previous['configure_argv'] if value.startswith('--ninja='))
    commands = run([ninja, '-t', 'commands', 'qemu-system-aarch64'], cwd=build).stdout.splitlines()
    candidates = [shlex.split(line) for line in commands if ' -o qemu-system-aarch64-unsigned ' in line]
    if len(candidates) != 1:
        raise ValueError('q2_exact_link_command_unavailable')
    argv = candidates[0]
    target = output / 'qemu-system-aarch64'
    argv[argv.index('-o') + 1] = str(target)
    for name, old in previous['objects']['objects'].items():
        if argv.count(old) != 1:
            raise ValueError('q2_link_object_binding_unavailable')
        argv[argv.index(old)] = objects['objects'][name]
    result = run(argv, cwd=build, timeout=1800)
    (output / 'link.stdout.log').write_text(result.stdout)
    (output / 'link.stderr.log').write_text(result.stderr)
    receipt = dict(previous, binary=str(target), sha256=digest(target), objects=objects,
                   relinked_from=previous['sha256'], link_argv=argv, qemu_executions=0)
    (output / 'build-receipt.json').write_text(canonical(receipt))
    return receipt


def code_identity(binary):
    run(['codesign', '--verify', '--strict', binary])
    result = run(['codesign', '--display', '--verbose=4', binary])
    values = dict(line.split('=', 1) for line in result.stderr.splitlines() if '=' in line)
    ent = run(['codesign', '--display', '--entitlements', '-', '--xml', binary])
    actual = plistlib.loads(ent.stdout.encode())
    if actual != ENTITLEMENTS or not values.get('CDHash') or not values.get('Identifier'):
        raise ValueError('q2_exact_signed_sandbox_identity_required')
    return {'cdhash': values['CDHash'], 'identifier': values['Identifier'], 'entitlements': actual}


def _bundle_libraries(binary, frameworks):
    # Execute the original packaging helper in its own Python module scope.
    # Its Q1 import convention expects that directory on sys.path.
    code = ('import json,sys;from pathlib import Path;from package_candidate import bundle_libraries;'
            'print(json.dumps(bundle_libraries(Path(sys.argv[1]),Path(sys.argv[2]))))')
    return json.loads(run([sys.executable, '-c', code, binary, frameworks], cwd=Q1).stdout)


def _control_socket(stack, family, kind, address):
    stream = stack.enter_context(socket.socket(family, kind))
    stream.bind(address)
    if kind == socket.SOCK_STREAM:
        stream.listen(4)
    return stream


def _policy(root, resources, fixture, source_bindings, objects):
    if digest(fixture) != FIXTURE_SHA256:
        raise ValueError('q2_public_keychain_fixture_required')
    controls = root / 'public-denied'
    controls.mkdir()
    forbidden = {}
    for name in ('home', 'provider', 'board', 'session_db', 'project', 'ssh_key'):
        path = controls / name
        path.write_text('Q2 public disposable calibration marker; not a credential.\n')
        forbidden[name] = str(path)
    keychain = controls / 'public-test.keychain'
    shutil.copyfile(fixture, keychain)
    short = Path(tempfile.mkdtemp(prefix='hq2-', dir='/private/tmp'))
    unix = {name: str(short / name) for name in ('ssh_agent', 'docker')}
    with ExitStack() as stack:
        ports = {}
        for family, suffix in ((socket.AF_INET, '4'), (socket.AF_INET6, '6')):
            for kind, label in ((socket.SOCK_STREAM, 'tcp'), (socket.SOCK_DGRAM, 'udp')):
                server = _control_socket(stack, family, kind, ('::1' if suffix == '6' else '127.0.0.1', 0))
                ports[label + suffix] = server.getsockname()[1]
    return {'schema': 'HERMES_Q2_STATIC_POLICY_V1', 'sources': source_bindings,
            'preflight_object_sha256': objects['object_sha256']['preflight'],
            'gate_object_sha256': objects['object_sha256']['gate'], 'forbidden': forbidden,
            'unix': unix, 'ports': ports, 'legacy_fixture': str(keychain),
            'approved': [str(resources / name) for name in ('kernel.Image', 'initramfs.cpio.gz')],
            'roles': ['developer', 'reviewer'], 'device_kinds': ['root', 'task', 'assignment'],
            'max_manifest_bytes': 65536, 'max_disk_bytes': 8 * 1024**3,
            'network': False, 'qemu_executions': 0}


def package_candidate(*, binary, objects, kernel, initramfs, output, fixture, source_bindings):
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    app = root / 'HermesQ2HVF.app'
    macos, resources, frameworks = [app / 'Contents' / name for name in ('MacOS', 'Resources', 'Frameworks')]
    for directory in (macos, resources, frameworks):
        directory.mkdir(parents=True)
    helper = macos / 'qemu-system-aarch64'
    shutil.copyfile(binary, helper)
    helper.chmod(0o755)
    libraries = _bundle_libraries(helper, frameworks)
    for original, name in ((kernel, 'kernel.Image'), (initramfs, 'initramfs.cpio.gz')):
        shutil.copyfile(original, resources / name)
        if digest(original) != digest(resources / name):
            raise ValueError('q2_copy_digest_changed')
    identifier = 'org.hermes.q2.' + hashlib.sha256(canonical(source_bindings).encode()).hexdigest()[:16]
    info = {'CFBundleIdentifier': identifier, 'CFBundleExecutable': helper.name,
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSBackgroundOnly': True}
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    policy = _policy(root, resources, Path(fixture), source_bindings, objects)
    policy_path = resources / 'static-policy.json'
    policy_path.write_text(canonical(policy))
    run(['codesign', '--force', '--sign', '-', '--entitlements', Q1 / 'helper.entitlements', app])
    identity = code_identity(helper)
    positive_app = root / 'Calibration.app'
    positive_macos = positive_app / 'Contents/MacOS'
    positive_resources = positive_app / 'Contents/Resources'
    positive_macos.mkdir(parents=True)
    positive_resources.mkdir()
    positive = positive_macos / 'sandbox-canary'
    shutil.copyfile(objects['canary'], positive)
    positive.chmod(0o755)
    (positive_app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleExecutable=positive.name)))
    for name in ('kernel.Image', 'initramfs.cpio.gz', 'static-policy.json'):
        shutil.copyfile(resources / name, positive_resources / name)
    run(['codesign', '--force', '--sign', '-', positive_app])
    inventory = {str(path): digest(path) for path in app.rglob('*') if path.is_file()}
    receipt = {'schema': 'HERMES_Q2_HELPER_PACKAGE_V1', 'app': str(app), 'helper': str(helper),
               'resources': str(resources), 'helper_sha256': digest(helper),
               'positive': str(positive), 'positive_resources': str(positive_resources),
               'positive_inventory': {str(path): digest(path) for path in positive_app.rglob('*') if path.is_file()},
               'static_policy': str(policy_path), 'static_policy_sha256': digest(policy_path),
               'identity': identity, 'inventory': inventory, 'libraries': libraries, 'objects': objects,
               'source_bindings': source_bindings, 'qemu_executions': 0,
               'helper_execution': 'NOT_RUN'}
    receipt['metadata_sha256'] = emit_metadata(root, receipt)
    (root / 'package-receipt.json').write_text(canonical(receipt))
    return receipt



def emit_metadata(root, receipt):
    identity = hashlib.sha256(canonical(receipt['inventory']).encode()).hexdigest()
    packages = [{'name': 'QEMU', 'SPDXID': 'SPDXRef-QEMU', 'versionInfo': '11.1.3',
                 'downloadLocation': 'https://download.qemu.org/qemu-11.1.3.tar.xz',
                 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
                 'licenseDeclared': 'GPL-2.0-only', 'copyrightText': 'NOASSERTION',
                 'checksums': [{'algorithm': 'SHA256', 'checksumValue': QEMU_SHA256}]}]
    for index, (source, record) in enumerate(sorted(receipt['libraries'].items())):
        packages.append({'name': Path(source).name, 'SPDXID': 'SPDXRef-Library-' + str(index),
                         'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                         'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
                         'copyrightText': 'NOASSERTION', 'sourceInfo': source,
                         'checksums': [{'algorithm': 'SHA256', 'checksumValue': record['source_sha256']}]})
    files = [{'fileName': str(Path(name).relative_to(root)), 'SPDXID': 'SPDXRef-File-' + str(index),
              'checksums': [{'algorithm': 'SHA256', 'checksumValue': sha}],
              'licenseConcluded': 'NOASSERTION', 'licenseInfoInFiles': ['NOASSERTION'],
              'copyrightText': 'NOASSERTION'}
             for index, (name, sha) in enumerate(sorted(receipt['inventory'].items()))]
    sbom = {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'Hermes Q2 offline HVF Helper', 'documentNamespace': 'https://hermes.local/q2-helper/' + identity,
            'creationInfo': {'creators': ['Tool: hermes-q2-offline-helper-packager-v1'],
                             'created': '2026-11-22T00:00:00Z'},
            'packages': packages, 'files': files, 'relationships': [
                {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                 'relatedSpdxElement': package['SPDXID']} for package in packages]}
    provenance = {'_type': 'https://in-toto.io/Statement/v1',
                  'subject': [{'name': str(Path(name).relative_to(root)), 'digest': {'sha256': sha}}
                              for name, sha in sorted(receipt['inventory'].items())],
                  'predicateType': 'https://slsa.dev/provenance/v1',
                  'predicate': {'buildDefinition': {
                      'buildType': 'hermes-q2-fixed-qemu-hvf-helper-v1',
                      'externalParameters': {'sources': receipt['source_bindings'], 'native_execution': False},
                      'internalParameters': {'objects': receipt['objects']['object_sha256'],
                                             'entitlements': ENTITLEMENTS},
                      'resolvedDependencies': [{'uri': 'https://download.qemu.org/qemu-11.1.3.tar.xz',
                                                'digest': {'sha256': QEMU_SHA256}}]},
                      'runDetails': {'builder': {'id': 'hermes-q2-offline-helper-packager-v1'},
                                     'metadata': {'invocationId': identity}}}}
    result = {}
    for name, value in [('sbom.spdx.json', sbom), ('provenance.json', provenance)]:
        target = root / name
        target.write_text(canonical(value))
        result[name] = digest(target)
    (root / 'LICENSE-OBLIGATIONS.txt').write_text(
        'Local candidate only; no distribution qualification or publication. QEMU as a whole is GPLv2; '
        'source files/component exceptions apply. Retain the exact QEMU archive, DTC revision, Q1 teardown '
        'patch, Q2 patch/gate/canary sources and complete build/link recipes. Bundled GLib/gettext/PCRE '
        'notices and matching sources/relink obligations require a full audit before distribution. '
        'SPDX NOASSERTION is not a license clearance. No production signing key was used.\n')
    return result


def qemu_argv(resources, devices, serial_fd, role):
    resources = Path(resources)
    args = ['-L', str(resources), '-nodefaults', '-display', 'none', '-monitor', 'none', '-qmp', 'stdio',
            '-chardev', f'socket,id=worker,fd={serial_fd}', '-serial', 'chardev:worker',
            '-nic', 'none', '-accel', 'hvf', '-machine', 'virt', '-cpu', 'host', '-smp', '2', '-m', '2048',
            '-no-reboot', '-kernel', str(resources / 'kernel.Image'),
            '-initrd', str(resources / 'initramfs.cpio.gz'),
            '-append', 'console=tty0 root=/dev/vda ro rdinit=/init panic=-1']
    for index, name in enumerate(('root', 'task', 'assignment'), 1):
        writable = role == 'developer' and name == 'task'
        args += ['-add-fd', f'fd={devices[name]["fd"]},set={index}']
        if writable:
            args += ['-add-fd', f'fd={devices[name]["ro_fd"]},set=2']
        args += ['-drive', f'file=/dev/fdset/{index},format=raw,if=none,id={name},readonly={"off" if writable else "on"}',
                 '-device', 'virtio-blk-pci,drive=' + name]
    return args


def make_bootstrap(package, devices, serial_fd, role, owner):
    if role not in ('developer', 'reviewer') or set(devices) != {'root', 'task', 'assignment'}:
        raise ValueError('q2_exact_role_devices_required')
    projected = {}
    for name, record in devices.items():
        extra = ('ro_fd',) if name == 'task' and role == 'developer' else ()
        if extra and 'ro_fd' not in record:
            raise ValueError('q2_task_readonly_handle_required')
        if not extra and 'ro_fd' in record:
            raise ValueError('q2_unapproved_readonly_handle')
        projected[name] = {key: record[key] for key in ('fd', 'st_dev', 'st_ino', 'size') + extra}
    if role == 'developer':
        ro_fd = projected['task']['ro_fd']
        if (type(ro_fd) is not int or ro_fd < 3 or ro_fd == serial_fd
                or ro_fd in {row['fd'] for row in projected.values()}):
            raise ValueError('q2_distinct_task_readonly_handle_required')
    return {'schema': 'HERMES_Q2_SANDBOX_PLAN_V1', 'role': role,
            'policy_sha256': package['static_policy_sha256'],
            'devices': projected,
            'serial_fd': serial_fd, 'qemu_argv': qemu_argv(package['resources'], projected, serial_fd, role), 'owner': owner}


def verify_sandbox_controls(report, package):
    """Exact diagnostics are evidence, never authority to initialize a VM."""
    if (report.get('schema') != 'HERMES_Q2_SANDBOX_CONTROLS_V2'
            or report.get('status') != 'PASS_EXACT_HELPER_SANDBOX_PREFLIGHT'
            or report.get('helper_execution') != 'NO_VM_PREFLIGHT_ONLY'
            or report.get('helper_identity') != package['identity']
            or report.get('package_inventory') != package['inventory']
            or report.get('helper_sha256') != package['helper_sha256']
            or report.get('preflight_object_sha256') != package['objects']['object_sha256']['preflight']
            or report.get('execution_counts') != {
                'helper_preflight_invocations': 2, 'qemu_runtime_entries': 0,
                'qemu_vm_creates': 0, 'guest_starts': 0, 'worker_executions': 0}):
        raise ValueError('q2_sandbox_controls_unavailable')
    expected_order = [(role, mode) for role in ('developer', 'reviewer')
                      for mode in ('unrestricted', 'sandboxed', 'positive-recheck')]
    try:
        if ([(row['role'], row['mode']) for row in report['results']] != expected_order
                or report['static_policy_sha256'] != package['static_policy_sha256']
                or report.get('same_cdhash_helper_execution') is not True):
            raise ValueError('q2_sandbox_control_identity_mismatch')
        for row in report['results']:
            verify_control_record(row, package)
    except (KeyError, TypeError, AttributeError) as failure:
        raise ValueError('q2_sandbox_control_unavailable') from failure
    if code_identity(package['helper']) != package['identity']:
        raise ValueError('q2_helper_identity_changed')
    verify_package_files(package)
    return True


def verify_control_record(row, package):
    """Bind the Helper's own report to the program, role and inherited FDs."""
    report, role = row['report'], row['role']
    sandboxed = row['mode'] == 'sandboxed'
    if (not _calibration_ok(report, sandboxed, role)
            or row['returncode'] != (0 if sandboxed else 2)
            or report.get('role') != role or report.get('canary') is not True
            or not isinstance(report.get('pid'), int) or report['pid'] < 1
            or report['pid'] != row['child_pid']):
        raise ValueError('q2_sandbox_control_unsettled')
    for name in ('root', 'task', 'assignment'):
        observed, expected = report['devices'][name], row['devices'][name]
        if (observed.get('observed') is not True
                or {key: observed.get(key) for key in ('fd', 'st_dev', 'st_ino', 'size')} != {
                    key: expected[key] for key in ('fd', 'st_dev', 'st_ino', 'size')}
                or observed.get('access') != (os.O_RDWR if role == 'developer' and name == 'task' else os.O_RDONLY)):
            raise ValueError('q2_sandbox_descriptor_identity_changed')
    if role == 'developer':
        expected_ro = {key: row['devices']['task'][key] for key in ('st_dev', 'st_ino', 'size')}
        expected_ro['fd'] = row['devices']['task']['ro_fd']
        observed_ro = report['devices']['task']['ro']
        if {key: observed_ro.get(key) for key in expected_ro} != expected_ro or observed_ro.get('observed') is not True:
            raise ValueError('q2_task_readonly_identity_changed')
    if report.get('serial_fd') != row['serial_fd']:
        raise ValueError('q2_sandbox_serial_identity_changed')
    if sandboxed:
        identity = dict(package['identity'], executable=package['helper'],
                        executable_sha256=package['helper_sha256'], package_inventory=package['inventory'])
        if (row.get('argv', [])[:2] != [package['helper'], PREFLIGHT_FLAG]
                or report['identity'] != identity):
            raise ValueError('q2_exact_helper_code_identity_changed')


def verify_preflight_programs(package):
    helper, positive = Path(package['helper']), Path(package['positive'])
    if (helper.name != 'qemu-system-aarch64' or helper.parents[2].name != 'HermesQ2HVF.app'
            or positive.name != 'sandbox-canary' or positive.parents[2].name != 'Calibration.app'
            or helper.resolve() == positive.resolve()):
        raise ValueError('q2_exact_helper_preflight_required')
    dependencies = run(['otool', '-L', positive]).stdout
    symbols = run(['nm', '-u', positive]).stdout
    if 'Hypervisor.framework' in dependencies or '_hv_vm_create' in symbols or '_hv_vm_destroy' in symbols:
        raise ValueError('q2_hypervisor_binary_forbidden_in_calibration')
    if code_identity(helper) != package['identity'] or digest(helper) != package['helper_sha256']:
        raise ValueError('q2_helper_identity_changed')


def verify_package_files(package):
    for app, key in ((Path(package['app']), 'inventory'),
                     (Path(package['positive']).parents[2], 'positive_inventory')):
        paths = list(app.rglob('*'))
        if (any(path.is_symlink() for path in paths)
                or {str(path) for path in paths if path.is_file()} != set(package[key])):
            raise ValueError('q2_exact_app_inventory_required')
        run(['codesign', '--verify', '--strict', app])
        for name, expected in package[key].items():
            if Path(name).stat().st_nlink != 1 or digest(name) != expected:
                raise ValueError('q2_package_changed')
    if (digest(package['helper']) != package['helper_sha256']
            or digest(package['static_policy']) != package['static_policy_sha256']):
        raise ValueError('q2_package_changed')


def _calibration_ok(report, sandboxed, role):
    if (set(report['negative_writes']) != {'home', 'provider', 'board', 'session_db', 'project', 'ssh_key'}
            or set(report['negative']) != {'home', 'provider', 'board', 'session_db', 'project',
                                   'ssh_key', 'ssh_agent', 'docker'}
            or set(report['network']) != {'tcp4', 'udp4', 'tcp6', 'udp6', 'listen4', 'listen6'}
            or set(report['devices']) != {'root', 'task', 'assignment', 'serial_identity'}):
        return False
    if (report.get('vm_created') is not False or report.get('descriptor_identity') is not True
            or not _task_ro_control_ok(report['devices']['task'], role)
            or report.get('approved_reads') is not True or not report['devices']['serial_identity']):
        return False
    if not all(row['read'] and row['write'] == (role == 'developer' and name == 'task')
               for name, row in report['devices'].items() if name != 'serial_identity'):
        return False
    if sandboxed:
        return (report['pass'] is True and report['sandbox'] is True and report['hypervisor'] is True
                and report['network_entitlements_absent'] is True
                and all(not row['allowed'] and row['errno'] in (1, 13) for row in report['negative'].values())
                and all(not row['allowed'] and row['errno'] in (1, 13) for row in report['negative_writes'].values())
                and not report['bundle_write']['allowed'] and report['bundle_write']['errno'] in (1, 13)
                and all(not row['allowed'] and row['errno'] in (1, 13) for row in report['network'].values())
                and not report['legacy_keychain']['public_dummy_matches'])
    return (report['sandbox'] is False and report['hypervisor'] is False
            and all(row['allowed'] for row in report['negative'].values())
            and all(row['allowed'] for row in report['negative_writes'].values())
            and report['bundle_write']['allowed'] is True
            and all(row['allowed'] for row in report['network'].values())
            and report['legacy_keychain']['public_dummy_matches'] is True)


def _task_ro_control_ok(task, role):
    if role != 'developer':
        return 'ro' not in task
    ro = task.get('ro')
    return (isinstance(ro, dict) and ro.get('read') is True and ro.get('write') is False
            and ro.get('write_errno') == 9 and ro.get('access') == os.O_RDONLY)


def _invoke_control(argv, fds, output):
    """Wait for this exact diagnostic child and persist timeout evidence too."""
    with subprocess.Popen(argv, pass_fds=tuple(fds), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding='utf-8',
                          env={'PATH': '/usr/bin:/bin', 'HOME': str(output / 'unrelated-host-home')}) as child:
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            stdout, stderr = child.communicate(timeout=5)
        (output / 'stdout.log').write_text(stdout)
        (output / 'stderr.log').write_text(stderr)
        (output / 'exact-wait.json').write_text(canonical({
            'pid': child.pid, 'returncode': child.returncode, 'timed_out': timed_out,
            'termination_signal': -child.returncode if child.returncode < 0 else None,
            'wait_reaped': child.poll() is not None,
            'stdout_closed': child.stdout.closed, 'stderr_closed': child.stderr.closed}))
        if timed_out:
            raise RuntimeError('q2_preflight_timeout_exact_child_reaped')
        return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr), child.pid


def _one_control(package, role, mode, output):
    output.mkdir()
    fds = []
    with ExitStack() as stack:
        devices = {}
        for name in ('root', 'task', 'assignment'):
            path = output / (name + '.public')
            path.write_bytes(b'Q2_PUBLIC_FD_CALIBRATION\n')
            fd = os.open(path, os.O_RDWR if role == 'developer' and name == 'task' else os.O_RDONLY)
            stack.callback(os.close, fd)
            fds.append(fd)
            stat = os.fstat(fd)
            devices[name] = {'fd': fd, 'st_dev': stat.st_dev, 'st_ino': stat.st_ino, 'size': stat.st_size}
        if role == 'developer':
            ro_fd = os.open(output / 'task.public', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, ro_fd)
            fds.append(ro_fd)
            devices['task']['ro_fd'] = ro_fd
        parent, child = socket.socketpair()
        stack.callback(parent.close)
        stack.callback(child.close)
        fds.append(child.fileno())
        current = dict(package)
        if mode != 'sandboxed':
            current['resources'] = package['positive_resources']
        owner = {'task_id': 'PUBLIC_CANARY', 'run_id': 1, 'epoch': 1,
                 'vm_id': 'NO_VM', 'attempt': role + '-' + mode, 'instance': 'NO_OWNER_CANARY'}
        bootstrap = make_bootstrap(current, devices, child.fileno(), role, owner)
        manifest = output / 'bootstrap.json'
        manifest.write_text(canonical(bootstrap))
        fd = os.open(manifest, os.O_RDONLY)
        stack.callback(os.close, fd)
        fds.append(fd)
        binary = package['helper'] if mode == 'sandboxed' else package['positive']
        argv = [binary, *([PREFLIGHT_FLAG] if mode == 'sandboxed' else []),
                '/dev/fd/' + str(fd), *bootstrap['qemu_argv']]
        (output / 'invocation.json').write_text(canonical({
            'argv': argv, 'devices': devices, 'serial_fd': child.fileno(), 'mode': mode, 'role': role}))
        result, child_pid = _invoke_control(argv, fds, output)
        rows = [line[len(PREFIX):] for line in result.stderr.splitlines() if line.startswith(PREFIX)]
        if len(rows) != 1:
            raise RuntimeError('q2_preflight_report_missing:rc=' + str(result.returncode) + ':' + result.stderr[-1000:])
        report = json.loads(rows[0])
        row = {'role': role, 'mode': mode, 'returncode': result.returncode,
               'report': report, 'argv': argv, 'devices': devices, 'serial_fd': child.fileno(), 'child_pid': child_pid,
               'bootstrap_sha256': digest(manifest), 'stderr_sha256': digest(output / 'stderr.log')}
        try:
            verify_control_record(row, package)
        except ValueError as error:
            raise RuntimeError('q2_preflight_control_failed:' + str(error)) from error
        if result.stdout or any(marker in result.stderr for marker in (
                'HERMES_HVF_CORE_LIMIT_V1', 'HERMES_HVF_VM_CREATE_V1', 'HERMES_HVF_VM_DESTROY_V1',
                'QEMU_RUNTIME_ENTRY', 'HERMES_Q2_QEMU_INIT_FORBIDDEN')):
            raise RuntimeError('q2_preflight_entered_qemu_runtime')
        return row


def run_sandbox_controls(package, output):
    """Two exact Helper diagnostic invocations; zero normal QEMU/VM entries."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    verify_preflight_programs(package)
    verify_package_files(package)
    policy = json.loads(Path(package['static_policy']).read_text())
    results = []
    with ExitStack() as stack:
        for path in policy['unix'].values():
            _control_socket(stack, socket.AF_UNIX, socket.SOCK_STREAM, path)
        for key, port in policy['ports'].items():
            family = socket.AF_INET6 if key.endswith('6') else socket.AF_INET
            kind = socket.SOCK_STREAM if key.startswith('tcp') else socket.SOCK_DGRAM
            _control_socket(stack, family, kind, ('::1' if family == socket.AF_INET6 else '127.0.0.1', port))
        for role in ('developer', 'reviewer'):
            for mode in ('unrestricted', 'sandboxed', 'positive-recheck'):
                results.append(_one_control(package, role, mode, output / (role + '-' + mode)))
    report = {'schema': 'HERMES_Q2_SANDBOX_CONTROLS_V2',
              'status': 'PASS_EXACT_HELPER_SANDBOX_PREFLIGHT', 'results': results,
              'helper_identity': package['identity'], 'helper_sha256': package['helper_sha256'],
              'package_inventory': package['inventory'],
              'preflight_object_sha256': package['objects']['object_sha256']['preflight'],
              'static_policy_sha256': package['static_policy_sha256'],
              'execution_counts': {'helper_preflight_invocations': 2, 'qemu_runtime_entries': 0,
                  'qemu_vm_creates': 0, 'guest_starts': 0, 'worker_executions': 0},
              'vm_operations': 'NOT_RUN', 'helper_execution': 'NO_VM_PREFLIGHT_ONLY',
              'same_cdhash_helper_execution': True,
              'limit': 'Early diagnostic main return only. Upstream pre-main RCU support initialization is not VM initialization; exact process wait terminates its support thread. Native three-slot grant remains NOT_ISSUED.'}
    verify_sandbox_controls(report, package)
    (output / 'sandbox-controls.json').write_text(canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-package', type=Path, required=True)
    parser.add_argument('--controls-output', type=Path)
    args = parser.parse_args()
    package = json.loads(args.verify_package.read_text())
    if args.controls_output:
        report = run_sandbox_controls(package, args.controls_output)
        print(canonical({'status': report['status'], 'execution_counts': report['execution_counts']}))
    else:
        for name, expected in package['inventory'].items():
            if digest(name) != expected:
                raise ValueError('q2_package_changed')
        print(canonical({'helper': code_identity(package['helper']), 'helper_execution': 'NOT_RUN'}))


if __name__ == '__main__':
    main()
