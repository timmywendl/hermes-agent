"""Q2 packaging/control contracts; no QEMU, Guest, Worker or model is executed."""
from copy import deepcopy
import json
import os
import subprocess
from pathlib import Path

import pytest

from native.qemu_guest.qualification_package import (
    _calibration_ok, build_objects, make_bootstrap, package_candidate,
    qemu_argv, run_sandbox_controls, verify_sandbox_controls,
)


def device_records():
    return {name: {'fd': index, 'st_dev': 1, 'st_ino': index, 'size': 4096,
                   'sha256': 'a' * 64, 'readonly': name != 'task'}
            for index, name in enumerate(('root', 'task', 'assignment'), 10)}


def test_bootstrap_projects_capabilities_without_guest_path_authority():
    devices = device_records()
    owner = {'task_id': 'task', 'run_id': 1, 'epoch': 1, 'vm_id': 'vm',
             'attempt': 'one', 'instance': 'owner'}
    package = {'static_policy_sha256': 'b' * 64, 'resources': '/approved/Resources'}
    bootstrap = make_bootstrap(package, devices, 20, 'reviewer', owner)
    assert set(bootstrap['devices']['task']) == {'fd', 'st_dev', 'st_ino', 'size'}
    assert bootstrap['owner'] == owner
    assert bootstrap['role'] == 'reviewer'
    args = bootstrap['qemu_argv']
    assert '-nic' in args and args[args.index('-nic') + 1] == 'none'
    assert len([value for value in args if value == '-add-fd']) == 3
    assert all('readonly=on' in value for value in args if value.startswith('file=/dev/fdset/'))
    assert not any(value.startswith('/host/') for value in args)


@pytest.mark.parametrize('role', ['foreign', '', None])
def test_bootstrap_refuses_unapproved_role(role):
    with pytest.raises(ValueError):
        make_bootstrap({'static_policy_sha256': 'b' * 64, 'resources': '/approved'},
                       device_records(), 20, role, {})


def test_developer_is_the_only_writable_fdset():
    args = qemu_argv(Path('/approved'), device_records(), 20, 'developer')
    drives = [value for value in args if value.startswith('file=/dev/fdset/')]
    assert len(drives) == 3
    assert [value for value in drives if value.endswith('readonly=off')] == [
        'file=/dev/fdset/2,format=raw,if=none,id=task,readonly=off']
    assert args[args.index('-smp') + 1] == '2'
    assert args[args.index('-m') + 1] == '2048'
    assert '-no-reboot' in args


def control(role, sandboxed):
    writable = role == 'developer'
    return {'vm_created': False, 'descriptor_identity': True, 'approved_reads': True,
            'devices': {'root': {'read': True, 'write': False},
                        'task': {'read': True, 'write': writable},
                        'assignment': {'read': True, 'write': False}, 'serial_identity': True},
            'pass': sandboxed, 'sandbox': sandboxed, 'hypervisor': sandboxed,
            'network_entitlements_absent': True,
            'negative': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                         for key in ('home', 'provider', 'board', 'session_db', 'project', 'ssh_key', 'ssh_agent', 'docker')},
            'negative_writes': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                                for key in ('home', 'provider', 'board', 'session_db', 'project', 'ssh_key')},
            'bundle_write': {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0},
            'network': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                        for key in ('tcp4', 'udp4', 'tcp6', 'udp6', 'listen4', 'listen6')},
            'legacy_keychain': {'public_dummy_matches': not sandboxed},
            'identity': {'identifier': 'fixed', 'cdhash': 'canary'}}


def package_report():
    package = {'identity': {'identifier': 'fixed', 'cdhash': 'helper'},
               'canary_identity': {'identifier': 'fixed', 'cdhash': 'canary'},
               'helper': 'helper', 'canary': 'canary', 'inventory': {},
               'static_policy_sha256': 'a' * 64, 'canary_static_policy_sha256': 'c' * 64, 'canary_inventory': {}, 'objects': {'object_sha256': {'preflight': 'b' * 64}}}
    rows = [{'role': role, 'mode': mode, 'returncode': 0 if mode == 'sandboxed' else 2,
             'report': control(role, mode == 'sandboxed')}
            for role in ('developer', 'reviewer') for mode in ('unrestricted', 'sandboxed', 'positive-recheck')]
    report = {'schema': 'HERMES_Q2_SANDBOX_CONTROLS_V1', 'status': 'PASS_POLICY_EQUIVALENT_CANARY_ONLY',
              'helper_execution': 'NOT_RUN', 'helper_identity': package['identity'],
              'canary_identity': package['canary_identity'], 'package_inventory': {},
              'preflight_object_sha256': 'b' * 64, 'static_policy_sha256': 'a' * 64,
              'qemu_executions': 0, 'same_cdhash_canary_execution': False, 'results': rows,
              'canary_static_policy_sha256': 'c' * 64, 'canary_inventory': {}}
    return package, report


@pytest.mark.parametrize('damage', ['missing-role', 'uncalibrated', 'allowed-home', 'allowed-network',
                                    'reviewer-write', 'helper-identity', 'canary-identity', 'native-claim',
                                    'same-cdhash', 'policy', 'bad-errno', 'missing-denials', 'allowed-write', 'bundle-write'])
def test_stored_control_cannot_hide_missing_or_failed_os_evidence(monkeypatch, damage):
    import native.qemu_guest.qualification_package as module
    package, report = package_report()
    monkeypatch.setattr(module, 'verify_package_files', lambda _package: None)
    monkeypatch.setattr(module, 'code_identity', lambda name: deepcopy(package[name + '_identity']
                        if name == 'canary' else package['identity']))
    operations = {
        'missing-role': lambda: report['results'].pop(),
        'uncalibrated': lambda: report['results'][0]['report']['network']['tcp4'].update(allowed=False),
        'allowed-home': lambda: report['results'][1]['report']['negative']['home'].update(allowed=True),
        'allowed-network': lambda: report['results'][1]['report']['network']['tcp4'].update(allowed=True),
        'reviewer-write': lambda: report['results'][4]['report']['devices']['task'].update(write=True),
        'helper-identity': lambda: report.update(helper_identity={'identifier': 'foreign'}),
        'canary-identity': lambda: report['results'][1]['report']['identity'].update(cdhash='foreign'),
        'native-claim': lambda: report.update(helper_execution='PASS'),
        'same-cdhash': lambda: report.update(same_cdhash_canary_execution=True),
        'policy': lambda: report.update(static_policy_sha256='foreign'),
        'bad-errno': lambda: report['results'][1]['report']['negative']['home'].update(errno=2),
        'missing-denials': lambda: report['results'][1]['report']['negative'].clear(),
        'allowed-write': lambda: report['results'][1]['report']['negative_writes']['project'].update(allowed=True),
        'bundle-write': lambda: report['results'][1]['report']['bundle_write'].update(allowed=True),
    }
    operations[damage]()
    with pytest.raises(ValueError):
        verify_sandbox_controls(report, package)


def test_complete_controls_keep_exact_helper_execution_unqualified(monkeypatch):
    import native.qemu_guest.qualification_package as module
    package, report = package_report()
    monkeypatch.setattr(module, 'verify_package_files', lambda _package: None)
    monkeypatch.setattr(module, 'code_identity', lambda name: package['canary_identity']
                        if name == 'canary' else package['identity'])
    assert verify_sandbox_controls(report, package) is True
    assert report['helper_execution'] == 'NOT_RUN'
    assert report['same_cdhash_canary_execution'] is False


@pytest.fixture
def signed_canary_package(tmp_path):
    fixture = Path('/Users/timmywen/Documents/AI_Colleague/evidence/'
                   'pr15-qemu-hvf-feasibility-20261121/apple-public-test.keychain')
    if not fixture.is_file():
        pytest.skip('External exact public Apple test fixture unavailable; never use a real keychain')
    objects = build_objects(tmp_path / 'objects')
    kernel, initramfs = tmp_path / 'kernel.fixture', tmp_path / 'initramfs.fixture'
    kernel.write_bytes(b'PUBLIC_CANARY_READ_ONLY_KERNEL_BYTES')
    initramfs.write_bytes(b'PUBLIC_CANARY_READ_ONLY_INITRAMFS_BYTES')
    return package_candidate(binary=objects['canary'], objects=objects, kernel=kernel,
        initramfs=initramfs, output=tmp_path / 'package', fixture=fixture,
        source_bindings={'guest': '9a270a78b421565a64901182062b18a0d3b2e673'})


@pytest.mark.platforms('macos')
def test_real_signed_no_hvf_canary_controls(tmp_path, signed_canary_package):
    package = signed_canary_package
    report = run_sandbox_controls(package, tmp_path / 'controls')
    assert verify_sandbox_controls(report, package)
    assert len(report['results']) == 6 and report['qemu_executions'] == 0
    assert package['helper_execution'] == 'NOT_RUN'
    assert report['canary_identity']['identifier'] == report['helper_identity']['identifier']
    assert json.loads((tmp_path / 'controls/sandbox-controls.json').read_text()) == report


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('damage', ['extra-argument', 'wrong-role', 'wrong-inode', 'writable-root', 'hardlink-root', 'duplicate-key'])
def test_compiled_preflight_refuses_changed_manifest_before_any_vm(tmp_path, signed_canary_package, monkeypatch, damage):
    import native.qemu_guest.qualification_package as module
    original = module.make_bootstrap
    if damage == 'duplicate-key':
        encode = module.canonical
        monkeypatch.setattr(module, 'canonical', lambda value: encode(value)[:-1] + ',"role":"developer"}'
                            if value.get('schema') == 'HERMES_Q2_SANDBOX_PLAN_V1' else encode(value))
    def changed(*args):
        record = original(*args)
        operations = {
            'extra-argument': lambda: record['qemu_argv'].extend(['-netdev', 'user,id=forbidden']),
            'wrong-role': lambda: record.update(role='reviewer'),
            'wrong-inode': lambda: record['devices']['root'].update(st_ino=record['devices']['root']['st_ino'] + 1),
            'writable-root': lambda: record['devices'].update(root=dict(record['devices']['task'])),
            'hardlink-root': lambda: os.link(tmp_path / 'refused/root.public', tmp_path / 'foreign-link'),
            'duplicate-key': lambda: None,
        }
        operations[damage]()
        return record
    monkeypatch.setattr(module, 'make_bootstrap', changed)
    with pytest.raises(RuntimeError, match='q2_canary_report_missing:rc=2:'):
        module._one_control(signed_canary_package, 'developer', 'unrestricted', tmp_path / 'refused')
    assert 'HERMES_Q2_PREFLIGHT_REFUSED' in (tmp_path / 'refused/stderr.log').read_text()


@pytest.mark.parametrize('field', ['descriptor_identity', 'approved_reads'])
def test_calibration_rejects_unobserved_required_fact(field):
    report = control('developer', True)
    report[field] = False
    assert _calibration_ok(report, True, 'developer') is False



@pytest.mark.parametrize('name', ['qemu-system-aarch64', 'arbitrary-helper'])
def test_control_selector_refuses_helper_before_any_program_probe(monkeypatch, name):
    import native.qemu_guest.qualification_package as module
    package = {'canary': '/approved/Canary.app/Contents/MacOS/' + name,
               'positive': '/approved/Calibration.app/Contents/MacOS/sandbox-canary',
               'helper': '/approved/Helper.app/Contents/MacOS/qemu-system-aarch64'}
    calls = []
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match='q2_no_hvf_canary_required'):
        module.verify_canary_programs(package)
    assert calls == []


@pytest.mark.platforms('macos')
@pytest.mark.parametrize(('plan', 'release', 'returncode', 'core_reports'), [
    ('accepted', b'HERMES_HVF_RELEASE_V1\n', 0, 1),
    ('rejected', b'HERMES_HVF_RELEASE_V1\n', 2, 0),
    ('accepted', b'WRONG_RELEASE\n', 2, 1),
])
def test_q2_composes_one_existing_pre_qmp_release_reader(tmp_path, plan, release, returncode, core_reports):
    source = Path(__file__).resolve().parents[2] / 'native'
    driver = tmp_path / 'inert-driver.c'
    driver.write_text('#include <string.h>\n'
                      'extern int hermes_q2_gate(const char*,int,char**);\n'
                      'int hermes_q2_preflight(const char*p,int c,char**v){(void)c;(void)v;return strcmp(p,"accepted")?2:0;}\n'
                      'int main(int c,char**v){return c==2?hermes_q2_gate(v[1],0,0):2;}\n')
    binary = tmp_path / 'inert-release-driver'
    subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', driver,
                    source / 'qemu_guest/qualification_gate.c', source / 'qemu_hvf/admission_gate.c',
                    '-o', binary], check=True, capture_output=True, timeout=30)
    result = subprocess.run([binary, plan], input=release, capture_output=True, check=False, timeout=3)
    assert result.returncode == returncode
    assert result.stderr.count(b'HERMES_HVF_CORE_LIMIT_V1 ') == core_reports


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('role', ['developer', 'reviewer'])
@pytest.mark.parametrize('append_newline', [False, True])
def test_original_owner_bootstrap_is_consumed_by_actual_native_parser(
        tmp_path, signed_canary_package, role, append_newline):
    """Exercise Owner-produced bytes, never Helper/QEMU or a Native VM."""
    from contextlib import ExitStack
    from types import SimpleNamespace
    import hashlib
    import socket
    from gateway.session_guest_hvf import _bootstrap
    from native.qemu_guest.qualification_package import PREFIX, _control_socket, verify_canary_programs

    package = dict(signed_canary_package, resources=signed_canary_package['canary_resources'],
                   static_policy_sha256=signed_canary_package['canary_static_policy_sha256'])
    verify_canary_programs(package)
    record = {'task_id': 'PUBLIC_OWNER_WRITER_FIXTURE', 'run_id': 1, 'epoch': 1,
              'vm_id': 'NO_VM', 'attempt': 'owner-native-parser-' + role,
              'instance': 'NO_OWNER_CANARY', 'slot': 2 if role == 'reviewer' else 1}
    handle = SimpleNamespace(record=record, batch=SimpleNamespace(body={'helper_package': package}))
    with ExitStack() as stack:
        policy = json.loads(Path(package['static_policy']).read_text())
        for path in policy['unix'].values():
            _control_socket(stack, socket.AF_UNIX, socket.SOCK_STREAM, path)
        descriptors = {}
        for name in ('root', 'task', 'assignment'):
            path = tmp_path / (name + '.owner-writer-public')
            path.write_bytes(b'PUBLIC_OWNER_WRITER_INERT_DEVICE\n')
            mode = os.O_RDWR if role == 'developer' and name == 'task' else os.O_RDONLY
            fd = os.open(path, mode)
            stack.callback(os.close, fd)
            stat = os.fstat(fd)
            descriptors[name] = {'fd': fd, 'st_dev': stat.st_dev, 'st_ino': stat.st_ino, 'size': stat.st_size}
        parent, child = socket.socketpair()
        stack.callback(parent.close)
        stack.callback(child.close)
        manifest = tmp_path / 'owner-bootstrap.json'
        plan, checksum = _bootstrap(handle, SimpleNamespace(descriptors=lambda: descriptors), child.fileno(), manifest)
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == checksum
        if append_newline:
            with manifest.open('ab') as stream:
                stream.write(b'\n')
        fd = os.open(manifest, os.O_RDONLY)
        stack.callback(os.close, fd)
        result = subprocess.run([package['canary'], '/dev/fd/' + str(fd), *plan['qemu_argv']],
            pass_fds=tuple(row['fd'] for row in descriptors.values()) + (child.fileno(), fd),
            capture_output=True, text=True, check=False, timeout=20,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path / 'unrelated-host-home')})
    if append_newline:
        assert result.returncode == 2
        assert 'HERMES_Q2_PREFLIGHT_REFUSED manifest_policy_or_fd' in result.stderr
        assert PREFIX not in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        reports = [json.loads(line[len(PREFIX):]) for line in result.stderr.splitlines() if line.startswith(PREFIX)]
        assert len(reports) == 1 and reports[0]['pass'] is True
        assert reports[0]['vm_created'] is False and reports[0]['canary'] is True
