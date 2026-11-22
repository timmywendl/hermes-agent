"""Q2 exact diagnostic contracts using compiled inert fixtures, never a QEMU VM."""
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


def device_records(role='developer'):
    records = {name: {'fd': index, 'st_dev': 1, 'st_ino': index, 'size': 4096,
                   'sha256': 'a' * 64, 'readonly': name != 'task'}
            for index, name in enumerate(('root', 'task', 'assignment'), 10)}
    if role == 'developer':
        records['task']['ro_fd'] = 13
    return records


def test_bootstrap_projects_capabilities_without_guest_path_authority():
    devices = device_records('reviewer')
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
    assert args.count('-add-fd') == 4
    assert [args[i + 1] for i, value in enumerate(args) if value == '-add-fd' and 'set=2' in args[i + 1]] == [
        'fd=11,set=2', 'fd=13,set=2']
    assert not any('auto-read-only' in value for value in args)


@pytest.mark.parametrize('damage', ['missing', 'alias', 'serial', 'reviewer'])
def test_bootstrap_rejects_unbound_task_readonly_handle(damage):
    role = 'reviewer' if damage == 'reviewer' else 'developer'
    records = device_records(role)
    operations = {'missing': lambda: records['task'].pop('ro_fd'),
                  'alias': lambda: records['task'].update(ro_fd=records['task']['fd']),
                  'serial': lambda: records['task'].update(ro_fd=20),
                  'reviewer': lambda: records['task'].update(ro_fd=13)}
    operations[damage]()
    with pytest.raises(ValueError):
        make_bootstrap({'static_policy_sha256': 'b' * 64, 'resources': '/approved'}, records, 20, role, {})


def control(role, sandboxed):
    writable = role == 'developer'
    bindings = device_records(role)
    devices = {name: dict({key: row[key] for key in ('fd', 'st_dev', 'st_ino', 'size')},
                          read=True, write=name == 'task' and writable, observed=True,
                          access=os.O_RDWR if name == 'task' and writable else os.O_RDONLY)
               for name, row in bindings.items()}
    if role == 'developer':
        devices['task']['ro'] = dict(devices['task'], fd=bindings['task']['ro_fd'], write=False, write_errno=9, access=os.O_RDONLY)
    return {'vm_created': False, 'descriptor_identity': True, 'approved_reads': True,
            'devices': dict(devices, serial_identity=True), 'role': role, 'serial_fd': 20,
            'pid': 123, 'canary': True,
            'pass': sandboxed, 'sandbox': sandboxed, 'hypervisor': sandboxed,
            'network_entitlements_absent': True,
            'negative': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                         for key in ('home', 'provider', 'board', 'session_db', 'project', 'ssh_key', 'ssh_agent', 'docker')},
            'negative_writes': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                                for key in ('home', 'provider', 'board', 'session_db', 'project', 'ssh_key')},
            'bundle_write': {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0},
            'network': {key: {'allowed': not sandboxed, 'errno': 1 if sandboxed else 0}
                        for key in ('tcp4', 'udp4', 'tcp6', 'udp6', 'listen4', 'listen6')},
            'legacy_keychain': {'public_dummy_matches': not sandboxed}, 'identity': {}}


def package_report():
    from native.qemu_guest.qualification_package import ENTITLEMENTS, PREFLIGHT_FLAG
    package = {'identity': {'identifier': 'fixed', 'cdhash': 'helper', 'entitlements': ENTITLEMENTS},
               'helper': '/public/HermesQ2HVF.app/Contents/MacOS/qemu-system-aarch64', 'inventory': {},
               'helper_sha256': 'd' * 64, 'static_policy_sha256': 'a' * 64,
               'objects': {'object_sha256': {'preflight': 'b' * 64}}}
    rows = []
    for role in ('developer', 'reviewer'):
        for mode in ('unrestricted', 'sandboxed', 'positive-recheck'):
            record = control(role, mode == 'sandboxed')
            record['identity'] = dict(package['identity'], executable=package['helper'],
                executable_sha256=package['helper_sha256'], package_inventory=package['inventory'])
            rows.append({'role': role, 'mode': mode, 'returncode': 0 if mode == 'sandboxed' else 2,
                         'report': record, 'argv': [package['helper'], PREFLIGHT_FLAG], 'child_pid': 123,
                         'devices': {name: {key: row[key] for key in ('fd', 'st_dev', 'st_ino', 'size') + (('ro_fd',) if role == 'developer' and name == 'task' else ())}
                                     for name, row in device_records(role).items()}, 'serial_fd': 20})
    report = {'schema': 'HERMES_Q2_SANDBOX_CONTROLS_V2', 'status': 'PASS_EXACT_HELPER_SANDBOX_PREFLIGHT',
              'helper_execution': 'NO_VM_PREFLIGHT_ONLY', 'helper_identity': package['identity'],
              'helper_sha256': package['helper_sha256'], 'package_inventory': {},
              'preflight_object_sha256': 'b' * 64, 'static_policy_sha256': 'a' * 64,
              'same_cdhash_helper_execution': True, 'results': rows,
              'execution_counts': {'helper_preflight_invocations': 2, 'qemu_runtime_entries': 0,
                  'qemu_vm_creates': 0, 'guest_starts': 0, 'worker_executions': 0}}
    return package, report


@pytest.mark.parametrize('damage', ['missing-role', 'uncalibrated', 'allowed-home', 'allowed-network',
                                    'reviewer-write', 'helper-identity', 'cdhash', 'native-claim',
                                    'same-cdhash', 'policy', 'bad-errno', 'missing-denials', 'allowed-write',
                                    'bundle-write', 'entitlement', 'executable-sha', 'inventory', 'wrong-role',
                                    'fd-identity', 'fd-access', 'serial-fd', 'old-canary', 'wrong-entry',
                                    'runtime-entry', 'vm-create', 'extra-invocation', 'child-pid',
                                    'ro-missing', 'ro-write', 'ro-mode', 'ro-inode', 'ro-fd'])
def test_stored_control_cannot_hide_missing_or_failed_os_evidence(monkeypatch, damage):
    import native.qemu_guest.qualification_package as module
    package, report = package_report()
    monkeypatch.setattr(module, 'verify_package_files', lambda _package: None)
    monkeypatch.setattr(module, 'code_identity', lambda _name: deepcopy(package['identity']))
    observed = report['results'][1]['report']
    operations = {
        'missing-role': lambda: report['results'].pop(),
        'uncalibrated': lambda: report['results'][0]['report']['network']['tcp4'].update(allowed=False),
        'allowed-home': lambda: observed['negative']['home'].update(allowed=True),
        'allowed-network': lambda: observed['network']['tcp4'].update(allowed=True),
        'reviewer-write': lambda: report['results'][4]['report']['devices']['task'].update(write=True),
        'helper-identity': lambda: report.update(helper_identity={'identifier': 'foreign'}),
        'cdhash': lambda: observed['identity'].update(cdhash='foreign'),
        'native-claim': lambda: report.update(helper_execution='PASS'),
        'same-cdhash': lambda: report.update(same_cdhash_helper_execution=False),
        'policy': lambda: report.update(static_policy_sha256='foreign'),
        'bad-errno': lambda: observed['negative']['home'].update(errno=2),
        'missing-denials': lambda: observed['negative'].clear(),
        'allowed-write': lambda: observed['negative_writes']['project'].update(allowed=True),
        'bundle-write': lambda: observed['bundle_write'].update(allowed=True),
        'entitlement': lambda: observed['identity'].update(entitlements={'com.apple.security.hypervisor': True}),
        'executable-sha': lambda: observed['identity'].update(executable_sha256='foreign'),
        'inventory': lambda: observed['identity'].update(package_inventory={'foreign': 'd' * 64}),
        'wrong-role': lambda: observed.update(role='reviewer'),
        'fd-identity': lambda: observed['devices']['root'].update(st_ino=999),
        'fd-access': lambda: observed['devices']['root'].update(access=os.O_RDWR),
        'serial-fd': lambda: observed.update(serial_fd=99),
        'old-canary': lambda: report.update(status='PASS_POLICY_EQUIVALENT_CANARY_ONLY'),
        'wrong-entry': lambda: report['results'][1].update(argv=['foreign-canary']),
        'runtime-entry': lambda: report['execution_counts'].update(qemu_runtime_entries=1),
        'vm-create': lambda: report['execution_counts'].update(qemu_vm_creates=1),
        'extra-invocation': lambda: report['execution_counts'].update(helper_preflight_invocations=3),
        'child-pid': lambda: observed.update(pid=456),
        'ro-missing': lambda: observed['devices']['task'].pop('ro'),
        'ro-write': lambda: observed['devices']['task']['ro'].update(write=True),
        'ro-mode': lambda: observed['devices']['task']['ro'].update(access=os.O_RDWR),
        'ro-inode': lambda: observed['devices']['task']['ro'].update(st_ino=999),
        'ro-fd': lambda: observed['devices']['task']['ro'].update(fd=observed['devices']['task']['fd']),
    }
    operations[damage]()
    with pytest.raises(ValueError):
        verify_sandbox_controls(report, package)


def test_complete_exact_controls_bind_same_helper_and_never_authorize_a_vm(monkeypatch):
    import native.qemu_guest.qualification_package as module
    package, report = package_report()
    monkeypatch.setattr(module, 'verify_package_files', lambda _package: None)
    monkeypatch.setattr(module, 'code_identity', lambda _name: package['identity'])
    assert verify_sandbox_controls(report, package) is True
    assert report['helper_execution'] == 'NO_VM_PREFLIGHT_ONLY'
    assert report['same_cdhash_helper_execution'] is True


def test_legacy_canary_cannot_be_promoted_by_relabeling_its_summary(monkeypatch):
    import native.qemu_guest.qualification_package as module
    package, report = package_report()
    monkeypatch.setattr(module, 'verify_package_files', lambda _package: None)
    monkeypatch.setattr(module, 'code_identity', lambda _name: package['identity'])
    report['results'][1]['report']['identity'] = {'identifier': 'fixed', 'cdhash': 'different-canary'}
    with pytest.raises(ValueError, match='q2_exact_helper_code_identity_changed'):
        verify_sandbox_controls(report, package)


def test_relink_cannot_claim_a_changed_main_without_compiling_it(tmp_path, monkeypatch):
    import native.qemu_guest.qualification_package as module
    commands = []
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs: commands.append(args))
    with pytest.raises(ValueError, match='q2_changed_main_requires_fresh_build'):
        module.relink_helper({'q2_patch_sha256': '0' * 64}, tmp_path / 'refused')
    assert not (tmp_path / 'refused').exists()
    assert commands == []


def compile_patched_main(output, objects=None):
    """Apply the production patch to an inert main with observable trap entries."""
    from native.qemu_guest.qualification_package import HERE
    output.mkdir()
    system = output / 'system'
    system.mkdir()
    source = system / 'main.c'
    source.write_text(
        '#include <stdio.h>\n#include <string.h>\n'
        'static void qemu_init(int c,char**v){(void)c;(void)v;fputs("QEMU_RUNTIME_ENTRY\\n",stderr);}\n'
        'static int os_darwin_cfrunloop_main(void){fputs("QEMU_MAIN_ENTRY\\n",stderr);return 91;}\n'
        '#if 1\nint (*qemu_main)(void) = os_darwin_cfrunloop_main;\n#endif\n\n'
        'extern int hermes_hvf_admission_gate(void);\n'
        'extern int hermes_hvf_preflight(const char *plan_path);\n\n'
        'int main(int argc, char **argv)\n{\n'
        '    if (argc < 3 || strcmp(argv[1], "--hermes-hvf-q1") != 0) {\n'
        '        return 2;\n    }\n'
        '    if (hermes_hvf_admission_gate() != 0 || hermes_hvf_preflight(argv[2]) != 0) {\n'
        '        return 2;\n    }\n'
        '    char *executable = argv[0];\n'
        '    argc -= 2;\n    argv += 2;\n    argv[0] = executable;\n'
        '    qemu_init(argc, argv);\n    return qemu_main();\n}\n')
    subprocess.run(['patch', '--fuzz=0', '-p1', '-i', HERE / 'qualification-main.patch'],
                   cwd=output, capture_output=True, check=True, timeout=10)
    if objects is None:
        stub = output / 'diagnostic-stub.c'
        stub.write_text(
            '#include <stdio.h>\n'
            'int hermes_q2_gate(const char*p,int c,char**v){(void)p;(void)c;(void)v;'
            'fputs("GATE_ENTRY\\n",stderr);return 0;}\n'
            'int hermes_q2_canary(const char*p,int c,char**v){(void)p;(void)c;(void)v;'
            'fputs("DIAGNOSTIC_ENTRY\\n",stderr);return 67;}\n')
        inputs, frameworks = [stub], []
    else:
        inputs = list(objects['objects'].values())
        frameworks = ['-framework', 'Foundation', '-framework', 'Security', '-framework', 'LocalAuthentication']
    binary = output / 'inert-main'
    subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', source, *inputs,
                    *frameworks, '-o', binary], capture_output=True, check=True, timeout=30)
    return binary


@pytest.mark.platforms('macos')
@pytest.mark.parametrize(('argv', 'code', 'markers'), [
    (['--hermes-q2-sandbox-preflight', '/dev/fd/4'], 67, ['DIAGNOSTIC_ENTRY']),
    (['--hermes-q2-sandbox-preflight'], 2, []),
    (['--hermes-q2-sandbox-preflight-foreign', '/dev/fd/4'], 2, []),
    ([], 2, []),
    (['--hermes-hvf-q2', 'manifest'], 91, ['GATE_ENTRY', 'QEMU_RUNTIME_ENTRY', 'QEMU_MAIN_ENTRY']),
])
def test_actual_main_patch_returns_before_all_normal_runtime_entries(tmp_path, argv, code, markers):
    binary = compile_patched_main(tmp_path / 'patched')
    result = subprocess.run([binary, *argv], capture_output=True, check=False, text=True, timeout=5)
    assert result.returncode == code
    assert result.stderr.splitlines() == markers
    assert result.stdout == ''


@pytest.fixture
def signed_inert_helper_package(tmp_path):
    fixture = Path('/Users/timmywen/Documents/AI_Colleague/evidence/'
                   'pr15-qemu-hvf-feasibility-20261121/apple-public-test.keychain')
    if not fixture.is_file():
        pytest.skip('External exact public Apple test fixture unavailable; never use a real keychain')
    objects = build_objects(tmp_path / 'objects')
    kernel, initramfs = tmp_path / 'kernel.fixture', tmp_path / 'initramfs.fixture'
    kernel.write_bytes(b'PUBLIC_CANARY_READ_ONLY_KERNEL_BYTES')
    initramfs.write_bytes(b'PUBLIC_CANARY_READ_ONLY_INITRAMFS_BYTES')
    return package_candidate(binary=compile_patched_main(tmp_path / 'patched', objects), objects=objects, kernel=kernel,
        initramfs=initramfs, output=tmp_path / 'package', fixture=fixture,
        source_bindings={'guest': '9a270a78b421565a64901182062b18a0d3b2e673'})


@pytest.mark.platforms('macos')
def test_signed_inert_main_fixture_uses_exact_primary_diagnostic(tmp_path, signed_inert_helper_package):
    package = signed_inert_helper_package
    report = run_sandbox_controls(package, tmp_path / 'controls')
    assert verify_sandbox_controls(report, package)
    assert len(report['results']) == 6 and report['execution_counts']['qemu_runtime_entries'] == 0
    assert package['helper_execution'] == 'NOT_RUN'
    assert report['same_cdhash_helper_execution'] is True
    assert json.loads((tmp_path / 'controls/sandbox-controls.json').read_text()) == report


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('marker', ['HERMES_HVF_VM_CREATE_V1', 'HERMES_HVF_VM_DESTROY_V1', 'QEMU_RUNTIME_ENTRY'])
def test_exact_diagnostic_rejects_any_normal_runtime_marker(tmp_path, signed_inert_helper_package, monkeypatch, marker):
    import native.qemu_guest.qualification_package as module
    original = module._invoke_control
    def observed(*args):
        result, pid = original(*args)
        if args[0][0] == signed_inert_helper_package['helper']:
            result.stderr += '\n' + marker + '\n'
        return result, pid
    monkeypatch.setattr(module, '_invoke_control', observed)
    with pytest.raises(RuntimeError, match='q2_preflight_entered_qemu_runtime'):
        run_sandbox_controls(signed_inert_helper_package, tmp_path / 'controls')
    assert not (tmp_path / 'controls/reviewer-unrestricted').exists()


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('entitlements', [
    {'com.apple.security.app-sandbox': True},
    {'com.apple.security.hypervisor': True},
    {'com.apple.security.app-sandbox': True, 'com.apple.security.hypervisor': True,
     'com.apple.security.network.client': True},
])
def test_signed_helper_wrong_entitlement_is_rejected_without_execution(tmp_path, signed_inert_helper_package, entitlements):
    import plistlib
    from native.qemu_guest.qualification_package import code_identity
    manifest = tmp_path / 'wrong.entitlements'
    manifest.write_bytes(plistlib.dumps(entitlements))
    subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', manifest,
                    signed_inert_helper_package['app']], check=True, capture_output=True, timeout=10)
    with pytest.raises(ValueError, match='q2_exact_signed_sandbox_identity_required'):
        code_identity(signed_inert_helper_package['helper'])


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('damage', ['missing', 'writable', 'inode', 'size', 'alias', 'serial', 'malformed', 'reviewer'])
def test_native_dual_handle_rejects_tampering_before_any_runtime(tmp_path, signed_inert_helper_package, monkeypatch, damage):
    import native.qemu_guest.qualification_package as module
    original_make, original_invoke = module.make_bootstrap, module._invoke_control
    replaced = {}
    role = 'reviewer' if damage == 'reviewer' else 'developer'
    def changed(package, devices, serial, selected_role, owner):
        plan = original_make(package, devices, serial, selected_role, owner)
        if damage in {'writable', 'inode', 'size'}:
            path = tmp_path / 'refused/task.public' if damage == 'writable' else tmp_path / 'foreign.public'
            if damage != 'writable':
                path.write_bytes(b'x' if damage == 'size' else (tmp_path / 'refused/task.public').read_bytes())
            fd = os.open(path, os.O_RDWR if damage == 'writable' else os.O_RDONLY)
            replaced.update(old=devices['task']['ro_fd'], new=fd)
            plan['devices']['task']['ro_fd'] = fd
        else:
            operations = {'missing': lambda: plan['devices']['task'].pop('ro_fd'),
                          'alias': lambda: plan['devices']['task'].update(ro_fd=devices['task']['fd']),
                          'serial': lambda: plan['devices']['task'].update(ro_fd=serial),
                          'malformed': lambda: plan['devices']['task'].update(ro_fd='not-an-fd'),
                          'reviewer': lambda: plan['devices']['task'].update(ro_fd=devices['task']['fd'])}
            operations[damage]()
        if damage not in {'missing', 'malformed'}:
            plan['qemu_argv'] = module.qemu_argv(package['resources'], plan['devices'], serial, selected_role)
        return plan
    def invoked(argv, fds, output):
        if replaced:
            fds = [fd for fd in fds if fd != replaced['old']] + [replaced['new']]
        return original_invoke(argv, fds, output)
    monkeypatch.setattr(module, 'make_bootstrap', changed)
    monkeypatch.setattr(module, '_invoke_control', invoked)
    try:
        with pytest.raises(RuntimeError, match='q2_preflight_report_missing:rc=2:'):
            module._one_control(signed_inert_helper_package, role, 'unrestricted', tmp_path / 'refused')
    finally:
        if replaced:
            os.close(replaced['new'])
    assert 'HERMES_Q2_PREFLIGHT_REFUSED' in (tmp_path / 'refused/stderr.log').read_text()


@pytest.mark.platforms('macos')
@pytest.mark.parametrize('damage', ['extra-argument', 'wrong-role', 'wrong-inode', 'writable-root', 'hardlink-root', 'duplicate-key'])
def test_compiled_preflight_refuses_changed_manifest_before_any_vm(tmp_path, signed_inert_helper_package, monkeypatch, damage):
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
    with pytest.raises(RuntimeError, match='q2_preflight_report_missing:rc=2:'):
        module._one_control(signed_inert_helper_package, 'developer', 'unrestricted', tmp_path / 'refused')
    assert 'HERMES_Q2_PREFLIGHT_REFUSED' in (tmp_path / 'refused/stderr.log').read_text()


@pytest.mark.parametrize('field', ['descriptor_identity', 'approved_reads'])
def test_calibration_rejects_unobserved_required_fact(field):
    report = control('developer', True)
    report[field] = False
    assert _calibration_ok(report, True, 'developer') is False



@pytest.mark.parametrize('name', ['sandbox-canary', 'arbitrary-helper'])
def test_control_selector_refuses_helper_before_any_program_probe(monkeypatch, name):
    import native.qemu_guest.qualification_package as module
    package = {'helper': '/approved/HermesQ2HVF.app/Contents/MacOS/' + name,
               'positive': '/approved/Calibration.app/Contents/MacOS/sandbox-canary',
               'identity': {}}
    calls = []
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match='q2_exact_helper_preflight_required'):
        module.verify_preflight_programs(package)
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
        tmp_path, signed_inert_helper_package, role, append_newline):
    """Exercise Owner-produced bytes, never Helper/QEMU or a Native VM."""
    from contextlib import ExitStack
    from types import SimpleNamespace
    import hashlib
    import socket
    from gateway.session_guest_hvf import _bootstrap
    from native.qemu_guest.qualification_package import PREFLIGHT_FLAG, PREFIX, _control_socket, verify_preflight_programs

    package = signed_inert_helper_package
    verify_preflight_programs(package)
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
        if role == 'developer':
            ro_fd = os.open(tmp_path / 'task.owner-writer-public', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, ro_fd)
            descriptors['task']['ro_fd'] = ro_fd
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
        result = subprocess.run([package['helper'], PREFLIGHT_FLAG, '/dev/fd/' + str(fd), *plan['qemu_argv']],
            pass_fds=tuple(row['fd'] for row in descriptors.values()) + ((descriptors['task']['ro_fd'],) if role == 'developer' else ()) + (child.fileno(), fd),
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
