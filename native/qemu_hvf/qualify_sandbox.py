"""Disposable OS probes only; no QEMU execution, VM creation or admission authority."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import socket
import subprocess

HERE = Path(__file__).resolve().parent
FIXTURE_SHA256 = '87a34479ff2f4f9fd8c6c982a9e461f637a7bd9b88e82b03f3e765a58bf77582'


def build_probes(output):
    flags = ['xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror']
    libs = ['-framework', 'Security', '-framework', 'Foundation', '-framework', 'LocalAuthentication']
    legacy = output / 'legacy.o'
    subprocess.run([*flags, '-DHERMES_HVF_EMBEDDED', '-c', str(HERE / 'legacy_keychain_canary.m'),
                    '-o', str(legacy)], check=True, capture_output=True, text=True, timeout=30)
    binary = output / 'sandbox-canary'
    subprocess.run([*flags, str(HERE / 'sandbox_canary.m'), str(legacy), *libs, '-o', str(binary)],
                   check=True, capture_output=True, text=True, timeout=30)
    return binary


def bind_socket(stack, family, kind, address):
    server = stack.enter_context(socket.socket(family, kind))
    server.bind(address)
    if kind == socket.SOCK_STREAM:
        server.listen(16)
    return server


def make_plan(root, resources, fixture, stack, approved=None):
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != FIXTURE_SHA256:
        raise ValueError('unapproved_public_keychain_fixture')
    negative = root / 'denied'
    negative.mkdir()
    files = {}
    for label in ('home', 'board', 'session_db', 'other_project', 'ssh_key'):
        path = negative / label
        path.write_text('Disposable public canary; no production data.\n')
        files[label] = str(path)
    legacy = negative / 'public-test.keychain'
    shutil.copyfile(fixture, legacy)
    unix = {}
    for label in ('ssh_agent', 'docker'):
        path = negative / label
        # Darwin's sockaddr_un is bounded; long evidence roots are not valid UDS names.
        if len(str(path).encode()) >= 104:
            raise ValueError('canary_root_too_long_for_unix_socket')
        bind_socket(stack, socket.AF_UNIX, socket.SOCK_STREAM, str(path))
        unix[label] = str(path)
    tcp = bind_socket(stack, socket.AF_INET, socket.SOCK_STREAM, ('127.0.0.1', 0))
    udp = bind_socket(stack, socket.AF_INET, socket.SOCK_DGRAM, ('127.0.0.1', 0))
    marker = resources / 'approved-marker'
    marker.write_text('Disposable approved input.\n')
    return {'schema': 'HERMES_HVF_CANARY_PLAN_V1', 'forbidden': files, 'unix': unix,
            'approved': [str(marker), *[str(p) for p in (approved or [])]],
            'write_probe': str(marker),
            'legacy_fixture': str(legacy), 'outside_write': str(negative / 'forbidden-write'),
            'tcp_port': tcp.getsockname()[1], 'udp_port': udp.getsockname()[1]}


def run_controls(root, fixture):
    root.mkdir()
    app = root / 'Canary.app'
    macos = app / 'Contents/MacOS'
    resources = app / 'Contents/Resources'
    macos.mkdir(parents=True)
    resources.mkdir()
    binary = build_probes(root)
    shutil.copyfile(binary, macos / 'canary')
    (macos / 'canary').chmod(0o755)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'org.hermes.pr15.sandbox-canary', 'CFBundleExecutable': 'canary',
        'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSBackgroundOnly': True}))
    with ExitStack() as stack:
        plan = make_plan(root, resources, fixture, stack)
        plan_path = resources / 'canary-plan.json'
        plan_path.write_text(json.dumps(plan, sort_keys=True))
        results = []
        for mode in ('unrestricted', 'sandboxed', 'positive-recheck'):
            command = ['codesign', '--force', '--sign', '-']
            if mode == 'sandboxed':
                command += ['--entitlements', str(HERE / 'helper.entitlements')]
            subprocess.run([*command, str(app)], check=True, capture_output=True, timeout=20)
            result = subprocess.run([str(macos / 'canary'), str(plan_path)],
                                    env={'PATH': '/usr/bin:/bin', 'HOME': str(root / 'host-home')},
                                    capture_output=True, text=True, timeout=20, check=False)
            prefix = 'HERMES_HVF_SANDBOX_V1 '
            lines = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            if len(lines) != 1:
                raise RuntimeError(f'probe_report_unavailable: {result.stderr}')
            results.append({'mode': mode, 'returncode': result.returncode,
                            'report': json.loads(lines[0]), 'stderr': result.stderr})
        baseline, sandboxed, recheck = (r['report'] for r in results)
        for positive in (baseline, recheck):
            if not (positive['approved_reads'] and positive['legacy_keychain']['public_dummy_matches']
                    and all(value['allowed'] for value in positive['negative'].values())
                    and positive['tcp_client']['allowed'] and positive['udp_client']['allowed']
                    and positive['tcp_server']['allowed'] and positive['bundle_write']['allowed']):
                raise RuntimeError('unrestricted_positive_control_failed')
        if not sandboxed['pass'] or results[1]['returncode'] != 0:
            raise RuntimeError('effective_sandbox_negative_control_failed')
    return {'status': 'PASS_OFFLINE_OS_CANARIES_ONLY', 'native_vm_operations': 'NOT_RUN',
            'results': results, 'no_default_keychain_or_search_list_mutation': True}
