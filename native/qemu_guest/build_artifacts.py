"""Offline Q2 construction. Never executes ARM64, mounts a disk or invokes QEMU."""
from __future__ import annotations

import argparse
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from gateway.session_guest_workspace import prepare_workspace
from native.qemu_guest.artifact_fs import EPOCH, POLICY, deb_data, extract_tar, extract_wheel, ext4, newc, policy_header
from native.qemu_guest.build_inputs import SOURCE_HEAD, canonical, digest

HERE = Path(__file__).resolve().parent
RUNTIME_DIRS = frozenset({'agent', 'tools', 'hermes_cli', 'gateway', 'hermes_platform',
                         'pm', 'cron', 'plugins', 'tui_gateway'})
STARTUP_DIRECTORY = '.hermes-q2-startup-v1'
STARTUP_STAGES = {name: index for index, name in enumerate((
    'ROOT_TRANSITION', 'MOUNTS', 'TASK_MOUNTED', 'UART', 'LIMITS', 'IDENTITY',
    'TASK_CWD', 'PYTHON_EXEC', 'PYTHON_ENTRY_IMPORT', 'ENTRY_MAIN',
    'PRE_READY_VALIDATION', 'SERIAL_OPERATION', 'WORKER_RUNTIME', 'CHILD_EXIT',
    'INVALID_DIAGNOSTIC',
), 1)}
# A small failure recorder around the accepted entry, not another Worker.
# Only fixed stage/error numbers survive; never exception text or tracebacks.
PYTHON_STARTUP = r'''import errno
import json
import os
import stat

DIRECTORY = "/task/.hermes-q2-startup-v1"
STAGES = __STAGES__
EXCEPTIONS = {"ModuleNotFoundError": 1, "ImportError": 2, "PermissionError": 3,
              "FileNotFoundError": 4, "ValueError": 5, "OSError": 6,
              "SystemExit": 7}

def encode_receipt(stage, error=0, exception=0, exit_code=-1, signal=0):
    return (json.dumps(dict(version=1, stage=stage, errno=error, exception=exception,
                            exit_code=exit_code, signal=signal),
                       sort_keys=True, separators=(",", ":")) + "\n").encode()

def write_failure(stage, failure):
    # Reviewer must never acquire a writable task capability, even for diagnosis.
    with open("/assignment/policy", "rb") as policy:
        if policy.read(32) != b"developer\n":
            return
    error = getattr(failure, "errno", 0)
    error = error if type(error) is int and 0 <= error <= 4095 else 0
    raw = encode_receipt(stage, error, EXCEPTIONS.get(type(failure).__name__, 8))
    directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError(errno.EPERM, "diagnostic_directory")
        fd = os.open(".pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            if os.write(fd, raw) != len(raw):
                raise OSError(errno.EIO, "diagnostic_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(".pending", "receipt.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)

def classify(failure, stage):
    trace = failure.__traceback__
    for _ in range(64):
        if trace is None:
            break
        module = trace.tb_frame.f_globals.get("__name__")
        function = trace.tb_frame.f_code.co_name
        if ((module == "native.qemu_guest.guest_entry" and function == "validate_mount")
                or (module == "agent.runtime_session_guest" and function == "validate_guest_work")):
            return STAGES["PRE_READY_VALIDATION"]
        if module == "agent.guest_serial":
            stage = STAGES["SERIAL_OPERATION"]
        if module == "agent.managed_worker":
            return STAGES["WORKER_RUNTIME"]
        trace = trace.tb_next
    return stage

def run_entry(load_entry):
    stage = STAGES["PYTHON_ENTRY_IMPORT"]
    try:
        entry = load_entry()
        stage = STAGES["ENTRY_MAIN"]
        entry.main()
    except BaseException as failure:
        try:
            write_failure(classify(failure, stage), failure)
        except OSError:
            raise SystemExit(112) from None  # Diagnostic persistence unavailable.
        raise SystemExit(111) from None

if __name__ == "__main__":
    import importlib
    run_entry(lambda: importlib.import_module("native.qemu_guest.guest_entry"))
'''.replace('__STAGES__', repr(STARTUP_STAGES))
MKE2FS_CONFIG = """[defaults]
base_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr
blocksize = 4096
inode_size = 256
inode_ratio = 16384
[fs_types]
ext4 = {
features = extent,64bit,flex_bg,extra_isize,dir_nlink,huge_file
}
"""


def run(argv, *, env=None, cwd=None):
    return subprocess.check_output([str(value) for value in argv], cwd=cwd, env=env,
                                   stderr=subprocess.PIPE, timeout=300).decode().strip()


def accepted_source(source, root):
    if run(['git', '-C', source, 'rev-parse', SOURCE_HEAD + '^{commit}']) != SOURCE_HEAD:
        raise ValueError('accepted_source_missing')
    data = subprocess.check_output(['git', '-C', str(source), 'archive', SOURCE_HEAD], timeout=60)
    selected = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data)) as original, tarfile.open(fileobj=selected, mode='w') as archive:
        for member in original.getmembers():
            parts = Path(member.name).parts
            keep = (parts[0] in RUNTIME_DIRS or
                    (len(parts) == 1 and (member.name.endswith('.py') or member.name in ('LICENSE', 'uv.lock', 'pyproject.toml'))) or
                    member.name == 'native/qemu_guest/guest_entry.py')
            if keep:
                archive.addfile(member, original.extractfile(member) if member.isreg() else None)
    extract_tar(selected.getvalue(), root / 'opt/hermes')


def root_tree(args, lock, output):
    root = output / 'root-tree'
    root.mkdir()
    for row in lock['inputs']:
        archive = args.downloads / row['filename']
        if archive.is_symlink() or digest(archive) != row['sha256']:
            raise ValueError('build_input_changed:' + row['name'])
        if row['kind'] == 'deb':
            extract_tar(deb_data(archive), root)
        elif row['kind'] == 'python':
            extract_tar(archive.read_bytes(), root / 'opt/python', strip_prefix='python/')
        elif row['kind'] == 'wheel':
            extract_wheel(archive, root / 'opt/python/lib/python3.14/site-packages')
    accepted_source(args.source, root)
    # Tests in a binary Python distribution can contain credential fixtures.
    for name in ('test', 'idlelib/idle_test', 'tkinter/test'):
        shutil.rmtree(root / 'opt/python/lib/python3.14' / name, ignore_errors=True)
    for directory in ('dev', 'proc', 'sys', 'run', 'tmp', 'task', 'assignment', 'home/guest', 'etc', 'sbin'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name, target in (('bin', 'usr/bin'), ('lib', 'usr/lib')):
        if not (root / name).exists():
            (root / name).symlink_to(target)
    if not (root / 'usr/bin/sh').exists():
        (root / 'usr/bin/sh').symlink_to('bash')
    (root / 'etc/passwd').write_text('root:x:0:0:root:/nonexistent:/usr/bin/false\nguest:x:1000:1000:Q2:/home/guest:/bin/bash\n')
    (root / 'etc/group').write_text('root:x:0:\nguest:x:1000:\n')
    (root / 'etc/shadow').write_text('root:*:1:0:99999:7:::\nguest:*:1:0:99999:7:::\n')
    (root / 'etc/shadow').chmod(0o600)
    (root / 'etc/hostname').write_text('q2-offline-candidate\n')
    (root / 'etc/hermes-q2-policy.json').write_text(canonical(POLICY))
    return root


def boot_files(args, output, root, lock):
    binary = output / 'q2-init'
    stages = ''.join(f'#define Q2_STAGE_{name} {value}\n' for name, value in STARTUP_STAGES.items())
    (output / 'q2_policy.h').write_text(policy_header() + stages)
    command = [args.zig, 'cc', '-target', 'aarch64-linux-musl', '-static', '-O2',
               '-Wall', '-Wextra', '-Werror', '-fno-ident', '-s', '-Wl,--build-id=none',
               '-I', output, HERE / 'boot_init.c', '-o', binary]
    run(command, env={**os.environ, 'SOURCE_DATE_EPOCH': str(EPOCH),
                      'ZIG_LOCAL_CACHE_DIR': str(output / 'compiler-cache'),
                      'ZIG_GLOBAL_CACHE_DIR': str(output / 'compiler-global-cache')})
    shutil.copyfile(binary, root / 'sbin/q2-init')
    (root / 'sbin/q2-init').chmod(0o755)
    (root / 'sbin/q2-startup.py').write_text(PYTHON_STARTUP)
    (root / 'sbin/q2-startup.py').chmod(0o444)
    init = output / 'initramfs-tree'
    for name in ('dev', 'proc', 'sys', 'newroot', 'modules'):
        (init / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, init / 'init')
    (init / 'init').chmod(0o755)
    selected = lock['kernel_payload']['modules']
    kernel_package = next(row for row in lock['inputs'] if row['kind'] == 'kernel')
    archive = args.downloads / kernel_package['filename']
    if digest(archive) != kernel_package['sha256']:
        raise ValueError('kernel_package_changed')
    with tarfile.open(fileobj=io.BytesIO(deb_data(archive))) as stream:
        members = {member.name.removeprefix('./'): member for member in stream.getmembers()}
        kernel = stream.extractfile(members[lock['kernel_payload']['image']]).read()
        (output / 'kernel.Image').write_bytes(kernel)
        for row in selected:
            data = stream.extractfile(members[row['vendor_path']]).read()
            data = lzma.decompress(data) if row['vendor_path'].endswith('.xz') else data
            target = init / 'modules' / (row['name'] + '.ko')
            target.write_bytes(data)
            if digest(target) != row['sha256']:
                raise ValueError('vendor_module_changed')
    (output / 'initramfs.cpio.gz').write_bytes(newc(init))
    if digest(output / 'kernel.Image') != lock['kernel_payload']['sha256']:
        raise ValueError('vendor_kernel_changed')
    return {'compiler_argv': [str(value) for value in command],
            'compiler_sha256': digest(args.zig), 'init_sha256': digest(binary),
            'kernel_sha256': digest(output / 'kernel.Image'), 'modules': selected}


def task_fixture(output):
    fixture = output / 'task-fixture'
    fixture.mkdir()
    (fixture / 'README.md').write_text('Q2 offline artifact fixture. No real project or execution authority.\n')
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_AUTHOR_NAME': 'Q2 Offline Build', 'GIT_AUTHOR_EMAIL': 'offline@example.invalid',
           'GIT_COMMITTER_NAME': 'Q2 Offline Build', 'GIT_COMMITTER_EMAIL': 'offline@example.invalid',
           'GIT_AUTHOR_DATE': f'{EPOCH} +0000', 'GIT_COMMITTER_DATE': f'{EPOCH} +0000'}
    run(['git', 'init', '-q', '--object-format=sha1', fixture], env=env)
    run(['git', '-C', fixture, 'add', 'README.md'], env=env)
    run(['git', '-C', fixture, '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Q2 offline device fixture'], env=env)
    return fixture, run(['git', '-C', fixture, 'rev-parse', 'HEAD'], env=env)


def assignment_tree(output, role, head):
    root = output / (role + '-assignment-tree')
    root.mkdir()
    scope = {'session_id': 'OFFLINE_BUILD_ONLY', 'generation': 1, 'epoch': 1,
             'execution_id': 'OFFLINE_BUILD_ONLY:' + role, 'task_id': 'OFFLINE_BUILD_ONLY',
             'run_id': 1, 'vm_id': 'OFFLINE_BUILD_ONLY:' + role, 'connection_generation': 1,
             'image_digest': '0' * 64, 'policy_digest': '0' * 64}
    work = {'version': 'HERMES_GUEST_WORK_V1', 'assignment': scope, 'title': 'Offline artifact fixture',
            'body': 'No admission, execution grant, model or real project is supplied.',
            'repo': 'offline/q2-artifact', 'base_commit': head, 'branch': 'task/guest',
            'workspace': '/task', 'role': role, 'model': 'D2_NOT_ACCEPTED', 'completion_contract': 'NOT_RUN'}
    (root / 'work.json').write_text(canonical(work))
    (root / 'policy').write_text(role + '\n')
    return root


def provision_startup_directory(root, role):
    """Builder-owned reserved path; ext4 normalization supplies UID/GID1000."""
    root = Path(root)
    reserved = root / STARTUP_DIRECTORY
    if reserved.exists() or reserved.is_symlink():
        raise ValueError('q2_reserved_startup_path')
    if role not in ('developer', 'reviewer'):
        raise ValueError('q2_startup_role_invalid')
    if role == 'reviewer':
        return
    reserved.mkdir(mode=0o700)
    reserved.chmod(0o700)
    exclude = root / '.git/info/exclude'
    exclude.parent.mkdir(exist_ok=True)
    with exclude.open('a') as stream:
        stream.write('\n/' + STARTUP_DIRECTORY + '/\n')


def private_git_snapshot(root):
    """Omit Host stat-cache/reflog data while retaining a valid private index."""
    shutil.rmtree(root / '.git/logs')
    (root / '.git/index').unlink()
    run(['git', '-C', root, '-c', 'core.hooksPath=/dev/null', 'read-tree', 'HEAD'],
        env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'})


def require_case_sensitive(directory):
    probe = Path(directory) / 'CaseSensitiveProbe'
    probe.write_bytes(b'case-sensitive Linux staging required')
    try:
        if probe.with_name('casesensitiveprobe').exists():
            raise ValueError('case_sensitive_build_volume_required')
    finally:
        probe.unlink()


def verify_tools(args, lock):
    for name in ('zig', 'mke2fs'):
        if digest(getattr(args, name)) != lock['host_tools'][name]['sha256']:
            raise ValueError('build_tool_changed:' + name)


def build(args):
    lock = json.loads((HERE / 'artifact-inputs.lock.json').read_text())
    if (lock['source_head'] != SOURCE_HEAD or digest(args.source / 'uv.lock') != lock['uv_lock_sha256']
            or digest(args.source / 'pm/lock.json') != lock['pm_lock_sha256']):
        raise ValueError('source_dependency_lock_changed')
    verify_tools(args, lock)
    args.output.mkdir(parents=True, exist_ok=False)
    require_case_sensitive(args.output)
    for name in ('builder-home', 'builder-tmp'):
        (args.output / name).mkdir()
    os.environ.update(HOME=str(args.output / 'builder-home'), TMPDIR=str(args.output / 'builder-tmp'))
    config = args.output / 'mke2fs.conf'
    config.write_text(MKE2FS_CONFIG)
    root = root_tree(args, lock, args.output)
    boot = boot_files(args, args.output, root, lock)
    fixture, head = task_fixture(args.output)
    images = {}
    images['root'] = ext4(root, args.output / 'root.raw', label='Q2ROOT', mib=1024,
                          tool=args.mke2fs, config=config)
    for role in ('developer', 'reviewer'):
        task = prepare_workspace(fixture, args.output / (role + '-task-tree'), head=head, role=role)
        private_git_snapshot(task.root)
        provision_startup_directory(task.root, role)
        images[role + '_task'] = ext4(task.root, args.output / (role + '-task.raw'),
            label='Q2DEV' if role == 'developer' else 'Q2REVIEW', mib=64,
            tool=args.mke2fs, config=config, owner=1000)
        assignment = assignment_tree(args.output, role, head)
        images[role + '_assignment'] = ext4(assignment, args.output / (role + '-assignment.raw'),
            label='Q2DEVASSIGN' if role == 'developer' else 'Q2REVASSIGN', mib=16,
            tool=args.mke2fs, config=config)
    facts = {'schema': 'HERMES_Q2_BUILD_FACTS_V1', 'accepted_source_head': SOURCE_HEAD,
             'source_date_epoch': EPOCH, 'task_fixture_head': head, 'boot': boot,
             'images': images, 'input_lock_sha256': digest(HERE / 'artifact-inputs.lock.json'),
             'recipe_sha256': {name: digest(HERE / name) for name in (
                 'build_artifacts.py', 'artifact_fs.py', 'build_inputs.py', 'boot_init.c')},
             'startup_directory': {'developer_preprovisioned': True, 'path': STARTUP_DIRECTORY,
                                   'uid': 1000, 'gid': 1000, 'mode': '0700', 'reviewer': 'ABSENT'},
             'target_execution': 'NOT_RUN'}
    (args.output / 'build-facts.json').write_text(canonical(facts))
    print(canonical({'output': str(args.output), 'artifacts_constructed': 7, 'boot': 'NOT_RUN'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'downloads', 'output', 'zig', 'mke2fs'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    # Only this packaging process is changed; no Host profile/environment edits.
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', TZ='UTC',
                      GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                      GIT_TERMINAL_PROMPT='0')
    try:
        build(args)
    except subprocess.CalledProcessError as failure:
        if failure.stderr:
            sys.stderr.write(failure.stderr.decode(errors='replace'))
        raise


if __name__ == '__main__':
    main()
