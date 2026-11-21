"""Stage/sign an already built QEMU candidate. Never executes QEMU or creates a VM."""
from contextlib import ExitStack
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

from qualify_sandbox import make_plan

HERE = Path(__file__).resolve().parent


def run(argv):
    return subprocess.run([str(p) for p in argv], check=True, capture_output=True, text=True, timeout=30).stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependencies(binary):
    return [line.strip().split(' (compatibility')[0] for line in run(['otool', '-L', binary]).splitlines()[1:]]


def bundle_libraries(binary, frameworks):
    originals = {}
    pending = [binary]
    while pending:
        target = pending.pop()
        for name in dependencies(target):
            if name.startswith(('/System/', '/usr/lib/', '@')):
                continue
            original = Path(name)
            if name not in originals:
                bundled = frameworks / original.name
                if bundled.exists():
                    raise ValueError('dependency_basename_collision')
                shutil.copyfile(original, bundled)
                originals[name] = {'bundled': str(bundled), 'source_sha256': digest(original)}
                pending.append(bundled)
    for target in (binary, *(Path(v['bundled']) for v in originals.values())):
        for name in dependencies(target):
            if name in originals:
                replacement = ('@executable_path/../Frameworks/' if target == binary else '@loader_path/') + Path(name).name
                run(['install_name_tool', '-change', name, replacement, target])
        if target != binary:
            run(['install_name_tool', '-id', '@rpath/' + target.name, target])
            run(['codesign', '--force', '--sign', '-', target])
        if any(not name.startswith(('/System/', '/usr/lib/', '@')) for name in dependencies(target)):
            raise ValueError('external_runtime_dependency')
    return originals


def package(args):
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    app = root / 'HermesQ1HVF.app'
    macos, resources, frameworks = (app / 'Contents' / name for name in ('MacOS', 'Resources', 'Frameworks'))
    for directory in (macos, resources, frameworks):
        directory.mkdir(parents=True)
    helper = macos / 'qemu-system-aarch64'
    shutil.copyfile(args.binary, helper)
    helper.chmod(0o755)
    libraries = bundle_libraries(helper, frameworks)
    for source, name in ((args.kernel, 'kernel.Image'), (args.initramfs, 'serial-initramfs.cpio.gz'), (args.disk, 'root-disk.raw')):
        shutil.copyfile(source, resources / name)
    info = {'CFBundleIdentifier': 'org.hermes.pr15.qemu-hvf', 'CFBundleExecutable': helper.name,
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSBackgroundOnly': True}
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    # A short Darwin temp path is needed for actual sockaddr_un. All markers are public.
    controls = Path(tempfile.mkdtemp(prefix='h15-', dir='/private/tmp'))
    with ExitStack() as stack:
        plan = make_plan(controls, resources, args.fixture, stack,
                         [resources / name for name in ('kernel.Image', 'serial-initramfs.cpio.gz', 'root-disk.raw')])
    # Calibration listener files are never reused as Native listener paths.
    plan['unix'] = {name: path + '-native' for name, path in plan['unix'].items()}
    plan_path = resources / 'canary-plan.json'
    plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + '\n')
    run(['codesign', '--force', '--sign', '-', '--entitlements', HERE / 'helper.entitlements', app])
    run(['codesign', '--verify', '--strict', app])
    inventory = {str(p): digest(p) for p in app.rglob('*') if p.is_file()}
    receipt = {'package': 'HERMES_Q1_HVF_PROCESS_OWNED_GUEST_FEASIBILITY_V1', 'grant': '7058818518',
               'native_processes_started': 0, 'controls_root': str(controls), 'libraries': libraries,
               'unsigned_input_sha256': digest(args.binary), 'files': inventory,
               'helper': str(helper), 'plan': str(plan_path), 'app': str(app)}
    (root / 'package-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'kernel', 'initramfs', 'disk', 'fixture', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    print(json.dumps(package(parser.parse_args()), sort_keys=True))


if __name__ == '__main__':
    main()
