"""Independent task-private Git exports for a future approved Guest block device.

No shared Host worktree, git common-dir, credentials, hooks or remote config is
exported. Reviewer requires an exact immutable commit and a read-only VM device;
POSIX modes alone are deliberately not accepted as a Guest isolation proof.
"""
from dataclasses import dataclass
from pathlib import Path
import re
import os
import subprocess


@dataclass(frozen=True)
class GuestWorkspace:
    root: Path
    head: str
    role: str
    readonly_device: bool

    def device_contract(self):
        return {'kind': 'directory_snapshot', 'mount': '/task', 'head': self.head, 'role': self.role,
                'readonly': self.readonly_device, 'host_share': False}


def _git(root, *args):
    env = {key: value for key, value in os.environ.items() if key in ('PATH', 'TMPDIR', 'LANG', 'TZ')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null',
                                    *args], text=True, timeout=30, env=env, stderr=subprocess.PIPE).strip()


def prepare_workspace(source, destination, *, head, role):
    if role not in ('developer', 'reviewer') or not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('guest_workspace_exact_head_required')
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve(strict=False)
    source_root = Path(_git(source, 'rev-parse', '--show-toplevel')).resolve(strict=True)
    source_common = Path(_git(source, 'rev-parse', '--path-format=absolute', '--git-common-dir')).resolve(strict=True)
    protected = (source_root, source_common, source_common.parent if source_common.name == '.git' else source_common)
    if any(destination.is_relative_to(root) for root in protected):
        raise ValueError('guest_workspace_nested_source')
    if destination.exists() or _git(source, 'rev-parse', head + '^{commit}') != head:
        raise ValueError('guest_workspace_not_private')
    destination.mkdir(parents=True, mode=0o700)
    # Transfer objects, not Host .git/config, hooks, alternates or worktree links.
    _git(destination, 'init', '-q')
    verify_common_dir(destination, source_common)
    _git(destination, '-c', 'protocol.file.allow=always', 'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules', str(source), head)
    _git(destination, 'checkout', '--detach', head)
    if role == 'developer':
        _git(destination, 'checkout', '-b', 'task/guest')
    if _git(destination, 'rev-parse', 'HEAD') != head or _git(destination, 'remote'):
        raise ValueError('guest_workspace_identity_mismatch')
    verify_common_dir(destination, source_common)
    # FETCH_HEAD contains the Host source path; it is not part of Guest context.
    (destination / '.git/FETCH_HEAD').unlink()
    return GuestWorkspace(destination, head, role, role == 'reviewer')


def verify_common_dir(destination, source_common):
    """A directory snapshot must own its Git metadata, not a linked Host worktree."""
    destination, source_common = Path(destination).resolve(strict=True), Path(source_common).resolve(strict=True)
    expected = destination / '.git'
    common = Path(_git(destination, 'rev-parse', '--path-format=absolute', '--git-common-dir')).resolve(strict=True)
    git_dir = Path(_git(destination, 'rev-parse', '--absolute-git-dir')).resolve(strict=True)
    if (not expected.is_dir() or expected.is_symlink() or common != expected or git_dir != expected
            or os.path.samefile(common, source_common) or (expected / 'objects/info/alternates').exists()):
        raise ValueError('guest_workspace_shared_common_dir')
