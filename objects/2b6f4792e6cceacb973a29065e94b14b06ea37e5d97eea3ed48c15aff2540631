"""Repair the macOS launchd identity used by a Hermes Dashboard.

A launchd job that starts the Dashboard directly with uv's versioned Python makes that
interpreter the TCC responsible host for descendant MCP processes.  The existing Hermes
launchd implementation already has a supported identity boundary: ``/usr/bin/osascript``
with an ``exec`` child.  This module applies that boundary to a Dashboard plist without
changing Chrome, TCC.db, the MCP command, or the service lifecycle.

The repair is deliberately one-shot and explicit.  It edits only ``ProgramArguments`` and
never bootstraps, kickstarts, or otherwise restarts launchd; the caller must do that after
reviewing the result.
"""

from __future__ import annotations

import json
import os
import plistlib
import platform
import re
import shlex
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from hermes_cli.gateway_launchd import launchd_program_arguments
from hermes_constants import PROFILE_ID_RE
from utils import atomic_write_text

TCC_HOST_IDENTITY = "/usr/bin/osascript"
DEFAULT_DASHBOARD_PLIST = "ai.hermes.dashboard.plist"


class DashboardTccRepairError(RuntimeError):
    """The selected plist is not a safe Dashboard launchd target."""


@dataclass(frozen=True)
class DashboardTccRepairResult:
    """Safe, non-secret result of inspecting or repairing one Dashboard plist."""

    status: str
    plist_path: Path
    tcc_host_identity: str | None = None
    changed: bool = False
    detail: str = ""


def default_dashboard_plist_path() -> Path:
    """Return the conventional per-user Dashboard LaunchAgent path."""

    return _user_home() / "Library" / "LaunchAgents" / DEFAULT_DASHBOARD_PLIST


def _user_home() -> Path:
    """Return the account home from the passwd database, not the mutable HOME env var."""

    import pwd

    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _valid_profile_selector(value: str) -> bool:
    return value.isascii() and PROFILE_ID_RE.fullmatch(value.lower()) is not None


def _is_python_executable(token: str) -> bool:
    name = Path(token).name
    return Path(token).is_absolute() and re.fullmatch(r"python(?:3(?:\.\d+)?)?", name) is not None


def _is_hermes_script(token: str) -> bool:
    path = Path(token)
    return (
        path.is_absolute()
        and path.name in {"hermes", "hermes.py"}
        and path.parent.name == "bin"
        and path.parent.parent.name in {"venv", ".venv"}
    )


def _is_hermes_main_module_script(token: str) -> bool:
    path = Path(token)
    return path.is_absolute() and path.name == "main.py" and path.parent.name == "hermes_cli"


def _current_hermes_root() -> Path:
    return Path(__file__).absolute().resolve().parent.parent


def _current_hermes_main_path() -> Path:
    return _current_hermes_root() / "hermes_cli" / "main.py"


def _entrypoint_matches_runtime(arguments: list[str]) -> bool:
    """Bind a candidate command to the Hermes runtime performing this repair."""

    current_python = Path(sys.executable).absolute().resolve(strict=False)
    current_argv0 = Path(sys.argv[0]).absolute().resolve(strict=False) if sys.argv else None
    current_main = _current_hermes_main_path().resolve(strict=False)
    if _is_hermes_script(arguments[0]):
        candidate = Path(arguments[0]).absolute().resolve(strict=False)
        return current_argv0 in {candidate, current_main} and candidate.parent.parent.parent == _current_hermes_root()
    if not _is_python_executable(arguments[0]):
        return False
    if Path(arguments[0]).absolute().resolve(strict=False) != current_python:
        return False
    if len(arguments) >= 2 and _is_hermes_script(arguments[1]):
        candidate = Path(arguments[1]).absolute().resolve(strict=False)
        return current_argv0 in {candidate, current_main} and candidate.parent.parent.parent == _current_hermes_root()
    if len(arguments) >= 2 and _is_hermes_main_module_script(arguments[1]):
        return Path(arguments[1]).absolute().resolve(strict=False) == current_main
    return len(arguments) >= 3 and arguments[1:3] == ["-m", "hermes_cli.main"] and current_argv0 == current_main


def _valid_server_tail(mode: str, tail: list[str]) -> bool:
    """Validate the small, explicit server-only option grammar."""

    common_flags = {"--insecure", "--skip-build", "--isolated"}
    common_values = {"--port", "--host", "--open-profile"}
    dashboard_flags = {"--no-open", "--tui"}
    serve_flags = {"--no-open"}
    serve_values = {"--ssh-session-token-file", "--ssh-owner-nonce"}
    flags = common_flags | (dashboard_flags if mode == "dashboard" else serve_flags)
    values = common_values | (serve_values if mode == "serve" else set())
    value_seen: set[str] = set()
    if "--stop" in tail or "--status" in tail:
        return False
    index = 0
    while index < len(tail):
        token = tail[index]
        if token == "--" or not token.startswith("-"):
            return False
        if "=" in token:
            name, _, value = token.partition("=")
            if name not in values or not value or name in value_seen:
                return False
            if name == "--port":
                try:
                    int(value)
                except ValueError:
                    return False
            if name == "--open-profile" and not _valid_profile_selector(value):
                return False
            value_seen.add(name)
            index += 1
            continue
        if token in flags:
            index += 1
            continue
        if token not in values or token in value_seen or index + 1 >= len(tail) or tail[index + 1].startswith("-"):
            return False
        if token == "--port":
            try:
                int(tail[index + 1])
            except ValueError:
                return False
        if token == "--open-profile" and not _valid_profile_selector(tail[index + 1]):
            return False
        value_seen.add(token)
        index += 2
    return True


def _dashboard_mode_index(arguments: list[str]) -> int | None:
    """Return the exact position of a supported top-level server command."""

    if not arguments:
        return None
    if _is_hermes_script(arguments[0]):
        index = 1
    elif (
        len(arguments) >= 2
        and _is_python_executable(arguments[0])
        and _is_hermes_script(arguments[1])
        and Path(arguments[0]).parent == Path(arguments[1]).parent
    ):
        index = 2
    elif len(arguments) >= 2 and _is_python_executable(arguments[0]) and (
        _is_hermes_main_module_script(arguments[1])
        or (arguments[1:3] == ["-m", "hermes_cli.main"])
    ):
        index = 2 if _is_hermes_main_module_script(arguments[1]) else 3
    else:
        return None

    # The CLI's only supported global argument that can appear between the entrypoint and
    # the subcommand in a launchd argv is the profile selector.
    profile_seen = False
    while index < len(arguments):
        token = arguments[index]
        if token in {"-p", "--profile"}:
            if profile_seen or index + 1 >= len(arguments):
                return None
            profile_value = arguments[index + 1]
            if not _valid_profile_selector(profile_value):
                return None
            profile_seen = True
            index += 2
            continue
        if token.startswith("--profile="):
            if profile_seen or not _valid_profile_selector(token.partition("=")[2]):
                return None
            profile_seen = True
            index += 1
            continue
        break
    if index >= len(arguments) or arguments[index] not in {"dashboard", "serve"}:
        return None
    tail = arguments[index + 1 :]
    if not _valid_server_tail(arguments[index], tail):
        return None
    return index


def _is_dashboard_command(arguments: list[str]) -> bool:
    """Recognize only a Hermes ``dashboard`` or ``serve`` command."""

    return bool(arguments) and _dashboard_mode_index(arguments) is not None and _entrypoint_matches_runtime(arguments)


def _wrap_command_applescript(command: list[str], stdout_log: Path, stderr_log: Path) -> list[str]:
    """Reproduce the pre-JXA Hermes ``osascript -e 'do shell script …'`` wrapper.

    Hermes shipped this form until the JXA wrapper replaced it.  A plist produced by the
    older release must round-trip byte-for-byte, otherwise an already-repaired job would be
    rejected as malformed instead of being recognised as using the osascript identity.
    """

    shell = f"exec {shlex.join(command)} >> {shlex.quote(str(stdout_log))} 2>> {shlex.quote(str(stderr_log))}"
    applescript = shell.replace("\\", "\\\\").replace('"', '\\"')
    return [TCC_HOST_IDENTITY, "-e", f'do shell script "{applescript}"']


def _is_osascript_wrapper(arguments: list[str]) -> bool:
    """Return whether arguments already use Hermes' stable Apple host boundary."""

    if arguments[:1] != [TCC_HOST_IDENTITY]:
        return False
    if len(arguments) == 3 and arguments[1] == "-e":
        return arguments[2].startswith('do shell script "') and arguments[2].endswith('"')
    return (
        len(arguments) == 5
        and arguments[1:4] == ["-l", "JavaScript", "-e"]
        and arguments[4].startswith('ObjC.import("stdlib"); const status=$.system("')
        and arguments[4].endswith("$.exit(status === -1 ? 1 : signal === 0 ? (status >> 8) & 255 : 128 + signal);")
    )


def _wrapped_child_arguments(
    arguments: list[str], stdout_path: Path, stderr_path: Path,
) -> list[str] | None:
    """Decode the command embedded in Hermes' generated osascript wrapper."""

    if arguments and (not all(isinstance(item, str) for item in arguments) or arguments[0] != TCC_HOST_IDENTITY):
        return None
    if not _is_osascript_wrapper(arguments):
        raise DashboardTccRepairError("refusing malformed osascript ProgramArguments")
    if len(arguments) == 3:
        script = arguments[2]
        prefix, suffix = 'do shell script "', '"'
        body = script[len(prefix) : -len(suffix)]
        shell = re.sub(r"\\(.)", r"\1", body)
        legacy_form = True
    else:
        # Coupled to `gateway_launchd.launchd_program_arguments` (the JXA template): if that
        # template changes, the round-trip equality below fails closed rather than admitting
        # an unrecognised wrapper.
        script = arguments[4]
        prefix = 'ObjC.import("stdlib"); const status=$.system("'
        suffix = '); const signal=status & 127; $.exit(status === -1 ? 1 : signal === 0 ? (status >> 8) & 255 : 128 + signal);'
        body = script[len(prefix) : -len(suffix)]
        body = body.removesuffix('"')
        try:
            shell = json.loads('"' + body + '"')
        except ValueError as exc:
            raise DashboardTccRepairError("refusing malformed osascript shell payload") from exc
        legacy_form = False
    try:
        tokens = shlex.split(shell)
    except ValueError as exc:
        raise DashboardTccRepairError("refusing malformed osascript shell payload") from exc
    if len(tokens) < 6 or tokens[0] != "exec":
        raise DashboardTccRepairError("refusing osascript wrapper without an exact exec/redirection shape")
    if tokens[-4] != ">>" or tokens[-2] != "2>>":
        raise DashboardTccRepairError("refusing osascript wrapper with unexpected shell redirections")
    child = tokens[1:-4]
    if not child:
        raise DashboardTccRepairError("refusing osascript wrapper with an empty shell command")
    expected = (
        _wrap_command_applescript(child, stdout_path, stderr_path)
        if legacy_form
        else launchd_program_arguments(child, stdout_path, stderr_path)
    )
    if expected != arguments:
        raise DashboardTccRepairError("refusing osascript wrapper with an unexpected shell command")
    return child


def _load_plist(path: Path) -> dict[str, Any]:
    try:
        data = plistlib.loads(path.read_bytes())
    except OSError as exc:
        raise DashboardTccRepairError(f"cannot read launchd plist {path}: {exc}") from exc
    except (plistlib.InvalidFileException, ExpatError, TypeError, ValueError) as exc:
        raise DashboardTccRepairError(f"invalid launchd plist {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DashboardTccRepairError(f"launchd plist {path} is not a dictionary")
    return data


def _program_arguments(data: dict[str, Any], path: Path) -> list[str]:
    raw = data.get("ProgramArguments")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise DashboardTccRepairError(f"launchd plist {path} has no valid ProgramArguments array")
    return list(raw)


def _log_path(data: dict[str, Any], key: str) -> Path:
    value = data.get(key)
    if value is None or value == "":
        return Path(os.devnull)
    if not isinstance(value, str):
        raise DashboardTccRepairError(f"launchd plist field {key} must be a string")
    return Path(value)


def _validated_plist_path(plist_path: Path | str | None) -> Path:
    """Bind the write target to the user's canonical Dashboard LaunchAgent plist."""

    raw = Path(plist_path).expanduser() if plist_path is not None else default_dashboard_plist_path()
    if raw.is_symlink():
        raise DashboardTccRepairError(f"refusing symlinked Dashboard launchd plist: {raw}")
    expected = default_dashboard_plist_path().resolve(strict=False)
    path = raw.absolute().resolve(strict=False)
    if path != expected:
        raise DashboardTccRepairError(
            f"refusing {path}: only the canonical per-user Dashboard plist {expected} may be repaired"
        )
    try:
        info = path.lstat()
    except OSError as exc:
        raise DashboardTccRepairError(f"cannot inspect launchd plist {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise DashboardTccRepairError(f"refusing non-regular Dashboard launchd plist: {path}")
    if info.st_uid != os.getuid():
        raise DashboardTccRepairError(f"refusing Dashboard launchd plist not owned by the current user: {path}")
    return path


def repair_dashboard_launchd_tcc_host(
    plist_path: Path | str | None = None,
    *,
    apply: bool = False,
) -> DashboardTccRepairResult:
    """Inspect or explicitly repair one Dashboard LaunchAgent plist.

    ``apply=False`` is a read-only preview.  ``apply=True`` atomically replaces only the
    ``ProgramArguments`` field after proving the existing command is a Hermes Dashboard or
    headless ``serve`` backend.  No launchctl operation is performed.
    """

    if platform.system() != "Darwin":
        path = Path(plist_path).expanduser() if plist_path is not None else Path()
        return DashboardTccRepairResult(status="unsupported", plist_path=path)
    path = _validated_plist_path(plist_path)
    if not path.is_file():
        raise DashboardTccRepairError(f"Dashboard launchd plist not found: {path}")

    data = _load_plist(path)
    if data.get("Label") != "ai.hermes.dashboard":
        raise DashboardTccRepairError(f"refusing {path}: Label is not ai.hermes.dashboard")
    if "Program" in data:
        raise DashboardTccRepairError(f"refusing {path}: conflicting Program key is present")
    if "EnableGlobbing" in data:
        raise DashboardTccRepairError(f"refusing {path}: EnableGlobbing must be absent")
    arguments = _program_arguments(data, path)
    stdout_path = _log_path(data, "StandardOutPath")
    stderr_path = _log_path(data, "StandardErrorPath")
    wrapped_child = _wrapped_child_arguments(arguments, stdout_path, stderr_path)
    if wrapped_child is not None:
        if not _is_dashboard_command(wrapped_child):
            raise DashboardTccRepairError(
                f"refusing {path}: osascript wrapper does not contain a Hermes dashboard or serve command"
            )
        return DashboardTccRepairResult(
            status="already_repaired",
            plist_path=path,
            tcc_host_identity=TCC_HOST_IDENTITY,
            detail="ProgramArguments already use the stable osascript host",
        )
    if not _is_dashboard_command(arguments):
        raise DashboardTccRepairError(
            f"refusing {path}: ProgramArguments is not a Hermes dashboard or serve command"
        )

    wrapped = launchd_program_arguments(
        arguments,
        stdout_path,
        stderr_path,
    )
    if not apply:
        return DashboardTccRepairResult(
            status="needs_repair",
            plist_path=path,
            tcc_host_identity=TCC_HOST_IDENTITY,
            detail="direct Python Dashboard launch would make uv Python the TCC responsible host",
        )

    data["ProgramArguments"] = wrapped
    try:
        rendered = plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8")
        atomic_write_text(path, rendered, preserve_mode=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DashboardTccRepairError(f"cannot write repaired launchd plist {path}: {exc}") from exc
    return DashboardTccRepairResult(
        status="repaired",
        plist_path=path,
        tcc_host_identity=TCC_HOST_IDENTITY,
        changed=True,
        detail="ProgramArguments now launch the Dashboard through the existing osascript identity boundary",
    )


def cmd_dashboard_tcc_repair(args) -> int:
    """CLI handler for ``hermes dashboard repair-tcc-host``."""

    path = getattr(args, "plist", None)
    try:
        result = repair_dashboard_launchd_tcc_host(path, apply=bool(getattr(args, "apply", False)))
    except DashboardTccRepairError as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"PLIST={result.plist_path}")
    print(f"STATUS={result.status}")
    if result.tcc_host_identity:
        print(f"TCC_HOST_IDENTITY={result.tcc_host_identity}")
    if result.detail:
        print(f"DETAIL={result.detail}")
    if result.changed:
        print("LAUNCHD_RESTART_REQUIRED=YES")
        print("NEXT=review the plist, then kickstart the existing ai.hermes.dashboard job")
    return 0
