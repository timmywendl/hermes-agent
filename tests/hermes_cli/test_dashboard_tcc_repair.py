from __future__ import annotations

import argparse
import plistlib
import json
import re
import shlex
from pathlib import Path

import pytest

import hermes_cli.dashboard_tcc_repair as repair


def _write_plist(tmp_path, command, *, stdout_path=None, stderr_path=None):
    stdout_path = stdout_path or (tmp_path / "logs" / "dashboard.log")
    stderr_path = stderr_path or (tmp_path / "logs" / "dashboard.error.log")
    data = {
        "Label": "ai.hermes.dashboard",
        "ProgramArguments": command,
        "EnvironmentVariables": {"HERMES_HOME": str(tmp_path / ".hermes")},
        "WorkingDirectory": str(tmp_path),
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
    }
    path = tmp_path / "Library" / "LaunchAgents" / "ai.hermes.dashboard.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False))
    return path, data


def _load(path):
    return plistlib.loads(path.read_bytes())


def _unwrap_osascript(program_arguments):
    assert program_arguments[0] == "/usr/bin/osascript"
    if len(program_arguments) == 3:
        assert program_arguments[1] == "-e"
        script = program_arguments[2]
        prefix, suffix = 'do shell script "', '"'
        shell = re.sub(r"\\(.)", r"\1", script[len(prefix) : -len(suffix)])
    else:
        assert program_arguments[1:4] == ["-l", "JavaScript", "-e"]
        script = program_arguments[4]
        prefix = 'ObjC.import("stdlib"); const status=$.system("'
        suffix = '); const signal=status & 127; $.exit(status === -1 ? 1 : signal === 0 ? (status >> 8) & 255 : 128 + signal);'
        body = script[len(prefix) : -len(suffix)]
        body = body.removesuffix('"')
        shell = json.loads('"' + body + '"')
    exec_name, *rest = shlex.split(shell)
    assert exec_name == "exec"
    assert rest[-4:-3] == [">>"] and rest[-2:-1] == ["2>>"]
    return rest[:-4]


def _darwin(monkeypatch, home):
    monkeypatch.setattr(repair.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(repair, "_user_home", lambda: home)


def _bind_runtime(monkeypatch, command):
    monkeypatch.setattr(repair.sys, "executable", command[0])
    if command[1] == "-m":
        root = Path("/tmp")
        argv0 = str(root / "hermes_cli" / "main.py")
    else:
        script = Path(command[1])
        root = script.parent.parent.parent
        argv0 = command[1]
    monkeypatch.setattr(repair, "_current_hermes_root", lambda: root)
    monkeypatch.setattr(repair.sys, "argv", [argv0])


def test_dry_run_identifies_direct_dashboard_python_without_writing(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        str(tmp_path / "venv" / "bin" / "python"),
        str(tmp_path / "venv" / "bin" / "hermes"),
        "dashboard",
        "--port",
        "9119",
        "--host",
        "127.0.0.1",
        "--no-open",
    ]
    _bind_runtime(monkeypatch, command)
    path, _ = _write_plist(tmp_path, command)
    before = path.read_bytes()

    result = repair.repair_dashboard_launchd_tcc_host(path, apply=False)

    assert result.status == "needs_repair"
    assert result.changed is False
    assert result.tcc_host_identity == "/usr/bin/osascript"
    assert path.read_bytes() == before


def test_apply_wraps_dashboard_under_existing_osascript_identity(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "dashboard",
        "--port",
        "9119",
        "--host",
        "127.0.0.1",
        "--no-open",
    ]
    _bind_runtime(monkeypatch, command)
    path, data = _write_plist(tmp_path, command)
    path.chmod(0o640)
    original_mode = path.stat().st_mode & 0o777

    result = repair.repair_dashboard_launchd_tcc_host(path, apply=True)

    assert result.status == "repaired"
    assert result.changed is True
    installed = _load(path)
    program_arguments = installed["ProgramArguments"]
    assert program_arguments[0] == "/usr/bin/osascript"
    assert _unwrap_osascript(program_arguments) == command
    assert installed["EnvironmentVariables"] == data["EnvironmentVariables"]
    assert installed["KeepAlive"] == data["KeepAlive"]
    assert path.stat().st_mode & 0o777 == original_mode


def test_repair_is_idempotent_after_first_apply(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "serve",
        "--port",
        "9119",
    ]
    _bind_runtime(monkeypatch, command)
    path, _ = _write_plist(tmp_path, command)
    first = repair.repair_dashboard_launchd_tcc_host(path, apply=True)
    after_first = path.read_bytes()

    second = repair.repair_dashboard_launchd_tcc_host(path, apply=True)

    assert first.status == "repaired"
    assert second.status == "already_repaired"
    assert second.changed is False
    assert path.read_bytes() == after_first


def test_shell_hostile_paths_round_trip_through_wrapper(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        str(tmp_path / 'home "quoted"' / "venv" / "bin" / "python"),
        str(tmp_path / 'home "quoted"' / "venv" / "bin" / "hermes"),
        "dashboard",
        "--host",
        "127.0.0.1",
    ]
    _bind_runtime(monkeypatch, command)
    stdout = tmp_path / 'logs with "quotes"' / "dashboard.log"
    stderr = tmp_path / 'logs with "quotes"' / "dashboard.error.log"
    path, _ = _write_plist(tmp_path, command, stdout_path=stdout, stderr_path=stderr)

    repair.repair_dashboard_launchd_tcc_host(path, apply=True)

    installed = _load(path)["ProgramArguments"]
    assert _unwrap_osascript(installed) == command
    assert f">> {shlex.quote(str(stdout))}" in json.loads(re.match(r'.*\$\.system\((.*)\); const signal', installed[4]).group(1))
    assert f"2>> {shlex.quote(str(stderr))}" in json.loads(re.match(r'.*\$\.system\((.*)\); const signal', installed[4]).group(1))


def test_non_dashboard_plist_fails_closed(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    path, _ = _write_plist(tmp_path, ["/usr/bin/python3", "-m", "hermes_cli.main", "gateway", "run"])

    with pytest.raises(repair.DashboardTccRepairError, match="dashboard or serve"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=True)


@pytest.mark.parametrize(
    "command",
    [
        ["/usr/bin/echo", "hermes", "dashboard"],
        ["/tmp/python3.not-python", "/tmp/hermes", "dashboard"],
        ["/usr/bin/python3", "-c", "hermes dashboard"],
        ["/tmp/hermes", "dashboard", "register"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "gateway", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--host", "127.0.0.1", "register"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--stop"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--status"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--bogus"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--port"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "--profile", "--stop", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "--profile=bad=name", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "--profile", "one", "--profile", "two", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--open-profile=--stop"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--open-profile=bad=name"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--open-profile", "one", "--open-profile", "two"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "--profile", "ß", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "--profile=ẞ", "dashboard"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--open-profile", "ß"],
        ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard", "--open-profile=ﬃ"],
        [
            "/usr/bin/python3",
            "-m",
            "hermes_cli.main",
            "dashboard",
            "--no-open",
            "repair-tcc-host",
            "--apply",
        ],
    ],
)
def test_command_admission_rejects_marker_tokens_and_nested_commands(tmp_path, monkeypatch, command):
    _darwin(monkeypatch, tmp_path)
    path, _ = _write_plist(tmp_path, command)

    with pytest.raises(repair.DashboardTccRepairError, match="dashboard or serve"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=True)


def test_malformed_osascript_wrapper_fails_closed_without_traceback(tmp_path, monkeypatch, capsys):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "dashboard",
    ]
    _bind_runtime(monkeypatch, command)
    path, data = _write_plist(tmp_path, command)
    valid = repair.launchd_program_arguments(
        command,
        repair.Path(data["StandardOutPath"]),
        repair.Path(data["StandardErrorPath"]),
    )
    malformed = valid[2][:-1] + '; touch "/tmp/should-not-run""'
    plist = _load(path)
    plist["ProgramArguments"] = [valid[0], valid[1], malformed]
    path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))

    result = repair.cmd_dashboard_tcc_repair(argparse.Namespace(plist=str(path), apply=True))

    captured = capsys.readouterr()
    assert result == 1
    assert "ERROR:" in captured.out
    assert "Traceback" not in captured.out


def test_malformed_osascript_quote_is_controlled_error(tmp_path, monkeypatch, capsys):
    _darwin(monkeypatch, tmp_path)
    path, _ = _write_plist(
        tmp_path,
        [repair.TCC_HOST_IDENTITY, "-e", 'do shell script "exec /tmp/unclosed'],
    )

    result = repair.cmd_dashboard_tcc_repair(argparse.Namespace(plist=str(path), apply=True))

    captured = capsys.readouterr()
    assert result == 1
    assert "malformed" in captured.out


def test_malformed_plist_xml_is_controlled_error(tmp_path, monkeypatch, capsys):
    _darwin(monkeypatch, tmp_path)
    path = tmp_path / "Library" / "LaunchAgents" / "ai.hermes.dashboard.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"<?xml version='1.0'?><plist><dict><key>Label</key><string>broken&")

    result = repair.cmd_dashboard_tcc_repair(argparse.Namespace(plist=str(path), apply=True))

    captured = capsys.readouterr()
    assert result == 1
    assert "invalid launchd plist" in captured.out
    assert "Traceback" not in captured.out


def test_plist_scope_label_and_symlink_checks_fail_closed(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "dashboard",
    ]
    path, _ = _write_plist(tmp_path, command)

    out_of_scope = tmp_path / "other.plist"
    out_of_scope.write_bytes(path.read_bytes())
    with pytest.raises(repair.DashboardTccRepairError, match="canonical"):
        repair.repair_dashboard_launchd_tcc_host(out_of_scope, apply=True)

    wrong_label = _load(path)
    wrong_label["Label"] = "com.example.other"
    path.write_bytes(plistlib.dumps(wrong_label, fmt=plistlib.FMT_XML, sort_keys=False))
    with pytest.raises(repair.DashboardTccRepairError, match="Label"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=True)

    path.unlink()
    target = tmp_path / "target.plist"
    target.write_bytes(plistlib.dumps(_load(out_of_scope), fmt=plistlib.FMT_XML, sort_keys=False))
    path.symlink_to(target)
    with pytest.raises(repair.DashboardTccRepairError, match="symlinked"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=True)


def test_module_mode_is_bound_to_current_python_runtime(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = ["/usr/bin/python3", "-m", "hermes_cli.main", "serve", "--port", "9119"]
    monkeypatch.setattr(repair.sys, "executable", command[0])
    monkeypatch.setattr(repair.sys, "argv", ["/tmp/hermes_cli/main.py"])
    monkeypatch.setattr(repair, "_current_hermes_root", lambda: Path("/tmp"))
    path, _ = _write_plist(tmp_path, command)

    result = repair.repair_dashboard_launchd_tcc_host(path, apply=False)

    assert result.status == "needs_repair"

    monkeypatch.setattr(repair.sys, "executable", "/tmp/python3")
    with pytest.raises(repair.DashboardTccRepairError, match="dashboard or serve"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=False)


def test_installed_dashboard_launchd_argv_shape_is_admitted(tmp_path, monkeypatch):
    """The real live-shaped argv (venv python + venv hermes) is admitted and runtime-bound.

    The `home_io_guard` fixture forbids real `~/.hermes` I/O, so the runtime binding is
    exercised through the module's own resolution seams rather than the live install.
    """

    _darwin(monkeypatch, tmp_path)
    root = tmp_path / "install"
    (root / "venv/bin").mkdir(parents=True)
    (root / "hermes_cli").mkdir(parents=True)
    (root / "hermes_cli/main.py").write_text("")
    (root / "venv/bin/python").touch()
    (root / "venv/bin/hermes").touch()
    command = [
        str(root / "venv/bin/python"),
        str(root / "venv/bin/hermes"),
        "dashboard",
        "--port",
        "9119",
        "--host",
        "127.0.0.1",
        "--no-open",
    ]
    monkeypatch.setattr(repair.sys, "executable", command[0])
    monkeypatch.setattr(repair.sys, "argv", [command[1]])
    monkeypatch.setattr(repair, "_current_hermes_root", lambda: root)
    path, _ = _write_plist(tmp_path, command)

    assert repair._entrypoint_matches_runtime(command) is True
    result = repair.repair_dashboard_launchd_tcc_host(path, apply=False)

    assert result.status == "needs_repair"

    mismatched = [str(tmp_path / "other/venv/bin/python"), *command[1:]]
    (tmp_path / "other/venv/bin").mkdir(parents=True)
    (tmp_path / "other/venv/bin/python").touch()
    (tmp_path / "other/venv/bin/hermes").touch()
    assert repair._entrypoint_matches_runtime(mismatched) is False


def test_valid_profile_selector_is_admitted_and_conflicting_launchd_keys_are_rejected(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "--profile",
        "work_1",
        "dashboard",
        "--no-open",
    ]
    _bind_runtime(monkeypatch, command)
    path, _ = _write_plist(tmp_path, command)
    assert repair.repair_dashboard_launchd_tcc_host(path, apply=False).status == "needs_repair"

    for key, value in (
        ("Program", "/usr/bin/python3"),
        ("Program", ""),
        ("EnableGlobbing", True),
        ("EnableGlobbing", []),
    ):
        plist = _load(path)
        plist[key] = value
        path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))
        with pytest.raises(repair.DashboardTccRepairError, match="Program|EnableGlobbing"):
            repair.repair_dashboard_launchd_tcc_host(path, apply=False)
        plist.pop(key)
        path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))


@pytest.mark.parametrize(
    "command",
    [
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "--profile",
            "ß",
            "dashboard",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "--profile",
            "K",
            "dashboard",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "-p",
            "K",
            "dashboard",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "--profile=ẞ",
            "dashboard",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "--profile",
            "default\n",
            "dashboard",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "dashboard",
            "--open-profile",
            "K",
        ],
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "dashboard",
            "--open-profile=ﬃ",
        ],
    ],
)
def test_unicode_profile_aliases_fail_with_matching_runtime(tmp_path, monkeypatch, command):
    _darwin(monkeypatch, tmp_path)
    _bind_runtime(monkeypatch, command)
    path, _ = _write_plist(tmp_path, command)

    with pytest.raises(repair.DashboardTccRepairError, match="dashboard or serve"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=False)


def test_non_macos_is_unsupported_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(repair.platform, "system", lambda: "Linux")
    path, _ = _write_plist(tmp_path, ["/usr/bin/python3", "-m", "hermes_cli.main", "dashboard"])
    before = path.read_bytes()

    result = repair.repair_dashboard_launchd_tcc_host(None, apply=True)

    assert result.status == "unsupported"
    assert result.changed is False
    assert path.read_bytes() == before


def _legacy_wrapper(command, stdout_path, stderr_path):
    """Reproduce the v0.21.x `osascript -e 'do shell script ...'` wrapper."""

    shell = f"exec {shlex.join(command)} >> {shlex.quote(str(stdout_path))} 2>> {shlex.quote(str(stderr_path))}"
    escaped = shell.replace("\\", "\\\\").replace('"', '\\"')
    return ["/usr/bin/osascript", "-e", f'do shell script "{escaped}"']


def test_legacy_applescript_wrapper_reports_already_repaired(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "dashboard",
        "--port",
        "9119",
        "--no-open",
    ]
    _bind_runtime(monkeypatch, command)
    path, data = _write_plist(tmp_path, command)
    legacy = _legacy_wrapper(command, data["StandardOutPath"], data["StandardErrorPath"])
    plist = _load(path)
    plist["ProgramArguments"] = legacy
    path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))
    before = path.read_bytes()

    assert _unwrap_osascript(legacy) == command

    result = repair.repair_dashboard_launchd_tcc_host(path, apply=True)

    assert result.status == "already_repaired"
    assert result.changed is False
    assert result.tcc_host_identity == "/usr/bin/osascript"
    assert path.read_bytes() == before


def test_legacy_wrapper_with_extra_shell_command_is_refused(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    command = [
        "/Users/example/.hermes/hermes-agent/venv/bin/python",
        "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
        "serve",
        "--port",
        "9119",
    ]
    _bind_runtime(monkeypatch, command)
    path, data = _write_plist(tmp_path, command)
    tail = shlex.join(command)
    poisoned = [
        "/usr/bin/osascript",
        "-e",
        f'do shell script "exec {tail} >> {data["StandardOutPath"]} 2>> {data["StandardErrorPath"]}; rm -rf /tmp/x"',
    ]
    plist = _load(path)
    plist["ProgramArguments"] = poisoned
    path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))
    before = path.read_bytes()

    with pytest.raises(repair.DashboardTccRepairError):
        repair.repair_dashboard_launchd_tcc_host(path, apply=True)
    assert path.read_bytes() == before


def test_unknown_osascript_shape_is_refused(tmp_path, monkeypatch):
    _darwin(monkeypatch, tmp_path)
    path, _ = _write_plist(
        tmp_path,
        [
            "/Users/example/.hermes/hermes-agent/venv/bin/python",
            "/Users/example/.hermes/hermes-agent/venv/bin/hermes",
            "dashboard",
        ],
    )
    plist = _load(path)
    plist["ProgramArguments"] = ["/usr/bin/osascript", "--totally-unknown", "1", "2", "3", "4", "5"]
    path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=False))

    with pytest.raises(repair.DashboardTccRepairError, match="malformed osascript"):
        repair.repair_dashboard_launchd_tcc_host(path, apply=False)


def test_dashboard_parser_exposes_explicit_no_restart_repair_command():
    from hermes_cli.subcommands.dashboard import build_dashboard_parser

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_dashboard_parser(
        subparsers,
        cmd_dashboard=lambda args: args,
        cmd_dashboard_register=lambda args: args,
        cmd_dashboard_tcc_repair=lambda args: args,
    )

    args = parser.parse_args(["dashboard", "repair-tcc-host", "--apply", "--plist", "/tmp/dashboard.plist"])

    assert args.dashboard_subcommand == "repair-tcc-host"
    assert args.apply is True
    assert args.plist == "/tmp/dashboard.plist"


def test_full_cli_parser_round_trips_dashboard_launch_shape(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    from hermes_cli.subcommands.dashboard import build_dashboard_parser

    root = argparse.ArgumentParser(prog="hermes")
    subparsers = root.add_subparsers(dest="command")
    build_dashboard_parser(
        subparsers,
        cmd_dashboard=lambda args: 0,
        cmd_dashboard_register=lambda args: 0,
        cmd_dashboard_tcc_repair=lambda args: 0,
    )
    args = root.parse_args(
        ["dashboard", "--port", "9119", "--host", "127.0.0.1", "--no-open"]
    )

    assert args.command == "dashboard"
    assert args.dashboard_subcommand is None
    assert args.port == 9119
    assert args.host == "127.0.0.1"
    assert args.no_open is True
