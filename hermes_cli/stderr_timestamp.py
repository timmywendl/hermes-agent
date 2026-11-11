"""Run a child process while prefixing each stdout and stderr line with a timestamp."""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Sequence, TextIO

EXTERNAL_SUPERVISOR_FLAG = "--external-supervisor"
_LAUNCHD_LABEL_ENV = "HERMES_LAUNCHD_LABEL"
# gateway.restart.GATEWAY_FATAL_CONFIG_EXIT_CODE. This wrapper is a launcher boot
# file: it runs from a source slice and stays stdlib-only.
_GATEWAY_FATAL_CONFIG_EXIT_CODE = 78

_TIMESTAMP_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}(?:\s|$)")
# A grandchild that inherited stdout can hold the pipe open after the child exits; the
# wrapper must still exit with the child's status so launchd KeepAlive sees it.
_STDOUT_DRAIN_TIMEOUT_S = 5.0


def timestamp() -> str:
    """Local time in logging.Formatter's default ``%(asctime)s`` shape, which ``hermes logs --since`` parses."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:23]


def stamp_line(line: str) -> str:
    """*line* with a leading :func:`timestamp` (kept as-is if it already has one) and one ``\\n``."""
    rendered = line.rstrip("\r\n")
    prefix = "" if _TIMESTAMP_PREFIX.match(rendered) else f"{timestamp()} "
    return f"{prefix}{rendered}\n"


def _write_timestamped_line(log_file: TextIO, line: str) -> None:
    log_file.write(stamp_line(line))
    log_file.flush()


def _open_log(log_path: Path) -> TextIO:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return log_path.open("a", encoding="utf-8", buffering=1)


def _copy_stderr_with_timestamps(stderr: BinaryIO, log_path: Path) -> None:
    with _open_log(log_path) as log_file:
        for raw_line in iter(stderr.readline, b""):
            _write_timestamped_line(log_file, raw_line.decode("utf-8", errors="replace"))


def _copy_stdout_with_timestamps(stdout: BinaryIO) -> None:
    # fd 1 is the caller's target (launchd appends it to gateway.log, the logging handler's
    # file), so lines keep their destination and gain the stamp `hermes logs --since` needs.
    with open(1, "w", encoding="utf-8", buffering=1, closefd=False) as out:
        for raw_line in iter(stdout.readline, b""):
            _write_timestamped_line(out, raw_line.decode("utf-8", errors="replace"))


def _install_signal_forwarders(proc: subprocess.Popen[bytes]) -> dict[int, object]:
    def _forward(signum: int, _frame: object) -> None:
        try:
            proc.send_signal(signum)
        except ProcessLookupError:
            pass

    previous: dict[int, object] = {}
    # SIGUSR1 is the gateway's drain-aware restart request. launchd owns THIS wrapper's PID,
    # so `hermes update` signals us, not the gateway; an unforwarded SIGUSR1 kills the wrapper
    # (Python's default action), launchd tears the group down with SIGTERM and applies its
    # ~60 s crash back-off per sibling profile (#101426). SIGUSR2 is the gateway's
    # faulthandler stack-dump request (gateway/run_startup.py); unforwarded it terminates
    # the wrapper the same way instead of dumping stacks.
    forwarded = (
        signal.SIGTERM,
        signal.SIGINT,
        getattr(signal, "SIGHUP", None),
        getattr(signal, "SIGUSR1", None),
        getattr(signal, "SIGUSR2", None),
    )
    for signum in forwarded:
        if signum is not None:
            try:
                previous[signum] = signal.getsignal(signum)
                signal.signal(signum, _forward)
            except (OSError, RuntimeError, ValueError):
                previous.pop(signum, None)
    return previous


def _is_hermes_gateway_run_argv(command: Sequence[str]) -> bool:
    """True for Hermes ``gateway run`` argv this wrapper is allowed to upgrade.

    The wrapper is generic. Only historical/current Hermes gateway shapes get ``--external-
    supervisor``; an arbitrary launchd child must not be marked as gateway-supervised (#87005).
    """
    try:
        from gateway.status import looks_like_gateway_command_line
    except Exception:
        return False
    return bool(looks_like_gateway_command_line(" ".join(str(part) for part in command)))


def _child_launchd_label_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Env vars that carry this wrapper's launchd identity to the grandchild.

    launchd stamps ``XPC_SERVICE_NAME=<job label>`` only on this wrapper (its direct child; an
    interactive shell has none, the grandchild sees ``XPC_SERVICE_NAME=0``). Re-exporting the
    label lets the gateway resolve its job without it (the stop-drain cap reading the live
    ``ExitTimeOut``, the exit-75 restart route, the control-socket supervisor declaration — all
    via ``gateway.restart.launchd_job_label``). Only ``ai.hermes.*`` labels are exported;
    app-coalition labels are meaningless as a job identity.
    """
    env = os.environ if environ is None else environ
    for variable in ("XPC_SERVICE_NAME", _LAUNCHD_LABEL_ENV):
        label = str(env.get(variable, "") or "").strip()
        if label.startswith("ai.hermes"):
            return {_LAUNCHD_LABEL_ENV: label}
    return {}


def _prepare_child_command(command: Sequence[str], environ: Mapping[str, str] | None = None) -> list[str]:
    """Return the argv to exec, upgrading stale launchd-wrapped gateway commands.

    launchd stamps ``XPC_SERVICE_NAME=<job label>`` only on this wrapper (its direct child; an
    interactive shell has none, the grandchild sees ``XPC_SERVICE_NAME=0``). Newly generated
    plists put ``--external-supervisor`` on the inner ``gateway run`` so ``hermes update`` can see
    the flag on the live process argv.
    """
    argv = [str(part) for part in command]
    env = os.environ if environ is None else environ
    xpc_service = str(env.get("XPC_SERVICE_NAME", "")).strip()
    if EXTERNAL_SUPERVISOR_FLAG not in argv and xpc_service and xpc_service != "0" and _is_hermes_gateway_run_argv(argv):
        argv.append(EXTERNAL_SUPERVISOR_FLAG)
    return argv


def _child_returncode_for_supervisor(command: Sequence[str], returncode: int) -> int:
    """Exit status the launchd wrapper reports for *returncode* from *command*.

    Signal deaths stay 128+N. Gateway EX_CONFIG (78) becomes 0 so
    ``KeepAlive.SuccessfulExit=false`` parks the job instead of crash-looping;
    a non-gateway child that happens to exit 78 is left alone.
    """
    if returncode < 0:
        return 128 + abs(returncode)
    if returncode == _GATEWAY_FATAL_CONFIG_EXIT_CODE and _is_hermes_gateway_run_argv(command):
        return 0
    return returncode


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a command, timestamp each stderr line into a log file and each stdout line to stdout."
    )
    parser.add_argument("--error-log", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command after --")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    log_path: Path = args.error_log

    try:
        proc = subprocess.Popen(
            _prepare_child_command(args.command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **_child_launchd_label_env()},
        )
    except OSError as exc:
        with _open_log(log_path) as log_file:
            _write_timestamped_line(log_file, f"failed to start stderr-timestamped command: {exc}")
        return 127

    assert proc.stdout is not None and proc.stderr is not None
    stdout_pump = threading.Thread(target=_copy_stdout_with_timestamps, args=(proc.stdout,), daemon=True)
    stdout_pump.start()
    previous_handlers = _install_signal_forwarders(proc)
    try:
        _copy_stderr_with_timestamps(proc.stderr, log_path)
        # Keep forwarding until the child has actually exited: a signal that lands between
        # its stderr EOF and wait() would otherwise kill the wrapper with the default action.
        returncode = proc.wait()
        stdout_pump.join(_STDOUT_DRAIN_TIMEOUT_S)
    finally:
        proc.stderr.close()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return _child_returncode_for_supervisor(args.command, returncode)




def run_isolated_profile(spec, *, provider=None):
    """Supervise a separately approved disposable Core/Control pair.

    The programmatic launch owner supplies the provider. A JSON launch plan or
    CLI flag cannot establish bootstrap authority; the default is denied.
    """
    import hashlib
    import selectors
    import socket
    import time
    import uuid
    from agent.native_wire import receive, send, verified
    from agent.native_bootstrap import PinnedBootstrapProvider
    from hermes_platform.native_peer import process_snapshot

    if provider is None:
        raise PermissionError('isolated supervisor trust root UNKNOWN')
    wrapper_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    provider.verify_launch(spec, wrapper_digest)
    profile = Path(spec['profile']).resolve()
    if not (profile / '.hermes-isolated-profile').is_file():
        raise PermissionError('disposable isolated profile required')
    owner_lock = (profile / '.native-supervisor.lock').open('a')
    import fcntl
    try:
        fcntl.flock(owner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        owner_lock.close()
        raise PermissionError('isolated supervisor owner already alive') from None
    epoch = uuid.uuid4().hex
    children = {}
    exit_signal = []
    previous = {}
    wrapper_identity = process_snapshot(os.getpid())
    log_path = Path(spec['error_log'])

    def forward(signum, _frame):
        exit_signal.append(signum)
        for item in children.values():
            try:item['process'].send_signal(signum)
            except ProcessLookupError:pass

    def packet(role, operation, data):
        item = children[role]
        item['seq'] += 1
        send(item['socket'], {'contract': 'hermes.private-bootstrap/1', 'role': role,
            'profile': str(profile), 'supervisor': wrapper_identity, 'channel': item['channel'],
            'seq': item['seq'], 'operation': operation, 'data': data})
        reply = receive(item['socket'], 5)
        if reply.get('channel') != item['channel'] or reply.get('seq') != item['seq']:
            raise PermissionError('bootstrap acknowledgment mismatch')
        return reply['result']

    def spawn(role):
        config = spec[role]
        artifact = hashlib.sha256(Path(config['artifact']).read_bytes()).hexdigest()
        if artifact != config['artifact_digest']:
            raise PermissionError('isolated child artifact mismatch')
        parent, child = socket.socketpair()
        parent.set_inheritable(False);child.set_inheritable(False)
        fd = child.fileno()
        command = [*config['command'], '--native-bootstrap-fd', str(fd)]
        env = {'HOME': str(profile.parent), 'HERMES_HOME': str(profile),
               'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            proc = subprocess.Popen(command, pass_fds=(fd,), close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        except BaseException:
            parent.close();raise
        finally:child.close()
        item = {'process': proc, 'socket': parent, 'seq': 0, 'channel': uuid.uuid4().hex}
        children[role] = item
        item['pumps'] = [threading.Thread(target=_copy_stdout_with_timestamps,args=(proc.stdout,),daemon=True),
                         threading.Thread(target=_copy_stderr_with_timestamps,args=(proc.stderr,log_path),daemon=True)]
        for pump in item['pumps']:pump.start()
        hello = receive(parent, 5)
        actual = process_snapshot(proc.pid)
        if (hello.get('contract') != 'hermes.private-bootstrap/1' or hello.get('role') != role
                or hello.get('profile') != str(profile) or hello.get('process') != actual
                or hello.get('artifact_digest') != artifact):
            raise PermissionError('isolated child readiness mismatch')
        item.update(identity=actual, hello=hello)
        return item

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, forward)
        core, control = spawn('core'), spawn('control')
        nonce = uuid.uuid4().hex
        proof = packet('core', 'prove', {'nonce': nonce, 'control_epoch': control['hello']['data']['control_epoch']})
        public = core['hello']['data']
        body = verified(public['manager']['public_key'], proof)
        if body != {'nonce': nonce, 'control_epoch': control['hello']['data']['control_epoch'], 'public': public}:
            raise PermissionError('Core Manager bootstrap proof mismatch')
        approvals = []
        for role in ('manager', 'business'):
            identity = public[role]
            record = {'role': role, 'profile': str(profile), 'process': core['identity'],
                'approval_ref': uuid.uuid4().hex, 'supervisor_epoch': epoch,
                'control_epoch': control['hello']['data']['control_epoch'],
                'artifact_digest': spec['core']['artifact_digest'], 'expires_at': time.time()+300, **identity}
            # Provider corroborates the owned Popen identities/artifact/profile.
            provider.verify_child(role, record, core['identity'])
            PinnedBootstrapProvider(record).verify(record)
            packet('control', 'approval', record)
            packet('core', 'approval', record)
            approvals.append(record['approval_ref'])
        packet('core', 'connect', {'control': control['identity'], 'path': control['hello']['data']['path']})
        ready = {'wrapper': wrapper_identity, 'supervisor_epoch': epoch,
                 'control_epoch': control['hello']['data']['control_epoch'],
                 'children': {role: item['process'].pid for role,item in children.items()},
                 'approval_refs': approvals}
        callback = getattr(provider, 'ready', None)
        if callable(callback):callback(ready)
        selector = selectors.DefaultSelector()
        for role,item in children.items():selector.register(item['socket'], selectors.EVENT_READ, role)
        try:
            while not exit_signal:
                ended = [item['process'] for item in children.values() if item['process'].poll() is not None]
                if ended:return _child_returncode_for_supervisor([], ended[0].returncode)
                for key,_ in selector.select(.02):
                    # Unexpected EOF/unsolicited frames close both children, never promote a successor.
                    if not key.fileobj.recv(1, socket.MSG_PEEK):
                        if exit_signal:return 128 + exit_signal[0]
                        try:
                            rc = children[key.data]['process'].wait(timeout=.2)
                        except subprocess.TimeoutExpired:
                            return 127
                        return _child_returncode_for_supervisor([], rc)
                    raise PermissionError('unsolicited bootstrap data')
                if callable(getattr(provider, 'should_stop', None)) and provider.should_stop():
                    packet('core', 'revoke', {'operation_id': uuid.uuid4().hex})
                    return 0
        finally:selector.close()
        return 128 + exit_signal[0]
    except (EOFError, OSError):
        if exit_signal:return 128 + exit_signal[0]
        raise
    finally:
        # Closing private FDs also lets children terminate on wrapper fail-stop.
        for item in children.values():
            try:item['socket'].shutdown(socket.SHUT_RDWR)
            except OSError:pass
            item['socket'].close()
        for item in children.values():
            proc = item['process']
            if proc.poll() is None:
                try:proc.terminate()
                except ProcessLookupError:pass
            try:proc.wait(3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(2)
            for pump in item.get('pumps', ()):pump.join(1)
            for pipe in (proc.stdout,proc.stderr):
                if pipe:pipe.close()
        for signum, handler in previous.items():signal.signal(signum, handler)
        owner_lock.close()


def isolated_profile_main(argv):
    """Launch plans carry no authority; deployment provider is intentionally absent."""
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument('--isolated-profile', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        return run_isolated_profile(json.loads(args.isolated_profile.read_text()))
    except (OSError, ValueError, PermissionError) as exc:
        print(f'Isolated native bootstrap unavailable: {type(exc).__name__}', file=sys.stderr)
        return 78


if __name__ == "__main__":
    if sys.argv[1:2] == ["--isolated-profile"]:
        sys.exit(isolated_profile_main(sys.argv[1:]))
    sys.exit(main())
